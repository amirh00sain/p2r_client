package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// SOCKS5 protocol constants (RFC 1928).
const (
	socksVersion5 = 0x05

	authNone         = 0x00
	authNoAcceptable = 0xFF

	cmdConnect      = 0x01
	cmdBind         = 0x02
	cmdUDPAssociate = 0x03

	repSuccess              = 0x00
	repGeneralFailure       = 0x01
	repNotAllowed           = 0x02
	repNetworkUnreachable   = 0x03
	repHostUnreachable      = 0x04
	repConnectionRefused    = 0x05
	repTTLExpired           = 0x06
	repCommandNotSupported  = 0x07
	repAddressNotSupported  = 0x08

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	handshakeTimeout = 10 * time.Second
	udpIdleTimeout   = 2 * time.Minute
)

// SOCKS5Server is the local proxy applications connect to.
type SOCKS5Server struct {
	cfg *Config
	tun *Tunnel
	log *Logger

	ln net.Listener
}

// NewSOCKS5Server prepares the local proxy (not yet listening).
func NewSOCKS5Server(cfg *Config, tun *Tunnel, log *Logger) *SOCKS5Server {
	return &SOCKS5Server{cfg: cfg, tun: tun, log: log}
}

// Listen binds the local address without serving yet.
func (s *SOCKS5Server) Listen() error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.Listen, err)
	}
	s.ln = ln
	return nil
}

// Addr returns the bound address (useful when port 0 was requested).
func (s *SOCKS5Server) Addr() net.Addr {
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Serve accepts connections until ctx is cancelled or the listener closes.
func (s *SOCKS5Server) Serve(ctx context.Context) error {
	if s.ln == nil {
		if err := s.Listen(); err != nil {
			return err
		}
	}
	go func() {
		<-ctx.Done()
		_ = s.ln.Close()
	}()

	var wg sync.WaitGroup
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			wg.Wait()
			return err
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					s.log.Errorf("socks5 panic from %s: %v", c.RemoteAddr(), r)
				}
			}()
			s.handleConn(c)
		}(conn)
	}
}

// handleConn runs greeting -> authentication -> request for one TCP client.
func (s *SOCKS5Server) handleConn(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()

	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))

	// ---- greeting: VER NMETHODS METHODS... ----
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		s.log.Debugf("%s: greeting read: %v", remote, err)
		return
	}
	if head[0] != socksVersion5 {
		s.log.Warnf("%s: unsupported SOCKS version 0x%02x", remote, head[0])
		return
	}
	methods := make([]byte, int(head[1]))
	if len(methods) > 0 {
		if _, err := io.ReadFull(conn, methods); err != nil {
			return
		}
	}
	if !containsByte(methods, authNone) {
		_, _ = conn.Write([]byte{socksVersion5, authNoAcceptable})
		s.log.Warnf("%s: no acceptable auth method (client offered %v)", remote, methods)
		return
	}
	if _, err := conn.Write([]byte{socksVersion5, authNone}); err != nil {
		return
	}

	// ---- request: VER CMD RSV ATYP ADDR PORT ----
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		s.log.Debugf("%s: request read: %v", remote, err)
		return
	}
	if req[0] != socksVersion5 {
		return
	}
	cmd := req[1]
	host, port, err := readSocksAddress(conn, req[3])
	if err != nil {
		s.log.Warnf("%s: bad address in request: %v", remote, err)
		_ = writeSocksReply(conn, repAddressNotSupported, "0.0.0.0", 0)
		return
	}
	portNum, _ := strconv.ParseUint(port, 10, 16)
	target := net.JoinHostPort(host, port)

	_ = conn.SetDeadline(time.Time{}) // traffic phase has its own deadlines

	switch cmd {
	case cmdConnect:
		s.handleConnect(conn, remote, target)
	case cmdUDPAssociate:
		s.handleUDPAssociate(conn, remote, host, uint16(portNum))
	case cmdBind:
		s.log.Warnf("%s: BIND command rejected", remote)
		_ = writeSocksReply(conn, repCommandNotSupported, "0.0.0.0", 0)
	default:
		s.log.Warnf("%s: unsupported command 0x%02x", remote, cmd)
		_ = writeSocksReply(conn, repCommandNotSupported, "0.0.0.0", 0)
	}
}

// handleConnect creates a tunnel session and pipes bytes both ways.
func (s *SOCKS5Server) handleConnect(conn net.Conn, remote, target string) {
	sid, ok := s.tun.allocSessionID()
	if !ok {
		s.log.Warnf("%s: CONNECT %s rejected: local session limit %d", remote, target, s.cfg.MaxSessions)
		_ = writeSocksReply(conn, repGeneralFailure, "0.0.0.0", 0)
		return
	}

	sess := &TCPSession{
		tun:    s.tun,
		log:    s.log,
		sid:    sid,
		local:  conn,
		target: target,
	}
	if err := s.tun.Register(sess); err != nil {
		s.log.Warnf("%s: CONNECT %s rejected: %v", remote, target, err)
		_ = writeSocksReply(conn, repGeneralFailure, "0.0.0.0", 0)
		return
	}

	// The tunnel may be mid-reconnect; wait briefly instead of failing an
	// application that connected the moment the network came back.
	waitCtx, cancel := context.WithTimeout(context.Background(), WaitReadyTimeout)
	waitErr := s.tun.WaitReady(waitCtx)
	cancel()
	if waitErr != nil {
		s.tun.Unregister(sid)
		s.log.Warnf("%s: CONNECT %s rejected: %v", remote, target, waitErr)
		_ = writeSocksReply(conn, repNetworkUnreachable, "0.0.0.0", 0)
		return
	}

	if err := s.tun.Send(MsgOpen, sid, []byte(target)); err != nil {
		s.tun.Unregister(sid)
		s.log.Warnf("%s: CONNECT %s rejected: %v", remote, target, err)
		_ = writeSocksReply(conn, repGeneralFailure, "0.0.0.0", 0)
		return
	}

	if err := writeSocksReply(conn, repSuccess, "0.0.0.0", 0); err != nil {
		sess.LocalClose("reply failed")
		return
	}

	s.log.Infof("%s: CONNECT sid=%d -> %s", remote, sid, target)
	s.tun.opens.Add(1)
	sess.pump() // blocks until the local socket is done
}

// handleUDPAssociate binds a local UDP relay, registers a UDP session, and
// keeps the control connection open for its lifetime (RFC 1928 §6).
func (s *SOCKS5Server) handleUDPAssociate(conn net.Conn, remote, host string, port uint16) {
	if !s.cfg.EnableUDP {
		s.log.Warnf("%s: UDP ASSOCIATE disabled by config", remote)
		_ = writeSocksReply(conn, repCommandNotSupported, "0.0.0.0", 0)
		return
	}

	// Bind the relay next to the control connection's local address so the
	// application gets a usable BND.ADDR.
	controlLocal := conn.LocalAddr().String()
	bindHost, _, err := net.SplitHostPort(controlLocal)
	if err != nil || bindHost == "" {
		bindHost = "127.0.0.1"
	}
	pc, err := net.ListenPacket("udp", net.JoinHostPort(bindHost, "0"))
	if err != nil {
		s.log.Errorf("%s: UDP relay bind failed: %v", remote, err)
		_ = writeSocksReply(conn, repGeneralFailure, "0.0.0.0", 0)
		return
	}
	relay := pc.(*net.UDPConn)
	relayAddr := relay.LocalAddr().(*net.UDPAddr)

	sid, ok := s.tun.allocSessionID()
	if !ok {
		_ = relay.Close()
		_ = writeSocksReply(conn, repGeneralFailure, "0.0.0.0", 0)
		return
	}

	usp := &UDPAssocSession{
		tun:    s.tun,
		log:    s.log,
		sid:    sid,
		conn:   relay,
		remote: remote,
	}
	if err := s.tun.Register(usp); err != nil {
		_ = relay.Close()
		_ = writeSocksReply(conn, repGeneralFailure, "0.0.0.0", 0)
		return
	}

	target := "udp://" + relayAddr.String()
	if err := s.tun.Send(MsgOpen, sid, []byte(target)); err != nil {
		s.tun.Unregister(sid)
		_ = relay.Close()
		_ = writeSocksReply(conn, repGeneralFailure, "0.0.0.0", 0)
		return
	}

	if err := writeSocksReply(conn, repSuccess, relayAddr.IP.String(), uint16(relayAddr.Port)); err != nil {
		usp.LocalClose("reply failed")
		return
	}

	s.log.Infof("%s: UDP ASSOCIATE sid=%d relay=%s (requested %s:%d)",
		remote, sid, relayAddr.String(), host, port)
	s.tun.opens.Add(1)
	s.tun.OpenCount()

	// RFC 1928: the association lives as long as the control TCP connection.
	go usp.relayLoop()
	buf := make([]byte, 64)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		n, err := conn.Read(buf)
		if n == 0 && err != nil {
			break
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue // idle control conn: keep the association
			}
			break
		}
	}
	usp.LocalClose("udp associate ended")
	s.log.Infof("%s: UDP ASSOCIATE sid=%d finished", remote, sid)
}

// ----------------------------------------------------------------------------
// TCP session
// ----------------------------------------------------------------------------

// TCPSession bridges one local SOCKS5 CONNECT socket to a tunnel session.
type TCPSession struct {
	tun    *Tunnel
	log    *Logger
	sid    uint32
	local  net.Conn
	target string

	closeOnce sync.Once
}

// Sid implements Session.
func (s *TCPSession) Sid() uint32 { return s.sid }

// Description implements Session.
func (s *TCPSession) Description() string { return s.target }

// pump copies local -> tunnel until the socket closes, then notifies the server.
func (s *TCPSession) pump() {
	defer s.Close("local closed")
	buf := make([]byte, s.tun.cfg.bufferSize())
	for {
		n, err := s.local.Read(buf)
		if n > 0 {
			if serr := s.tun.Send(MsgData, s.sid, buf[:n]); serr != nil {
				s.log.Debugf("sid=%d send data: %v", s.sid, serr)
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				s.log.Debugf("sid=%d local read ended: %v", s.sid, err)
			}
			return
		}
	}
}

// HandleData implements Session: tunnel -> local socket.
func (s *TCPSession) HandleData(payload []byte) {
	if len(payload) == 0 {
		return
	}
	_ = s.local.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if _, err := s.local.Write(payload); err != nil {
		s.log.Debugf("sid=%d local write: %v", s.sid, err)
		s.Close("local write failed")
	}
}

// Close tears the session down and tells the server to drop its side.
func (s *TCPSession) Close(reason string) {
	s.closeOnce.Do(func() {
		_ = s.local.Close()
		s.tun.Unregister(s.sid)
		_ = s.tun.Send(MsgClose, s.sid, []byte(reason))
		s.log.Debugf("sid=%d closed (%s)", s.sid, reason)
	})
}

// LocalClose implements Session: the server (or the tunnel) ended the session.
// Frames are dispatched sequentially on one goroutine, so every DATA frame
// that preceded the CLOSE has already been written — no draining needed.
func (s *TCPSession) LocalClose(reason string) {
	s.closeOnce.Do(func() {
		_ = s.local.Close()
		s.log.Debugf("sid=%d closed locally (%s)", s.sid, reason)
	})
}

// ----------------------------------------------------------------------------
// UDP session
// ----------------------------------------------------------------------------

// UDPAssocSession bridges one SOCKS5 UDP ASSOCIATE relay socket.
type UDPAssocSession struct {
	tun    *Tunnel
	log    *Logger
	sid    uint32
	conn   *net.UDPConn
	remote string

	mu       sync.Mutex
	appAddr  *net.UDPAddr
	lastSeen time.Time

	closeOnce sync.Once
}

// Sid implements Session.
func (s *UDPAssocSession) Sid() uint32 { return s.sid }

// Description implements Session.
func (s *UDPAssocSession) Description() string { return "udp-assoc" }

// relayLoop reads datagrams from the application and pushes them upstream.
func (s *UDPAssocSession) relayLoop() {
	defer s.LocalClose("relay stopped")
	buf := make([]byte, s.tun.cfg.maxUDPPacket())
	for {
		n, from, err := s.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		dst, data, err := parseSocksUDP(buf[:n])
		if err != nil {
			s.log.Debugf("sid=%d bad socks udp packet: %v", s.sid, err)
			continue
		}
		s.setApp(from.(*net.UDPAddr))
		enc := joinUDPDatagram(dst, data)
		if err := s.tun.Send(MsgData, s.sid, enc); err != nil {
			s.log.Debugf("sid=%d udp send: %v", s.sid, err)
			return
		}
	}
}

// HandleData implements Session: tunnel -> application socket.
func (s *UDPAssocSession) HandleData(payload []byte) {
	src, data, err := splitUDPDatagram(payload)
	if err != nil {
		s.log.Debugf("sid=%d bad tunnel datagram: %v", s.sid, err)
		return
	}
	s.mu.Lock()
	app := s.appAddr
	s.mu.Unlock()
	if app == nil || len(data) == 0 {
		return
	}
	pkt := append(socksUDPHeader(src), data...)
	_, _ = s.conn.WriteToUDP(pkt, app)
}

// LocalClose tears the relay down.
func (s *UDPAssocSession) LocalClose(reason string) {
	s.closeOnce.Do(func() {
		_ = s.conn.Close()
		s.log.Debugf("sid=%d udp closed (%s)", s.sid, reason)
	})
}

func (s *UDPAssocSession) setApp(addr *net.UDPAddr) {
	s.mu.Lock()
	s.appAddr = addr
	s.lastSeen = time.Now()
	s.mu.Unlock()
}

// ----------------------------------------------------------------------------
// SOCKS5 wire helpers
// ----------------------------------------------------------------------------

func containsByte(haystack []byte, needle byte) bool {
	for _, b := range haystack {
		if b == needle {
			return true
		}
	}
	return false
}

// readSocksAddress reads ATYP + address + port after the 4-byte header.
func readSocksAddress(r io.Reader, atyp byte) (string, string, error) {
	switch atyp {
	case atypIPv4:
		buf := make([]byte, 4+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", "", err
		}
		ip := net.IP(buf[:4]).String()
		return ip, fmt.Sprint(binary.BigEndian.Uint16(buf[4:])), nil
	case atypIPv6:
		buf := make([]byte, 16+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", "", err
		}
		ip := net.IP(buf[:16]).String()
		return ip, fmt.Sprint(binary.BigEndian.Uint16(buf[16:])), nil
	case atypDomain:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(r, lb); err != nil {
			return "", "", err
		}
		if lb[0] == 0 {
			return "", "", fmt.Errorf("empty domain")
		}
		rest := make([]byte, int(lb[0])+2)
		if _, err := io.ReadFull(r, rest); err != nil {
			return "", "", err
		}
		domain := string(rest[:len(rest)-2])
		port := binary.BigEndian.Uint16(rest[len(rest)-2:])
		return domain, fmt.Sprint(port), nil
	default:
		return "", "", fmt.Errorf("unsupported address type 0x%02x", atyp)
	}
}

// writeSocksReply sends VER REP RSV ATYP BND.ADDR BND.PORT.
func writeSocksReply(w io.Writer, rep byte, bndHost string, bndPort uint16) error {
	ip := net.ParseIP(bndHost)
	var addr []byte
	var atyp byte
	switch {
	case ip == nil || ip.To4() != nil:
		atyp = atypIPv4
		addr = make([]byte, 4)
		if ip4 := ip.To4(); ip4 != nil {
			copy(addr, ip4)
		}
	case len(ip) == net.IPv6len:
		atyp = atypIPv6
		addr = ip.To16()
	default:
		atyp = atypIPv4
		addr = []byte{0, 0, 0, 0}
	}
	buf := make([]byte, 0, 4+len(addr)+2)
	buf = append(buf, socksVersion5, rep, 0x00, atyp)
	buf = append(buf, addr...)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], bndPort)
	buf = append(buf, port[0], port[1])
	_, err := w.Write(buf)
	return err
}

// parseSocksUDP decodes FRAG=0 UDP headers: RSV(2) FRAG(1) ATYP ADDR PORT DATA.
func parseSocksUDP(b []byte) (string, []byte, error) {
	if len(b) < 4 {
		return "", nil, fmt.Errorf("packet too short (%d)", len(b))
	}
	if b[2] != 0 {
		return "", nil, fmt.Errorf("fragmentation not supported")
	}
	atyp := b[3]
	switch atyp {
	case atypIPv4:
		if len(b) < 4+4+2 {
			return "", nil, fmt.Errorf("truncated ipv4 header")
		}
		ip := net.IP(b[4:8]).String()
		port := binary.BigEndian.Uint16(b[8:10])
		return net.JoinHostPort(ip, fmt.Sprint(port)), b[10:], nil
	case atypIPv6:
		if len(b) < 4+16+2 {
			return "", nil, fmt.Errorf("truncated ipv6 header")
		}
		ip := net.IP(b[4:20]).String()
		port := binary.BigEndian.Uint16(b[20:22])
		return net.JoinHostPort(ip, fmt.Sprint(port)), b[22:], nil
	case atypDomain:
		if len(b) < 5 {
			return "", nil, fmt.Errorf("truncated domain header")
		}
		dl := int(b[4])
		if dl == 0 || len(b) < 5+dl+2 {
			return "", nil, fmt.Errorf("bad domain length %d", dl)
		}
		domain := string(b[5 : 5+dl])
		port := binary.BigEndian.Uint16(b[5+dl : 7+dl])
		return net.JoinHostPort(domain, fmt.Sprint(port)), b[7+dl:], nil
	default:
		return "", nil, fmt.Errorf("unsupported atyp 0x%02x", atyp)
	}
}

// socksUDPHeader builds the reply header around a "host:port" source.
func socksUDPHeader(src string) []byte {
	host, portStr, err := net.SplitHostPort(src)
	if err != nil {
		return []byte{0, 0, 0, atypIPv4, 0, 0, 0, 0, 0, 0}
	}
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	ip := net.ParseIP(host)

	var out []byte
	switch {
	case ip != nil && ip.To4() != nil:
		out = []byte{0, 0, 0, atypIPv4}
		out = append(out, ip.To4()...)
	case ip != nil && ip.To16() != nil:
		out = []byte{0, 0, 0, atypIPv6}
		out = append(out, ip.To16()...)
	default:
		// Domain form; only reached for non-IP sources (should not happen).
		if len(host) > 255 {
			host = host[:255]
		}
		out = []byte{0, 0, 0, atypDomain, byte(len(host))}
		out = append(out, host...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	return append(out, p[0], p[1])
}

// String helpers shared by the client binary.
