package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// wsConn wraps a gorilla connection with a write lock (gorilla allows only
// one concurrent writer) and the send/receive primitives the tunnel needs.
type wsConn struct {
	conn *websocket.Conn
	url  string

	writeMu sync.Mutex
	readMu  sync.Mutex

	lastRX atomicTime
	closed atomicBool
}

// dialWebSocket performs the authenticated WSS handshake. The token travels
// both as a query parameter and as a header so the server's extractor can
// pick either one up.
func dialWebSocket(cfg *Config, log *Logger) (*wsConn, error) {
	endpoint, err := withToken(cfg.Server, cfg.Token)
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.InsecureSkipTLS {
		tlsCfg.InsecureSkipVerify = true
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: cfg.DialTimeout,
		Subprotocols:     []string{"spider-wss-v1"},
		TLSClientConfig:  tlsCfg,
		NetDialContext:   nil,
		Proxy:            http.ProxyFromEnvironment,
	}

	hdr := http.Header{}
	hdr.Set("X-Spider-Token", cfg.Token)
	hdr.Set("Authorization", "Bearer "+cfg.Token)

	ctxDial, cancel := context.WithTimeout(context.Background(), cfg.DialTimeout)
	defer cancel()

	type result struct {
		conn *websocket.Conn
		resp *http.Response
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		c, resp, err := dialer.DialContext(ctxDial, endpoint, hdr)
		ch <- result{c, resp, err}
	}()

	var out result
	select {
	case <-ctxDial.Done():
		return nil, fmt.Errorf("dial %s: %w", hostOf(cfg.Server), ctxDial.Err())
	case out = <-ch:
	}
	if out.err != nil {
		if out.resp != nil && out.resp.StatusCode > 0 {
			return nil, fmt.Errorf("dial %s: %w (HTTP %d)", hostOf(cfg.Server), out.err, out.resp.StatusCode)
		}
		return nil, fmt.Errorf("dial %s: %w", hostOf(cfg.Server), out.err)
	}

	w := &wsConn{conn: out.conn, url: endpoint}
	w.lastRX.set(time.Now())
	w.conn.SetReadLimit(int64(HeaderSize + MaxPayloadSize))
	log.Debugf("wss established: %s", hostOf(cfg.Server))
	return w, nil
}

// withToken appends the token to the endpoint URL.
func withToken(serverURL, token string) (string, error) {
	if serverURL == "" {
		return "", fmt.Errorf("empty server url")
	}
	sep := "?"
	if strings.Contains(serverURL, "?") {
		sep = "&"
	}
	return serverURL + sep + "token=" + urlQueryEscape(token), nil
}

// urlQueryEscape keeps tokens with reserved characters valid in a query.
func urlQueryEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func hostOf(u string) string {
	u = strings.TrimPrefix(u, "wss://")
	u = strings.TrimPrefix(u, "ws://")
	if i := strings.IndexAny(u, "/?"); i >= 0 {
		u = u[:i]
	}
	return u
}

// send writes one protocol frame.
func (w *wsConn) send(typ byte, sessionID uint32, payload []byte) error {
	if w.isClosed() {
		return fmt.Errorf("tunnel connection is closed")
	}
	buf := EncodeFrame(typ, sessionID, payload)
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	_ = w.conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	if err := w.conn.WriteMessage(websocket.BinaryMessage, buf); err != nil {
		w.close()
		return err
	}
	return nil
}

// read blocks for the next binary message.
func (w *wsConn) read() (int, []byte, error) {
	w.readMu.Lock()
	defer w.readMu.Unlock()
	typ, data, err := w.conn.ReadMessage()
	if err != nil {
		return 0, nil, err
	}
	w.lastRX.set(time.Now())
	return typ, data, nil
}

// ping sends a WebSocket-level ping control frame in addition to protocol
// PING frames; both keep middleboxes from dropping the idle tunnel.
func (w *wsConn) ping() error {
	if w.isClosed() {
		return fmt.Errorf("tunnel connection is closed")
	}
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	_ = w.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return w.conn.WriteControl(websocket.PingMessage, []byte("hb"), time.Now().Add(5*time.Second))
}

func (w *wsConn) isClosed() bool { return w.closed.get() }

func (w *wsConn) close() {
	if w.closed.swap(true) {
		return
	}
	_ = w.conn.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(time.Second),
	)
	_ = w.conn.Close()
}

// lastReceive returns when the last inbound message arrived.
func (w *wsConn) lastReceive() time.Time { return w.lastRX.get() }

// ----------------------------------------------------------------------------
// tiny atomics local to the client (keeps imports minimal)
// ----------------------------------------------------------------------------

type atomicBool struct {
	mu sync.Mutex
	v  bool
}

func (b *atomicBool) get() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.v
}

func (b *atomicBool) set(v bool) {
	b.mu.Lock()
	b.v = v
	b.mu.Unlock()
}

// swap sets v and returns the previous value.
func (b *atomicBool) swap(v bool) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	old := b.v
	b.v = v
	return old
}

type atomicTime struct {
	mu sync.Mutex
	t  time.Time
}

func (a *atomicTime) set(t time.Time) {
	a.mu.Lock()
	a.t = t
	a.mu.Unlock()
}

func (a *atomicTime) get() time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.t
}
