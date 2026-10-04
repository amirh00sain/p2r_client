package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// Session is one tunneled flow owned by the client (TCP via SOCKS5 CONNECT,
// or UDP via SOCKS5 UDP ASSOCIATE).
type Session interface {
	Sid() uint32
	// HandleData delivers a DATA payload that arrived from the server.
	HandleData(payload []byte)
	// LocalClose tears the session down locally after the server sent CLOSE
	// (or the tunnel died); it must NOT echo CLOSE back to the server.
	LocalClose(reason string)
	Description() string
}

// Errors surfaced to the SOCKS5 layer.
var (
	ErrTunnelDown    = errors.New("tunnel is not connected")
	ErrTooManyOpens  = errors.New("session limit reached")
	ErrSessionExists = errors.New("session id already in use")
)

// Tunnel owns the live WSS connection, the session table and the heartbeat.
type Tunnel struct {
	cfg *Config
	log *Logger

	mu       sync.RWMutex
	conn     *wsConn
	sessions map[uint32]Session

	nextID atomic.Uint32
	opens   atomic.Uint64
	closes  atomic.Uint64

	readyMu sync.RWMutex
	ready   bool
	readyCh chan struct{} // replaced whenever readiness toggles

	connGeneration atomic.Uint64
}

// NewTunnel prepares an empty tunnel (not yet connected).
func NewTunnel(cfg *Config, log *Logger) *Tunnel {
	t := &Tunnel{
		cfg:      cfg,
		log:      log,
		sessions: make(map[uint32]Session),
		readyCh:  make(chan struct{}),
	}
	t.nextID.Store(1)
	return t
}

// ----------------------------------------------------------------------------
// Connection management (driven by reconnect.go)
// ----------------------------------------------------------------------------

// install swaps in a freshly dialled connection and marks the tunnel ready.
func (t *Tunnel) install(w *wsConn) {
	t.mu.Lock()
	old := t.conn
	t.conn = w
	t.mu.Unlock()
	if old != nil {
		old.close()
	}

	t.readyMu.Lock()
	if !t.ready {
		t.ready = true
		close(t.readyCh)
	}
	t.readyMu.Unlock()

	t.connGeneration.Add(1)
}

// detach clears the connection and flips readiness back to false.
func (t *Tunnel) detach() *wsConn {
	t.mu.Lock()
	w := t.conn
	t.conn = nil
	t.mu.Unlock()

	t.readyMu.Lock()
	if t.ready {
		t.ready = false
		t.readyCh = make(chan struct{})
	}
	t.readyMu.Unlock()

	return w
}

// IsReady reports whether frames can be sent right now.
func (t *Tunnel) IsReady() bool {
	t.readyMu.RLock()
	defer t.readyMu.RUnlock()
	return t.ready
}

// WaitReady blocks until the tunnel is connected or ctx expires.
func (t *Tunnel) WaitReady(ctx context.Context) error {
	for {
		t.readyMu.RLock()
		ch := t.readyCh
		ready := t.ready
		t.readyMu.RUnlock()
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return ErrTunnelDown
		case <-ch:
		}
	}
}

// Send transmits one frame over the current connection.
func (t *Tunnel) Send(typ byte, sessionID uint32, payload []byte) error {
	t.mu.RLock()
	w := t.conn
	t.mu.RUnlock()
	if w == nil {
		return ErrTunnelDown
	}
	return w.send(typ, sessionID, payload)
}

// currentConn exposes the active socket for read loops.
func (t *Tunnel) currentConn() *wsConn {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.conn
}

// ----------------------------------------------------------------------------
// Session table
// ----------------------------------------------------------------------------

// Register reserves a session id for a freshly created local session.
func (t *Tunnel) Register(s Session) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.sessions) >= t.cfg.MaxSessions {
		return ErrTooManyOpens
	}
	if _, ok := t.sessions[s.Sid()]; ok {
		return ErrSessionExists
	}
	t.sessions[s.Sid()] = s
	return nil
}

// Unregister drops a session from the table (idempotent).
func (t *Tunnel) Unregister(sid uint32) {
	t.mu.Lock()
	delete(t.sessions, sid)
	t.mu.Unlock()
}

func (t *Tunnel) lookup(sid uint32) (Session, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	s, ok := t.sessions[sid]
	return s, ok
}

// SessionCount returns the number of live local sessions.
func (t *Tunnel) SessionCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.sessions)
}

// OpenCount reports cumulative OPEN frames (for -stats output).
func (t *Tunnel) OpenCount() uint64 { return t.opens.Load() }

// CloseCount reports cumulative CLOSE frames.
func (t *Tunnel) CloseCount() uint64 { return t.closes.Load() }

// allocSessionID finds an unused id, wrapping at 2^32.
func (t *Tunnel) allocSessionID() (uint32, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.sessions) >= t.cfg.MaxSessions {
		return 0, false
	}
	for i := 0; i < 1<<20; i++ {
		id := t.nextID.Add(1)
		if id == 0 {
			continue
		}
		if _, taken := t.sessions[id]; !taken {
			return id, true
		}
	}
	return 0, false
}

// closeAllSessions tears down every local session (tunnel died / shutting down).
func (t *Tunnel) closeAllSessions(reason string) {
	t.mu.Lock()
	sessions := make([]Session, 0, len(t.sessions))
	for _, s := range t.sessions {
		sessions = append(sessions, s)
	}
	t.sessions = make(map[uint32]Session)
	t.mu.Unlock()

	for _, s := range sessions {
		s.LocalClose(reason)
	}
}

// ----------------------------------------------------------------------------
// Read loop + heartbeat for one connection
// ----------------------------------------------------------------------------

// serveConn reads frames until the connection breaks, then returns the error.
func (t *Tunnel) serveConn(ctx context.Context, w *wsConn) error {
	readErr := make(chan error, 1)

	go func() {
		for {
			msgType, data, err := w.read()
			if err != nil {
				readErr <- err
				return
			}
			if msgType != websocket.BinaryMessage {
				continue
			}
			frame, err := DecodeFrame(data)
			if err != nil {
				t.log.Warnf("dropped malformed frame: %v", err)
				continue
			}
			t.dispatch(frame)
		}
	}()

	// Heartbeat: PING every HeartbeatInterval, and force a reconnect when the
	// server has been silent for 3x that interval.
	ping := time.NewTicker(t.cfg.HeartbeatInterval)
	defer ping.Stop()
	silenceLimit := t.cfg.HeartbeatInterval * 3

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-readErr:
			return err
		case <-ping.C:
			if time.Since(w.lastReceive()) > silenceLimit {
				return fmt.Errorf("heartbeat timeout: no data for %s", time.Since(w.lastReceive()).Round(time.Second))
			}
			if err := w.ping(); err != nil {
				return fmt.Errorf("ws ping: %w", err)
			}
			if err := t.Send(MsgPing, 0, []byte("hb")); err != nil {
				return fmt.Errorf("protocol ping: %w", err)
			}
			t.log.Debugf("heartbeat sent (idle %s)", time.Since(w.lastReceive()).Round(time.Second))
		}
	}
}

// dispatch routes one inbound frame.
func (t *Tunnel) dispatch(f *Frame) {
	switch f.Type {
	case MsgData:
		s, ok := t.lookup(f.SessionID)
		if !ok {
			// Session we no longer know about: tell the server to forget it.
			t.log.Debugf("DATA for unknown sid=%d (%d bytes) dropped", f.SessionID, len(f.Payload))
			_ = t.Send(MsgClose, f.SessionID, []byte("unknown session"))
			return
		}
		s.HandleData(f.Payload)
	case MsgClose:
		t.closes.Add(1)
		s, ok := t.lookup(f.SessionID)
		if !ok {
			return
		}
		reason := string(f.Payload)
		if reason == "" {
			reason = "closed by server"
		}
		t.log.Debugf("CLOSE sid=%d (%s)", f.SessionID, reason)
		t.Unregister(f.SessionID)
		s.LocalClose(reason)
	case MsgPing:
		_ = t.Send(MsgPong, f.SessionID, f.Payload)
	case MsgPong:
		// Server proved it is alive; lastReceive already refreshed.
	case MsgOpen:
		// Server-side OPEN frames are not part of the protocol; ignore.
	}
}

// String renders a short status line for the console.
func (t *Tunnel) String() string {
	state := "disconnected"
	if t.IsReady() {
		state = "connected"
	}
	return fmt.Sprintf("%s sessions=%d opened=%d", state, t.SessionCount(), t.OpenCount())
}
