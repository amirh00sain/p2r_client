package main

import (
	"context"
	"errors"
	"time"
)

// Run keeps the tunnel alive for the whole process lifetime: dial, serve,
// back off, redial. Authentication (token) is re-sent on every attempt, and
// local sessions survive as long as the connection does — when the tunnel
// drops, all of them are closed so applications see a clean reset instead of
// a black hole.
//
// The SOCKS5 listener is completely independent: it keeps accepting new
// connections while the tunnel is down and refuses them cleanly (or waits up
// to WaitReadyTimeout for a reconnect that is already in flight).
func (t *Tunnel) Run(ctx context.Context) {
	backoff := t.cfg.ReconnectMin
	attempt := 0
	first := true

	for {
		if ctx.Err() != nil {
			return
		}

		if first {
			t.log.Infof("connecting to %s …", hostOf(t.cfg.Server))
			first = false
		} else {
			t.log.Infof("reconnecting in %s (attempt %d) …", backoff, attempt+1)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
		}
		attempt++

		started := time.Now()
		err := t.connectOnce(ctx)
		uptime := time.Since(started)
		if ctx.Err() != nil {
			return
		}

		// Whatever happened, local sessions belong to a dead pipe now.
		t.closeAllSessions("tunnel disconnected")
		if w := t.detach(); w != nil {
			w.close()
		}

		if err != nil && !errors.Is(err, context.Canceled) {
			t.log.Warnf("tunnel lost after %s: %v", uptime.Round(time.Second), err)
		} else {
			t.log.Warnf("tunnel lost after %s", uptime.Round(time.Second))
		}

		// A connection that stayed up for a while proves the network is fine,
		// so reset the backoff instead of staying at the previous ceiling.
		if uptime > 30*time.Second {
			backoff = t.cfg.ReconnectMin
		} else {
			backoff *= 2
			if backoff > t.cfg.ReconnectMax {
				backoff = t.cfg.ReconnectMax
			}
		}
	}
}

// connectOnce dials, installs the connection and serves it until it breaks.
func (t *Tunnel) connectOnce(ctx context.Context) error {
	w, err := dialWebSocket(t.cfg, t.log)
	if err != nil {
		return err
	}

	t.install(w)
	t.log.Infof("connected to %s (token=%s…, sessions=%d)",
		hostOf(t.cfg.Server), maskToken(t.cfg.Token), t.SessionCount())

	serveErr := t.serveConn(ctx, w)
	w.close()
	return serveErr
}

// WaitReadyTimeout is how long the SOCKS5 handler waits for an in-flight
// reconnect before answering the application with a failure.
const WaitReadyTimeout = 8 * time.Second

func maskToken(tok string) string {
	if len(tok) <= 8 {
		return "****"
	}
	return tok[:4] + "…" + tok[len(tok)-4:]
}
