package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Wire protocol (binary, one WebSocket binary message per frame):
//
//	[0]      version   uint8  = 1
//	[1]      type      uint8  = OPEN|DATA|CLOSE|PING|PONG
//	[2:6]    session   uint32 BE
//	[6:10]   length    uint32 BE (payload byte count)
//	[10:10+n] payload
const (
	ProtocolVersion byte   = 1
	HeaderSize      int    = 10
	MaxPayloadSize  int    = 1 << 20 // hard cap: 1 MiB per frame
)

// Frame types.
const (
	MsgOpen  byte = 0x01 // client -> server: session_id + "host:port"
	MsgData  byte = 0x02 // bidirectional: raw payload bytes
	MsgClose byte = 0x03 // either side: session_id, optional reason payload
	MsgPing  byte = 0x04 // either side: heartbeat, payload echoed back
	MsgPong  byte = 0x05 // either side: reply to PING
)

// ErrFrameTooLarge is returned when a frame exceeds MaxPayloadSize.
var ErrFrameTooLarge = errors.New("frame payload exceeds limit")

// Frame is one decoded protocol packet.
type Frame struct {
	Type      byte
	SessionID uint32
	Payload   []byte
}

// MsgName renders a frame type for logs.
func MsgName(t byte) string {
	switch t {
	case MsgOpen:
		return "OPEN"
	case MsgData:
		return "DATA"
	case MsgClose:
		return "CLOSE"
	case MsgPing:
		return "PING"
	case MsgPong:
		return "PONG"
	default:
		return fmt.Sprintf("UNK(0x%02x)", t)
	}
}

// EncodeFrame serialises a frame into the on-wire representation.
func EncodeFrame(typ byte, sessionID uint32, payload []byte) []byte {
	buf := make([]byte, HeaderSize+len(payload))
	buf[0] = ProtocolVersion
	buf[1] = typ
	binary.BigEndian.PutUint32(buf[2:6], sessionID)
	binary.BigEndian.PutUint32(buf[6:10], uint32(len(payload)))
	copy(buf[HeaderSize:], payload)
	return buf
}

// DecodeFrame parses exactly one frame out of a WebSocket binary message.
func DecodeFrame(b []byte) (*Frame, error) {
	if len(b) < HeaderSize {
		return nil, fmt.Errorf("frame too short: %d < %d bytes", len(b), HeaderSize)
	}
	if b[0] != ProtocolVersion {
		return nil, fmt.Errorf("unsupported protocol version %d", b[0])
	}
	typ := b[1]
	switch typ {
	case MsgOpen, MsgData, MsgClose, MsgPing, MsgPong:
	default:
		return nil, fmt.Errorf("unknown frame type 0x%02x", typ)
	}
	sid := binary.BigEndian.Uint32(b[2:6])
	plen := int(binary.BigEndian.Uint32(b[6:10]))
	body := len(b) - HeaderSize
	if plen != body {
		return nil, fmt.Errorf("payload length mismatch: header %d, body %d", plen, body)
	}
	if plen > MaxPayloadSize {
		return nil, fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, plen, MaxPayloadSize)
	}
	payload := make([]byte, body)
	copy(payload, b[HeaderSize:])
	return &Frame{Type: typ, SessionID: sid, Payload: payload}, nil
}

// ValidateTarget checks a "host:port" destination before it is dialled.
func ValidateTarget(target string) error {
	if target == "" {
		return errors.New("empty target")
	}
	if len(target) > 300 {
		return fmt.Errorf("target too long (%d bytes)", len(target))
	}
	host, port, err := splitHostPort(target)
	if err != nil {
		return err
	}
	if host == "" {
		return fmt.Errorf("empty host in target %q", target)
	}
	if port == "" {
		return fmt.Errorf("empty port in target %q", target)
	}
	for _, r := range host {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("target host contains a control character: %q", target)
		}
	}
	return nil
}

// splitHostPort is net.SplitHostPort with friendlier errors for log output.
func splitHostPort(target string) (host, port string, err error) {
	i := strings.LastIndexByte(target, ':')
	if i < 0 {
		return "", "", fmt.Errorf("target %q must be host:port", target)
	}
	host = target[:i]
	port = target[i+1:]
	// Strip IPv6 brackets.
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	if port == "" {
		return "", "", fmt.Errorf("target %q has an empty port", target)
	}
	for _, r := range port {
		if r < '0' || r > '9' {
			return "", "", fmt.Errorf("target %q has a non-numeric port", target)
		}
	}
	n := 0
	for _, r := range port {
		n = n*10 + int(r-'0')
		if n > 65535 {
			return "", "", fmt.Errorf("target %q port out of range", target)
		}
	}
	return host, port, nil
}
