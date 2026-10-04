package main

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	payload := []byte("OPEN example.com:443")
	enc := EncodeFrame(MsgOpen, 42, payload)

	got, err := DecodeFrame(enc)
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	if got.Type != MsgOpen || got.SessionID != 42 {
		t.Errorf("got type=%d sid=%d, want type=%d sid=42", got.Type, got.SessionID, MsgOpen)
	}
	if !bytes.Equal(got.Payload, payload) {
		t.Errorf("payload = %q", got.Payload)
	}
}

func TestFrameRejectsBadVersionAndType(t *testing.T) {
	valid := EncodeFrame(MsgData, 1, []byte("x"))

	badVersion := append([]byte{}, valid...)
	badVersion[0] = 0x09
	if _, err := DecodeFrame(badVersion); err == nil {
		t.Error("expected an error for an unsupported version")
	}

	badType := append([]byte{}, valid...)
	badType[1] = 0x42
	if _, err := DecodeFrame(badType); err == nil {
		t.Error("expected an error for an unknown message type")
	}

	if _, err := DecodeFrame(valid[:3]); err == nil {
		t.Error("expected an error for a truncated frame")
	}
}

func TestUDPDatagramEncapsulation(t *testing.T) {
	datagram := []byte("a DNS query payload")
	enc := joinUDPDatagram("8.8.8.8:53", datagram)

	src, got, err := splitUDPDatagram(enc)
	if err != nil {
		t.Fatalf("splitUDPDatagram: %v", err)
	}
	if src != "8.8.8.8:53" {
		t.Errorf("source = %q, want 8.8.8.8:53", src)
	}
	if !bytes.Equal(got, datagram) {
		t.Errorf("datagram = %q, want %q", got, datagram)
	}
}

func TestUDPDatagramRejectsMalformed(t *testing.T) {
	if _, _, err := splitUDPDatagram(nil); err == nil {
		t.Error("expected an error for an empty frame")
	}
	if _, _, err := splitUDPDatagram([]byte{0x00}); err == nil {
		t.Error("expected an error for a truncated length")
	}
	// Declared source longer than the actual body.
	if _, _, err := splitUDPDatagram([]byte{0x00, 0x20, 'a', 'b'}); err == nil {
		t.Error("expected an error for a truncated source")
	}
	// Zero-length destination.
	if _, _, err := splitUDPDatagram([]byte{0x00, 0x00}); err == nil {
		t.Error("expected an error for a zero-length destination")
	}
	// An empty datagram body is structurally valid; the relay drops it.
	empty := joinUDPDatagram("8.8.8.8:53", nil)
	if _, _, err := splitUDPDatagram(empty); err != nil {
		t.Errorf("an empty datagram is structurally valid: %v", err)
	}
}

func TestSocksUDPHeaderRoundTrip(t *testing.T) {
	header := socksUDPHeader("127.0.0.1:9099")
	body := append(header, []byte("payload")...)
	dst, data, err := parseSocksUDP(body)
	if err != nil {
		t.Fatalf("parseSocksUDP: %v", err)
	}
	if dst != "127.0.0.1:9099" {
		t.Errorf("dst = %q, want 127.0.0.1:9099", dst)
	}
	if string(data) != "payload" {
		t.Errorf("data = %q, want payload", data)
	}
}

func TestSocksUDPRejectsFragments(t *testing.T) {
	pkt := []byte{0, 0, 1, atypIPv4, 127, 0, 0, 1, 0, 53, 'x'}
	if _, _, err := parseSocksUDP(pkt); err == nil {
		t.Error("fragmented datagrams must be rejected")
	}
}
