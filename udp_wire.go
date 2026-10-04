package main

import (
	"encoding/binary"
	"fmt"
)

// UDP datagram encapsulation, identical on both sides of the tunnel.
//
// A DATA frame of a UDP session carries:
//
//	[2B dst_len BE][dst "host:port" bytes][raw datagram...]
//
// The textual destination keeps the tunnel protocol-agnostic: DNS, games and
// VoIP all retarget datagrams within a single SOCKS5 ASSOCIATE.
const udpHeaderLen = 2

// joinUDPDatagram encodes an upstream datagram for a destination.
func joinUDPDatagram(dst string, datagram []byte) []byte {
	if len(dst) > 260 {
		dst = dst[:260]
	}
	out := make([]byte, udpHeaderLen+len(dst)+len(datagram))
	binary.BigEndian.PutUint16(out[:udpHeaderLen], uint16(len(dst)))
	copy(out[udpHeaderLen:], dst)
	copy(out[udpHeaderLen+len(dst):], datagram)
	return out
}

// splitUDPDatagram decodes a downstream datagram and its source tag.
func splitUDPDatagram(payload []byte) (string, []byte, error) {
	if len(payload) < udpHeaderLen {
		return "", nil, fmt.Errorf("udp frame too short: %d bytes", len(payload))
	}
	srcLen := int(binary.BigEndian.Uint16(payload[:udpHeaderLen]))
	if srcLen <= 0 || srcLen > 260 {
		return "", nil, fmt.Errorf("bad udp source length %d", srcLen)
	}
	if len(payload) < udpHeaderLen+srcLen {
		return "", nil, fmt.Errorf("udp frame truncated: need %d, have %d", udpHeaderLen+srcLen, len(payload))
	}
	src := string(payload[udpHeaderLen : udpHeaderLen+srcLen])
	return src, payload[udpHeaderLen+srcLen:], nil
}
