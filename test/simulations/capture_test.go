package simulations

import (
	"net"
	"testing"
	"time"

	"edgesight/internal/capture"

	"github.com/google/gopacket"
)

func buildIPv4TCP(srcIP, dstIP string, srcPort, dstPort uint16, flags uint8, payload []byte) []byte {
	sip := net.ParseIP(srcIP).To4()
	dip := net.ParseIP(dstIP).To4()
	tcpLen := 20 + len(payload)
	ipLen := 20 + tcpLen
	pkt := make([]byte, 14+ipLen)
	pkt[12], pkt[13] = 0x08, 0x00
	pkt[14] = 0x45
	pkt[14+2], pkt[14+3] = byte(ipLen>>8), byte(ipLen)
	pkt[14+9] = 6
	copy(pkt[14+12:14+16], sip)
	copy(pkt[14+16:14+20], dip)
	off := 34
	pkt[off], pkt[off+1] = byte(srcPort>>8), byte(srcPort)
	pkt[off+2], pkt[off+3] = byte(dstPort>>8), byte(dstPort)
	pkt[off+13] = flags
	copy(pkt[off+20:], payload)
	cs := ipChecksum(pkt[14:34])
	pkt[14+10], pkt[14+11] = byte(cs>>8), byte(cs)
	return pkt
}

func parseIPv4(s string) []byte {
	var b [4]byte
	var n int
	for i := 0; i < 4; i++ {
		start := n
		for n < len(s) && s[n] != '.' {
			n++
		}
		v := 0
		for j := start; j < n; j++ {
			v = v*10 + int(s[j]-'0')
		}
		b[i] = byte(v)
		n++
	}
	return b[:]
}

func ipChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i < len(b)-1; i += 2 {
		sum += uint32(uint16(b[i])<<8 | uint16(b[i+1]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func TestParseIPv4TCP(t *testing.T) {
	pkt := buildIPv4TCP("192.168.1.1", "10.0.0.1", 54321, 443, 0x18, []byte("hello"))
	meta := capture.ParsePacket(pkt, gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(pkt), Length: len(pkt)})
	if meta == nil {
		t.Fatal("nil meta")
	}
	if meta.SrcIP != "192.168.1.1" || meta.DstIP != "10.0.0.1" {
		t.Fatalf("IPs mismatch: %s -> %s", meta.SrcIP, meta.DstIP)
	}
	if meta.SrcPort != 54321 || meta.DstPort != 443 {
		t.Fatalf("ports mismatch: %d -> %d", meta.SrcPort, meta.DstPort)
	}
	if meta.Proto != "tcp" {
		t.Fatalf("proto %s", meta.Proto)
	}
	if meta.Flags != "PA" {
		t.Fatalf("flags %s", meta.Flags)
	}
}

func TestParseIPv4UDP(t *testing.T) {
	// Minimal UDP packet
	sip := parseIPv4("192.168.1.1")
	dip := parseIPv4("8.8.8.8")
	udpLen := 8 + 4
	ipLen := 20 + udpLen
	pkt := make([]byte, 14+ipLen)
	pkt[12], pkt[13] = 0x08, 0x00
	pkt[14] = 0x45
	pkt[16], pkt[17] = byte(ipLen>>8), byte(ipLen)
	pkt[23] = 17
	copy(pkt[26:30], sip)
	copy(pkt[30:34], dip)
	off := 34
	pkt[off], pkt[off+1] = 0x13, 0x88   // 5000
	pkt[off+2], pkt[off+3] = 0x00, 0x35 // 53
	pkt[off+4], pkt[off+5] = byte(udpLen>>8), byte(udpLen)
	copy(pkt[off+8:], []byte("dns"))
	meta := capture.ParsePacket(pkt, gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(pkt), Length: len(pkt)})
	if meta.DstPort != 53 || meta.Proto != "udp" {
		t.Fatalf("expected UDP/53, got %s/%d", meta.Proto, meta.DstPort)
	}
}
