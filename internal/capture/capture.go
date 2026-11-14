package capture

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"edgesight/internal/config"
	"edgesight/pkg/protocol"

	"github.com/google/gopacket"
)

// Source is an abstraction over packet capture (AF_PACKET or test injection).
type Source interface {
	Init(cfg *config.Config) error
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	Close()
	SetBPFFilter(expr string) error
}

// Engine consumes packets from a Source, parses metadata, and routes it to handlers.
type Engine struct {
	cfg       *config.Config
	src       Source
	handlers  []func(*protocol.PacketMeta)
	mu        sync.RWMutex
	running   bool
	pktCount  int64
	byteCount int64
	startTime time.Time
}

// NewEngine creates a new capture engine with the given source.
func NewEngine(cfg *config.Config, src Source) *Engine {
	return &Engine{cfg: cfg, src: src, startTime: time.Now()}
}

// Register adds a packet handler.
func (e *Engine) Register(h func(*protocol.PacketMeta)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.handlers = append(e.handlers, h)
}

// Start initializes and runs the capture loop.
func (e *Engine) Start(ctx context.Context) error {
	if err := e.src.Init(e.cfg); err != nil {
		return fmt.Errorf("init capture source: %w", err)
	}
	if e.cfg.BPFFilter != "" {
		if err := e.src.SetBPFFilter(e.cfg.BPFFilter); err != nil {
			fmt.Printf("warning: BPF filter not applied: %v\n", err)
		}
	}
	e.running = true
	defer e.src.Close()

	for e.running {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		data, ci, err := e.src.ReadPacketData()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		e.pktCount++
		e.byteCount += int64(ci.CaptureLength)
		meta := ParsePacket(data, ci)
		if meta == nil {
			continue
		}
		e.dispatch(meta)
	}
	return nil
}

// Stop halts the capture loop.
func (e *Engine) Stop() {
	e.running = false
	e.src.Close()
}

// Stats returns captured packet statistics.
func (e *Engine) Stats() (int64, int64, time.Duration) {
	return e.pktCount, e.byteCount, time.Since(e.startTime)
}

func (e *Engine) dispatch(m *protocol.PacketMeta) {
	e.mu.RLock()
	h := make([]func(*protocol.PacketMeta), len(e.handlers))
	copy(h, e.handlers)
	e.mu.RUnlock()
	for _, fn := range h {
		fn(m)
	}
}

// ParsePacket extracts metadata from raw bytes. Exposed for simulation tests.
func ParsePacket(data []byte, ci gopacket.CaptureInfo) *protocol.PacketMeta {
	meta := &protocol.PacketMeta{
		Timestamp: ci.Timestamp,
		Length:    ci.CaptureLength,
	}
	if meta.Timestamp.IsZero() {
		meta.Timestamp = time.Now()
	}

	// Parse link-layer. Assume Ethernet for AF_PACKET; fallback to raw IP.
	var offset int
	if len(data) >= 14 {
		ethType := binary.BigEndian.Uint16(data[12:14])
		offset = 14
		switch ethType {
		case 0x0800:
		case 0x86DD:
		default:
			return meta // keep minimal metadata
		}
	}

	if len(data) < offset+20 {
		return meta
	}
	ipData := data[offset:]
	version := ipData[0] >> 4
	switch version {
	case 4:
		if len(ipData) < 20 {
			return meta
		}
		hl := int(ipData[0]&0x0f) * 4
		meta.SrcIP = net.IP(ipData[12:16]).String()
		meta.DstIP = net.IP(ipData[16:20]).String()
		proto := ipData[9]
		meta.Proto = protoName(proto)
		transport := ipData[hl:]
		if len(transport) >= 4 {
			if proto == 6 || proto == 17 {
				meta.SrcPort = binary.BigEndian.Uint16(transport[0:2])
				meta.DstPort = binary.BigEndian.Uint16(transport[2:4])
			}
			if proto == 6 && len(transport) >= 14 {
				flags := transport[13]
				meta.Flags = tcpFlags(flags)
			}
		}
	case 6:
		if len(ipData) < 40 {
			return meta
		}
		meta.SrcIP = net.IP(ipData[8:24]).String()
		meta.DstIP = net.IP(ipData[24:40]).String()
		next := ipData[6]
		meta.Proto = protoName(next)
		transport := ipData[40:]
		if len(transport) >= 4 && (next == 6 || next == 17) {
			meta.SrcPort = binary.BigEndian.Uint16(transport[0:2])
			meta.DstPort = binary.BigEndian.Uint16(transport[2:4])
		}
	}

	// Save a bounded payload sample.
	payloadLimit := 256
	if len(data) > payloadLimit {
		meta.Payload = data[:payloadLimit]
	} else {
		meta.Payload = data
	}
	return meta
}

func protoName(p uint8) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 47:
		return "gre"
	case 50:
		return "esp"
	case 58:
		return "icmpv6"
	default:
		return fmt.Sprintf("ip:%d", p)
	}
}

func tcpFlags(f uint8) string {
	const (
		tcpFin = 1 << iota
		tcpSyn
		tcpRst
		tcpPsh
		tcpAck
		tcpUrg
		tcpEce
		tcpCwr
	)
	bits := []uint8{tcpFin, tcpSyn, tcpRst, tcpPsh, tcpAck, tcpUrg, tcpEce, tcpCwr}
	labels := []string{"F", "S", "R", "P", "A", "U", "E", "C"}
	var out []byte
	for i, b := range bits {
		if f&b != 0 {
			out = append(out, labels[i][0])
		}
	}
	if len(out) == 0 {
		return "."
	}
	return string(out)
}

// TestSource is an in-memory packet source for simulation tests.
type TestSource struct {
	mu      sync.Mutex
	packets []testPacket
	pos     int
	closed  bool
}

type testPacket struct {
	data []byte
	ci   gopacket.CaptureInfo
}

// NewTestSource creates a test source.
func NewTestSource() *TestSource { return &TestSource{} }

// Inject appends a raw packet.
func (t *TestSource) Inject(data []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.packets = append(t.packets, testPacket{data: data, ci: gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(data), Length: len(data)}})
}

// InjectEthIPv4TCP builds and injects a minimal Ethernet+IPv4+TCP packet.
func (t *TestSource) InjectEthIPv4TCP(srcIP, dstIP string, srcPort, dstPort uint16, flags uint8, payload []byte) {
	sip := net.ParseIP(srcIP).To4()
	dip := net.ParseIP(dstIP).To4()
	if sip == nil || dip == nil {
		return
	}
	tcpLen := 20 + len(payload)
	ipLen := 20 + tcpLen
	pkt := make([]byte, 14+ipLen)
	// Ethernet
	pkt[12], pkt[13] = 0x08, 0x00
	// IPv4
	pkt[14] = 0x45
	binary.BigEndian.PutUint16(pkt[16:18], uint16(ipLen))
	pkt[23] = 6 // TCP
	copy(pkt[26:30], sip)
	copy(pkt[30:34], dip)
	// TCP
	off := 34
	binary.BigEndian.PutUint16(pkt[off:off+2], srcPort)
	binary.BigEndian.PutUint16(pkt[off+2:off+4], dstPort)
	pkt[off+13] = flags
	copy(pkt[off+20:], payload)
	// Simple IP checksum
	cs := ipChecksum(pkt[14:34])
	binary.BigEndian.PutUint16(pkt[24:26], cs)
	t.Inject(pkt)
}

func ipChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i < len(b)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (t *TestSource) Init(cfg *config.Config) error  { return nil }
func (t *TestSource) SetBPFFilter(expr string) error { return nil }
func (t *TestSource) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
}
func (t *TestSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pos >= len(t.packets) {
		return nil, gopacket.CaptureInfo{}, fmt.Errorf("no more packets")
	}
	p := t.packets[t.pos]
	t.pos++
	return p.data, p.ci, nil
}
