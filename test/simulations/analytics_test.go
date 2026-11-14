package simulations

import (
	"context"
	"testing"
	"time"

	"edgesight/internal/analytics"
	"edgesight/internal/config"
	"edgesight/internal/storage"
	"edgesight/pkg/protocol"
)

func makeDetector(t *testing.T, z float64) (*storage.Store, *analytics.Detector, *[]*protocol.Event) {
	t.Helper()
	cfg := config.Default()
	cfg.AnomalyZScore = z
	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	var events []*protocol.Event
	d := analytics.NewDetector(cfg, db, func(e *protocol.Event) { events = append(events, e) })
	return db, d, &events
}

func eventsBySource(events []*protocol.Event, src string) []*protocol.Event {
	var out []*protocol.Event
	for _, e := range events {
		if e.Source == src {
			out = append(out, e)
		}
	}
	return out
}

func TestPortScanDetection(t *testing.T) {
	db, d, events := makeDetector(t, 999)
	defer db.Close()

	now := time.Now()
	for i := 0; i < 60; i++ {
		d.ProcessPacket(&protocol.PacketMeta{
			Timestamp: now,
			SrcIP:     "10.0.0.1",
			DstIP:     "10.0.0.2",
			SrcPort:   10000 + uint16(i),
			DstPort:   1 + uint16(i),
			Proto:     "tcp",
			Length:    60,
		})
	}
	if len(eventsBySource(*events, "port_scan")) == 0 {
		t.Fatal("expected port scan alert")
	}
}

func TestSYNFloodDetection(t *testing.T) {
	db, d, events := makeDetector(t, 999)
	defer db.Close()

	now := time.Now()
	for i := 0; i < 120; i++ {
		d.ProcessPacket(&protocol.PacketMeta{
			Timestamp: now,
			SrcIP:     "10.0.0.1",
			DstIP:     "10.0.0.2",
			SrcPort:   10000 + uint16(i),
			DstPort:   80,
			Proto:     "tcp",
			Flags:     "S",
			Length:    60,
		})
	}
	if len(eventsBySource(*events, "syn_flood")) == 0 {
		t.Fatal("expected SYN flood alert")
	}
}

func TestDNSTunnelDetection(t *testing.T) {
	db, d, events := makeDetector(t, 999)
	defer db.Close()

	now := time.Now()
	payload := make([]byte, 300)
	for i := 0; i < 10; i++ {
		d.ProcessPacket(&protocol.PacketMeta{
			Timestamp: now,
			SrcIP:     "10.0.0.1",
			DstIP:     "8.8.8.8",
			SrcPort:   10000 + uint16(i),
			DstPort:   53,
			Proto:     "udp",
			Length:    350,
			Payload:   payload,
		})
	}
	if len(eventsBySource(*events, "dns_tunnel")) == 0 {
		t.Fatal("expected DNS tunnel alert")
	}
}

func TestBaselineAnomaly(t *testing.T) {
	db, d, events := makeDetector(t, 2.0)
	defer db.Close()

	now := time.Now()
	for i := 0; i < 20; i++ {
		d.ProcessPacket(&protocol.PacketMeta{Timestamp: now, SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1000, DstPort: 80, Proto: "tcp", Length: 100})
		now = now.Add(5 * time.Second)
		d.FlushAt(context.Background(), now)
	}
	for i := 0; i < 200; i++ {
		d.ProcessPacket(&protocol.PacketMeta{Timestamp: now, SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: uint16(2000 + i), DstPort: 80, Proto: "tcp", Length: 100})
	}
	now = now.Add(70 * time.Second)
	d.FlushAt(context.Background(), now)
	if len(eventsBySource(*events, "baseline")) == 0 {
		t.Fatal("expected baseline anomaly")
	}
}
