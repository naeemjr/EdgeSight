package analytics

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"edgesight/internal/config"
	"edgesight/internal/mitre"
	"edgesight/internal/storage"
	"edgesight/pkg/protocol"
)

// Detector is the top-level analytics coordinator.
type Detector struct {
	cfg       *config.Config
	store     *storage.Store
	flowTable *flowTable
	baseline  *baseline
	sigs      *signatures
	emit      func(*protocol.Event)
	mu        sync.RWMutex
	metrics   protocol.MetricSnapshot
	lastFlush time.Time
}

// NewDetector builds the analytics pipeline.
func NewDetector(cfg *config.Config, store *storage.Store, emit func(*protocol.Event)) *Detector {
	return &Detector{
		cfg:       cfg,
		store:     store,
		flowTable: newFlowTable(),
		baseline:  newBaseline(store, cfg.BaselineWindow, cfg.AnomalyZScore),
		sigs:      newSignatures(),
		emit:      emit,
		lastFlush: time.Now(),
	}
}

// ProcessPacket is the entrypoint from the capture engine.
func (d *Detector) ProcessPacket(m *protocol.PacketMeta) {
	now := m.Timestamp
	d.flowTable.add(m, now)
	d.sigs.inspect(m, d.emitEvent)
}

// Tick performs periodic aggregation, baselining, anomaly detection, and metric flushing.
func (d *Detector) Tick(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			d.flush(ctx, now)
		}
	}
}

func (d *Detector) flush(ctx context.Context, now time.Time) {
	flows := d.flowTable.snapshotAndExpire(now, 60*time.Second)
	var totalBytes int64
	for _, f := range flows {
		totalBytes += f.Bytes
		if d.store != nil {
			_ = d.store.SaveFlow(ctx, f)
		}
	}

	elapsed := now.Sub(d.lastFlush).Seconds()
	if elapsed <= 0 {
		elapsed = 1
	}

	fps := float64(len(flows)) / elapsed
	bps := float64(totalBytes) / elapsed

	d.baseline.update("flows_per_sec", fps)
	d.baseline.update("bytes_per_sec", bps)

	alerts := 0
	if d.baseline.isAnomaly("flows_per_sec", fps) {
		alerts++
		d.emitEvent(&protocol.Event{
			ID:        newID(),
			Kind:      protocol.EventKindAnomaly,
			Severity:  6,
			Timestamp: now,
			Source:    "baseline",
			Title:     "Unusual flow rate",
			Message:   fmt.Sprintf("Flow rate %.2f/s deviates from baseline", fps),
		})
	}
	if d.baseline.isAnomaly("bytes_per_sec", bps) {
		alerts++
		d.emitEvent(&protocol.Event{
			ID:        newID(),
			Kind:      protocol.EventKindAnomaly,
			Severity:  6,
			Timestamp: now,
			Source:    "baseline",
			Title:     "Unusual byte rate",
			Message:   fmt.Sprintf("Byte rate %.2f B/s deviates from baseline", bps),
		})
	}

	d.mu.Lock()
	d.metrics = protocol.MetricSnapshot{
		Timestamp:   now,
		FlowsPerSec: fps,
		BytesPerSec: bps,
		ActiveFlows: len(d.flowTable.active()),
		Alerts:      alerts,
	}
	d.lastFlush = now
	d.mu.Unlock()

	if d.store != nil {
		_ = d.store.SaveMetric(ctx, &d.metrics)
	}
}

// Flush forces an immediate aggregation/metric flush. Exposed for tests.
func (d *Detector) Flush(ctx context.Context) {
	d.flush(ctx, time.Now())
}

// FlushAt forces a flush at a specific time.
func (d *Detector) FlushAt(ctx context.Context, at time.Time) {
	d.flush(ctx, at)
}

// Metrics returns the latest snapshot.
func (d *Detector) Metrics() protocol.MetricSnapshot {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.metrics
}

func (d *Detector) emitEvent(e *protocol.Event) {
	if e.ID == "" {
		e.ID = newID()
	}
	if len(e.MITRE) == 0 && e.Source != "" {
		if sig, ok := mitre.Map(e.Source); ok {
			e.MITRE = []protocol.MITREMapping{sig}
		}
	}
	if d.emit != nil {
		d.emit(e)
	}
	if d.store != nil {
		_ = d.store.SaveEvent(context.Background(), e)
	}
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// flowTable aggregates packets into flows.
type flowTable struct {
	mu    sync.Mutex
	flows map[string]*protocol.FlowRecord
}

func newFlowTable() *flowTable { return &flowTable{flows: map[string]*protocol.FlowRecord{}} }

func (ft *flowTable) add(m *protocol.PacketMeta, now time.Time) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	key := fmt.Sprintf("%s:%d-%s:%d/%s", m.SrcIP, m.SrcPort, m.DstIP, m.DstPort, m.Proto)
	f, ok := ft.flows[key]
	if !ok {
		f = &protocol.FlowRecord{
			ID:        newID(),
			StartTime: now,
			SrcIP:     m.SrcIP,
			DstIP:     m.DstIP,
			SrcPort:   m.SrcPort,
			DstPort:   m.DstPort,
			Proto:     m.Proto,
		}
		ft.flows[key] = f
	}
	f.EndTime = now
	f.Bytes += int64(m.Length)
	f.Packets++
}

func (ft *flowTable) snapshotAndExpire(now time.Time, timeout time.Duration) []*protocol.FlowRecord {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	var out []*protocol.FlowRecord
	for k, f := range ft.flows {
		if now.Sub(f.EndTime) > timeout {
			out = append(out, f)
			delete(ft.flows, k)
		}
	}
	return out
}

func (ft *flowTable) active() []*protocol.FlowRecord {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	var out []*protocol.FlowRecord
	for _, f := range ft.flows {
		out = append(out, f)
	}
	return out
}

// baseline implements Welford's online mean/variance.
type baseline struct {
	store    *storage.Store
	window   time.Duration
	z        float64
	mu       sync.Mutex
	stats    map[string]*protocol.BaselineStat
	lastSave time.Time
}

func newBaseline(store *storage.Store, window time.Duration, z float64) *baseline {
	b := &baseline{store: store, window: window, z: z, stats: map[string]*protocol.BaselineStat{}, lastSave: time.Now()}
	if store != nil {
		for _, k := range []string{"flows_per_sec", "bytes_per_sec"} {
			st, _ := store.GetBaseline(context.Background(), k)
			if st.Key != "" {
				b.stats[k] = &st
			}
		}
	}
	return b
}

func (b *baseline) update(key string, value float64) {
	b.mu.Lock()
	st, ok := b.stats[key]
	if !ok {
		st = &protocol.BaselineStat{Key: key}
		b.stats[key] = st
	}
	st.Count++
	delta := value - st.Mean
	st.Mean += delta / float64(st.Count)
	delta2 := value - st.Mean
	st.M2 += delta * delta2
	if st.Count > 1 {
		st.Stddev = math.Sqrt(st.M2 / float64(st.Count-1))
	}
	st.LastUpdate = time.Now().UnixMilli()
	if b.store != nil && time.Since(b.lastSave) > 30*time.Second {
		_ = b.store.SetBaseline(context.Background(), *st)
		b.lastSave = time.Now()
	}
	b.mu.Unlock()
}

func (b *baseline) isAnomaly(key string, value float64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	st, ok := b.stats[key]
	if !ok || st.Count < 10 {
		return false
	}
	if st.Stddev == 0 {
		return false
	}
	return math.Abs(value-st.Mean) > b.z*st.Stddev
}

// signatures implements lightweight signature-based detection.
type signatures struct {
	mu          sync.Mutex
	scanTracker map[string]map[uint16]int // srcIP -> dstPort -> count
	synTracker  map[string]int            // dstIP -> syn count
	dnsTracker  map[string]int            // srcIP -> dns query bytes
	lastReset   time.Time
}

func newSignatures() *signatures {
	return &signatures{
		scanTracker: map[string]map[uint16]int{},
		synTracker:  map[string]int{},
		dnsTracker:  map[string]int{},
		lastReset:   time.Now(),
	}
}

func (s *signatures) inspect(m *protocol.PacketMeta, emit func(*protocol.Event)) {
	now := m.Timestamp
	s.mu.Lock()
	if now.Sub(s.lastReset) > 10*time.Second {
		s.scanTracker = map[string]map[uint16]int{}
		s.synTracker = map[string]int{}
		s.dnsTracker = map[string]int{}
		s.lastReset = now
	}

	// Port scan detection.
	if m.Proto == "tcp" || m.Proto == "udp" {
		if s.scanTracker[m.SrcIP] == nil {
			s.scanTracker[m.SrcIP] = map[uint16]int{}
		}
		s.scanTracker[m.SrcIP][m.DstPort]++
		if len(s.scanTracker[m.SrcIP]) > 50 {
			s.mu.Unlock()
			emit(&protocol.Event{
				Kind:      protocol.EventKindAlert,
				Severity:  7,
				Timestamp: now,
				Source:    "port_scan",
				Title:     "Possible port scan",
				Message:   fmt.Sprintf("%s touched %d distinct ports", m.SrcIP, len(s.scanTracker[m.SrcIP])),
				MITRE:     mitre.Maps("port_scan"),
				Packet:    m,
			})
			return
		}
	}

	// SYN flood detection.
	if m.Proto == "tcp" && strings.Contains(m.Flags, "S") && !strings.Contains(m.Flags, "A") {
		s.synTracker[m.DstIP]++
		if s.synTracker[m.DstIP] > 100 {
			s.mu.Unlock()
			emit(&protocol.Event{
				Kind:      protocol.EventKindAlert,
				Severity:  8,
				Timestamp: now,
				Source:    "syn_flood",
				Title:     "Possible SYN flood",
				Message:   fmt.Sprintf("%s received %d SYNs in window", m.DstIP, s.synTracker[m.DstIP]),
				MITRE:     mitre.Maps("syn_flood"),
				Packet:    m,
			})
			return
		}
	}

	// DNS tunnel heuristic: large DNS payloads over UDP/53.
	if m.Proto == "udp" && m.DstPort == 53 && len(m.Payload) > 200 {
		s.dnsTracker[m.SrcIP] += len(m.Payload)
		if s.dnsTracker[m.SrcIP] > 2000 {
			s.mu.Unlock()
			emit(&protocol.Event{
				Kind:      protocol.EventKindAlert,
				Severity:  6,
				Timestamp: now,
				Source:    "dns_tunnel",
				Title:     "Possible DNS tunneling",
				Message:   fmt.Sprintf("%s sent %d bytes in DNS queries", m.SrcIP, s.dnsTracker[m.SrcIP]),
				MITRE:     mitre.Maps("dns_tunnel"),
				Packet:    m,
			})
			return
		}
	}
	s.mu.Unlock()

	// ICMP tunnel heuristic.
	if m.Proto == "icmp" && len(m.Payload) > 128 {
		emit(&protocol.Event{
			Kind:      protocol.EventKindAlert,
			Severity:  5,
			Timestamp: now,
			Source:    "icmp_tunnel",
			Title:     "Large ICMP payload",
			Message:   fmt.Sprintf("%s sent ICMP payload of %d bytes", m.SrcIP, len(m.Payload)),
			MITRE:     mitre.Maps("icmp_tunnel"),
			Packet:    m,
		})
	}

	// New external connection heuristic.
	if m.DstPort == 22 || m.DstPort == 3389 || m.DstPort == 445 {
		dst := net.ParseIP(m.DstIP)
		if dst != nil && !dst.IsLoopback() && !dst.IsPrivate() {
			emit(&protocol.Event{
				Kind:      protocol.EventKindAlert,
				Severity:  4,
				Timestamp: now,
				Source:    "new_external_conn",
				Title:     "Outbound sensitive service connection",
				Message:   fmt.Sprintf("%s -> %s:%d", m.SrcIP, m.DstIP, m.DstPort),
				MITRE:     mitre.Maps("new_external_conn"),
				Packet:    m,
			})
		}
	}
}
