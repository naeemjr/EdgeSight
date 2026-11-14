package protocol

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// FlowKey identifies a unidirectional flow.
type FlowKey struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	Proto   uint8
}

func (k FlowKey) String() string {
	return fmt.Sprintf("%s:%d->%s:%d/%d", k.SrcIP, k.SrcPort, k.DstIP, k.DstPort, k.Proto)
}

// PacketMeta is the parsed metadata extracted from a captured packet.
type PacketMeta struct {
	Timestamp time.Time `json:"timestamp"`
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	SrcPort   uint16    `json:"src_port,omitempty"`
	DstPort   uint16    `json:"dst_port,omitempty"`
	Proto     string    `json:"proto"`
	Length    int       `json:"length"`
	Flags     string    `json:"flags,omitempty"`
	Payload   []byte    `json:"payload,omitempty"`
}

// EventKind classifies a security/storage event.
type EventKind string

const (
	EventKindAlert   EventKind = "alert"
	EventKindAnomaly EventKind = "anomaly"
	EventKindFlow    EventKind = "flow"
	EventKindEnrich  EventKind = "enrich"
)

// Event is the canonical record stored/propagated by EdgeSight.
type Event struct {
	ID        string          `json:"id"`
	Kind      EventKind       `json:"kind"`
	Severity  int             `json:"severity"` // 0-10
	Timestamp time.Time       `json:"timestamp"`
	Source    string          `json:"source"`
	Title     string          `json:"title"`
	Message   string          `json:"message"`
	MITRE     []MITREMapping  `json:"mitre,omitempty"`
	Packet    *PacketMeta     `json:"packet,omitempty"`
	Enrich    *EnrichmentData `json:"enrichment,omitempty"`
	Raw       json.RawMessage `json:"raw,omitempty"`
}

// MITREMapping links an event to ATT&CK tactics/techniques.
type MITREMapping struct {
	Tactic      string `json:"tactic"`
	TechniqueID string `json:"technique_id"`
	Name        string `json:"name"`
}

// EnrichmentData holds external lookup results.
type EnrichmentData struct {
	IP         string         `json:"ip"`
	Shodan     map[string]any `json:"shodan,omitempty"`
	VirusTotal map[string]any `json:"virustotal,omitempty"`
	Censys     map[string]any `json:"censys,omitempty"`
	AbuseIPDB  map[string]any `json:"abuseipdb,omitempty"`
	QueriedAt  time.Time      `json:"queried_at"`
}

// MetricSnapshot is a periodic performance/behavior sample.
type MetricSnapshot struct {
	Timestamp   time.Time `json:"timestamp"`
	FlowsPerSec float64   `json:"flows_per_sec"`
	BytesPerSec float64   `json:"bytes_per_sec"`
	ActiveFlows int       `json:"active_flows"`
	Alerts      int       `json:"alerts"`
}

// FlowRecord is a summarized network flow.
type FlowRecord struct {
	ID        string    `json:"id"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	SrcPort   uint16    `json:"src_port,omitempty"`
	DstPort   uint16    `json:"dst_port,omitempty"`
	Proto     string    `json:"proto"`
	Bytes     int64     `json:"bytes"`
	Packets   int64     `json:"packets"`
}

// BaselineStat tracks a Welford-style baseline statistic.
type BaselineStat struct {
	Key        string  `json:"key"`
	Mean       float64 `json:"mean"`
	M2         float64 `json:"m2"`     // sum of squares of differences from the current mean
	Stddev     float64 `json:"stddev"` // cached sqrt(M2/count)
	Count      int64   `json:"count"`
	LastUpdate int64   `json:"last_update"`
}
