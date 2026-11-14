package simulations

import (
	"strings"
	"testing"
	"time"

	"edgesight/internal/mitre"
	"edgesight/internal/syslog"
	"edgesight/pkg/protocol"
)

func TestSyslogFormat(t *testing.T) {
	e := &protocol.Event{
		ID:        "abc-123",
		Kind:      protocol.EventKindAlert,
		Severity:  8,
		Timestamp: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		Source:    "syn_flood",
		Title:     "Flood",
		Message:   "Many SYNs",
	}
	msg := syslog.Format("host", "edgesight", e)
	if !strings.HasPrefix(msg, "<10>1 ") {
		t.Fatalf("expected RFC 5424 prefix, got %s", msg[:20])
	}
	if !strings.Contains(msg, "abc-123") {
		t.Fatal("missing event id")
	}
	if !strings.Contains(msg, "edgesight@1") {
		t.Fatal("missing structured data")
	}
}

func TestMITREMap(t *testing.T) {
	m, ok := mitre.Map("port_scan")
	if !ok || m.TechniqueID != "T1046" {
		t.Fatalf("unexpected mapping: %+v", m)
	}
	_, ok = mitre.Map("not_real")
	if ok {
		t.Fatal("expected miss")
	}
}
