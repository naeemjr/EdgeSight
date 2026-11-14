package simulations

import (
	"context"
	"os"
	"testing"
	"time"

	"edgesight/internal/storage"
	"edgesight/pkg/protocol"
)

func TestStorageEventCRUD(t *testing.T) {
	db := tempDB(t)
	defer db.Close()

	e := &protocol.Event{
		ID:        "evt-1",
		Kind:      protocol.EventKindAlert,
		Severity:  7,
		Timestamp: time.Now(),
		Source:    "port_scan",
		Title:     "scan",
		Message:   "detected",
	}
	if err := db.SaveEvent(context.Background(), e); err != nil {
		t.Fatalf("save event: %v", err)
	}
	ev, err := db.ListEvents(context.Background(), "", 10, 0)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(ev) != 1 {
		t.Fatalf("expected 1 event, got %d", len(ev))
	}
	if ev[0].Source != "port_scan" {
		t.Fatalf("unexpected source %s", ev[0].Source)
	}
}

func TestStorageFlowCRUD(t *testing.T) {
	db := tempDB(t)
	defer db.Close()

	f := &protocol.FlowRecord{
		ID:        "flow-1",
		StartTime: time.Now(),
		EndTime:   time.Now(),
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		SrcPort:   12345,
		DstPort:   80,
		Proto:     "tcp",
		Bytes:     1000,
		Packets:   10,
	}
	if err := db.SaveFlow(context.Background(), f); err != nil {
		t.Fatalf("save flow: %v", err)
	}
	rows, err := db.Query(context.Background(), "SELECT COUNT(*) as c FROM flows")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
}

func TestStorageQuery(t *testing.T) {
	db := tempDB(t)
	defer db.Close()

	for i := 0; i < 5; i++ {
		e := &protocol.Event{ID: id(i), Kind: protocol.EventKindAlert, Severity: 5, Timestamp: time.Now(), Source: "test", Title: "t", Message: "m"}
		_ = db.SaveEvent(context.Background(), e)
	}
	rows, err := db.Query(context.Background(), "SELECT id FROM events WHERE kind=? ORDER BY timestamp DESC LIMIT 3", "alert")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(rows))
	}
}

func tempDB(t *testing.T) *storage.Store {
	t.Helper()
	f, err := os.CreateTemp("", "edgesight-*.db")
	if err != nil {
		t.Fatalf("temp db: %v", err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	db, err := storage.Open(f.Name())
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	return db
}

func id(i int) string {
	return string([]rune{rune('a' + i)})
}
