package simulations

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"edgesight/internal/analytics"
	"edgesight/internal/api"
	"edgesight/internal/config"
	"edgesight/internal/storage"
	"edgesight/pkg/protocol"
)

func TestAPIEvents(t *testing.T) {
	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	defer db.Close()

	cfg := config.Default()
	d := analytics.NewDetector(cfg, db, nil)
	_ = db.SaveEvent(context.Background(), &protocol.Event{
		ID: "x1", Kind: protocol.EventKindAlert, Severity: 5, Timestamp: time.Now(), Source: "test", Title: "T", Message: "M",
	})

	srv := api.NewServer(cfg, db, d)
	req := httptest.NewRequest(http.MethodGet, "/api/events?limit=5", nil)
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var events []protocol.Event
	if err := json.Unmarshal(rec.Body.Bytes(), &events); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
}

func TestAPIQuery(t *testing.T) {
	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	defer db.Close()

	cfg := config.Default()
	d := analytics.NewDetector(cfg, db, nil)
	_ = db.SaveEvent(context.Background(), &protocol.Event{
		ID: "x2", Kind: protocol.EventKindFlow, Severity: 1, Timestamp: time.Now(), Source: "test", Title: "F", Message: "M",
	})

	srv := api.NewServer(cfg, db, d)
	body, _ := json.Marshal(map[string]string{"q": "SELECT id, kind FROM events"})
	req := httptest.NewRequest(http.MethodPost, "/api/query", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var rows []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
}
