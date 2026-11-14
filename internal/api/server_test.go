package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"edgesight/internal/analytics"
	"edgesight/internal/config"
	"edgesight/internal/storage"
	"edgesight/pkg/protocol"
)

func TestEventsLimitFromConfig(t *testing.T) {
	store, err := storage.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	for i := 0; i < 200; i++ {
		if err := store.SaveEvent(context.Background(), &protocol.Event{
			ID:        fmt.Sprintf("e%d", i),
			Kind:      protocol.EventKindAlert,
			Severity:  5,
			Timestamp: time.Now(),
			Source:    "test",
			Title:     "t",
			Message:   "m",
		}); err != nil {
			t.Fatalf("save event: %v", err)
		}
	}

	cfg := &config.Config{MaxEventsLimit: 150}
	srv := NewServer(cfg, store, analytics.NewDetector(cfg, store, nil))
	req := httptest.NewRequest(http.MethodGet, "/api/events?limit=200", nil)
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	count := 0
	for i := 0; i < len(body); i++ {
		if body[i] == '"' && i+1 < len(body) && body[i+1] == 'i' && i+2 < len(body) && body[i+2] == 'd' {
			count++
		}
	}
	if count != 150 {
		t.Fatalf("expected 150 events, got %d", count)
	}
}
