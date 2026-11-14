package simulations

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"edgesight/internal/config"
	"edgesight/internal/plugins"
	"edgesight/pkg/protocol"
)

func TestCSVPlugin(t *testing.T) {
	f, err := os.CreateTemp("", "edgesight-csv-*.csv")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	os.Remove(f.Name())

	cfg := config.Default()
	cfg.CSVExportPath = f.Name()
	p, err := plugins.NewManager(cfg, []string{"csv"})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	defer p.Close()

	e := &protocol.Event{ID: "e1", Kind: protocol.EventKindAlert, Severity: 5, Timestamp: time.Now(), Source: "test", Title: "T", Message: "M"}
	p.Dispatch(context.Background(), e)
	time.Sleep(100 * time.Millisecond)

	r, err := os.Open(f.Name())
	if err != nil {
		t.Fatalf("open csv: %v", err)
	}
	defer r.Close()
	rows, err := csv.NewReader(r).ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}
}

func TestWebhookPlugin(t *testing.T) {
	var received *protocol.Event
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var e protocol.Event
		_ = json.Unmarshal(b, &e)
		received = &e
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := config.Default()
	cfg.WebhookURL = ts.URL
	p, err := plugins.NewManager(cfg, []string{"webhook"})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	defer p.Close()

	e := &protocol.Event{ID: "e2", Kind: protocol.EventKindAlert, Severity: 3, Timestamp: time.Now(), Source: "test", Title: "T", Message: "M"}
	p.Dispatch(context.Background(), e)
	time.Sleep(200 * time.Millisecond)

	if received == nil || received.ID != "e2" {
		t.Fatal("webhook did not receive event")
	}
}
