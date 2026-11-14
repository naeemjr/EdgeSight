package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"edgesight/internal/config"
	"edgesight/pkg/protocol"
)

// WebhookPlugin POSTs events to a configured URL.
type WebhookPlugin struct {
	url    string
	client *http.Client
}

func (w *WebhookPlugin) Name() string { return "webhook" }

func (w *WebhookPlugin) Init(cfg *config.Config) error {
	if cfg.WebhookURL == "" {
		return fmt.Errorf("webhook plugin requires webhook_url")
	}
	w.url = cfg.WebhookURL
	w.client = &http.Client{Timeout: 10 * time.Second}
	return nil
}

func (w *WebhookPlugin) HandleEvent(ctx context.Context, e *protocol.Event) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}

func (w *WebhookPlugin) Close() error { return nil }
