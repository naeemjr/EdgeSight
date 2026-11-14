package plugins

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"sync"
	"time"

	"edgesight/internal/config"
	"edgesight/pkg/protocol"
)

// CSVPlugin appends events to a CSV file.
type CSVPlugin struct {
	path   string
	mu     sync.Mutex
	file   *os.File
	writer *csv.Writer
}

func (c *CSVPlugin) Name() string { return "csv" }

func (c *CSVPlugin) Init(cfg *config.Config) error {
	c.path = cfg.CSVExportPath
	if c.path == "" {
		c.path = "edgesight_events.csv"
	}
	f, err := os.OpenFile(c.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	c.file = f
	c.writer = csv.NewWriter(f)
	info, err := f.Stat()
	if err == nil && info.Size() == 0 {
		_ = c.writer.Write([]string{"timestamp", "id", "kind", "severity", "source", "title", "message"})
		c.writer.Flush()
	}
	return nil
}

func (c *CSVPlugin) HandleEvent(ctx context.Context, e *protocol.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	row := []string{
		e.Timestamp.Format(time.RFC3339),
		e.ID,
		string(e.Kind),
		fmt.Sprintf("%d", e.Severity),
		e.Source,
		e.Title,
		e.Message,
	}
	if err := c.writer.Write(row); err != nil {
		return err
	}
	c.writer.Flush()
	return c.writer.Error()
}

func (c *CSVPlugin) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writer != nil {
		c.writer.Flush()
	}
	if c.file != nil {
		return c.file.Close()
	}
	return nil
}
