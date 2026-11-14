package plugins

import (
	"context"
	"testing"
	"time"

	"edgesight/internal/config"
	"edgesight/pkg/protocol"
)

type countingPlugin struct {
	name    string
	count   int
	initErr error
	handle  func(*protocol.Event) error
}

func (c *countingPlugin) Name() string { return c.name }
func (c *countingPlugin) Init(cfg *config.Config) error {
	return c.initErr
}
func (c *countingPlugin) HandleEvent(ctx context.Context, e *protocol.Event) error {
	c.count++
	if c.handle != nil {
		return c.handle(e)
	}
	return nil
}
func (c *countingPlugin) Close() error { return nil }

func TestManagerDispatchesAndWaits(t *testing.T) {
	p1 := &countingPlugin{name: "p1"}
	p2 := &countingPlugin{name: "p2"}
	m := &Manager{plugins: []Plugin{p1, p2}}

	m.Dispatch(context.Background(), &protocol.Event{ID: "e1"})
	m.Wait()

	if p1.count != 1 || p2.count != 1 {
		t.Fatalf("expected each plugin to receive 1 event, got p1=%d p2=%d", p1.count, p2.count)
	}
}

func TestManagerCloseWaits(t *testing.T) {
	p := &countingPlugin{
		name: "slow",
		handle: func(e *protocol.Event) error {
			time.Sleep(50 * time.Millisecond)
			return nil
		},
	}
	m := &Manager{plugins: []Plugin{p}}

	start := time.Now()
	m.Dispatch(context.Background(), &protocol.Event{ID: "e1"})
	if err := m.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 50*time.Millisecond {
		t.Fatalf("close returned too early: %v", elapsed)
	}
	if p.count != 1 {
		t.Fatalf("expected 1 event, got %d", p.count)
	}
}
