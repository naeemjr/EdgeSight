package plugins

import (
	"context"
	"fmt"
	"log"
	"sync"

	"edgesight/internal/config"
	"edgesight/pkg/protocol"
)

// Plugin is the extension interface for event consumers.
type Plugin interface {
	Name() string
	Init(cfg *config.Config) error
	HandleEvent(ctx context.Context, e *protocol.Event) error
	Close() error
}

// Registry lists built-in plugin names.
var Registry = []string{"webhook", "csv", "enrich", "syslog"}

// Build constructs a plugin instance by name.
func Build(name string) (Plugin, error) {
	switch name {
	case "webhook":
		return &WebhookPlugin{}, nil
	case "csv":
		return &CSVPlugin{}, nil
	case "enrich":
		return &EnrichPlugin{}, nil
	case "syslog":
		return &SyslogPlugin{}, nil
	default:
		return nil, fmt.Errorf("unknown plugin %q", name)
	}
}

// Manager orchestrates active plugins.
type Manager struct {
	plugins []Plugin
	wg      sync.WaitGroup
}

// NewManager builds and initializes enabled plugins.
func NewManager(cfg *config.Config, names []string) (*Manager, error) {
	var plugins []Plugin
	for _, n := range names {
		p, err := Build(n)
		if err != nil {
			return nil, err
		}
		if err := p.Init(cfg); err != nil {
			return nil, fmt.Errorf("init plugin %s: %w", n, err)
		}
		plugins = append(plugins, p)
	}
	return &Manager{plugins: plugins}, nil
}

// Dispatch sends an event to all plugins concurrently and tracks in-flight work.
func (m *Manager) Dispatch(ctx context.Context, e *protocol.Event) {
	for _, p := range m.plugins {
		m.wg.Add(1)
		go func(pl Plugin) {
			defer m.wg.Done()
			if err := pl.HandleEvent(ctx, e); err != nil {
				log.Printf("plugin %s error: %v", pl.Name(), err)
			}
		}(p)
	}
}

// Wait blocks until all in-flight plugin handlers complete.
func (m *Manager) Wait() {
	m.wg.Wait()
}

// Close shuts down all plugins. It waits for in-flight handlers first.
func (m *Manager) Close() error {
	m.Wait()
	var first error
	for _, p := range m.plugins {
		if err := p.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
