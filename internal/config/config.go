package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config is the runtime configuration for EdgeSight.
type Config struct {
	Interface      string         `json:"interface"`
	Promiscuous    bool           `json:"promiscuous"`
	BPFFilter      string         `json:"bpf_filter"`
	DatabasePath   string         `json:"database_path"`
	ListenAddr     string         `json:"listen_addr"`
	APIKey         string         `json:"api_key"`
	SyslogTarget   string         `json:"syslog_target"`
	SyslogEnabled  bool           `json:"syslog_enabled"`
	PluginsEnabled []string       `json:"plugins_enabled"`
	EnrichmentKeys EnrichmentKeys `json:"enrichment_keys"`
	WebhookURL     string         `json:"webhook_url"`
	CSVExportPath  string         `json:"csv_export_path"`
	BaselineWindow time.Duration  `json:"baseline_window"`
	AnomalyZScore  float64        `json:"anomaly_z_score"`
	MaxPacketSize  int            `json:"max_packet_size"`
	MaxEventsLimit int            `json:"max_events_limit"`
	EnrichRate     time.Duration  `json:"enrich_rate"`
	TUI            bool           `json:"tui"`
	Verbose        bool           `json:"verbose"`
	Raw            map[string]any `json:"-"`
}

// EnrichmentKeys holds optional API keys for enrichment plugins.
type EnrichmentKeys struct {
	Shodan     string `json:"shodan"`
	VirusTotal string `json:"virustotal"`
	Censys     string `json:"censys"`
	AbuseIPDB  string `json:"abuseipdb"`
}

// Default returns a sane default configuration.
func Default() *Config {
	return &Config{
		Interface:      "eth0",
		Promiscuous:    true,
		BPFFilter:      "",
		DatabasePath:   "edgesight.db",
		ListenAddr:     "127.0.0.1:8080",
		SyslogEnabled:  false,
		PluginsEnabled: []string{"csv"},
		BaselineWindow: 5 * time.Minute,
		AnomalyZScore:  3.0,
		MaxPacketSize:  65535,
		MaxEventsLimit: 10000,
		EnrichRate:     100 * time.Millisecond,
	}
}

// Load reads configuration from a JSON file, merging with defaults.
func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(b, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

// Save writes the configuration to disk as JSON.
func Save(path string, cfg *Config) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
