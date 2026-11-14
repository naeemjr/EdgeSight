package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"edgesight/internal/config"
	"edgesight/pkg/protocol"
)

// EnrichPlugin performs best-effort external IP enrichment.
type EnrichPlugin struct {
	keys    config.EnrichmentKeys
	client  *http.Client
	recent  map[string]time.Time
	mu      sync.Mutex
	limiter *time.Ticker
}

func (e *EnrichPlugin) Name() string { return "enrich" }

func (e *EnrichPlugin) Init(cfg *config.Config) error {
	e.keys = cfg.EnrichmentKeys
	e.client = &http.Client{Timeout: 10 * time.Second}
	e.recent = map[string]time.Time{}
	rate := cfg.EnrichRate
	if rate <= 0 {
		rate = 100 * time.Millisecond
	}
	e.limiter = time.NewTicker(rate)
	return nil
}

func (e *EnrichPlugin) HandleEvent(ctx context.Context, ev *protocol.Event) error {
	ip := ""
	if ev.Packet != nil {
		ip = ev.Packet.SrcIP
	}
	if ip == "" {
		return nil
	}
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.IsLoopback() || parsed.IsPrivate() {
		return nil
	}
	e.mu.Lock()
	if t, ok := e.recent[ip]; ok && time.Since(t) < 5*time.Minute {
		e.mu.Unlock()
		return nil
	}
	e.recent[ip] = time.Now()
	e.mu.Unlock()

	<-e.limiter.C
	enrich := &protocol.EnrichmentData{IP: ip, QueriedAt: time.Now()}
	if e.keys.Shodan != "" {
		enrich.Shodan = e.query(ctx, fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", ip, e.keys.Shodan))
	}
	if e.keys.VirusTotal != "" {
		enrich.VirusTotal = e.queryVT(ctx, ip)
	}
	if e.keys.Censys != "" {
		enrich.Censys = e.query(ctx, fmt.Sprintf("https://search.censys.io/api/v2/hosts/%s", ip))
	}
	if e.keys.AbuseIPDB != "" {
		enrich.AbuseIPDB = e.queryAbuseIPDB(ctx, ip)
	}
	ev.Enrich = enrich
	return nil
}

func (e *EnrichPlugin) query(ctx context.Context, url string) map[string]any {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func (e *EnrichPlugin) queryVT(ctx context.Context, ip string) map[string]any {
	u := fmt.Sprintf("https://www.virustotal.com/api/v3/ip-addresses/%s", ip)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("x-apikey", e.keys.VirusTotal)
	resp, err := e.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func (e *EnrichPlugin) queryAbuseIPDB(ctx context.Context, ip string) map[string]any {
	u := "https://api.abuseipdb.com/api/v2/check"
	v := url.Values{"ipAddress": {ip}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u+"?"+v.Encode(), nil)
	req.Header.Set("Key", e.keys.AbuseIPDB)
	req.Header.Set("Accept", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func (e *EnrichPlugin) Close() error {
	if e.limiter != nil {
		e.limiter.Stop()
	}
	return nil
}
