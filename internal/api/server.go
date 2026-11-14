package api

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"

	"edgesight/internal/analytics"
	"edgesight/internal/config"
	"edgesight/internal/storage"
)

//go:embed all:web/dist
var webDist embed.FS

// Server wraps the HTTP API and embedded dashboard.
type Server struct {
	cfg      *config.Config
	store    *storage.Store
	detector *analytics.Detector
}

// NewServer creates the API server.
func NewServer(cfg *config.Config, store *storage.Store, detector *analytics.Detector) *Server {
	return &Server{cfg: cfg, store: store, detector: detector}
}

// Router builds the HTTP handler.
func (s *Server) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/events", s.withKey(s.handleEvents))
	mux.HandleFunc("/api/metrics", s.withKey(s.handleMetrics))
	mux.HandleFunc("/api/query", s.withKey(s.handleQuery))
	mux.HandleFunc("/api/status", s.withKey(s.handleStatus))
	mux.HandleFunc("/", s.withKey(s.handleDashboard))
	return mux
}

// withKey authenticates requests using a single documented mechanism: the
// "X-API-Key" HTTP header, compared in constant time. URL query-string
// credentials are intentionally NOT accepted (they leak into logs, proxies,
// and browser history). When the configured key is empty the server only ever
// starts in loopback-only local-development mode (enforced by bindGuard in
// Listen), so an empty key can never expose an externally reachable API.
func (s *Server) withKey(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.APIKey != "" {
			provided := r.Header.Get("X-API-Key")
			if subtle.ConstantTimeCompare([]byte(provided), []byte(s.cfg.APIKey)) != 1 {
				// Generic message only; no detail about why it failed and no
				// echo of the provided value.
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		next(w, r)
	}
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	maxLimit := s.cfg.MaxEventsLimit
	if maxLimit <= 0 {
		maxLimit = 10000
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	kind := r.URL.Query().Get("kind")
	events, err := s.store.ListEvents(r.Context(), kind, limit, offset)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	writeJSON(w, events)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.detector.Metrics())
}

func (s *Server) handleQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Q string `json:"q"`
	}
	b, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(b, &req)
	rows, err := s.store.Query(r.Context(), req.Q)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	writeJSON(w, rows)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	cnt, _ := s.store.CountEvents(r.Context(), "")
	writeJSON(w, map[string]any{
		"status":       "running",
		"total_events": cnt,
		"listen_addr":  s.cfg.ListenAddr,
	})
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}
	b, err := webDist.ReadFile("web/dist/" + path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if strings.HasSuffix(path, ".js") {
		w.Header().Set("Content-Type", "application/javascript")
	} else if strings.HasSuffix(path, ".css") {
		w.Header().Set("Content-Type", "text/css")
	}
	_, _ = w.Write(b)
}

// Listen starts the HTTP server. It fails closed: an empty API key is only
// permitted when the server binds to a loopback address.
func (s *Server) Listen() error {
	if err := bindGuard(s.cfg.ListenAddr, s.cfg.APIKey); err != nil {
		return err
	}
	if s.cfg.APIKey == "" {
		log.Printf("WARNING: EdgeSight API running in loopback-only local mode with NO api_key; "+
			"set api_key in the config before binding to any non-loopback address (%s)", s.cfg.ListenAddr)
	}
	log.Printf("API listening on http://%s", s.cfg.ListenAddr)
	return http.ListenAndServe(s.cfg.ListenAddr, s.Router())
}

// bindGuard rejects an externally reachable bind when no API key is set.
// It is a pure function so it can be unit-tested without opening a socket.
func bindGuard(listenAddr, apiKey string) error {
	if apiKey != "" {
		return nil
	}
	if isLoopbackListen(listenAddr) {
		return nil
	}
	return fmt.Errorf("refusing to start: api_key is empty and listen_addr %q is not loopback; "+
		"set api_key or bind to 127.0.0.1/::1 for local-development mode", listenAddr)
}

// isLoopbackListen reports whether listenAddr binds only to a loopback
// interface. A missing/empty/wildcard host is treated as non-loopback.
func isLoopbackListen(listenAddr string) bool {
	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		host = listenAddr // may be a bare host
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func writeJSON(w http.ResponseWriter, v any) {
	_ = json.NewEncoder(w).Encode(v)
}
