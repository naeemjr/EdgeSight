package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"edgesight/internal/config"
)

// These tests cover the P0 fail-closed authentication behavior:
//  1. non-loopback bind with no key is refused;
//  2. empty-key local (loopback) mode is explicitly permitted;
//  3. a valid header key is accepted;
//  4. a missing/invalid header key is rejected;
//  5. URL query-string credentials are rejected;
//  6. key material is not echoed back to the client.

func TestBindGuard_RefusesNonLoopbackWithoutKey(t *testing.T) {
	bad := []string{"0.0.0.0:8080", ":8080", "192.168.1.10:8080", "[::]:8080"}
	for _, addr := range bad {
		if err := bindGuard(addr, ""); err == nil {
			t.Errorf("bindGuard(%q, \"\") = nil; want refusal", addr)
		}
	}
}

func TestBindGuard_AllowsLoopbackLocalMode(t *testing.T) {
	ok := []string{"127.0.0.1:8080", "localhost:8080", "[::1]:8080"}
	for _, addr := range ok {
		if err := bindGuard(addr, ""); err != nil {
			t.Errorf("bindGuard(%q, \"\") = %v; want nil (loopback local mode)", addr, err)
		}
	}
}

func TestBindGuard_AllowsAnyBindWithKey(t *testing.T) {
	if err := bindGuard("0.0.0.0:8080", "a-real-key"); err != nil {
		t.Errorf("bindGuard with key set must allow non-loopback bind, got %v", err)
	}
}

func newTestServer(apiKey string) *Server {
	return &Server{cfg: &config.Config{APIKey: apiKey, ListenAddr: "127.0.0.1:0"}}
}

func okHandler(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }

func TestWithKey_ValidHeaderAccepted(t *testing.T) {
	s := newTestServer("secret-key")
	h := s.withKey(okHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.Header.Set("X-API-Key", "secret-key")
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid header key: got %d, want 200", rec.Code)
	}
}

func TestWithKey_MissingOrWrongHeaderRejected(t *testing.T) {
	s := newTestServer("secret-key")
	h := s.withKey(okHandler)
	for _, tc := range []struct{ name, val string }{
		{"missing", ""},
		{"wrong", "nope"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
		if tc.val != "" {
			req.Header.Set("X-API-Key", tc.val)
		}
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s key: got %d, want 401", tc.name, rec.Code)
		}
	}
}

func TestWithKey_QueryStringCredentialRejected(t *testing.T) {
	s := newTestServer("secret-key")
	h := s.withKey(okHandler)
	// Correct key supplied ONLY via the query string must be rejected.
	req := httptest.NewRequest(http.MethodGet, "/api/status?api_key=secret-key", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("query-string credential must be rejected: got %d, want 401", rec.Code)
	}
}

func TestWithKey_EmptyKeyLoopbackAllows(t *testing.T) {
	s := newTestServer("") // loopback local mode (bindGuard enforces loopback at Listen)
	h := s.withKey(okHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("empty-key loopback mode should allow: got %d, want 200", rec.Code)
	}
}

func TestWithKey_DoesNotEchoKeyMaterial(t *testing.T) {
	s := newTestServer("super-secret-value")
	h := s.withKey(okHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.Header.Set("X-API-Key", "wrong-guess-value")
	rec := httptest.NewRecorder()
	h(rec, req)
	body := rec.Body.String()
	if contains(body, "super-secret-value") || contains(body, "wrong-guess-value") {
		t.Fatalf("response body must not echo key material, got %q", body)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
