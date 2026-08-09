package discovery

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandler_ServeHTTP(t *testing.T) {
	h := NewHandler("https://mcp.example.com", []string{"https://auth.example.com"}, WithScopes([]string{"scope1", "scope2"}))

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Expected Content-Type %s, got %s", "application/json", ct)
	}

	var res ProtectedResourceMetadata
	if err := json.NewDecoder(rec.Body).Decode(&res); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if res.Resource != "https://mcp.example.com" {
		t.Errorf("Expected Resource %s, got %s", "https://mcp.example.com", res.Resource)
	}
	if len(res.AuthorizationServers) != 1 || res.AuthorizationServers[0] != "https://auth.example.com" {
		t.Errorf("AuthorizationServers: got %v", res.AuthorizationServers)
	}
	if len(res.ScopesSupported) != 2 || res.ScopesSupported[0] != "scope1" || res.ScopesSupported[1] != "scope2" {
		t.Errorf("Expected ScopesSupported %v, got %v", []string{"scope1", "scope2"}, res.ScopesSupported)
	}
}

func TestHandler_OmitsOptionalFields(t *testing.T) {
	h := NewHandler("https://mcp.example.com", []string{"https://auth.example.com"})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if bytes.Contains(rec.Body.Bytes(), []byte("scopes_supported")) {
		t.Error("expected scopes_supported to be omitted when unset")
	}
}

func TestHandler_MethodNotAllowed(t *testing.T) {
	h := NewHandler("https://mcp.example.com", []string{"https://auth.example.com"})
	req := httptest.NewRequest(http.MethodPost, "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status code %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
	if allow := rec.Header().Get("Allow"); allow != http.MethodGet {
		t.Errorf("Allow header: got %q, want %q", allow, http.MethodGet)
	}
}
