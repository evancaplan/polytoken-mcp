package challenge

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUnauthorized_SetsStatusAndHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	prmURL := "https://mcp.example.com/.well-known/oauth-protected-resource"
	Unauthorized(rec, prmURL)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	want := fmt.Sprintf(`Bearer resource_metadata="%s"`, prmURL)

	if got := rec.Header().Get("WWW-Authenticate"); got != want {
		t.Errorf("WWW-Authenticate: got %q, want %q", got, want)
	}
}
