package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/evancaplan/polytoken-mcp/token"
	"github.com/evancaplan/polytoken/principal"
	"github.com/evancaplan/polytoken/resolver"
	"github.com/evancaplan/polytoken/validator"
)

type fakeValidator struct {
	canHandle bool
	principal *principal.Principal
	err       error
}

func (f *fakeValidator) CanHandle(t string) bool { return f.canHandle }
func (f *fakeValidator) Validate(ctx context.Context, t string) (*principal.Principal, error) {
	return f.principal, f.err
}

func newTestGuard(fv *fakeValidator, expectedResource, expectedIssuer string) *Guard {
	res := resolver.NewResolver([]validator.TokenValidator{fv})
	v := token.NewValidator(res)
	return NewGuard(v, expectedResource, expectedIssuer, "https://mcp.example.com/.well-known/oauth-protected-resource")
}

func TestGuard_Wrap_AllChecksPass(t *testing.T) {
	iss := "https://auth.example.com"
	resource := "https://mcp.example.com"
	p := &principal.Principal{
		Iss:    iss,
		Claims: map[string]any{"aud": resource},
	}
	v := fakeValidator{canHandle: true, principal: p}
	g := newTestGuard(&v, resource, iss)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		got, ok := PrincipalFromContext(r.Context())
		if !ok {
			t.Error("expected principal in context")
		}
		if got != p {
			t.Errorf("principal in context: got %v, want %v", got, p)
		}
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer 123456")
	rec := httptest.NewRecorder()

	g.Wrap(next).ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("next was not called")
	}
}

func TestGuard_Wrap_TokenValidationFails(t *testing.T) {
	iss := "https://auth.example.com"
	resource := "https://mcp.example.com"
	p := &principal.Principal{
		Iss:    iss,
		Claims: map[string]any{"aud": resource},
	}
	v := fakeValidator{canHandle: true, principal: p}
	g := newTestGuard(&v, resource, iss)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	g.Wrap(next).ServeHTTP(rec, req)

	if nextCalled {
		t.Error("next was called")
	}

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("rec.Code: got %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Error("expected WWW-Authenticate header to be set")
	}
}

func TestGuard_Wrap_ResourceMismatch(t *testing.T) {
	iss := "https://auth.example.com"
	resource := "https://mcp.example.com"
	p := &principal.Principal{
		Iss:    iss,
		Claims: map[string]any{"aud": "https://other.example.com"},
	}
	v := fakeValidator{canHandle: true, principal: p}
	g := newTestGuard(&v, resource, iss)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer 123456")

	rec := httptest.NewRecorder()

	g.Wrap(next).ServeHTTP(rec, req)

	if nextCalled {
		t.Error("next was called")
	}

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("rec.Code: got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestGuard_Wrap_IssuerMismatch(t *testing.T) {
	iss := "https://auth.example.com"
	resource := "https://mcp.example.com"
	p := &principal.Principal{
		Iss:    iss,
		Claims: map[string]any{"aud": "https://mcp.example.com"},
	}
	v := fakeValidator{canHandle: true, principal: p}
	g := newTestGuard(&v, resource, "https://other.example.com")

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer 123456")

	rec := httptest.NewRecorder()

	g.Wrap(next).ServeHTTP(rec, req)

	if nextCalled {
		t.Error("next was called")
	}

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("rec.Code: got %d, want %d", rec.Code, http.StatusUnauthorized)
	}

}
