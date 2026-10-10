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
		Sub:    "user-123",
		Iss:    iss,
		Claims: map[string]any{"aud": resource},
	}
	v := fakeValidator{canHandle: true, principal: p}
	g := newTestGuard(&v, resource, iss)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		got, ok := principal.FromContext(r.Context())
		if !ok {
			t.Fatal("expected principal in context")
		}
		if got.Sub != "user-123" {
			t.Errorf("Sub: got %q, want %q", got.Sub, "user-123")
		}
		if got.Iss != iss {
			t.Errorf("Iss: got %q, want %q", got.Iss, iss)
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

func TestGuard_Wrap_FailingCheckNeverCallsNext(t *testing.T) {
	iss := "https://auth.example.com"
	resource := "https://mcp.example.com"

	tests := []struct {
		name           string
		authHeader     string
		principal      *principal.Principal
		expectedIssuer string
	}{
		{
			name:           "missing token",
			principal:      &principal.Principal{Sub: "user-123", Iss: iss, Claims: map[string]any{"aud": resource}},
			expectedIssuer: iss,
		},
		{
			name:           "resource mismatch",
			authHeader:     "Bearer 123456",
			principal:      &principal.Principal{Sub: "user-123", Iss: iss, Claims: map[string]any{"aud": "https://other.example.com"}},
			expectedIssuer: iss,
		},
		{
			name:           "issuer mismatch",
			authHeader:     "Bearer 123456",
			principal:      &principal.Principal{Sub: "user-123", Iss: iss, Claims: map[string]any{"aud": resource}},
			expectedIssuer: "https://other.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := fakeValidator{canHandle: true, principal: tt.principal}
			g := newTestGuard(&v, resource, tt.expectedIssuer)

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Error("next was called")
			})

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rec := httptest.NewRecorder()

			g.Wrap(next).ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("rec.Code: got %d, want %d", rec.Code, http.StatusUnauthorized)
			}
		})
	}
}
