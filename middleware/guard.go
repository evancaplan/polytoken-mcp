package middleware

import (
	"net/http"

	"github.com/evancaplan/polytoken-mcp/challenge"
	"github.com/evancaplan/polytoken-mcp/token"

	"github.com/evancaplan/polytoken/principal"
)

// Guard wraps an http.Handler with MCP-spec authorization: validates the bearer
// token and checks its resource and issuer. Failing requests get a 401 challenge.
type Guard struct {
	validator        *token.Validator
	expectedResource string
	expectedIssuer   string
	prmURL           string
	sessions         SessionStore
}

// Option configures optional Guard behavior.
type Option func(*Guard)

func WithSessionBinding(store SessionStore) Option {
	return func(g *Guard) {
		g.sessions = store
	}
}

func NewGuard(v *token.Validator, expectedResource, expectedIssuer, prmURL string, opts ...Option) *Guard {
	g := &Guard{
		validator:        v,
		expectedResource: expectedResource,
		expectedIssuer:   expectedIssuer,
		prmURL:           prmURL,
	}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

// Wrap returns an http.Handler that enforces this Guard's checks before delegating to next.
func (g *Guard) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		princ, err := g.validator.Validate(r.Context(), r)
		if err != nil {
			challenge.Unauthorized(w, g.prmURL)
			return
		}
		err = token.CheckIssuerBinding(princ, g.expectedIssuer)
		if err != nil {
			challenge.Unauthorized(w, g.prmURL)
			return
		}
		err = token.CheckResourceIndicator(princ, g.expectedResource)
		if err != nil {
			challenge.Unauthorized(w, g.prmURL)
			return
		}

		ctx := principal.WithPrincipal(r.Context(), princ)
		r = r.WithContext(ctx)
		if g.sessions != nil {
			g.serveWithSessionBinding(w, r, next, Identity{Issuer: princ.Iss, Subject: princ.Sub})
			return
		}
		next.ServeHTTP(w, r)
	})
}
