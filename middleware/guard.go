package middleware

import (
	"context"
	"net/http"

	"github.com/evancaplan/polytoken-mcp/challenge"
	"github.com/evancaplan/polytoken-mcp/token"

	"github.com/evancaplan/polytoken/principal"
)

// principalContextKey is an unexported type, so this package's context key
// can never collide with a key from another package, even if they happen
// to use the same underlying string.
type principalContextKey struct{}

// Guard wraps an http.Handler with MCP-spec authorization: validates the
// bearer token, confirms it was issued for this resource, and confirms it
// came from the expected authorization server. Requests that fail any
// check get a 401 with a WWW-Authenticate challenge instead of reaching
// the wrapped handler.
type Guard struct {
	validator        *token.Validator
	expectedResource string
	expectedIssuer   string
	prmURL           string
}

func NewGuard(v *token.Validator, expectedResource, expectedIssuer, prmURL string) *Guard {
	return &Guard{
		validator:        v,
		expectedResource: expectedResource,
		expectedIssuer:   expectedIssuer,
		prmURL:           prmURL,
	}
}

// Wrap returns an http.Handler that enforces this Guard's checks before
// delegating to next.
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

		ctx := WithPrincipal(r.Context(), princ)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func WithPrincipal(ctx context.Context, p *principal.Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, p)
}

func PrincipalFromContext(ctx context.Context) (*principal.Principal, bool) {
	p, ok := ctx.Value(principalContextKey{}).(*principal.Principal)
	return p, ok
}
