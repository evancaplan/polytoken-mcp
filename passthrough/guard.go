package passthrough

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// ErrTokenPassthrough is returned when a request would forward the client's inbound token unmodified.
var ErrTokenPassthrough = errors.New("passthrough: refusing to forward client token to upstream")

// Guard wraps an http.RoundTripper and refuses outgoing requests whose Authorization
// header matches the client's original inbound token.
type Guard struct {
	roundTripper http.RoundTripper
}

func NewGuard(next http.RoundTripper) *Guard {
	if next == nil {
		next = http.DefaultTransport
	}
	return &Guard{roundTripper: next}
}

type tokenContextKey struct{}

// RoundTrip implements http.RoundTripper.
func (g *Guard) RoundTrip(req *http.Request) (*http.Response, error) {
	inbound, ok := TokenFromContext(req.Context())
	outbound := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")

	if ok && outbound == inbound {
		return nil, ErrTokenPassthrough
	}

	return g.roundTripper.RoundTrip(req)
}

func WithToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, tokenContextKey{}, token)
}

func TokenFromContext(ctx context.Context) (string, bool) {
	t, ok := ctx.Value(tokenContextKey{}).(string)
	return t, ok
}
