package passthrough

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// ErrTokenPassthrough is returned when an outgoing upstream request would
// have forwarded the client's original inbound token unmodified
var ErrTokenPassthrough = errors.New("passthrough: refusing to forward client token to upstream")

// Guard wraps an http.RoundTripper and refuses to send any outgoing
// request whose Authorization header exactly matches the client's
// original inbound token.
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

// RoundTrip implements http.RoundTripper. This is the interception point
// every outgoing request made through an *http.Client configured with
// this Guard as its Transport passes through here first.
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
