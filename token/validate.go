package token

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/evancaplan/polytoken/principal"
	"github.com/evancaplan/polytoken/resolver"
)

var (
	// ErrMissingAuthHeader means the request had no Authorization header at all.
	ErrMissingAuthHeader = errors.New("token: missing Authorization header")

	// ErrInvalidAuthScheme means the header was present but wasn't a Bearer scheme.
	ErrInvalidAuthScheme = errors.New("token: Authorization header must use Bearer scheme")

	// ErrEmptyToken means the header used "Bearer " but had no token after it.
	ErrEmptyToken = errors.New("token: empty bearer token")
)

const bearerPrefix = "Bearer "

// Validator extracts a bearer token and validates it via the underlying polytoken resolver.
type Validator struct {
	resolver *resolver.Resolver
}

func NewValidator(r *resolver.Resolver) *Validator {
	return &Validator{resolver: r}
}

// Validate extracts and validates the bearer token, returning the resolved principal.
func (v *Validator) Validate(ctx context.Context, r *http.Request) (*principal.Principal, error) {
	token, err := extractBearerToken(r)
	if err != nil {
		return nil, err
	}

	p, err := v.resolver.Validate(ctx, token)
	if err != nil {
		return nil, err
	}

	return p, nil
}

// extractBearerToken pulls the token out of the Authorization header.
func extractBearerToken(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", ErrMissingAuthHeader
	}

	if !strings.HasPrefix(header, bearerPrefix) {
		return "", ErrInvalidAuthScheme
	}

	token := strings.TrimPrefix(header, bearerPrefix)
	if token == "" {
		return "", ErrEmptyToken
	}

	return token, nil
}
