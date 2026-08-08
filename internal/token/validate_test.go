package token

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/evancaplan/polytoken/principal"
	"github.com/evancaplan/polytoken/resolver"
	"github.com/evancaplan/polytoken/validator"
)

// fakeValidator lets you control CanHandle/Validate behavior per test case,
// without needing a real HS256/RS256 validator or a real token.
type fakeValidator struct {
	canHandle bool
	principal *principal.Principal
	err       error
}

func (f *fakeValidator) CanHandle(token string) bool {
	return f.canHandle
}

func (f *fakeValidator) Validate(ctx context.Context, token string) (*principal.Principal, error) {
	return f.principal, f.err
}

func newRequestWithAuthHeader(t *testing.T, headerValue string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if headerValue != "" {
		req.Header.Set("Authorization", headerValue)
	}
	return req
}

func TestExtractBearerToken(t *testing.T) {
	t.Run("valid bearer token", func(t *testing.T) {
		tokVal := "abc123"
		tok, err := extractBearerToken(newRequestWithAuthHeader(t, "Bearer "+tokVal))
		if err != nil {
			t.Errorf("expected no error, got '%v'", err)
		}
		if tok != tokVal {
			t.Errorf("expected token to be '%s', got '%s'", tokVal, tok)
		}
	})

	t.Run("empty bearer token", func(t *testing.T) {
		_, err := extractBearerToken(newRequestWithAuthHeader(t, "Bearer "))
		if !errors.Is(err, ErrEmptyToken) {
			t.Errorf("expected error to be ErrEmptyToken, got '%v'", err)
		}
	})

	t.Run("missing auth header", func(t *testing.T) {
		_, err := extractBearerToken(newRequestWithAuthHeader(t, ""))
		if !errors.Is(err, ErrMissingAuthHeader) {
			t.Errorf("expected error to be ErrMissingAuthHeader, got '%v'", err)
		}
	})

	t.Run("wrong scheme", func(t *testing.T) {
		_, err := extractBearerToken(newRequestWithAuthHeader(t, "Basic abc123"))
		if !errors.Is(err, ErrInvalidAuthScheme) {
			t.Errorf("expected error to be ErrWrongScheme, got '%v'", err)
		}
	})
}

func TestValidator_Validate_Success(t *testing.T) {
	p := &principal.Principal{
		Sub:       "12334",
		Iss:       "www.example.com",
		Scopes:    nil,
		Roles:     nil,
		IssuedAt:  time.Time{},
		ExpiresAt: time.Time{},
		Claims:    nil,
	}

	fv := &fakeValidator{canHandle: true, principal: p}
	res := resolver.NewResolver([]validator.TokenValidator{fv})
	val := NewValidator(res)

	prin, err := val.Validate(t.Context(), newRequestWithAuthHeader(t, "Bearer abc123"))
	if err != nil {
		t.Errorf("expected no error, got '%v'", err)
	}
	if !reflect.DeepEqual(prin, fv.principal) {
		t.Errorf("expected principal to be %v, got %v", fv.principal, prin)
	}
}

func TestValidator_Validate_MissingHeader(t *testing.T) {
	fv := &fakeValidator{canHandle: true, principal: &principal.Principal{}}
	res := resolver.NewResolver([]validator.TokenValidator{fv})
	val := NewValidator(res)

	princ, err := val.Validate(t.Context(), newRequestWithAuthHeader(t, ""))
	if princ != nil {
		t.Errorf("expected principal to be nil, got %v", princ)
	}
	if !errors.Is(err, ErrMissingAuthHeader) {
		t.Errorf("expected error to be ErrMissingAuthHeader, got '%v'", err)
	}
}

func TestValidator_Validate_WrongScheme(t *testing.T) {
	fv := &fakeValidator{canHandle: true, principal: &principal.Principal{}}
	res := resolver.NewResolver([]validator.TokenValidator{fv})
	val := NewValidator(res)

	princ, err := val.Validate(t.Context(), newRequestWithAuthHeader(t, "Basic abc123"))
	if princ != nil {
		t.Errorf("expected principal to be nil, got %v", princ)
	}
	if !errors.Is(err, ErrInvalidAuthScheme) {
		t.Errorf("expected error to be ErrInvalidAuthScheme, got '%v'", err)
	}
}

func TestValidator_Validate_EmptyToken(t *testing.T) {
	fv := &fakeValidator{canHandle: true, principal: &principal.Principal{}}
	res := resolver.NewResolver([]validator.TokenValidator{fv})
	val := NewValidator(res)
	princ, err := val.Validate(t.Context(), newRequestWithAuthHeader(t, "Bearer "))
	if princ != nil {
		t.Errorf("expected principal to be nil, got %v", princ)
	}
	if !errors.Is(err, ErrEmptyToken) {
		t.Errorf("expected error to be ErrEmptyToken, got '%v'", err)
	}
}

func TestValidator_Validate_ResolverRejects(t *testing.T) {
	fv := &fakeValidator{canHandle: false, principal: &principal.Principal{}}
	res := resolver.NewResolver([]validator.TokenValidator{fv})
	val := NewValidator(res)

	princ, err := val.Validate(t.Context(), newRequestWithAuthHeader(t, "Bearer abc123"))
	if princ != nil {
		t.Errorf("expected principal to be nil, got %v", princ)
	}
	if !errors.Is(err, resolver.ErrNoValidator) {
		t.Errorf("expected error to be '%v', got '%v'", resolver.ErrNoValidator, err)
	}
}

func TestValidator_Validate_UnderlyingValidatorFails(t *testing.T) {
	wantErr := errors.New("bad signature")
	fv := &fakeValidator{canHandle: true, err: wantErr}
	res := resolver.NewResolver([]validator.TokenValidator{fv})
	val := NewValidator(res)

	princ, err := val.Validate(t.Context(), newRequestWithAuthHeader(t, "Bearer abc123"))
	if princ != nil {
		t.Errorf("expected principal to be nil, got %v", princ)
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("expected error to be '%v', got '%v'", wantErr, err)
	}
}
