package passthrough

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeRoundTripper struct {
	called bool
}

func (f *fakeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	f.called = true
	return &http.Response{StatusCode: http.StatusOK}, nil
}

func TestGuard_RoundTrip_BlocksExactTokenReuse(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://upstream.example.com", nil)
	req.Header.Set("Authorization", "Bearer sometoken")
	req = req.WithContext(WithToken(req.Context(), "sometoken"))
	guard := NewGuard(&fakeRoundTripper{})

	res, err := guard.RoundTrip(req)
	if !errors.Is(err, ErrTokenPassthrough) {
		t.Errorf("expected ErrTokenPassthrough, got '%v'", err)
	}
	if res != nil {
		t.Errorf("expected nil response, got '%v'", res)
	}
	if guard.roundTripper.(*fakeRoundTripper).called {
		t.Error("expected fakeRoundTripper to not have been called")
	}
}

func TestGuard_RoundTrip_AllowsDifferentToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://upstream.example.com", nil)
	req.Header.Set("Authorization", "Bearer sometoken")
	req = req.WithContext(WithToken(req.Context(), "otherToken"))
	guard := NewGuard(&fakeRoundTripper{})

	res, err := guard.RoundTrip(req)
	if err != nil {
		t.Errorf("expected nil error, got '%v'", err)
	}
	if res == nil {
		t.Error("expected non-nil response")
	}
	if !guard.roundTripper.(*fakeRoundTripper).called {
		t.Error("expected fakeRoundTripper to have been called")
	}
}

func TestGuard_RoundTrip_AllowsWhenNoInboundToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://upstream.example.com", nil)
	req.Header.Set("Authorization", "Bearer sometoken")
	guard := NewGuard(&fakeRoundTripper{})

	res, err := guard.RoundTrip(req)
	if err != nil {
		t.Errorf("expected nil error, got '%v'", err)
	}
	if res == nil {
		t.Error("expected non-nil response")
	}
	if !guard.roundTripper.(*fakeRoundTripper).called {
		t.Error("expected fakeRoundTripper to have been called")
	}
}
