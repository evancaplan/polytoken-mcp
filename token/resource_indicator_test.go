package token

import (
	"errors"
	"strings"
	"testing"

	"github.com/evancaplan/polytoken/principal"
)

func TestCheckResourceIndicator_ExactMatch(t *testing.T) {
	resource := "https://mcp.example.com"
	err := CheckResourceIndicator(&principal.Principal{Claims: map[string]any{"aud": resource}}, resource)
	if err != nil {
		t.Errorf("CheckResourceIndicator returned unexpected error: %v", err)
	}
}

func TestCheckResourceIndicator_ArrayMatch(t *testing.T) {
	resources := []interface{}{"https://mcp.example.com", "https://other.example.com"}

	err := CheckResourceIndicator(
		&principal.Principal{Claims: map[string]any{"aud": resources}},
		"https://mcp.example.com",
	)
	if err != nil {
		t.Errorf("CheckResourceIndicator returned unexpected error: %v", err)
	}
}

func TestCheckResourceIndicator_NoMatch(t *testing.T) {
	resource := "https://mcp.example.com"
	err := CheckResourceIndicator(&principal.Principal{Claims: map[string]any{"aud": "https://other.example.com"}}, resource)
	if !errors.Is(err, ErrResourceMismatch) {
		t.Errorf("CheckResourceIndicator returned unexpected error: %v", err)
	}
}

func TestCheckResourceIndicator_MissingClaim(t *testing.T) {
	resource := "https://mcp.example.com"
	err := CheckResourceIndicator(&principal.Principal{Claims: map[string]any{}}, resource)
	if !errors.Is(err, ErrMissingResourceClaim) {
		t.Errorf("CheckResourceIndicator returned unexpected error: %v", err)
	}
}

func TestCheckResourceIndicator_TrailingSlash(t *testing.T) {
	resource := "https://mcp.example.com/"
	err := CheckResourceIndicator(&principal.Principal{Claims: map[string]any{"aud": resource}}, resource)
	if err != nil {
		t.Errorf("CheckResourceIndicator returned unexpected error: %v", err)
	}
}

func TestCheckResourceIndicator_CaseMismatch(t *testing.T) {
	resource := "https://mcp.example.com/"
	err := CheckResourceIndicator(&principal.Principal{Claims: map[string]any{"aud": strings.ToTitle(resource)}}, resource)
	if err != nil {
		t.Errorf("CheckResourceIndicator returned unexpected error: %v", err)
	}
}

func FuzzCheckResourceIndicator(f *testing.F) {
	f.Add("https://auth.example.com", "https://auth.example.com")
	f.Add("https://auth.example.com", "https://evil.example.com")
	f.Add("HTTPS://AUTH.EXAMPLE.COM", "https://auth.example.com")
	f.Add("", "https://auth.example.com")
	f.Add("https://auth.example.com", "")
	f.Add("", "")
	f.Add("not-a-url", "https://auth.example.com")
	f.Add("https://auth.example.com\x00", "https://auth.example.com")

	f.Fuzz(func(t *testing.T, audClaim string, expectedResource string) {
		p := &principal.Principal{
			Claims: map[string]any{"aud": audClaim},
		}
		_ = CheckResourceIndicator(p, expectedResource)
	})
}
