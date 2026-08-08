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
