package token

import (
	"errors"
	"strings"
	"testing"

	"github.com/evancaplan/polytoken/principal"
)

func TestCheckIssuerBinding_Match(t *testing.T) {
	iss := "https://auth.example.com"
	err := CheckIssuerBinding(&principal.Principal{Iss: iss}, iss)
	if err != nil {
		t.Errorf("CheckIssuerBinding returned unexpected error: %v", err)
	}
}

func TestCheckIssuerBinding_Mismatch(t *testing.T) {
	iss := "https://auth.example.com"
	err := CheckIssuerBinding(&principal.Principal{Iss: iss}, "https://other.example.com")
	if !errors.Is(err, ErrIssuerMismatch) {
		t.Errorf("CheckIssuerBinding returned unexpected error: %v", err)
	}
}

func TestCheckIssuerBinding_MissingIssuer(t *testing.T) {
	err := CheckIssuerBinding(&principal.Principal{Iss: ""}, "https://auth.example.com")
	if !errors.Is(err, ErrMissingIssuer) {
		t.Errorf("CheckIssuerBinding returned unexpected error: %v", err)
	}
}

func TestCheckIssuerBinding_CaseSensitivity(t *testing.T) {
	iss := "https://auth.example.com"
	err := CheckIssuerBinding(&principal.Principal{Iss: strings.ToTitle(iss)}, iss)
	if err != nil {
		t.Errorf("CheckIssuerBinding returned unexpected error: %v", err)
	}
}

func FuzzCheckIssuerBinding(f *testing.F) {
	f.Add("https://auth.example.com", "https://auth.example.com")
	f.Add("https://auth.example.com", "https://evil.example.com")
	f.Add("HTTPS://AUTH.EXAMPLE.COM", "https://auth.example.com")
	f.Add("", "https://auth.example.com")
	f.Add("https://auth.example.com", "")
	f.Add("", "")
	f.Add("not-a-url", "https://auth.example.com")
	f.Add("https://auth.example.com\x00", "https://auth.example.com")

	f.Fuzz(func(t *testing.T, iss string, expectedIssuer string) {
		p := &principal.Principal{Iss: iss}

		_ = CheckIssuerBinding(p, expectedIssuer)
	})
}
