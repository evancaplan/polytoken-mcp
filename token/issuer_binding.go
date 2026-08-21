package token

import (
	"errors"
	"strings"

	"github.com/evancaplan/polytoken/principal"
)

// ErrMissingIssuer means the token had no iss claim.
var ErrMissingIssuer = errors.New("token: missing issuer claim")

// ErrIssuerMismatch means the token's iss claim didn't match the expected issuer.
var ErrIssuerMismatch = errors.New("token: issuer mismatch")

// CheckIssuerBinding verifies the principal's issuer matches expectedIssuer, per RFC 9207.
func CheckIssuerBinding(p *principal.Principal, expectedIssuer string) error {
	iss := p.Iss
	if iss == "" {
		return ErrMissingIssuer
	}
	if !strings.EqualFold(iss, expectedIssuer) {
		return ErrIssuerMismatch
	}
	return nil
}
