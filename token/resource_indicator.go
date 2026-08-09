package token

import (
	"errors"
	"strings"

	"github.com/evancaplan/polytoken/principal"
)

// ErrMissingResourceClaim means the token had no aud/resource claim at all
var ErrMissingResourceClaim = errors.New("token: missing resource/audience claim")

// ErrResourceMismatch means the token's aud claim didn't include this server's
// canonical resource URI.
var ErrResourceMismatch = errors.New("token: resource indicator mismatch")

func CheckResourceIndicator(p *principal.Principal, expectedResource string) error {
	switch aud := p.Claims["aud"].(type) {
	case string:
		if !strings.EqualFold(aud, expectedResource) {
			return ErrResourceMismatch
		}
	case []interface{}:
		matched := false
		for _, a := range aud {
			audStr, ok := a.(string)
			if !ok {
				continue
			}
			if strings.EqualFold(audStr, expectedResource) {
				matched = true
				break
			}
		}
		if !matched {
			return ErrResourceMismatch
		}
	default:
		return ErrMissingResourceClaim
	}

	return nil
}
