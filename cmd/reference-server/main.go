package main

import (
	"crypto/rand"
	"encoding/json"
	"log"
	"net/http"

	"github.com/evancaplan/polytoken-mcp/internal/discovery"
	"github.com/evancaplan/polytoken-mcp/internal/middleware"
	"github.com/evancaplan/polytoken-mcp/internal/token"
	"github.com/evancaplan/polytoken/resolver"
	"github.com/evancaplan/polytoken/validator"
)

// TODO: pick real values for a working local demo. These four constants
// need to be consistent with each other — e.g. resourceURI is what both
// the PRM document AND the guard's expectedResource check against, so a
// typo/mismatch between them would make every request 401 even with a
// perfectly valid token.
const (
	resourceURI    = "http://localhost:8080"
	issuerURI      = "https://test.local"
	prmPath        = "/.well-known/oauth-protected-resource"
	demoHMACSecret = "my-test-secret"
)

func main() {
	hs256Validator := validator.NewHs256Validator(issuerURI, []byte(demoHMACSecret))
	res := resolver.NewResolver([]validator.TokenValidator{hs256Validator})

	tv := token.NewValidator(res)

	prmURL := resourceURI + prmPath
	guard := middleware.NewGuard(tv, resourceURI, issuerURI, prmURL)
	prmHandler := discovery.NewHandler(resourceURI, []string{issuerURI}, discovery.WithResourceDocumentation(prmURL))

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := middleware.PrincipalFromContext(r.Context())
		if !ok {
			http.Error(w, "no principal in context", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"sub": p.Sub, "iss": p.Iss})
	})

	mux := http.NewServeMux()
	mux.Handle(prmPath, prmHandler)
	mux.Handle("/mcp", guard.Wrap(protected))

	//upstreamClient := &http.Client{
	//	Transport: passthrough.NewGuard(http.DefaultTransport),
	//}

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func generateDemoSecret() ([]byte, error) {
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	if err != nil {
		return nil, err
	}
	return secret, nil
}
