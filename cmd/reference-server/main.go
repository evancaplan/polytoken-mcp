package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/evancaplan/polytoken-mcp/discovery"
	"github.com/evancaplan/polytoken-mcp/middleware"
	"github.com/evancaplan/polytoken-mcp/passthrough"
	"github.com/evancaplan/polytoken-mcp/token"
	"github.com/evancaplan/polytoken/principal"
	"github.com/evancaplan/polytoken/resolver"
	"github.com/evancaplan/polytoken/validator"
)

const (
	resourceURI    = "http://localhost:8080"
	issuerURI      = "https://test.local"
	prmPath        = "/.well-known/oauth-protected-resource"
	demoHMACSecret = "my-test-secret"
	upstreamPath   = "/upstream/echo"
)

func main() {
	hs256Validator := validator.NewHs256Validator(issuerURI, []byte(demoHMACSecret))
	res := resolver.NewResolver([]validator.TokenValidator{hs256Validator})

	tv := token.NewValidator(res)

	prmURL := resourceURI + prmPath
	guard := middleware.NewGuard(tv, resourceURI, issuerURI, prmURL)
	prmHandler := discovery.NewHandler(
		resourceURI,
		[]string{issuerURI},
		discovery.WithResourceDocumentation("https://github.com/evancaplan/polytoken-mcp"),
		discovery.WithScopes([]string{"mcp:read", "mcp:write"}),
	)

	// upstreamClient stands in for calling a downstream API; passthrough.Guard
	// refuses to forward the client's inbound MCP token unmodified.
	upstreamClient := &http.Client{Transport: passthrough.NewGuard(nil)}

	// upstream is a stand-in downstream API that echoes back the Authorization header it received.
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"received_authorization": r.Header.Get("Authorization")})
	})

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := principal.FromContext(r.Context())
		if !ok {
			http.Error(w, "no principal in context", http.StatusInternalServerError)
			return
		}

		inboundAuth := r.Header.Get("Authorization")
		ctx := passthrough.WithToken(r.Context(), strings.TrimPrefix(inboundAuth, "Bearer "))

		// Deliberately try to forward the inbound token unmodified; passthrough.Guard refuses it.
		upstreamReq, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceURI+upstreamPath, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		upstreamReq.Header.Set("Authorization", inboundAuth)

		_, err = upstreamClient.Do(upstreamReq)
		passthroughBlocked := errors.Is(err, passthrough.ErrTokenPassthrough)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"sub":                 p.Sub,
			"iss":                 p.Iss,
			"passthrough_blocked": passthroughBlocked,
		})
	})

	mux := http.NewServeMux()
	mux.Handle(prmPath, prmHandler)
	mux.Handle("/mcp", guard.Wrap(protected))
	mux.Handle(upstreamPath, upstream)

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
