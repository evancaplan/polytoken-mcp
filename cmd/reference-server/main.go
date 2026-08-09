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
	prmHandler := discovery.NewHandler(resourceURI, []string{issuerURI}, discovery.WithResourceDocumentation(prmURL))

	// upstreamClient stands in for the http.Client this server would use to
	// call a downstream API on the client's behalf. Routing it through
	// passthrough.Guard means any attempt to forward the client's inbound
	// MCP token to that downstream API unmodified gets refused.
	upstreamClient := &http.Client{Transport: passthrough.NewGuard(nil)}

	// upstream is a stand-in for a real downstream API, so the demo below
	// has something to call and can show what Authorization header it
	// actually received.
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"received_authorization": r.Header.Get("Authorization")})
	})

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := middleware.PrincipalFromContext(r.Context())
		if !ok {
			http.Error(w, "no principal in context", http.StatusInternalServerError)
			return
		}

		inboundAuth := r.Header.Get("Authorization")
		ctx := passthrough.WithToken(r.Context(), strings.TrimPrefix(inboundAuth, "Bearer "))

		// Deliberately try to forward the client's inbound token to the
		// upstream API unmodified, the way a confused-deputy bug would.
		// passthrough.Guard refuses this at the transport layer.
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
