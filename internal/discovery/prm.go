package discovery

import (
	"encoding/json"
	"net/http"
)

// ProtectedResourceMetadata represents the RFC 9728 metadata document
// served at /.well-known/oauth-protected-resource.
type ProtectedResourceMetadata struct {
	// Resource is the canonical URI identifying this protected resource
	// (this MCP server). REQUIRED.
	Resource string `json:"resource"`

	// AuthorizationServers is the list of authorization server issuer
	// URLs that can issue tokens for this resource. REQUIRED.
	AuthorizationServers []string `json:"authorization_servers"`

	// BearerMethodsSupported indicates how the client should present the
	// token, for example, "header". OPTIONAL but recommended for clarity.
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`

	// ResourceDocumentation is a human-facing URL describing this
	// resource. OPTIONAL.
	ResourceDocumentation string `json:"resource_documentation,omitempty"`

	// ScopesSupported lists the OAuth scopes this resource understands.
	// OPTIONAL, but useful for clients constructing an authorization request.
	ScopesSupported []string `json:"scopes_supported,omitempty"`
}

type Handler struct {
	metadata ProtectedResourceMetadata
}

func NewHandler(resourceURI string, authServers []string, opts ...Option) *Handler {
	h := &Handler{
		metadata: ProtectedResourceMetadata{
			Resource:               resourceURI,
			AuthorizationServers:   authServers,
			BearerMethodsSupported: []string{"header"},
		},
	}
	for _, opt := range opts {
		opt(&h.metadata)
	}
	return h
}

type Option func(*ProtectedResourceMetadata)

func WithResourceDocumentation(url string) Option {
	return func(m *ProtectedResourceMetadata) {
		m.ResourceDocumentation = url
	}
}

func WithScopes(scopes []string) Option {
	return func(m *ProtectedResourceMetadata) {
		m.ScopesSupported = scopes
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	_ = json.NewEncoder(w).Encode(h.metadata)
}
