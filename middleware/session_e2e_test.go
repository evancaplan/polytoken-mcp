package middleware_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evancaplan/polytoken-mcp/middleware"
	"github.com/evancaplan/polytoken-mcp/token"
	"github.com/evancaplan/polytoken/principal"
	"github.com/evancaplan/polytoken/resolver"
	"github.com/evancaplan/polytoken/validator"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	e2eIssuer   = "https://auth.example.com"
	e2eResource = "https://mcp.example.com"
)

type mapValidator map[string]*principal.Principal

func (m mapValidator) CanHandle(string) bool { return true }
func (m mapValidator) Validate(_ context.Context, t string) (*principal.Principal, error) {
	if p, ok := m[t]; ok {
		return p, nil
	}
	return nil, errors.New("unknown token")
}

type swappableAuth struct {
	tok atomic.Value // string

	mu              sync.Mutex
	sessionStatuses []int
}

func (s *swappableAuth) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+s.tok.Load().(string))
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err == nil && req.Header.Get(middleware.SessionIDHeader) != "" && req.Method == http.MethodPost {
		s.mu.Lock()
		s.sessionStatuses = append(s.sessionStatuses, resp.StatusCode)
		s.mu.Unlock()
	}
	return resp, err
}

func (s *swappableAuth) lastSessionStatus() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sessionStatuses) == 0 {
		return 0
	}
	return s.sessionStatuses[len(s.sessionStatuses)-1]
}

func TestSessionBinding_E2E_StreamableHTTP(t *testing.T) {
	tests := []struct {
		name    string
		opts    []middleware.Option
		wantHij bool // whether Scott's call reaches the tool as Bob
	}{
		{name: "binding off reproduces the leak", wantHij: true},
		{name: "binding on blocks the hijack", opts: []middleware.Option{middleware.WithSessionBinding(middleware.NewMemorySessionStore(time.Minute))}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			var mu sync.Mutex
			var toolCallers []string // principal subject seen by each tool invocation

			server := mcp.NewServer(&mcp.Implementation{Name: "e2e", Version: "v0"}, nil)
			mcp.AddTool(server, &mcp.Tool{Name: "whoami"}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
				sub := "<none>"
				if p, ok := principal.FromContext(ctx); ok {
					sub = p.Sub
				}
				mu.Lock()
				toolCallers = append(toolCallers, sub)
				mu.Unlock()
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: sub}}}, nil, nil
			})

			res := resolver.NewResolver([]validator.TokenValidator{mapValidator{
				"bob-token":   {Sub: "bob", Iss: e2eIssuer, Claims: map[string]any{"aud": e2eResource}},
				"scott-token": {Sub: "scott", Iss: e2eIssuer, Claims: map[string]any{"aud": e2eResource}},
			}})
			guard := middleware.NewGuard(token.NewValidator(res), e2eResource, e2eIssuer,
				e2eResource+"/.well-known/oauth-protected-resource", tt.opts...)

			handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
			ts := httptest.NewServer(guard.Wrap(handler))
			defer ts.Close()

			auth := &swappableAuth{}
			auth.tok.Store("bob-token")
			client := mcp.NewClient(&mcp.Implementation{Name: "e2e-client", Version: "v0"}, nil)
			cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{
				Endpoint:   ts.URL,
				HTTPClient: &http.Client{Transport: auth},
				MaxRetries: -1,
			}, nil)
			if err != nil {
				t.Fatalf("connect as bob: %v", err)
			}
			defer cs.Close()
			if cs.ID() == "" {
				t.Fatal("expected a stateful session ID")
			}

			// Positive control: Bob can use his own session.
			if _, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "whoami"}); err != nil {
				t.Fatalf("bob calling his own session: %v", err)
			}

			// Scott presents his own valid token with Bob's session ID.
			auth.tok.Store("scott-token")
			_, scottErr := cs.CallTool(ctx, &mcp.CallToolParams{Name: "whoami"})

			mu.Lock()
			callers := append([]string(nil), toolCallers...)
			mu.Unlock()

			if tt.wantHij {
				if scottErr != nil {
					t.Fatalf("expected the unprotected call to succeed, got %v", scottErr)
				}
				if len(callers) != 2 || callers[1] != "bob" {
					t.Fatalf("tool callers: got %v, want [bob bob] (Scott's request running as Bob)", callers)
				}
				return
			}

			if scottErr == nil {
				t.Fatal("scott's call on bob's session succeeded")
			}
			if got := auth.lastSessionStatus(); got != http.StatusNotFound {
				t.Errorf("scott's request status: got %d, want %d", got, http.StatusNotFound)
			}
			if len(callers) != 1 {
				t.Errorf("tool invoked %d times, want 1 (bob only): %v", len(callers), callers)
			}
		})
	}
}
