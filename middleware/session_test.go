package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/evancaplan/polytoken-mcp/token"
	"github.com/evancaplan/polytoken/principal"
	"github.com/evancaplan/polytoken/resolver"
	"github.com/evancaplan/polytoken/validator"
)

const (
	testIssuer   = "https://auth.example.com"
	testResource = "https://mcp.example.com"
)

type tokenValidator struct {
	principals map[string]*principal.Principal
}

func (tv *tokenValidator) CanHandle(string) bool { return true }
func (tv *tokenValidator) Validate(_ context.Context, t string) (*principal.Principal, error) {
	p, ok := tv.principals[t]
	if !ok {
		return nil, errors.New("unknown token")
	}
	return p, nil
}

func newPrincipal(iss, sub string) *principal.Principal {
	return &principal.Principal{Sub: sub, Iss: iss, Claims: map[string]any{"aud": testResource}}
}

var testPrincipals = map[string]*principal.Principal{
	"bob":          newPrincipal(testIssuer, "bob"),
	"scott":        newPrincipal(testIssuer, "scott"),
	"other-issuer": newPrincipal("https://AUTH.example.com", "bob"),
}

func newBindingGuard(store SessionStore) *Guard {
	res := resolver.NewResolver([]validator.TokenValidator{&tokenValidator{principals: testPrincipals}})
	return NewGuard(token.NewValidator(res), testResource, testIssuer,
		"https://mcp.example.com/.well-known/oauth-protected-resource", WithSessionBinding(store))
}

func newSessionRequest(method, tok, sessionID string) *http.Request {
	req := httptest.NewRequest(method, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	if sessionID != "" {
		req.Header.Set(SessionIDHeader, sessionID)
	}
	return req
}

// initializeHandler mimics an MCP server answering initialize with a new session ID.
func initializeHandler(sessionID string, status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(SessionIDHeader, sessionID)
		w.WriteHeader(status)
	})
}

func TestSessionBinding_InitializeBindsCaller(t *testing.T) {
	store := NewMemorySessionStore(time.Minute)
	g := newBindingGuard(store)

	rec := httptest.NewRecorder()
	g.Wrap(initializeHandler("sess-1", http.StatusOK)).ServeHTTP(rec, newSessionRequest(http.MethodPost, "bob", ""))

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusOK)
	}
	got, ok := store.Lookup("sess-1")
	if !ok {
		t.Fatal("expected sess-1 to be bound")
	}
	want := Identity{Issuer: testIssuer, Subject: "bob"}
	if got != want {
		t.Errorf("binding: got %+v, want %+v", got, want)
	}
}

func TestSessionBinding_ImplicitWriteHeaderBinds(t *testing.T) {
	store := NewMemorySessionStore(time.Minute)
	g := newBindingGuard(store)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(SessionIDHeader, "sess-1")
		_, _ = w.Write([]byte("{}")) // no explicit WriteHeader
	})
	g.Wrap(next).ServeHTTP(httptest.NewRecorder(), newSessionRequest(http.MethodPost, "bob", ""))

	if _, ok := store.Lookup("sess-1"); !ok {
		t.Fatal("expected sess-1 to be bound after implicit 200")
	}
}

func TestSessionBinding_BindingExistsBeforeResponseCommits(t *testing.T) {
	store := NewMemorySessionStore(time.Minute)
	g := newBindingGuard(store)

	rec := httptest.NewRecorder()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(SessionIDHeader, "sess-1")
		w.WriteHeader(http.StatusOK)
		// The client could already have the header at this point.
		if _, ok := store.Lookup("sess-1"); !ok {
			t.Error("binding not recorded by the time WriteHeader returned")
		}
	})
	g.Wrap(next).ServeHTTP(rec, newSessionRequest(http.MethodPost, "bob", ""))
}

func TestSessionBinding_NonSuccessInitializeDoesNotBind(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusNotFound, http.StatusInternalServerError, http.StatusFound} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			store := NewMemorySessionStore(time.Minute)
			g := newBindingGuard(store)

			g.Wrap(initializeHandler("sess-1", status)).ServeHTTP(httptest.NewRecorder(), newSessionRequest(http.MethodPost, "bob", ""))

			if _, ok := store.Lookup("sess-1"); ok {
				t.Errorf("status %d: binding recorded, want none", status)
			}
		})
	}
}

func TestSessionBinding_ExistingSession(t *testing.T) {
	tests := []struct {
		name       string
		bound      string // token whose identity owns sess-1; "" = unbound
		caller     string
		sessionID  string
		wantStatus int
		wantNext   bool
	}{
		{name: "same identity passes", bound: "bob", caller: "bob", sessionID: "sess-1", wantStatus: http.StatusOK, wantNext: true},
		{name: "different subject same issuer", bound: "bob", caller: "scott", sessionID: "sess-1", wantStatus: http.StatusNotFound},
		{name: "same subject different issuer", bound: "bob", caller: "other-issuer", sessionID: "sess-1", wantStatus: http.StatusNotFound},
		{name: "unknown session", bound: "bob", caller: "bob", sessionID: "sess-unknown", wantStatus: http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewMemorySessionStore(time.Minute)
			p := testPrincipals[tt.bound]
			_ = store.Bind("sess-1", Identity{Issuer: p.Iss, Subject: p.Sub})
			g := newBindingGuard(store)

			nextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextCalled = true })

			rec := httptest.NewRecorder()
			g.Wrap(next).ServeHTTP(rec, newSessionRequest(http.MethodPost, tt.caller, tt.sessionID))

			if rec.Code != tt.wantStatus {
				t.Errorf("status: got %d, want %d", rec.Code, tt.wantStatus)
			}
			if nextCalled != tt.wantNext {
				t.Errorf("next called: got %v, want %v", nextCalled, tt.wantNext)
			}
		})
	}
}

func TestSessionBinding_UnknownAndMismatchAreIndistinguishable(t *testing.T) {
	store := NewMemorySessionStore(time.Minute)
	_ = store.Bind("sess-1", Identity{Issuer: testIssuer, Subject: "bob"})
	g := newBindingGuard(store)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("next was called") })

	mismatch := httptest.NewRecorder()
	g.Wrap(next).ServeHTTP(mismatch, newSessionRequest(http.MethodPost, "scott", "sess-1"))
	unknown := httptest.NewRecorder()
	g.Wrap(next).ServeHTTP(unknown, newSessionRequest(http.MethodPost, "scott", "sess-nope"))

	if mismatch.Code != unknown.Code {
		t.Errorf("status: mismatch %d, unknown %d", mismatch.Code, unknown.Code)
	}
	if mismatch.Body.String() != unknown.Body.String() {
		t.Errorf("body: mismatch %q, unknown %q", mismatch.Body.String(), unknown.Body.String())
	}
	for _, h := range []string{"Content-Type", "X-Content-Type-Options"} {
		if mismatch.Header().Get(h) != unknown.Header().Get(h) {
			t.Errorf("%s: mismatch %q, unknown %q", h, mismatch.Header().Get(h), unknown.Header().Get(h))
		}
	}
}

func TestSessionBinding_DeleteRemovesBinding(t *testing.T) {
	store := NewMemorySessionStore(time.Minute)
	_ = store.Bind("sess-1", Identity{Issuer: testIssuer, Subject: "bob"})
	g := newBindingGuard(store)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })

	rec := httptest.NewRecorder()
	g.Wrap(next).ServeHTTP(rec, newSessionRequest(http.MethodDelete, "bob", "sess-1"))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE status: got %d, want %d", rec.Code, http.StatusNoContent)
	}

	rec = httptest.NewRecorder()
	g.Wrap(next).ServeHTTP(rec, newSessionRequest(http.MethodPost, "bob", "sess-1"))
	if rec.Code != http.StatusNotFound {
		t.Errorf("after DELETE: got %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestSessionBinding_DeleteByOtherIdentityKeepsBinding(t *testing.T) {
	store := NewMemorySessionStore(time.Minute)
	_ = store.Bind("sess-1", Identity{Issuer: testIssuer, Subject: "bob"})
	g := newBindingGuard(store)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("next was called") })

	rec := httptest.NewRecorder()
	g.Wrap(next).ServeHTTP(rec, newSessionRequest(http.MethodDelete, "scott", "sess-1"))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusNotFound)
	}
	if _, ok := store.Lookup("sess-1"); !ok {
		t.Error("another identity's DELETE removed the binding")
	}
}

type failingStore struct{ SessionStore }

func (failingStore) Bind(string, Identity) error { return errors.New("store down") }

func TestSessionBinding_BindFailureFailsClosed(t *testing.T) {
	g := newBindingGuard(failingStore{NewMemorySessionStore(time.Minute)})

	var writeErr error
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(SessionIDHeader, "sess-1")
		w.WriteHeader(http.StatusOK)
		_, writeErr = w.Write([]byte("data: hello\n\n"))
	})
	rec := httptest.NewRecorder()
	g.Wrap(next).ServeHTTP(rec, newSessionRequest(http.MethodPost, "bob", ""))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if got := rec.Header().Get(SessionIDHeader); got != "" {
		t.Errorf("session ID leaked despite failed bind: %q", got)
	}
	if writeErr == nil {
		t.Error("expected Write to fail after bind failure")
	}
	if strings.Contains(rec.Body.String(), "hello") {
		t.Error("handler body reached the client after bind failure")
	}
}

// flushRecorder counts flushes reaching the underlying writer.
type flushRecorder struct {
	*httptest.ResponseRecorder
	flushes int
}

func (f *flushRecorder) Flush() { f.flushes++; f.ResponseRecorder.Flush() }

func TestSessionBinding_WrapperFlushesAndUnwraps(t *testing.T) {
	store := NewMemorySessionStore(time.Minute)
	g := newBindingGuard(store)
	underlying := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := w.(http.Flusher); !ok {
			t.Fatal("wrapped ResponseWriter does not implement http.Flusher")
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			t.Fatal("wrapped ResponseWriter does not implement Unwrap")
		}
		if u.Unwrap() != underlying {
			t.Error("Unwrap did not return the underlying writer")
		}

		w.Header().Set(SessionIDHeader, "sess-1")
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: one\n\n"))
		w.(http.Flusher).Flush()
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("ResponseController.Flush: %v", err)
		}
	})
	g.Wrap(next).ServeHTTP(underlying, newSessionRequest(http.MethodPost, "bob", ""))

	if underlying.flushes != 2 {
		t.Errorf("flushes reaching underlying writer: got %d, want 2", underlying.flushes)
	}
	if _, ok := store.Lookup("sess-1"); !ok {
		t.Error("expected sess-1 to be bound")
	}
}

func TestSessionBinding_FlushBeforeWriteBinds(t *testing.T) {
	store := NewMemorySessionStore(time.Minute)
	g := newBindingGuard(store)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(SessionIDHeader, "sess-1")
		w.(http.Flusher).Flush() // commits an implicit 200
	})
	g.Wrap(next).ServeHTTP(httptest.NewRecorder(), newSessionRequest(http.MethodPost, "bob", ""))

	if _, ok := store.Lookup("sess-1"); !ok {
		t.Error("expected sess-1 to be bound after Flush committed the response")
	}
}

func TestSessionBinding_OffLeavesBehaviorUnchanged(t *testing.T) {
	res := resolver.NewResolver([]validator.TokenValidator{&tokenValidator{principals: testPrincipals}})
	g := NewGuard(token.NewValidator(res), testResource, testIssuer, "https://mcp.example.com/.well-known/oauth-protected-resource")

	var gotWriter http.ResponseWriter
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { gotWriter = w })

	rec := httptest.NewRecorder()
	g.Wrap(next).ServeHTTP(rec, newSessionRequest(http.MethodPost, "scott", "sess-belonging-to-nobody"))

	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusOK)
	}
	if gotWriter != rec {
		t.Error("ResponseWriter was wrapped with session binding off")
	}
}

func TestMemorySessionStore_TTL(t *testing.T) {
	now := time.Unix(0, 0)
	store := NewMemorySessionStore(10 * time.Minute)
	store.now = func() time.Time { return now }
	id := Identity{Issuer: testIssuer, Subject: "bob"}

	_ = store.Bind("active", id)
	_ = store.Bind("idle", id)

	// Lookups at 6m and 12m keep "active" alive past the original 10m expiry.
	now = now.Add(6 * time.Minute)
	if _, ok := store.Lookup("active"); !ok {
		t.Fatal("active expired early")
	}
	now = now.Add(6 * time.Minute)
	if _, ok := store.Lookup("active"); !ok {
		t.Error("active expired despite refresh")
	}
	if _, ok := store.Lookup("idle"); ok {
		t.Error("idle survived past ttl")
	}

	// 10m with no lookup expires "active" too.
	now = now.Add(10 * time.Minute)
	if _, ok := store.Lookup("active"); ok {
		t.Error("active survived past ttl after refreshes stopped")
	}
}

func TestMemorySessionStore_SweepsAbandonedEntries(t *testing.T) {
	now := time.Unix(0, 0)
	store := NewMemorySessionStore(time.Minute)
	store.now = func() time.Time { return now }

	for i := range 100 {
		_ = store.Bind(fmt.Sprintf("abandoned-%d", i), Identity{Issuer: testIssuer, Subject: "bob"})
	}
	now = now.Add(2 * time.Minute)
	_ = store.Bind("fresh", Identity{Issuer: testIssuer, Subject: "bob"})

	store.mu.Lock()
	n := len(store.entries)
	store.mu.Unlock()
	if n != 1 {
		t.Errorf("entries after sweep: got %d, want 1", n)
	}
}

func TestSessionBinding_ExpiredSessionIsNotFound(t *testing.T) {
	now := time.Unix(0, 0)
	store := NewMemorySessionStore(time.Minute)
	store.now = func() time.Time { return now }
	g := newBindingGuard(store)

	g.Wrap(initializeHandler("sess-1", http.StatusOK)).ServeHTTP(httptest.NewRecorder(), newSessionRequest(http.MethodPost, "bob", ""))
	now = now.Add(2 * time.Minute)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("next was called") })
	rec := httptest.NewRecorder()
	g.Wrap(next).ServeHTTP(rec, newSessionRequest(http.MethodPost, "bob", "sess-1"))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestNewMemorySessionStore_NonPositiveTTLPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("expected panic")
		}
	}()
	NewMemorySessionStore(0)
}

func TestSessionBinding_Concurrent(t *testing.T) {
	store := NewMemorySessionStore(time.Minute)
	g := newBindingGuard(store)
	tokens := []string{"bob", "scott"}

	const workers = 64
	const perWorker = 50

	var wg sync.WaitGroup
	errs := make(chan error, workers*perWorker)
	for w := range workers {
		wg.Go(func() {
			tok := tokens[w%len(tokens)]
			other := tokens[(w+1)%len(tokens)]
			for i := range perWorker {
				sid := fmt.Sprintf("sess-%d-%d", w, i)

				rec := httptest.NewRecorder()
				g.Wrap(initializeHandler(sid, http.StatusOK)).ServeHTTP(rec, newSessionRequest(http.MethodPost, tok, ""))

				ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
				rec = httptest.NewRecorder()
				g.Wrap(ok).ServeHTTP(rec, newSessionRequest(http.MethodPost, tok, sid))
				if rec.Code != http.StatusOK {
					errs <- fmt.Errorf("%s owner lookup: got %d", sid, rec.Code)
				}

				rec = httptest.NewRecorder()
				g.Wrap(ok).ServeHTTP(rec, newSessionRequest(http.MethodPost, other, sid))
				if rec.Code != http.StatusNotFound {
					errs <- fmt.Errorf("%s hijack: got %d", sid, rec.Code)
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	for w := range workers {
		for i := range perWorker {
			if _, ok := store.Lookup(fmt.Sprintf("sess-%d-%d", w, i)); !ok {
				t.Fatalf("lost binding sess-%d-%d", w, i)
			}
		}
	}
}

func TestSessionBinding_RequestEndRefreshesBinding(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration // how long the request runs
	}{
		{name: "request shorter than ttl", duration: 8 * time.Minute},
		{name: "request longer than ttl", duration: 15 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Unix(0, 0)
			store := NewMemorySessionStore(10 * time.Minute)
			store.now = func() time.Time { return now }
			_ = store.Bind("sess-1", Identity{Issuer: testIssuer, Subject: "bob"})
			g := newBindingGuard(store)

			slow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { now = now.Add(tt.duration) })
			g.Wrap(slow).ServeHTTP(httptest.NewRecorder(), newSessionRequest(http.MethodPost, "bob", "sess-1"))

			// The SDK's idle timer starts when the request ends; the binding must outlive it by the same margin.
			now = now.Add(9 * time.Minute)
			if _, ok := store.Lookup("sess-1"); !ok {
				t.Error("binding expired before ttl elapsed since the request ended")
			}
		})
	}
}

func TestSessionBinding_FailedDeleteKeepsBinding(t *testing.T) {
	store := NewMemorySessionStore(time.Minute)
	_ = store.Bind("sess-1", Identity{Issuer: testIssuer, Subject: "bob"})
	g := newBindingGuard(store)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})

	rec := httptest.NewRecorder()
	g.Wrap(next).ServeHTTP(rec, newSessionRequest(http.MethodDelete, "bob", "sess-1"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("DELETE status: got %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if _, ok := store.Lookup("sess-1"); !ok {
		t.Error("failed DELETE removed the binding")
	}
}

func TestMemorySessionStore_BindRefusesOtherOwner(t *testing.T) {
	now := time.Unix(0, 0)
	store := NewMemorySessionStore(time.Minute)
	store.now = func() time.Time { return now }
	bob := Identity{Issuer: testIssuer, Subject: "bob"}
	scott := Identity{Issuer: testIssuer, Subject: "scott"}

	if err := store.Bind("sess-1", bob); err != nil {
		t.Fatalf("first bind: %v", err)
	}
	if err := store.Bind("sess-1", bob); err != nil {
		t.Errorf("rebind by same owner: %v", err)
	}
	if err := store.Bind("sess-1", scott); !errors.Is(err, ErrSessionBound) {
		t.Errorf("bind by other owner: got %v, want ErrSessionBound", err)
	}
	if got, _ := store.Lookup("sess-1"); got != bob {
		t.Errorf("owner after refused bind: got %v, want %v", got, bob)
	}

	// Once the binding has expired, the ID is free to be bound again.
	now = now.Add(2 * time.Minute)
	if err := store.Bind("sess-1", scott); err != nil {
		t.Errorf("bind after expiry: %v", err)
	}
}

func TestSessionBinding_InitializeCannotTakeOverBoundSession(t *testing.T) {
	store := NewMemorySessionStore(time.Minute)
	_ = store.Bind("sess-1", Identity{Issuer: testIssuer, Subject: "bob"})
	g := newBindingGuard(store)

	// A handler that hands Scott an ID Bob already owns, e.g. by echoing a client-chosen ID.
	rec := httptest.NewRecorder()
	g.Wrap(initializeHandler("sess-1", http.StatusOK)).ServeHTTP(rec, newSessionRequest(http.MethodPost, "scott", ""))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if got := rec.Header().Get(SessionIDHeader); got != "" {
		t.Errorf("session ID handed out despite refused bind: %q", got)
	}
	if got, _ := store.Lookup("sess-1"); got.Subject != "bob" {
		t.Errorf("owner: got %q, want bob", got.Subject)
	}
}
