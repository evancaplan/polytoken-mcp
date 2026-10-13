package middleware

import (
	"errors"
	"net/http"
	"sync"
	"time"
)

// SessionIDHeader is the Streamable HTTP header that carries the MCP session ID.
const SessionIDHeader = "Mcp-Session-Id"

var errSessionBindFailed = errors.New("middleware: session binding failed")

// ErrSessionBound is returned by Bind when the session ID is already bound to a different Identity.
var ErrSessionBound = errors.New("middleware: session already bound to another identity")

type Identity struct {
	Issuer  string
	Subject string
}

type SessionStore interface {
	Bind(sessionID string, id Identity) error
	Lookup(sessionID string) (Identity, bool)
	Touch(sessionID string)
	Delete(sessionID string)
}

type MemorySessionStore struct {
	ttl time.Duration
	now func() time.Time

	mu        sync.Mutex
	entries   map[string]sessionEntry
	lastSweep time.Time
}

type sessionEntry struct {
	id      Identity
	expires time.Time
}

func NewMemorySessionStore(ttl time.Duration) *MemorySessionStore {
	if ttl <= 0 {
		panic("middleware: NewMemorySessionStore ttl must be positive")
	}
	return &MemorySessionStore{
		ttl:     ttl,
		now:     time.Now,
		entries: make(map[string]sessionEntry),
	}
}

// Bind records id as the owner of sessionID. It returns ErrSessionBound if sessionID already has a live
// binding to a different Identity; rebinding to the same Identity refreshes it.
func (s *MemorySessionStore) Bind(sessionID string, id Identity) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	s.sweepLocked(now)
	if e, ok := s.entries[sessionID]; ok && e.id != id && now.Before(e.expires) {
		return ErrSessionBound
	}
	s.entries[sessionID] = sessionEntry{id: id, expires: now.Add(s.ttl)}
	return nil
}

// Lookup returns the Identity bound to sessionID and refreshes its expiry.
func (s *MemorySessionStore) Lookup(sessionID string) (Identity, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	e, ok := s.entries[sessionID]
	if !ok {
		return Identity{}, false
	}
	if !now.Before(e.expires) {
		delete(s.entries, sessionID)
		return Identity{}, false
	}
	e.expires = now.Add(s.ttl)
	s.entries[sessionID] = e
	return e.id, true
}

// Touch refreshes the expiry of sessionID's binding, if any. Unlike Lookup it does not drop an entry that
// expired while a request was in flight, so a request running longer than the ttl keeps its binding.
func (s *MemorySessionStore) Touch(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if e, ok := s.entries[sessionID]; ok {
		e.expires = s.now().Add(s.ttl)
		s.entries[sessionID] = e
	}
}

// Delete removes the binding for sessionID, if any.
func (s *MemorySessionStore) Delete(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, sessionID)
}

func (s *MemorySessionStore) sweepLocked(now time.Time) {
	if now.Sub(s.lastSweep) < s.ttl {
		return
	}
	s.lastSweep = now
	for k, e := range s.entries {
		if !now.Before(e.expires) {
			delete(s.entries, k)
		}
	}
}

func sessionNotFound(w http.ResponseWriter) {
	http.Error(w, "session not found", http.StatusNotFound)
}

func (g *Guard) serveWithSessionBinding(w http.ResponseWriter, r *http.Request, next http.Handler, id Identity) {
	sessionID := r.Header.Get(SessionIDHeader)
	if sessionID == "" {
		bw := &bindingResponseWriter{ResponseWriter: w, store: g.sessions, id: id}
		next.ServeHTTP(bw, r)
		return
	}

	bound, ok := g.sessions.Lookup(sessionID)
	if !ok || bound != id {
		sessionNotFound(w)
		return
	}

	if r.Method == http.MethodDelete {
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if sw.status == 0 || (sw.status >= 200 && sw.status < 300) {
			g.sessions.Delete(sessionID)
			return
		}
		g.sessions.Touch(sessionID)
		return
	}

	next.ServeHTTP(w, r)
	// The SDK's idle timer restarts when a request ends, so the binding's must too.
	g.sessions.Touch(sessionID)
}

// statusWriter records the final status code written through it; 0 means nothing was written,
// which net/http sends as 200.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (sw *statusWriter) WriteHeader(code int) {
	if sw.status == 0 && code >= 200 {
		sw.status = code
	}
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Write(b []byte) (int, error) {
	if sw.status == 0 {
		sw.status = http.StatusOK
	}
	return sw.ResponseWriter.Write(b)
}

func (sw *statusWriter) Unwrap() http.ResponseWriter {
	return sw.ResponseWriter
}

type bindingResponseWriter struct {
	http.ResponseWriter
	store SessionStore
	id    Identity

	wroteHeader bool
	bindFailed  bool
}

func (bw *bindingResponseWriter) WriteHeader(code int) {
	if bw.wroteHeader {
		bw.ResponseWriter.WriteHeader(code) // let net/http report the superfluous call
		return
	}
	if code < 200 {
		// 1xx informational responses don't commit the final status.
		bw.ResponseWriter.WriteHeader(code)
		return
	}
	bw.wroteHeader = true

	sessionID := bw.Header().Get(SessionIDHeader)
	if sessionID != "" && code < 300 {
		if err := bw.store.Bind(sessionID, bw.id); err != nil {
			// Fail closed: never hand out a session ID we couldn't bind.
			bw.bindFailed = true
			bw.Header().Del(SessionIDHeader)
			http.Error(bw.ResponseWriter, "internal server error", http.StatusInternalServerError)
			return
		}
	}
	bw.ResponseWriter.WriteHeader(code)
}

func (bw *bindingResponseWriter) Write(b []byte) (int, error) {
	if !bw.wroteHeader {
		bw.WriteHeader(http.StatusOK)
	}
	if bw.bindFailed {
		return 0, errSessionBindFailed
	}
	return bw.ResponseWriter.Write(b)
}

// Flush implements http.Flusher; SSE responses depend on it.
func (bw *bindingResponseWriter) Flush() {
	if !bw.wroteHeader {
		bw.WriteHeader(http.StatusOK)
	}
	if bw.bindFailed {
		return
	}
	if f, ok := bw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (bw *bindingResponseWriter) Unwrap() http.ResponseWriter {
	return bw.ResponseWriter
}
