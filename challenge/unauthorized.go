package challenge

import (
	"fmt"
	"net/http"
)

// Unauthorized writes a 401 response with a WWW-Authenticate header
// pointing the client at this server's Protected Resource Metadata
// document, per RFC 9728 Section 5.1.
func Unauthorized(w http.ResponseWriter, prmURL string) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s"`, prmURL))
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
}
