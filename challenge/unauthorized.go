package challenge

import (
	"fmt"
	"net/http"
)

// Unauthorized writes a 401 with a WWW-Authenticate header pointing to the PRM URL.
func Unauthorized(w http.ResponseWriter, prmURL string) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s"`, prmURL))
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
}
