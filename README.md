# polytoken-mcp

Authorization middleware for [MCP](https://modelcontextprotocol.io) servers, implementing the OAuth 2.1 requirements
of the MCP authorization spec through the **2026-07-28** revision.

Built on [`polytoken`](https://github.com/evancaplan/polytoken), a multi-issuer JWT validation library. `polytoken-mcp`
extends that validation with the MCP-specific checks layered on top of standard OAuth 2.1: resource binding, issuer
binding, and token-passthrough prevention.

Write-up of the design and the reasoning behind it: [The Four Checks Most MCP Servers
Skip](https://www.evancaplan.dev/blog/go-mcp-auth).

## Why this exists

MCP servers have been OAuth 2.1 resource servers since the spec's June 2025 revision, which introduced Protected
Resource Metadata (RFC 9728) and resource indicators (RFC 8707). The 2026-07-28 revision hardened authorization
further, adding RFC 9207 issuer validation among other changes.

Adoption has not kept pace. Astrix Security's ["State of MCP Server Security
2025"](https://astrix.security/learn/blog/state-of-mcp-server-security-2025/) analyzed over 5,200 open-source MCP
server implementations and found only 8.5% using OAuth at all.

`polytoken-mcp` is a drop-in Go middleware covering the parts of the spec that are easy to get subtly wrong:

- **Discovery**: serves OAuth 2.0 Protected Resource Metadata (RFC 9728) so clients can find out how to authenticate
- **Token validation**: signature and expiry checks, delegated to `polytoken`
- **Resource Indicators** (RFC 8707): confirms a token was actually issued *for this server*, not replayed from another
  MCP server
- **Issuer binding** (RFC 9207): confirms the token came from the authorization server this client was supposed to use,
  closing the authorization-server mix-up
- **Token-passthrough prevention**: refuses to forward a client's inbound token to an upstream API unmodified

Both hand-written comparison paths are fuzz-tested, with ~92M and ~105M executions and no crashes. Details under
[Security Testing](#security-testing).

## Architecture

```
Client Request
      │
      ▼
┌─────────────────────────────────────────┐
│  middleware.Guard.Wrap(next)             │
│                                           │
│  1. token.Validator.Validate             │──▶ polytoken resolver (HS256/RS256)
│  2. token.CheckResourceIndicator (RFC 8707)
│  3. token.CheckIssuerBinding (RFC 9207)  │
│                                           │
│  ── any check fails ──▶ challenge.Unauthorized (401 + WWW-Authenticate)
│  ── all pass ──▶ next.ServeHTTP (principal attached to context)
└─────────────────────────────────────────┘

Outgoing requests to upstream APIs:
┌─────────────────────────────────────────┐
│  passthrough.Guard (http.RoundTripper)   │
│  Refuses to forward the client's inbound │
│  token to an upstream unmodified.        │
└─────────────────────────────────────────┘
```

## Installation

```bash
go get github.com/evancaplan/polytoken-mcp
```

`discovery`, `token`, `challenge`, `middleware`, and `passthrough` are all public packages, importable directly by
any Go project.

## Quickstart

```go
import (
	"net/http"

	"github.com/evancaplan/polytoken-mcp/discovery"
	"github.com/evancaplan/polytoken-mcp/middleware"
	"github.com/evancaplan/polytoken-mcp/token"
	"github.com/evancaplan/polytoken/resolver"
	"github.com/evancaplan/polytoken/validator"
)

hs256 := validator.NewHs256Validator("https://auth.example.com", []byte("your-secret"))
res := resolver.NewResolver([]validator.TokenValidator{hs256})
v := token.NewValidator(res)

prmURL := "https://mcp.example.com/.well-known/oauth-protected-resource"
guard := middleware.NewGuard(v, "https://mcp.example.com", "https://auth.example.com", prmURL)

prmHandler := discovery.NewHandler("https://mcp.example.com", []string{"https://auth.example.com"})

mux := http.NewServeMux()
mux.Handle("/.well-known/oauth-protected-resource", prmHandler)
mux.Handle("/mcp", guard.Wrap(yourMCPHandler))

http.ListenAndServe(":8080", mux)
```

### Try it against the reference server

A full working example lives at `cmd/reference-server`. Mint a test token with `polytoken`'s own CLI, then hit the
running server:

```bash
# terminal 1 (polytoken-mcp)
go run ./cmd/reference-server

# terminal 2 (polytoken)
go run ./cmd/mint --secret my-test-secret --iss https://test.local --aud http://localhost:8080

# terminal 2 (try it)
curl http://localhost:8080/.well-known/oauth-protected-resource
curl -i http://localhost:8080/mcp                                              # 401
curl -H "Authorization: Bearer <token-from-mint>" http://localhost:8080/mcp    # 200
```

The `/mcp` handler also demonstrates `passthrough.Guard`: it deliberately tries to forward the
client's inbound token, unmodified, to a stand-in upstream API (`/upstream/echo`) over an
`http.Client` whose `Transport` is a `passthrough.Guard`. The response's `passthrough_blocked`
field is `true` because the guard refuses that exact-token forward at the transport layer.

## Security Testing

Every hand-written parsing/comparison path (the two places this project does its own claim-shape handling rather than
delegating to `polytoken`) is fuzz-tested using Go's native fuzzing (`go test -fuzz`).

| Function                 | What it checks                      | Duration | Executions | Crashes |
|--------------------------|--------------------------------------|----------|------------|---------|
| `CheckResourceIndicator` | RFC 8707 audience/resource matching | 10 min   | ~92.1M     | 0       |
| `CheckIssuerBinding`     | RFC 9207 issuer matching            | 10 min   | ~104.5M    | 0       |

Seed corpus includes exact matches, mismatches, case differences, trailing-slash variants, empty values, malformed URIs,
unicode lookalikes, and control characters. Discovered corpus is committed under `token/testdata/fuzz/` and
replayed automatically as regression tests on every `go test` run.

```bash
go test -fuzz=FuzzCheckResourceIndicator -fuzztime=60s ./token
go test -fuzz=FuzzCheckIssuerBinding -fuzztime=60s ./token
```

Increase `-fuzztime` for a longer run. Any newly discovered crash is saved to `testdata/fuzz/<FuzzName>/` and becomes a
permanent test case.

## Design notes

A few deliberate decisions worth calling out for anyone reviewing this:

- **Uniform 401 response.** Whether a request fails on missing auth, resource mismatch, or issuer mismatch, the client
  sees the same generic `401 {"error":"unauthorized"}` with a `WWW-Authenticate` challenge. The specific failure reason
  is never leaked to an unauthenticated caller.
- **Case-insensitive resource/issuer comparison.** Technically a minor deviation from RFC 3986, which only treats
  scheme and host as case-insensitive, not the full path. Accepted as a simplicity/practicality tradeoff, since
  resource and issuer URIs in practice are fixed, lowercase configuration values rather than user-supplied paths.
- **`passthrough.Guard` is a heuristic, not a proof.** It blocks a request when the outgoing token is byte-for-byte
  identical to a stashed inbound token. It won't catch the same token moved into a query parameter or a request body,
  or a token exchanged for a different one that still carries the client's identity. It also has a known false
  positive: a token legitimately valid for both this server and the upstream is refused anyway. An opt-out for
  specific requests is not yet implemented.
- **Fail-open when there's nothing to compare against.** If no inbound token was stashed in context, the outgoing call
  goes through. A server makes plenty of outgoing calls unrelated to any client's token, and blocking those by default
  would cost real traffic to catch a problem that isn't there.

## Known gaps

- `scopes_supported` is not populated in the Protected Resource Metadata document, because scopes aren't enforced
  anywhere yet. Advertising scopes that aren't checked seemed worse than omitting the field.
- No logging on the middleware's failure paths. The client learning nothing shouldn't mean the operator learns nothing.
- No opt-out for the `passthrough.Guard` false positive described above.

## Project layout

```
cmd/reference-server   a full, runnable demonstration of the middleware
discovery              Protected Resource Metadata (RFC 9728) handler
token                  token validation, resource indicator + issuer binding checks
challenge              401 + WWW-Authenticate response helper
middleware             the Guard that ties the above together into an http.Handler wrapper
passthrough            the token-passthrough RoundTripper guard
```

## Status

This is a portfolio/reference implementation of the MCP authorization spec through the 2026-07-28 revision, built as a
companion to `polytoken`. It has not been used in a production deployment.