# Per-User Credential Routing — Design

**Date:** 2026-06-26
**Status:** Approved (design)
**Component:** `internal/bridge`

## Problem

`unipileBridge` is meant to be a per-user proxy: each Dust user acts only on
their own Unipile account. Today it does not do this. `HandleSSE` takes the
Bearer token (or `?api_key=`) and uses it directly as the Unipile API key, so
the bridge is effectively single-user. There is no credential store, no
`?dust_user_email` handling, and no validation that the caller is allowed to
reach the bridge at all — anyone who can reach the URL could impersonate any
user once routing exists.

This design adds:

1. A credential store loaded from `USER_MAP` (+ optional `UNIPILE_SHARED_KEY`).
2. `?dust_user_email` → per-user Unipile key resolution with a defined
   precedence chain.
3. Workspace authentication via `BRIDGE_AUTH_TOKEN` to close the
   impersonation hole.

## Prerequisite: module rename to camelCase

The canonical module name is **`github.com/idoption/unipileBridge`** (camelCase).
The repository is currently on the hyphenated name `unipile-bridge` (an earlier
build fix). Before/with this work, rename consistently so the build stays green:

- `go.mod`: `module github.com/idoption/unipileBridge`
- `main.go`: import `github.com/idoption/unipileBridge/internal/bridge`
- `internal/bridge/server.go`: imports of `.../internal/mcp` and `.../internal/unipile`
- `internal/bridge/tools.go`: imports of `.../internal/mcp` and `.../internal/unipile`

All module-qualified import paths in this spec use the camelCase form. Go
requires the `module` directive and every import to match **exactly** — a
mismatch produces `no required module provides package …`. The rename must be a
single atomic commit covering `go.mod` and all five import lines.

## Precedence chain

Two inputs drive resolution: the `?dust_user_email` query param and whether the
bridge is in *legacy mode* (`BRIDGE_AUTH_TOKEN` unset). `legacy` controls
exactly one thing: whether the Bearer token may be used as a Unipile key.

```
AUTH (on /sse):
  if BRIDGE_AUTH_TOKEN set:
      Bearer must equal it, else 401 immediately.   (Bearer is NOT a Unipile key)
      legacy = false
  if BRIDGE_AUTH_TOKEN unset:
      log loud WARNING; accept any caller.
      legacy = true                                  (Bearer MAY be used as key)

RESOLVE Unipile key:
  email given?
    ├─ in USER_MAP        -> user's key
    └─ not in USER_MAP    -> UNIPILE_SHARED_KEY, else REJECT
  no email?
    ├─ UNIPILE_SHARED_KEY -> shared key
    └─ else               -> legacy ? Bearer-as-key : REJECT
```

Key invariant: **a named-but-unknown email is ALWAYS rejected** (it never falls
back to the Bearer), regardless of legacy mode. The Bearer fallback exists only
for the no-email single-user/testing path.

## File-by-file design

### New: `internal/bridge/credentials.go`

Pure logic — no HTTP, no `os.Getenv`. Owns parsing and the full precedence chain
so it is unit-testable in isolation.

```go
package bridge

// Store resolves a Unipile API key for a caller from a per-user map
// (loaded from USER_MAP) plus an optional shared fallback key.
type Store struct {
    users     map[string]string // normalized email -> Unipile key
    sharedKey string
}

// ErrNoCredential means no key could be resolved; the caller should reject
// the connection (HTTP 401/403).
var ErrNoCredential = errors.New("no Unipile credential for caller")

// NewStore parses USER_MAP ("email:key,email:key,...") and the shared key.
// Malformed entries are logged and skipped — never fatal. Always returns a
// usable Store (possibly with an empty user map).
func NewStore(userMap, sharedKey string) *Store

// Resolve applies the precedence chain. `legacy` is true when
// BRIDGE_AUTH_TOKEN is unset (Bearer may be used as a Unipile key).
func (s *Store) Resolve(email, bearer string, legacy bool) (string, error)
```

Helper: `normalizeEmail(s) = strings.ToLower(strings.TrimSpace(s))`. Email
matching is case-insensitive and whitespace-tolerant.

### Changed: `internal/bridge/server.go`

```go
type Server struct {
    baseURL   string
    creds     *Store   // NEW
    authToken string   // NEW — BRIDGE_AUTH_TOKEN; "" => legacy (auth disabled)
    mu        sync.RWMutex
    sessions  map[string]*session
}

func NewServer(baseURL string, creds *Store, authToken string) *Server
```

`HandleSSE` head (replaces today's missing-Authorization check):

```go
bearer := extractBearer(r)

// 1. Bridge auth. A configured token makes a wrong/missing Bearer an
//    immediate 401. Unset token => legacy mode (auth disabled).
if s.authToken != "" && bearer != s.authToken {
    http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
    return
}
legacy := s.authToken == ""

// 2. Resolve this caller's Unipile key.
email := r.URL.Query().Get("dust_user_email")
apiKey, err := s.creds.Resolve(email, bearer, legacy)
if err != nil {
    http.Error(w, `{"error":"no Unipile credential for user"}`, http.StatusForbidden)
    return
}
// ... unchanged below: session uses unipile.NewClient(s.baseURL, apiKey)
```

The connect log line becomes (no key leakage):

```go
log.Printf("session %s connected (email=%q key=%s…)", sessionID, email, apiKey[:min(8, len(apiKey))])
```

`extractBearer`, `HandleMessages`, `handleRequest`, and the JSON-RPC router are
unchanged.

### Changed: `main.go`

```go
userMap   := os.Getenv("USER_MAP")
sharedKey := os.Getenv("UNIPILE_SHARED_KEY")
authToken := os.Getenv("BRIDGE_AUTH_TOKEN")

if authToken == "" {
    log.Println("⚠️  WARNING: BRIDGE_AUTH_TOKEN not set — bridge auth is DISABLED; any caller is accepted (legacy/testing mode)")
}

creds := bridge.NewStore(userMap, sharedKey)
srv   := bridge.NewServer(baseURL, creds, authToken)
```

The existing `UNIPILE_BASE_URL` default-and-warn behavior is unchanged. A
missing `BRIDGE_AUTH_TOKEN` only logs a loud warning — it never crashes, so
Railway cold starts succeed even before the var is set. Once the var is set, a
wrong Bearer is a 401 (enforced in `HandleSSE`).

## Startup validation: malformed `USER_MAP`

In `NewStore`, split `USER_MAP` on `,`, then each entry on its **first** `:`
(emails contain no colon; a Unipile key theoretically could). An entry is kept
only if, after trimming, the email is non-empty, contains `@`, and the key is
non-empty. Otherwise log `⚠️  skipping malformed USER_MAP entry: %q` and skip.
**The server always starts.** Duplicate emails: last wins (logged). An empty
`USER_MAP` yields an empty map with no warning.

| Raw entry | Result |
|-----------|--------|
| `ian@co.com:key_ian` | kept → `ian@co.com` → `key_ian` |
| ` Ian@Co.com : key ` | kept, normalized → `ian@co.com` → `key` |
| `no_colon_here` | skip + warn (no `:`) |
| `notanemail:key` | skip + warn (no `@`) |
| `:key` | skip + warn (empty email) |
| `ian@co.com:` | skip + warn (empty key) |
| `""` (whole map empty) | empty store, no warn |

## Test matrix — `credentials_test.go`

Table-driven. Fixture: `users = {"ian@company.com": "key_ian"}`; `sharedKey`
varies per row.

### `Resolve(email, bearer, legacy)`

| # | email | sharedKey | bearer | legacy | → key | → err |
|---|-------|-----------|--------|--------|-------|-------|
| 1 | ian@company.com | — | tok | false | `key_ian` | nil |
| 2 | ian@company.com | shared | tok | false | `key_ian` | nil (map beats shared) |
| 3 | bob@company.com | shared | tok | false | `shared` | nil |
| 4 | bob@company.com | — | tok | false | "" | `ErrNoCredential` (unknown → reject) |
| 5 | *(none)* | shared | tok | false | `shared` | nil |
| 6 | *(none)* | — | tok | false | "" | `ErrNoCredential` (auth mode: no bearer fallback) |
| 7 | *(none)* | — | tok | true | `tok` | nil (legacy bearer-as-key) |
| 8 | *(none)* | shared | tok | true | `shared` | nil (shared beats bearer) |
| 9 | *(none)* | — | "" | true | "" | `ErrNoCredential` |
| 10 | `IAN@Company.com ` | — | tok | false | `key_ian` | nil (case/space-insensitive) |
| 11 | bob@company.com | — | tok | true | "" | `ErrNoCredential` (named-unknown rejected even in legacy) |

### `NewStore` parsing

Cases: valid single, valid multi, no-colon, no-`@`, empty-email, empty-key,
whitespace-trim, empty-string map, duplicate-email-last-wins — mirroring the
malformed-`USER_MAP` table above.

## Environment & deployment

### New: `.env.example`

```dotenv
# Unipile API endpoint (region-specific DSN from your Unipile dashboard)
UNIPILE_BASE_URL=https://api6.unipile.com:13614

# Per-user routing: comma-separated email:unipile_key pairs
USER_MAP=ian@company.com:unipile_key_ian,alice@company.com:unipile_key_alice

# Optional fallback key when an email isn't in USER_MAP (or no email given)
UNIPILE_SHARED_KEY=

# Workspace token Dust must present as `Authorization: Bearer <token>`.
# If unset, bridge auth is DISABLED (legacy/testing). Set in production.
BRIDGE_AUTH_TOKEN=

# Local dev only; Railway injects PORT automatically
PORT=3000
```

### `railway.toml`

Unchanged. Healthcheck stays `/health`, timeout 10. The new env vars
(`USER_MAP`, `UNIPILE_SHARED_KEY`, `BRIDGE_AUTH_TOKEN`) are set in the Railway
service Variables tab, not in `railway.toml`.

## Out of scope (YAGNI)

- Hot-reload of `USER_MAP` (a Railway restart on env change is sufficient).
- Per-tool authorization or rate limiting.
- Changing the SSE/`/messages` transport or any of the 11 tool definitions.

## Affected files

| File | Change |
|------|--------|
| `go.mod` | Rename module to camelCase `unipileBridge` |
| `main.go` | Rename import; wire `USER_MAP`/`UNIPILE_SHARED_KEY`/`BRIDGE_AUTH_TOKEN` |
| `internal/bridge/server.go` | Rename imports; `Server` fields, `NewServer` signature, auth + resolve in `HandleSSE` |
| `internal/bridge/tools.go` | Rename imports |
| `internal/bridge/credentials.go` | **New** — `Store`, `NewStore`, `Resolve` |
| `internal/bridge/credentials_test.go` | **New** — table-driven tests |
| `.env.example` | **New** — document all env vars |
