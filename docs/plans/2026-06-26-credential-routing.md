# Per-User Credential Routing Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route each Dust user's tool calls to their own Unipile key by resolving `?dust_user_email` against a `USER_MAP` credential store, and gate access behind a `BRIDGE_AUTH_TOKEN`.

**Architecture:** A new pure `Store` type (`internal/bridge/credentials.go`) owns `USER_MAP` parsing and the entire credential-precedence chain, unit-tested in isolation. `server.go` does HTTP concerns only — validate the Bearer against `BRIDGE_AUTH_TOKEN`, read the email, call `Store.Resolve`. `main.go` wires env vars in. Implemented in strict TDD order, one commit per task, so the build stays green throughout.

**Tech Stack:** Go 1.22, standard library only (`net/http`, SSE), existing deps `github.com/google/uuid` and `github.com/joho/godotenv`. Module name is camelCase `github.com/idoption/unipileBridge`.

**Spec:** `docs/specs/2026-06-26-credential-routing-design.md`

---

## Prerequisites: how to run builds and tests

`go` is **not installed locally** and Docker may not be running in this
environment. Every verification step below uses this wrapper, which runs the
toolchain in a throwaway container:

```bash
# Build everything
docker run --rm -v "$PWD":/app -w /app golang:1.22-alpine go build ./...

# Run all tests (verbose)
docker run --rm -v "$PWD":/app -w /app golang:1.22-alpine go test ./... -v
```

**Before starting:** ensure Docker Desktop is running (`docker info` succeeds).
If Go 1.22 happens to be installed locally, the bare `go build ./...` /
`go test ./...` commands work too — substitute them for the wrapper. If neither
is available, the only verification is the Railway build on push; do not claim a
step passed without one of these actually succeeding.

Throughout this plan, **`GO=`** refers to either `go` (if local) or the Docker
wrapper `docker run --rm -v "$PWD":/app -w /app golang:1.22-alpine go`.

---

## Task 1: Atomic module rename to camelCase (prerequisite, no logic change)

The repo is currently on the hyphenated module name `github.com/idoption/unipile-bridge`.
Rename it and all imports to camelCase `github.com/idoption/unipileBridge` in a
single commit so the build never sees a mismatch. **No behavior changes.**

**Files:**
- Modify: `go.mod:1`
- Modify: `main.go:9`
- Modify: `internal/bridge/server.go:15-16`
- Modify: `internal/bridge/tools.go:7-8`

- [ ] **Step 1: Replace every occurrence of the hyphenated path**

Run this exact command from the repo root:

```bash
grep -rl 'idoption/unipile-bridge' --include='*.go' --include='go.mod' . \
  | xargs sed -i '' 's|idoption/unipile-bridge|idoption/unipileBridge|g'
```

(On GNU sed — e.g. inside Linux/Docker — drop the `''` after `-i`.)

- [ ] **Step 2: Verify nothing hyphenated remains and nothing else changed**

Run:

```bash
grep -rn 'idoption/unipile-bridge' . --include='*.go' --include='go.mod'; echo "exit=$? (1 = clean)"
grep -rn 'idoption/unipileBridge' . --include='*.go' --include='go.mod'
```

Expected: first grep prints nothing and `exit=1`; second grep lists exactly
6 lines (`go.mod:1`, `main.go:9`, `server.go:15`, `server.go:16`,
`tools.go:7`, `tools.go:8`).

- [ ] **Step 3: Build to confirm the rename is consistent**

Run: `$GO build ./...`
Expected: builds with no output (exit 0). A mismatch would print
`no required module provides package github.com/idoption/unipileBridge/...`.

- [ ] **Step 4: Commit**

```bash
git add go.mod main.go internal/bridge/server.go internal/bridge/tools.go
git commit -m "refactor: rename module to camelCase unipileBridge"
```

---

## Task 2: `credentials.go` + `credentials_test.go` (pure logic, TDD)

Build the `Store` with tests first. It has no HTTP and no env access, so it is
fully testable in isolation. Tests live in the same `bridge` package so they can
assert on the unexported `users` map.

**Files:**
- Create: `internal/bridge/credentials.go`
- Test: `internal/bridge/credentials_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/bridge/credentials_test.go`:

```go
package bridge

import (
	"errors"
	"testing"
)

func newTestStore(sharedKey string) *Store {
	return &Store{
		users:     map[string]string{"ian@company.com": "key_ian"},
		sharedKey: sharedKey,
	}
}

func TestResolve(t *testing.T) {
	cases := []struct {
		name      string
		email     string
		sharedKey string
		bearer    string
		legacy    bool
		wantKey   string
		wantErr   bool
	}{
		{"map hit, no shared", "ian@company.com", "", "tok", false, "key_ian", false},
		{"map beats shared", "ian@company.com", "shared", "tok", false, "key_ian", false},
		{"unknown email uses shared", "bob@company.com", "shared", "tok", false, "shared", false},
		{"unknown email no shared rejects", "bob@company.com", "", "tok", false, "", true},
		{"no email uses shared", "", "shared", "tok", false, "shared", false},
		{"no email auth mode rejects", "", "", "tok", false, "", true},
		{"no email legacy bearer", "", "", "tok", true, "tok", false},
		{"no email legacy shared beats bearer", "", "shared", "tok", true, "shared", false},
		{"no email legacy empty bearer rejects", "", "", "", true, "", true},
		{"email case and space insensitive", "  IAN@Company.com ", "", "tok", false, "key_ian", false},
		{"named unknown rejected even legacy", "bob@company.com", "", "tok", true, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(tc.sharedKey)
			got, err := s.Resolve(tc.email, tc.bearer, tc.legacy)
			if tc.wantErr {
				if !errors.Is(err, ErrNoCredential) {
					t.Fatalf("want ErrNoCredential, got key=%q err=%v", got, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.wantKey {
				t.Fatalf("want key %q, got %q", tc.wantKey, got)
			}
		})
	}
}

func TestNewStore(t *testing.T) {
	cases := []struct {
		name    string
		userMap string
		wantLen int
		check   func(*testing.T, *Store)
	}{
		{"valid single", "ian@company.com:key_ian", 1, func(t *testing.T, s *Store) {
			if s.users["ian@company.com"] != "key_ian" {
				t.Fatalf("missing ian: %v", s.users)
			}
		}},
		{"valid multi", "ian@c.com:k1,alice@c.com:k2", 2, nil},
		{"no colon skipped", "no_colon_here", 0, nil},
		{"no at sign skipped", "notanemail:key", 0, nil},
		{"empty email skipped", ":key", 0, nil},
		{"empty key skipped", "ian@co.com:", 0, nil},
		{"whitespace trimmed", " Ian@Co.com : key ", 1, func(t *testing.T, s *Store) {
			if s.users["ian@co.com"] != "key" {
				t.Fatalf("got %v", s.users)
			}
		}},
		{"empty map", "", 0, nil},
		{"duplicate last wins", "ian@c.com:k1,ian@c.com:k2", 1, func(t *testing.T, s *Store) {
			if s.users["ian@c.com"] != "k2" {
				t.Fatalf("last should win: %v", s.users)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewStore(tc.userMap, "")
			if len(s.users) != tc.wantLen {
				t.Fatalf("want %d entries, got %d: %v", tc.wantLen, len(s.users), s.users)
			}
			if tc.check != nil {
				tc.check(t, s)
			}
		})
	}
}
```

- [ ] **Step 2: Run tests to verify they fail to compile**

Run: `$GO test ./internal/bridge/ -run 'TestResolve|TestNewStore' -v`
Expected: FAIL — compile error `undefined: Store`, `undefined: NewStore`,
`undefined: ErrNoCredential`.

- [ ] **Step 3: Write the minimal implementation**

Create `internal/bridge/credentials.go`:

```go
package bridge

import (
	"errors"
	"log"
	"strings"
)

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
func NewStore(userMap, sharedKey string) *Store {
	users := make(map[string]string)
	for _, raw := range strings.Split(userMap, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue // empty/whole-empty map: not an error
		}
		idx := strings.Index(entry, ":") // split on FIRST colon
		if idx < 0 {
			log.Printf("⚠️  skipping malformed USER_MAP entry: %q", raw)
			continue
		}
		email := normalizeEmail(entry[:idx])
		key := strings.TrimSpace(entry[idx+1:])
		if email == "" || !strings.Contains(email, "@") || key == "" {
			log.Printf("⚠️  skipping malformed USER_MAP entry: %q", raw)
			continue
		}
		if _, dup := users[email]; dup {
			log.Printf("⚠️  duplicate USER_MAP email %q; last entry wins", email)
		}
		users[email] = key
	}
	return &Store{users: users, sharedKey: strings.TrimSpace(sharedKey)}
}

// Resolve applies the precedence chain. legacy is true when BRIDGE_AUTH_TOKEN
// is unset (the Bearer may then be used as a Unipile key).
//
//	email in map     -> user's key
//	email not in map -> sharedKey, else ErrNoCredential
//	no email         -> sharedKey, else legacy?bearer:ErrNoCredential
func (s *Store) Resolve(email, bearer string, legacy bool) (string, error) {
	if e := normalizeEmail(email); e != "" {
		if key, ok := s.users[e]; ok {
			return key, nil
		}
		if s.sharedKey != "" {
			return s.sharedKey, nil
		}
		return "", ErrNoCredential // named-but-unknown is ALWAYS rejected
	}
	// no email
	if s.sharedKey != "" {
		return s.sharedKey, nil
	}
	if legacy && bearer != "" {
		return bearer, nil
	}
	return "", ErrNoCredential
}

func normalizeEmail(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `$GO test ./internal/bridge/ -run 'TestResolve|TestNewStore' -v`
Expected: PASS — all 11 `TestResolve` subtests and all 9 `TestNewStore`
subtests green.

- [ ] **Step 5: Commit**

```bash
git add internal/bridge/credentials.go internal/bridge/credentials_test.go
git commit -m "feat: add credential Store with USER_MAP parsing and precedence resolution"
```

---

## Task 3: Wire `Store` + `BRIDGE_AUTH_TOKEN` into `server.go`

Add `creds` and `authToken` to `Server`, change `NewServer`, and replace the
old missing-Authorization guard with auth + resolution. Depends on Task 2's
`Store` interface being stable.

**Files:**
- Modify: `internal/bridge/server.go:1-4` (package doc), `:26-37` (`Server`,
  `NewServer`), `:46-60` (`HandleSSE` head), `:87` (log line)

- [ ] **Step 1: Update the package doc comment (lines 1-4)**

Replace the existing comment block:

```go
// Package bridge implements the MCP-over-SSE server that proxies Unipile.
// Each SSE connection resolves the caller's Unipile key from their
// ?dust_user_email (via the credential Store) and binds a per-user client to
// the session. The Authorization Bearer token authenticates Dust to the bridge.
package bridge
```

- [ ] **Step 2: Add fields to `Server` and change `NewServer` (lines 26-37)**

Replace the `Server` struct and `NewServer`:

```go
// Server is the MCP bridge server.
type Server struct {
	baseURL   string
	creds     *Store
	authToken string // BRIDGE_AUTH_TOKEN; "" => legacy mode (auth disabled)
	mu        sync.RWMutex
	sessions  map[string]*session
}

func NewServer(baseURL string, creds *Store, authToken string) *Server {
	return &Server{
		baseURL:   baseURL,
		creds:     creds,
		authToken: authToken,
		sessions:  make(map[string]*session),
	}
}
```

- [ ] **Step 3: Replace the `HandleSSE` head (lines 46-60)**

Replace from `func (s *Server) HandleSSE` through the `s.mu.Unlock()` that
closes the session insert. The new version:

```go
func (s *Server) HandleSSE(w http.ResponseWriter, r *http.Request) {
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

	sessionID := uuid.NewString()
	ch := make(chan mcp.Response, 32)

	s.mu.Lock()
	s.sessions[sessionID] = &session{
		ch:     ch,
		client: unipile.NewClient(s.baseURL, apiKey),
	}
	s.mu.Unlock()
```

- [ ] **Step 4: Update the connect log line (was line 87)**

Replace the `log.Printf("session %s connected ...")` line with:

```go
	log.Printf("session %s connected (email=%q key=%s…)", sessionID, email, apiKey[:min(8, len(apiKey))])
```

- [ ] **Step 5: Verify it does NOT build yet (main.go still calls old NewServer)**

Run: `$GO build ./...`
Expected: FAIL — `not enough arguments in call to bridge.NewServer` in
`main.go`. This is expected; Task 4 fixes the caller. (The `internal/bridge`
package itself compiles — confirm with
`$GO build ./internal/bridge/` → exit 0.)

- [ ] **Step 6: Run the package tests to confirm no regression**

Run: `$GO test ./internal/bridge/ -v`
Expected: PASS — Task 2 tests still green (they don't touch `Server`).

- [ ] **Step 7: Commit**

```bash
git add internal/bridge/server.go
git commit -m "feat: enforce BRIDGE_AUTH_TOKEN and resolve per-user key in HandleSSE"
```

Note: the repo build is briefly red between this commit and Task 4 (main.go
caller mismatch). The two tasks are sequential and the next commit restores
green. If a fully-green-every-commit invariant is required, squash Task 3 and
Task 4 commits at the end; otherwise proceed as-is.

---

## Task 4: Wire env vars into `main.go`

Load `USER_MAP`, `UNIPILE_SHARED_KEY`, `BRIDGE_AUTH_TOKEN`; build the `Store`;
pass both into `NewServer`. Restores the build. Depends on Task 3's `NewServer`
signature.

**Files:**
- Modify: `main.go:31-32` (insert env loading before `mux :=`, update the `srv :=` call)

- [ ] **Step 1: Insert env loading + Store before the server is built**

Immediately before `mux := http.NewServeMux()`, add:

```go
	userMap := os.Getenv("USER_MAP")
	sharedKey := os.Getenv("UNIPILE_SHARED_KEY")
	authToken := os.Getenv("BRIDGE_AUTH_TOKEN")
	if authToken == "" {
		log.Println("⚠️  WARNING: BRIDGE_AUTH_TOKEN not set — bridge auth is DISABLED; any caller is accepted (legacy/testing mode)")
	}
	creds := bridge.NewStore(userMap, sharedKey)
```

- [ ] **Step 2: Update the `NewServer` call**

Change:

```go
	srv := bridge.NewServer(baseURL)
```

to:

```go
	srv := bridge.NewServer(baseURL, creds, authToken)
```

- [ ] **Step 3: Build the whole module**

Run: `$GO build ./...`
Expected: PASS — exit 0, no output. The build is green again.

- [ ] **Step 4: Run the full test suite**

Run: `$GO test ./... -v`
Expected: PASS — all `internal/bridge` tests green; other packages have no
tests.

- [ ] **Step 5: Commit**

```bash
git add main.go
git commit -m "feat: load USER_MAP/UNIPILE_SHARED_KEY/BRIDGE_AUTH_TOKEN and wire credential Store"
```

---

## Task 5: Update `.env.example` (docs, no code dependency)

**Files:**
- Create: `.env.example`

- [ ] **Step 1: Create `.env.example`**

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

- [ ] **Step 2: Commit**

```bash
git add .env.example
git commit -m "docs: add .env.example documenting credential routing env vars"
```

---

## Done criteria

- `$GO build ./...` exits 0.
- `$GO test ./... -v` passes (11 `TestResolve` + 9 `TestNewStore` subtests).
- `grep -rn 'idoption/unipile-bridge' .` returns nothing (rename complete).
- Five commits, in order: rename → credentials → server → main → env.

## Post-merge follow-up (NOT part of this plan)

After deploy, set `USER_MAP`, `UNIPILE_SHARED_KEY` (optional), and
`BRIDGE_AUTH_TOKEN` in the Railway service Variables tab. Until `BRIDGE_AUTH_TOKEN`
is set, the service logs the loud auth-disabled warning and accepts any caller.
