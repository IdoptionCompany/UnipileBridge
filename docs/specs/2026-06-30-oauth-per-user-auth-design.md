# OAuth Per-User Authentication — Design

**Date:** 2026-06-30
**Status:** Approved (design)
**Component:** new `internal/oauth` package + `internal/bridge`, `main.go`

## Problem

The bridge needs per-user routing (each Dust user acts only on their own Unipile
account) through a **single shared Dust MCP connection**. Dust sends no per-user
identifier on a shared connection (bearer, headers, and meta fields are all
workspace-static), so neither `TOKEN_MAP` (per-user bearer) nor email-injection
works on one connection.

Dust's **Static OAuth + "Personal accounts"** mode solves this: each member runs
their own OAuth authorization-code flow on first use and Dust stores their token
per-member. We make the bridge the OAuth **Authorization Server** with a login
page that is simply a **personal-code input box**. The code identifies the user
(via `TOKEN_MAP`), and the bridge issues a signed token Dust replays on every
MCP call.

This is the secure realization of "route on the user's email": the email is now
established through a login the user completes, then carried in a bridge-signed
JWT — not a spoofable header.

## End-to-end flow (Dust Static OAuth + Personal accounts)

1. A member uses the tool for the first time → Dust opens the browser to
   `GET /oauth/authorize` with `response_type=code`, `client_id`,
   `redirect_uri=https://dust.tt/oauth/mcp_static/finalize`, `scope`, `state`,
   `code_challenge`, `code_challenge_method=S256`.
2. `/authorize` renders a single-input HTML page: "Enter your personal access code."
3. Member submits the code → bridge looks it up in `TOKEN_MAP` (code → email).
   - Valid → mint a single-use **authorization code** (stored in-memory with the
     PKCE challenge, redirect_uri, email, ~60s TTL); 302 to the redirect_uri with
     `?code=…&state=…`.
   - Invalid → re-render the form with an error (HTTP 200, no redirect).
4. Dust calls `POST /oauth/token` (`grant_type=authorization_code`, `code`,
   `code_verifier`, `client_id`, `client_secret`, `redirect_uri`). Bridge
   verifies client + PKCE + code (single-use) → issues a signed **JWT access
   token** (claims: `sub`/`email`, `aud`, `exp`, `iss`) and a refresh token.
5. Dust stores the token per member and sends `Authorization: Bearer <JWT>` on
   every MCP call.
6. MCP endpoints verify the JWT → extract `email` → resolve account. The existing
   isolation guards (forced account, chat-ownership, scoped `list_accounts`) key
   off the verified email.

Net: one shared Dust connection; each person enters their code once; every call
is routed to their own account.

## New package: `internal/oauth`

Pure, focused, unit-testable. Depends on the credential `Store` only through a
small injected lookup function, so it tests in isolation.

### `tokens.go`
```go
// Issuer mints and verifies bridge access/refresh tokens (HS256 via golang-jwt).
type Issuer struct {
    secret   []byte
    issuer   string        // PUBLIC_BASE_URL
    audience string        // bridge MCP URL
    accessTTL  time.Duration // ~1h
    refreshTTL time.Duration // ~30d
}

func NewIssuer(secret []byte, issuer, audience string) *Issuer
func (i *Issuer) IssueAccess(email string) (string, error)
func (i *Issuer) IssueRefresh(email string) (string, error)
// VerifyAccess returns the email claim, or an error if the token is invalid,
// expired, wrong issuer/audience, or tampered.
func (i *Issuer) VerifyAccess(token string) (email string, err error)
func (i *Issuer) VerifyRefresh(token string) (email string, err error)
```

### `codes.go`
```go
// authCode is a single-use authorization code awaiting exchange at /token.
type authCode struct {
    email         string
    codeChallenge string // PKCE S256
    redirectURI   string
    expiry        time.Time
}

// codeStore is an in-memory, mutex-guarded, TTL'd, single-use store.
type codeStore struct { mu sync.Mutex; codes map[string]authCode }

func newCodeStore() *codeStore
func (s *codeStore) put(code string, c authCode)
func (s *codeStore) take(code string) (authCode, bool) // deletes on read (single-use)
```

### `server.go`
```go
// Config holds the static-client + token settings.
type Config struct {
    ClientID     string
    ClientSecret string // optional; validated only if non-empty
    RedirectURI  string // allowlisted; default https://dust.tt/oauth/mcp_static/finalize
    Scope        string // default "mcp"
}

// Server implements the minimal OAuth 2.1 Authorization Server endpoints.
// resolveEmail maps a submitted personal code to an email ("" if unknown).
type Server struct {
    cfg          Config
    issuer       *Issuer
    codes        *codeStore
    resolveEmail func(code string) string
}

func NewServer(cfg Config, issuer *Issuer, resolveEmail func(string) string) *Server
func (s *Server) HandleAuthorize(w http.ResponseWriter, r *http.Request) // GET form, POST submit
func (s *Server) HandleToken(w http.ResponseWriter, r *http.Request)     // auth_code + refresh_token grants
```

`HandleAuthorize` (GET): validate `client_id`, `redirect_uri` (allowlist),
`response_type=code`, `code_challenge_method=S256`; render the code form, echoing
the OAuth params as hidden fields. (POST): read the submitted code →
`resolveEmail`; if unknown, re-render with an error; else `put` an auth code and
302 to `redirect_uri?code=…&state=…`.

`HandleToken`: dispatch on `grant_type`.
- `authorization_code`: validate `client_id` (+ `client_secret` if configured),
  `take` the code (single-use), verify `redirect_uri` matches, verify PKCE
  (`SHA256(code_verifier) == codeChallenge`), then return
  `{access_token, token_type:"Bearer", expires_in, refresh_token}`.
- `refresh_token`: verify the refresh token → issue a fresh access token.
- Errors use standard OAuth JSON (`{"error":"invalid_grant"}`, `invalid_client`,
  `invalid_request`) with appropriate status codes.

## Changes to `internal/bridge/server.go`

`resolveCaller` changes its identity source only:
```go
func (s *Server) resolveCaller(r *http.Request) (apiKey, accountID, userEmail string, status int, errBody string) {
    bearer := extractBearer(r)
    email, err := s.tokens.VerifyAccess(bearer) // bridge-issued JWT
    if err != nil {
        // 401 + WWW-Authenticate so Dust starts the OAuth flow.
        return "", "", "", http.StatusUnauthorized, `{"error":"unauthorized"}`
    }
    userEmail = email
    key, err := s.credentials.Resolve(userEmail, "", false)
    if err != nil {
        return "", "", userEmail, http.StatusForbidden, `{"error":"no Unipile credential for user"}`
    }
    return key, s.credentials.ResolveAccountID(userEmail), userEmail, 0, ""
}
```
- The 401 response MUST set `WWW-Authenticate: Bearer resource_metadata="<PUBLIC_BASE_URL>/.well-known/oauth-protected-resource"` (a minimal PRM endpoint is included for correctness even though Static OAuth doesn't require discovery).
- `Server` gains a `tokens *oauth.Issuer` field; `NewServer` takes it.
- Everything downstream is unchanged: forced account_id (`acctID`), chat-ownership
  (`ensureChatOwned`), scoped `ListAccounts` — all key off the (now JWT-derived)
  email.
- `TOKEN_MAP` is no longer read at request time; it backs the `/authorize` code
  lookup via `Store.ResolveEmailFromToken`.

## `main.go` + routes + env

New public (unauthenticated) routes:
- `GET/POST /oauth/authorize`
- `POST /oauth/token`
- `GET /.well-known/oauth-protected-resource` (minimal PRM: `resource`,
  `authorization_servers`, `scopes_supported`)

New env vars:

| Var | Purpose |
|---|---|
| `OAUTH_CLIENT_ID` | static client id pasted into Dust (required to enable OAuth) |
| `OAUTH_CLIENT_SECRET` | optional; PKCE covers security; validated if set |
| `OAUTH_JWT_SECRET` | HS256 signing key for tokens (required) |
| `PUBLIC_BASE_URL` | e.g. `https://unipilebridge-production.up.railway.app` (issuer/aud) |
| `OAUTH_REDIRECT_URI` | allowlisted redirect; default `https://dust.tt/oauth/mcp_static/finalize` |
| `OAUTH_SCOPE` | default `mcp` |

Retained: `TOKEN_MAP` (codes→email), `ACCOUNT_MAP` (email→account_id),
`UNIPILE_SHARED_KEY`, `UNIPILE_BASE_URL`. **Removed from request auth:**
`BRIDGE_AUTH_TOKEN` (OAuth replaces it).

## Dust configuration (what the admin pastes once)

- URL: `https://<bridge>/sse`
- Authentication: **Static OAuth**
- Connect: **Personal accounts**
- OAuth Client ID / Client Secret: from env
- Authorization Endpoint: `https://<bridge>/oauth/authorize`
- Token Endpoint: `https://<bridge>/oauth/token`
- Scope: `mcp`
- Redirect URI: Dust's fixed `https://dust.tt/oauth/mcp_static/finalize` (bridge allows it)
- Token Endpoint Auth Method: Request body

## Security

- **PKCE S256 required** on every authorization-code exchange.
- `redirect_uri` validated against the allowlist at both `/authorize` and `/token`.
- Access tokens short-lived (~1h) + refresh (~30d); `aud` = bridge URL, `iss` =
  `PUBLIC_BASE_URL`; reject tokens failing signature/exp/aud/iss.
- Authorization codes single-use, ~60s TTL.
- Personal codes are secrets — generate long random values; never log them.
- **Remove all the temporary `🔍 / 🔑 / credentials:` debug logging** added during
  the earlier debugging (it prints headers, tokens, and partial keys). Never log
  `Authorization`, tokens, codes, or `code_verifier`.
- HTTPS only in production (Railway terminates TLS).

## Error handling

- `/authorize` GET: invalid `client_id`/`redirect_uri`/`response_type` → 400 error
  page (no redirect). Valid → render code form.
- `/authorize` POST: unknown code → re-render form with inline error (200).
- `/token`: standard OAuth error JSON — `invalid_client`, `invalid_grant`,
  `invalid_request`, `unsupported_grant_type` — with 400/401 as appropriate.
- MCP endpoints: missing/invalid/expired JWT → 401 + `WWW-Authenticate`.

## Testing

`internal/oauth` (table-driven):
- `Issuer`: access/refresh round-trip; reject tampered, expired, wrong-issuer,
  wrong-audience tokens.
- PKCE: `SHA256(verifier)` match/mismatch.
- `codeStore`: single-use (second `take` fails), TTL expiry.
- `HandleToken`: authorization_code happy path; wrong client_secret →
  invalid_client; bad PKCE → invalid_grant; reused code → invalid_grant;
  refresh_token grant issues a new access token.
- `HandleAuthorize`: unknown code re-renders with error; bad redirect_uri → 400;
  valid code → 302 with `code`/`state`.

`internal/bridge`: `resolveCaller` accepts a valid JWT → email; rejects
missing/invalid with 401. Existing `credentials_test.go` unaffected (its
`NewStore` signature is unchanged).

## File structure

| File | Change |
|---|---|
| `internal/oauth/tokens.go` | **New** — JWT issue/verify (golang-jwt) |
| `internal/oauth/codes.go` | **New** — in-memory PKCE auth-code store |
| `internal/oauth/server.go` | **New** — `/authorize` + `/token` handlers |
| `internal/oauth/*_test.go` | **New** — table-driven tests |
| `internal/bridge/server.go` | `resolveCaller` verifies JWT; `Server.tokens`; 401 challenge |
| `main.go` | wire oauth routes + PRM; load new env; drop `BRIDGE_AUTH_TOKEN` |
| `go.mod` | add `github.com/golang-jwt/jwt/v5` |
| `.env.example` | document new OAuth env vars; remove `BRIDGE_AUTH_TOKEN` |

## Out of scope (YAGNI)

- No discovery/DCR beyond the minimal PRM (Static OAuth doesn't need it).
- No user database — personal codes live in `TOKEN_MAP`.
- No social/enterprise login.
- No UI beyond the single code-input page.
- Module name stays camelCase `github.com/idoption/unipileBridge`.
