# OAuth Per-User Authentication Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the bridge a minimal OAuth 2.1 Authorization Server with a personal-code login, so one shared Dust MCP connection (Static OAuth + Personal accounts) routes each user to their own Unipile account.

**Architecture:** A new, self-contained `internal/oauth` package issues/verifies signed JWT access tokens and runs the `/authorize` (code-entry page) + `/token` flow with PKCE. The bridge becomes a Resource Server: it verifies the JWT on each MCP call, extracts the email, and reuses the existing per-account isolation. Personal codes live in `TOKEN_MAP` (code→email); accounts in `ACCOUNT_MAP` (email→account_id).

**Tech Stack:** Go 1.22, `net/http`, `github.com/golang-jwt/jwt/v5` (new dep), existing `github.com/google/uuid`, `github.com/joho/godotenv`. Module: `github.com/idoption/unipileBridge`.

**Spec:** `docs/specs/2026-06-30-oauth-per-user-auth-design.md`

---

## Prerequisites: running builds and tests

`go` is not installed locally and Docker may not be running. Verify with this wrapper (ensure Docker Desktop is up first):

```bash
# GO = either local `go` or this Docker wrapper:
docker run --rm -v "$PWD":/app -w /app golang:1.22-alpine go <args>
```

Throughout, **`$GO`** means `go` (if installed) or the wrapper above. If neither is available, the only verification is the Railway build on push — do not claim a step passed without one of these succeeding.

---

## File structure

| File | Responsibility |
|------|----------------|
| `internal/oauth/tokens.go` | **New** — `Issuer`: sign/verify access+refresh JWTs (HS256) |
| `internal/oauth/codes.go` | **New** — in-memory single-use PKCE auth-code store + PKCE verify |
| `internal/oauth/server.go` | **New** — `/authorize` (code form) + `/token` handlers |
| `internal/oauth/tokens_test.go` / `codes_test.go` / `server_test.go` | **New** — table-driven tests |
| `internal/bridge/credentials.go` | Simplify `Resolve(email)`; remove debug logs |
| `internal/bridge/credentials_test.go` | Rewrite `TestResolve` for 1-arg signature |
| `internal/bridge/server.go` | `resolveCaller` verifies JWT + 403-on-no-account; drop `authToken`/`legacy`; new `NewServer`; 401 challenge; PRM handler; `extractBearer` drops `?api_key=`; strip debug logs |
| `main.go` | wire oauth routes + PRM + env; `NewServer(baseURL, creds, tokens)`; drop `BRIDGE_AUTH_TOKEN`; fail-fast on weak `OAUTH_JWT_SECRET` |
| `go.mod` / `go.sum` | add `golang-jwt/jwt/v5` |
| `.env.example` | document OAuth env; remove `BRIDGE_AUTH_TOKEN` |

---

## Chunk 1: The `internal/oauth` package

### Task 1: JWT `Issuer` (tokens.go)

**Files:**
- Create: `internal/oauth/tokens.go`
- Test: `internal/oauth/tokens_test.go`

- [ ] **Step 1: Write the failing test**

`internal/oauth/tokens_test.go`:
```go
package oauth

import (
	"testing"
	"time"
)

func testIssuer() *Issuer {
	return NewIssuer([]byte("test-secret-at-least-32-bytes-long!!"), "https://bridge.example", "https://bridge.example/sse")
}

func TestAccessRoundTrip(t *testing.T) {
	i := testIssuer()
	tok, err := i.IssueAccess("ian@idoption.ai")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	email, err := i.VerifyAccess(tok)
	if err != nil || email != "ian@idoption.ai" {
		t.Fatalf("verify: email=%q err=%v", email, err)
	}
}

func TestRefreshNotAcceptedAsAccess(t *testing.T) {
	i := testIssuer()
	tok, _ := i.IssueRefresh("ian@idoption.ai")
	if _, err := i.VerifyAccess(tok); err == nil {
		t.Fatal("refresh token must not verify as access")
	}
}

func TestVerifyRejectsEmptyTamperedExpiredWrongAudience(t *testing.T) {
	i := testIssuer()
	if _, err := i.VerifyAccess(""); err == nil {
		t.Fatal("empty token must fail")
	}
	tok, _ := i.IssueAccess("ian@idoption.ai")
	if _, err := i.VerifyAccess(tok + "x"); err == nil {
		t.Fatal("tampered token must fail")
	}
	// expired
	exp := testIssuer()
	exp.accessTTL = -time.Hour
	et, _ := exp.IssueAccess("ian@idoption.ai")
	if _, err := i.VerifyAccess(et); err == nil {
		t.Fatal("expired token must fail")
	}
	// wrong audience
	other := NewIssuer([]byte("test-secret-at-least-32-bytes-long!!"), "https://bridge.example", "https://OTHER/sse")
	ot, _ := other.IssueAccess("ian@idoption.ai")
	if _, err := i.VerifyAccess(ot); err == nil {
		t.Fatal("wrong-audience token must fail")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `$GO test ./internal/oauth/ -run TestAccess -v`
Expected: FAIL — `undefined: NewIssuer` (package doesn't compile).

- [ ] **Step 3: Write the implementation**

`internal/oauth/tokens.go`:
```go
package oauth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Issuer signs and verifies the bridge's access/refresh tokens (HS256).
type Issuer struct {
	secret     []byte
	issuer     string
	audience   string
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func NewIssuer(secret []byte, issuer, audience string) *Issuer {
	return &Issuer{
		secret:     secret,
		issuer:     issuer,
		audience:   audience,
		accessTTL:  time.Hour,
		refreshTTL: 30 * 24 * time.Hour,
	}
}

var ErrInvalidToken = errors.New("invalid token")

type claims struct {
	Email string `json:"email"`
	Typ   string `json:"typ"`
	jwt.RegisteredClaims
}

func (i *Issuer) sign(email, typ string, ttl time.Duration) (string, error) {
	now := time.Now()
	c := claims{
		Email: email,
		Typ:   typ,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.issuer,
			Subject:   email,
			Audience:  jwt.ClaimStrings{i.audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(i.secret)
}

func (i *Issuer) IssueAccess(email string) (string, error)  { return i.sign(email, "access", i.accessTTL) }
func (i *Issuer) IssueRefresh(email string) (string, error) { return i.sign(email, "refresh", i.refreshTTL) }

func (i *Issuer) verify(token, wantTyp string) (string, error) {
	c := &claims{}
	_, err := jwt.ParseWithClaims(token, c, func(t *jwt.Token) (any, error) {
		return i.secret, nil
	},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(i.issuer),
		jwt.WithAudience(i.audience),
		jwt.WithExpirationRequired(),
	)
	if err != nil || c.Typ != wantTyp || c.Email == "" {
		return "", ErrInvalidToken
	}
	return c.Email, nil
}

func (i *Issuer) VerifyAccess(token string) (string, error)  { return i.verify(token, "access") }
func (i *Issuer) VerifyRefresh(token string) (string, error) { return i.verify(token, "refresh") }
```

- [ ] **Step 4: Add the dependency and run tests**

Run:
```bash
$GO get github.com/golang-jwt/jwt/v5
$GO test ./internal/oauth/ -run 'TestAccess|TestRefresh|TestVerify' -v
```
Expected: PASS (all three tests green); `go.mod`/`go.sum` now list `golang-jwt/jwt/v5`.

- [ ] **Step 5: Commit**

```bash
git add internal/oauth/tokens.go internal/oauth/tokens_test.go go.mod go.sum
git commit -m "feat(oauth): JWT issuer for access/refresh tokens"
```

---

### Task 2: PKCE auth-code store (codes.go)

**Files:**
- Create: `internal/oauth/codes.go`
- Test: `internal/oauth/codes_test.go`

- [ ] **Step 1: Write the failing test**

`internal/oauth/codes_test.go`:
```go
package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"
)

func TestCodeStoreSingleUseAndExpiry(t *testing.T) {
	s := newCodeStore()
	s.put("abc", authCode{email: "ian@idoption.ai", expiry: time.Now().Add(time.Minute)})
	if _, ok := s.take("abc"); !ok {
		t.Fatal("first take should succeed")
	}
	if _, ok := s.take("abc"); ok {
		t.Fatal("second take must fail (single-use)")
	}
	s.put("old", authCode{email: "x@y.z", expiry: time.Now().Add(-time.Second)})
	if _, ok := s.take("old"); ok {
		t.Fatal("expired code must fail")
	}
}

func TestVerifyPKCE(t *testing.T) {
	verifier := "abc123verifier-value-long-enough"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if !verifyPKCE(verifier, challenge) {
		t.Fatal("matching verifier should pass")
	}
	if verifyPKCE("wrong", challenge) {
		t.Fatal("wrong verifier must fail")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `$GO test ./internal/oauth/ -run 'TestCodeStore|TestVerifyPKCE' -v`
Expected: FAIL — `undefined: newCodeStore`, `undefined: verifyPKCE`.

- [ ] **Step 3: Write the implementation**

`internal/oauth/codes.go`:
```go
package oauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"sync"
	"time"
)

// authCode is a single-use authorization code awaiting exchange at /token.
type authCode struct {
	email         string
	codeChallenge string // PKCE S256 (base64url, no padding)
	redirectURI   string
	expiry        time.Time
}

// codeStore is an in-memory, mutex-guarded, single-use, TTL'd store.
type codeStore struct {
	mu    sync.Mutex
	codes map[string]authCode
}

func newCodeStore() *codeStore { return &codeStore{codes: make(map[string]authCode)} }

func (s *codeStore) put(code string, c authCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code] = c
}

// take returns the code once then deletes it. Returns false if missing or expired.
func (s *codeStore) take(code string) (authCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[code]
	if !ok {
		return authCode{}, false
	}
	delete(s.codes, code)
	if time.Now().After(c.expiry) {
		return authCode{}, false
	}
	return c, true
}

// verifyPKCE checks base64url(SHA256(verifier)) == challenge (S256 only).
func verifyPKCE(verifier, challenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(want), []byte(challenge)) == 1
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `$GO test ./internal/oauth/ -run 'TestCodeStore|TestVerifyPKCE' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/oauth/codes.go internal/oauth/codes_test.go
git commit -m "feat(oauth): single-use PKCE auth-code store"
```

---

### Task 3: `/authorize` + `/token` handlers (server.go)

**Files:**
- Create: `internal/oauth/server.go`
- Test: `internal/oauth/server_test.go`

- [ ] **Step 1: Write the failing test**

`internal/oauth/server_test.go`:
```go
package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func testServer() *Server {
	cfg := Config{ClientID: "dust", ClientSecret: "shh", RedirectURI: "https://dust.tt/oauth/mcp_static/finalize", Scope: "mcp"}
	resolve := func(code string) string {
		if code == "ian-code" {
			return "ian@idoption.ai"
		}
		return ""
	}
	return NewServer(cfg, testIssuer(), resolve)
}

func TestAuthorizeRejectsBadRedirect(t *testing.T) {
	s := testServer()
	r := httptest.NewRequest("GET", "/oauth/authorize?client_id=dust&redirect_uri=https://evil.com&response_type=code&code_challenge=x&code_challenge_method=S256", nil)
	w := httptest.NewRecorder()
	s.HandleAuthorize(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestAuthorizeFullFlowAndToken(t *testing.T) {
	s := testServer()
	verifier := "verifier-value-long-enough-for-pkce"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	// POST the personal code to /authorize
	form := url.Values{"code": {"ian-code"}, "redirect_uri": {s.cfg.RedirectURI}, "state": {"st8"}, "code_challenge": {challenge}}
	r := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.HandleAuthorize(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("want 302, got %d", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("state") != "st8" {
		t.Fatal("state must round-trip")
	}
	authCodeVal := loc.Query().Get("code")
	if authCodeVal == "" {
		t.Fatal("missing auth code")
	}

	// Exchange at /token
	tf := url.Values{
		"grant_type": {"authorization_code"}, "code": {authCodeVal},
		"client_id": {"dust"}, "client_secret": {"shh"},
		"redirect_uri": {s.cfg.RedirectURI}, "code_verifier": {verifier},
	}
	tr := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(tf.Encode()))
	tr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tw := httptest.NewRecorder()
	s.HandleToken(tw, tr)
	if tw.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", tw.Code, tw.Body.String())
	}
	var resp map[string]any
	json.Unmarshal(tw.Body.Bytes(), &resp)
	if resp["access_token"] == nil || resp["token_type"] != "Bearer" {
		t.Fatalf("bad token response: %v", resp)
	}
	email, err := s.issuer.VerifyAccess(resp["access_token"].(string))
	if err != nil || email != "ian@idoption.ai" {
		t.Fatalf("issued token bad: email=%q err=%v", email, err)
	}
}

func TestAuthorizeUnknownCodeRerendersForm(t *testing.T) {
	s := testServer()
	form := url.Values{"code": {"nope"}, "redirect_uri": {s.cfg.RedirectURI}, "code_challenge": {"x"}}
	r := httptest.NewRequest("POST", "/oauth/authorize", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.HandleAuthorize(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "form") {
		t.Fatalf("unknown code should re-render form (200), got %d", w.Code)
	}
}

func TestTokenBadClientSecretAndReusedCode(t *testing.T) {
	s := testServer()
	verifier := "verifier-value-long-enough-for-pkce"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	s.codes.put("ac1", authCode{email: "ian@idoption.ai", codeChallenge: challenge, redirectURI: s.cfg.RedirectURI, expiry: timeNowPlusMin()})

	// wrong client secret
	bad := url.Values{"grant_type": {"authorization_code"}, "code": {"ac1"}, "client_id": {"dust"}, "client_secret": {"WRONG"}, "redirect_uri": {s.cfg.RedirectURI}, "code_verifier": {verifier}}
	br := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(bad.Encode()))
	br.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	bw := httptest.NewRecorder()
	s.HandleToken(bw, br)
	if bw.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret want 401, got %d", bw.Code)
	}

	// good exchange, then reuse same code
	good := url.Values{"grant_type": {"authorization_code"}, "code": {"ac1"}, "client_id": {"dust"}, "client_secret": {"shh"}, "redirect_uri": {s.cfg.RedirectURI}, "code_verifier": {verifier}}
	mk := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(good.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		s.HandleToken(w, r)
		return w
	}
	if mk().Code != http.StatusOK {
		t.Fatal("first exchange should succeed")
	}
	if mk().Code == http.StatusOK {
		t.Fatal("reused code must fail (single-use)")
	}
}
```

Add a tiny test helper at the bottom of `server_test.go`:
```go
func timeNowPlusMin() time.Time { return time.Now().Add(time.Minute) }
```
(and add `"time"` to the test imports).

- [ ] **Step 2: Run test to verify it fails**

Run: `$GO test ./internal/oauth/ -run 'TestAuthorize|TestToken' -v`
Expected: FAIL — `undefined: NewServer`, `Config`, `Server`.

- [ ] **Step 3: Write the implementation**

`internal/oauth/server.go`:
```go
package oauth

import (
	"crypto/subtle"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
)

type Config struct {
	ClientID     string
	ClientSecret string // optional; validated only if non-empty
	RedirectURI  string // allowlisted redirect (Dust's finalize URL)
	Scope        string
}

// Server implements the minimal OAuth 2.1 Authorization Server endpoints.
type Server struct {
	cfg          Config
	issuer       *Issuer
	codes        *codeStore
	resolveEmail func(code string) string // personal code -> email ("" if unknown)
}

func NewServer(cfg Config, issuer *Issuer, resolveEmail func(string) string) *Server {
	return &Server{cfg: cfg, issuer: issuer, codes: newCodeStore(), resolveEmail: resolveEmail}
}

var authForm = template.Must(template.New("form").Parse(`<!doctype html><html><head><meta charset="utf-8">
<title>Unipile Bridge — Sign in</title></head><body style="font-family:system-ui;max-width:420px;margin:80px auto">
<h2>Enter your personal access code</h2>
{{if .Err}}<p style="color:#c00">{{.Err}}</p>{{end}}
<form method="post">
<input name="code" autofocus placeholder="personal code" style="width:100%;padding:10px;font-size:16px" />
<input type="hidden" name="redirect_uri" value="{{.RedirectURI}}" />
<input type="hidden" name="state" value="{{.State}}" />
<input type="hidden" name="code_challenge" value="{{.Challenge}}" />
<button type="submit" style="margin-top:12px;padding:10px 16px">Continue</button>
</form></body></html>`))

type formData struct{ Err, RedirectURI, State, Challenge string }

func (s *Server) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		q := r.URL.Query()
		if q.Get("client_id") != s.cfg.ClientID ||
			q.Get("redirect_uri") != s.cfg.RedirectURI ||
			q.Get("response_type") != "code" ||
			q.Get("code_challenge_method") != "S256" ||
			q.Get("code_challenge") == "" {
			http.Error(w, "invalid authorization request", http.StatusBadRequest)
			return
		}
		renderForm(w, formData{RedirectURI: q.Get("redirect_uri"), State: q.Get("state"), Challenge: q.Get("code_challenge")})
		return
	}
	// POST: the user submitted their personal code
	_ = r.ParseForm()
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	challenge := r.FormValue("code_challenge")
	if redirectURI != s.cfg.RedirectURI || challenge == "" {
		http.Error(w, "invalid authorization request", http.StatusBadRequest)
		return
	}
	email := s.resolveEmail(r.FormValue("code"))
	if email == "" {
		w.WriteHeader(http.StatusOK)
		renderForm(w, formData{Err: "Unknown code — try again.", RedirectURI: redirectURI, State: state, Challenge: challenge})
		return
	}
	code := uuid.NewString()
	s.codes.put(code, authCode{email: email, codeChallenge: challenge, redirectURI: redirectURI, expiry: time.Now().Add(60 * time.Second)})
	u, _ := url.Parse(redirectURI)
	qq := u.Query()
	qq.Set("code", code)
	qq.Set("state", state)
	u.RawQuery = qq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func renderForm(w http.ResponseWriter, d formData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = authForm.Execute(w, d)
}

func (s *Server) HandleToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if r.FormValue("client_id") != s.cfg.ClientID {
		tokenError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	if s.cfg.ClientSecret != "" &&
		subtle.ConstantTimeCompare([]byte(r.FormValue("client_secret")), []byte(s.cfg.ClientSecret)) != 1 {
		tokenError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	switch r.FormValue("grant_type") {
	case "authorization_code":
		ac, ok := s.codes.take(r.FormValue("code"))
		if !ok || ac.redirectURI != r.FormValue("redirect_uri") || !verifyPKCE(r.FormValue("code_verifier"), ac.codeChallenge) {
			tokenError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		writeTokens(w, s.issuer, ac.email, s.cfg.Scope)
	case "refresh_token":
		email, err := s.issuer.VerifyRefresh(r.FormValue("refresh_token"))
		if err != nil {
			tokenError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		writeTokens(w, s.issuer, email, s.cfg.Scope)
	default:
		tokenError(w, http.StatusBadRequest, "unsupported_grant_type")
	}
}

func writeTokens(w http.ResponseWriter, iss *Issuer, email, scope string) {
	access, err := iss.IssueAccess(email)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error")
		return
	}
	refresh, _ := iss.IssueRefresh(email)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    int(iss.accessTTL.Seconds()),
		"refresh_token": refresh,
		"scope":         scope,
	})
}

func tokenError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `$GO test ./internal/oauth/ -v`
Expected: PASS — all oauth tests (Tasks 1–3) green.

- [ ] **Step 5: Commit**

```bash
git add internal/oauth/server.go internal/oauth/server_test.go
git commit -m "feat(oauth): /authorize code form + /token PKCE exchange"
```

---

## Chunk 2: Bridge integration

### Task 4: Simplify `Store.Resolve(email)`

**Files:**
- Modify: `internal/bridge/credentials.go`
- Modify: `internal/bridge/credentials_test.go`

- [ ] **Step 1: Update the test for the 1-arg signature**

In `internal/bridge/credentials_test.go`, replace `TestResolve` with:
```go
func TestResolve(t *testing.T) {
	cases := []struct {
		name      string
		email     string
		sharedKey string
		wantKey   string
		wantErr   bool
	}{
		{"map hit", "ian@company.com", "", "key_ian", false},
		{"map beats shared", "ian@company.com", "shared", "key_ian", false},
		{"unknown email uses shared", "bob@company.com", "shared", "shared", false},
		{"unknown email no shared rejects", "bob@company.com", "", "", true},
		{"empty email uses shared", "", "shared", "shared", false},
		{"empty email no shared rejects", "", "", "", true},
		{"case/space insensitive", "  IAN@Company.com ", "", "key_ian", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(tc.sharedKey)
			got, err := s.Resolve(tc.email)
			if tc.wantErr {
				if !errors.Is(err, ErrNoCredential) {
					t.Fatalf("want ErrNoCredential, got key=%q err=%v", got, err)
				}
				return
			}
			if err != nil || got != tc.wantKey {
				t.Fatalf("want %q, got %q (err=%v)", tc.wantKey, got, err)
			}
		})
	}
}
```
(Leave `newTestStore` and `TestNewStore` as-is.)

- [ ] **Step 2: Run test to verify it fails to compile**

Run: `$GO test ./internal/bridge/ -run TestResolve -v`
Expected: FAIL — too many arguments / signature mismatch (`Resolve` still takes 3 args).

- [ ] **Step 3: Simplify `Resolve` in `credentials.go`**

Replace the existing `func (s *Store) Resolve(email, bearer string, legacy bool) (string, error) { ... }` with:
```go
// Resolve returns the Unipile API key for a user's email: their USER_MAP key if
// present, else the shared key, else ErrNoCredential.
func (s *Store) Resolve(email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email != "" {
		if key, ok := s.users[email]; ok {
			return key, nil
		}
	}
	if s.sharedKey != "" {
		return s.sharedKey, nil
	}
	return "", ErrNoCredential
}
```

- [ ] **Step 4: Remove the debug logs in `credentials.go`**

Delete the two `log.Printf` lines: the `TOKEN_MAP loaded token=%q → email=%q` line inside `parseTokenMap`, and the `looking up token=%q in %d entries` line inside `ResolveEmailFromToken`. If `log` is then unused, remove it from imports.

- [ ] **Step 5: Run tests to verify they pass**

Run: `$GO test ./internal/bridge/ -run 'TestResolve|TestNewStore' -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/bridge/credentials.go internal/bridge/credentials_test.go
git commit -m "refactor(bridge): simplify Resolve(email); drop code-logging"
```

---

### Task 5: `resolveCaller` verifies JWT; drop `authToken`; 401 challenge; PRM; `extractBearer` cleanup; strip logs

**Files:**
- Modify: `internal/bridge/server.go`

- [ ] **Step 1: Update the `Server` struct and `NewServer` (final form)**

Add the import `"github.com/idoption/unipileBridge/internal/oauth"`. In the
`Server` struct: **drop** `authToken string`; **add** `publicURL string` (the
bridge's public URL, distinct from `baseURL` which is the Unipile API base) and
`tokens *oauth.Issuer`. New constructor written once in final form:
```go
func NewServer(baseURL, publicURL string, creds *Store, tokens *oauth.Issuer) *Server {
	return &Server{
		baseURL:     baseURL,
		publicURL:   publicURL,
		credentials: creds,
		tokens:      tokens,
		sessions:    make(map[string]*session),
	}
}
```

- [ ] **Step 2: Replace `resolveCaller`**

```go
// resolveCaller verifies the bridge-issued JWT access token and resolves the
// caller's Unipile credentials. status==0 on success; otherwise the HTTP status
// + JSON body to send.
func (s *Server) resolveCaller(r *http.Request) (apiKey, accountID, userEmail string, status int, errBody string) {
	email, err := s.tokens.VerifyAccess(extractBearer(r))
	if err != nil {
		return "", "", "", http.StatusUnauthorized, `{"error":"unauthorized"}`
	}
	userEmail = email
	accountID = s.credentials.ResolveAccountID(userEmail)
	if accountID == "" {
		// Verified user with no ACCOUNT_MAP entry — hard fail so isolation is never off.
		return "", "", userEmail, http.StatusForbidden, `{"error":"no account mapped for user"}`
	}
	key, err := s.credentials.Resolve(userEmail)
	if err != nil {
		return "", "", userEmail, http.StatusForbidden, `{"error":"no Unipile credential for user"}`
	}
	return key, accountID, userEmail, 0, ""
}
```

- [ ] **Step 3: Make the 401 responses send `WWW-Authenticate`**

The three handlers do `http.Error(w, errBody, status)` on `status != 0`. Add a helper and use it so a 401 advertises the PRM document:
```go
func (s *Server) writeAuthError(w http.ResponseWriter, status int, body string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate",
			`Bearer resource_metadata="`+s.baseURL+`/.well-known/oauth-protected-resource"`)
	}
	http.Error(w, body, status)
}
```
`s.publicURL` (added to the struct in Step 1) is the bridge's public URL. Replace the three `http.Error(w, errBody, status)` calls in `HandleSSE`, `HandleMessages`, and `HandleStreamableHTTP` (the `if status != 0` branches) with `s.writeAuthError(w, status, errBody)`.

- [ ] **Step 4: Add the PRM handler**

```go
func (s *Server) HandleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"resource":              s.publicURL + "/sse",
		"authorization_servers": []string{s.publicURL},
		"scopes_supported":      []string{"mcp"},
	})
}
```

- [ ] **Step 5: Simplify `extractBearer`**

Replace the body so it only reads the header (drop the `?api_key=` fallback):
```go
func extractBearer(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}
```

- [ ] **Step 6: Strip the remaining debug logs**

Delete these lines in `server.go`:
- the `🔍 GET /sse — …` log in `HandleSSE`,
- the `session %s connected (key: %.8s… …)` log in `HandleSSE`,
- the `🔍 /messages headers — %v` and `🔍 /messages url — %s` logs at the top of `HandleMessages`,
- the `🔑 /messages session … email=… accountID=…` log in `HandleMessages`,
- the `🔍 POST /sse — … headers=%v` log in `HandleStreamableHTTP`.

(Keep `session %s closed` and `session %s connected`-style lines only if they contain **no** key/email/header data; otherwise drop. Prefer removing all of the above outright.)

- [ ] **Step 7: Verify the package compiles (main.go not yet updated)**

Run: `$GO build ./internal/...`
Expected: PASS (the `internal/bridge` + `internal/oauth` packages compile). `$GO build ./...` will still FAIL on `main.go` (old `NewServer` call) — that's Task 6.

- [ ] **Step 8: Run bridge tests**

Run: `$GO test ./internal/bridge/ -v`
Expected: PASS (credentials tests; no test references the removed fields).

- [ ] **Step 9: Commit**

```bash
git add internal/bridge/server.go
git commit -m "feat(bridge): verify OAuth JWT in resolveCaller; PRM + 401 challenge; drop authToken/api_key/debug logs"
```

Note: repo build is briefly red between this commit and Task 6 (main.go caller). Squash with Task 6 at the end if a green-every-commit invariant is required.

---

### Task 6: Wire `main.go` — oauth routes, PRM, env, fail-fast

**Files:**
- Modify: `main.go`

- [ ] **Step 1: Load env + build the oauth issuer/server**

The current `main.go` has, in order: an `authToken := os.Getenv("BRIDGE_AUTH_TOKEN")` block (with a warning `log.Println`), then `userMap`, `sharedKey`, `accountMap`, `tokenMap := os.Getenv("TOKEN_MAP")`, then `creds := bridge.NewStore(userMap, sharedKey, accountMap, tokenMap)`.

(a) **Delete the entire `authToken := os.Getenv("BRIDGE_AUTH_TOKEN")` block** (the assignment and its `if authToken == "" { log.Println(...) }` warning).
(b) **Keep** the `userMap`/`sharedKey`/`accountMap`/`tokenMap` lines and the existing `creds := bridge.NewStore(userMap, sharedKey, accountMap, tokenMap)` line **unchanged** (`tokenMap` stays in use — do NOT introduce a duplicate `os.Getenv("TOKEN_MAP")`).
(c) **Insert** the OAuth setup immediately after the `creds := …` line:
```go
	publicURL := os.Getenv("PUBLIC_BASE_URL")
	if publicURL == "" {
		log.Fatal("PUBLIC_BASE_URL is required (e.g. https://unipilebridge-production.up.railway.app)")
	}
	jwtSecret := os.Getenv("OAUTH_JWT_SECRET")
	if len(jwtSecret) < 32 {
		log.Fatal("OAUTH_JWT_SECRET is required and must be at least 32 bytes")
	}
	clientID := os.Getenv("OAUTH_CLIENT_ID")
	if clientID == "" {
		log.Fatal("OAUTH_CLIENT_ID is required")
	}
	redirectURI := os.Getenv("OAUTH_REDIRECT_URI")
	if redirectURI == "" {
		redirectURI = "https://dust.tt/oauth/mcp_static/finalize"
	}
	scope := os.Getenv("OAUTH_SCOPE")
	if scope == "" {
		scope = "mcp"
	}

	tokenIssuer := oauth.NewIssuer([]byte(jwtSecret), publicURL, publicURL+"/sse")
	oauthSrv := oauth.NewServer(oauth.Config{
		ClientID:     clientID,
		ClientSecret: os.Getenv("OAUTH_CLIENT_SECRET"),
		RedirectURI:  redirectURI,
		Scope:        scope,
	}, tokenIssuer, creds.ResolveEmailFromToken)
```
Add the import `"github.com/idoption/unipileBridge/internal/oauth"` (keep `bridge`).

- [ ] **Step 2: Update the server construction + routes**

```go
	srv := bridge.NewServer(baseURL, publicURL, creds, tokenIssuer)

	mux := http.NewServeMux()
	// OAuth (public)
	mux.HandleFunc("/oauth/authorize", oauthSrv.HandleAuthorize)
	mux.HandleFunc("/oauth/token", oauthSrv.HandleToken)
	mux.HandleFunc("/.well-known/oauth-protected-resource", srv.HandleProtectedResourceMetadata)
	// MCP (token-protected) + health — existing handlers below unchanged
	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) { /* existing GET/POST/OPTIONS switch */ })
	mux.HandleFunc("/messages", srv.HandleMessages)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK); w.Write([]byte(`{"status":"ok"}`)) })
```
Keep the existing `/sse` method-switch body and `/health` exactly as they are; only the `NewServer` call and the three new routes are added.

- [ ] **Step 3: Build the whole module**

Run: `$GO build ./...`
Expected: PASS — exit 0.

- [ ] **Step 4: Run the full test suite**

Run: `$GO test ./... -v`
Expected: PASS — `internal/oauth` and `internal/bridge` green.

- [ ] **Step 5: Commit**

```bash
git add main.go
git commit -m "feat: wire OAuth routes + env; drop BRIDGE_AUTH_TOKEN; fail-fast on weak secret"
```

---

### Task 7: Update `.env.example`

**Files:**
- Modify: `.env.example`

- [ ] **Step 1: Replace the bridge-security section**

Remove `BRIDGE_AUTH_TOKEN`. Add:
```dotenv
# ─── OAuth (per-user auth via Dust Static OAuth) ──────────────────────────────

# Public URL of this bridge (issuer + token audience). No trailing slash.
PUBLIC_BASE_URL=https://unipilebridge-production.up.railway.app

# HS256 signing key for access/refresh tokens. REQUIRED, >= 32 bytes.
# Generate with: openssl rand -base64 48
OAUTH_JWT_SECRET=

# Static OAuth client you paste into Dust.
OAUTH_CLIENT_ID=dust-unipile-bridge
OAUTH_CLIENT_SECRET=

# Redirect URI Dust uses (default is Dust's fixed value).
OAUTH_REDIRECT_URI=https://dust.tt/oauth/mcp_static/finalize
OAUTH_SCOPE=mcp

# Personal codes each user enters on first login: code:email,code:email
TOKEN_MAP=ian-personal-code:ian@idoption.ai,bap-personal-code:baptiste@idoption.ai
```
Keep `UNIPILE_BASE_URL`, `UNIPILE_SHARED_KEY`, `ACCOUNT_MAP`, `PORT`.

- [ ] **Step 2: Commit**

```bash
git add .env.example
git commit -m "docs: document OAuth env vars; remove BRIDGE_AUTH_TOKEN"
```

---

## Done criteria

- `$GO build ./...` exits 0.
- `$GO test ./... -v` passes (oauth + bridge suites).
- `grep -rn 'authToken\|api_key\|🔍\|🔑\|TOKEN_MAP loaded\|looking up token' --include='*.go' .` returns nothing (auth + debug cleanup complete).
- Seven commits in order: jwt issuer → code store → authorize/token → resolve simplify → bridge integration → main wiring → env.

## Post-merge follow-up (NOT part of this plan)

In Railway set: `PUBLIC_BASE_URL`, `OAUTH_JWT_SECRET` (≥32 bytes), `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET`, `OAUTH_REDIRECT_URI` (or default), `OAUTH_SCOPE`, `TOKEN_MAP` (codes→email), `ACCOUNT_MAP`, `UNIPILE_*`. In Dust: Static OAuth + Personal accounts, paste client id/secret + `…/oauth/authorize` + `…/oauth/token` + scope `mcp`. Hand each user their personal code.
