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
	"time"
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

func timeNowPlusMin() time.Time { return time.Now().Add(time.Minute) }

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

	bad := url.Values{"grant_type": {"authorization_code"}, "code": {"ac1"}, "client_id": {"dust"}, "client_secret": {"WRONG"}, "redirect_uri": {s.cfg.RedirectURI}, "code_verifier": {verifier}}
	br := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(bad.Encode()))
	br.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	bw := httptest.NewRecorder()
	s.HandleToken(bw, br)
	if bw.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret want 401, got %d", bw.Code)
	}

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
