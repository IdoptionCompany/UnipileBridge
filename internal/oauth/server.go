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
		// renderForm sets Content-Type then writes the body (implicit 200);
		// do NOT WriteHeader first or the text/html type is lost.
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
