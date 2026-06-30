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
