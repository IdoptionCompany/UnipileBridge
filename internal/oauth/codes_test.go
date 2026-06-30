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
