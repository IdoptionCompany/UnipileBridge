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
	exp := testIssuer()
	exp.accessTTL = -time.Hour
	et, _ := exp.IssueAccess("ian@idoption.ai")
	if _, err := i.VerifyAccess(et); err == nil {
		t.Fatal("expired token must fail")
	}
	other := NewIssuer([]byte("test-secret-at-least-32-bytes-long!!"), "https://bridge.example", "https://OTHER/sse")
	ot, _ := other.IssueAccess("ian@idoption.ai")
	if _, err := i.VerifyAccess(ot); err == nil {
		t.Fatal("wrong-audience token must fail")
	}
}
