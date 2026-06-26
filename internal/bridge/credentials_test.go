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
