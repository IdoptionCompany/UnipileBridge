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
			s := NewStore(tc.userMap, "", "", "")
			if len(s.users) != tc.wantLen {
				t.Fatalf("want %d entries, got %d: %v", tc.wantLen, len(s.users), s.users)
			}
			if tc.check != nil {
				tc.check(t, s)
			}
		})
	}
}
