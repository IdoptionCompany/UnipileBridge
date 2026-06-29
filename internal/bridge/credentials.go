package bridge

import (
	"errors"
	"log"
	"strings"
)

var ErrNoCredential = errors.New("no Unipile credential for caller")

type Store struct {
	users      map[string]string
	accountIDs map[string]string
	sharedKey  string
}

func NewStore(userMap, sharedKey, accountMap string) *Store {
	return &Store{
		users:      parsePairs(userMap, "USER_MAP"),
		accountIDs: parsePairs(accountMap, "ACCOUNT_MAP"),
		sharedKey:  strings.TrimSpace(sharedKey),
	}
}

// parsePairs parses a comma-separated list of "email:value" pairs, splitting
// each entry on its first colon. Malformed entries are logged (tagged with
// label) and skipped. Emails are lowercased/trimmed for case-insensitive lookup.
func parsePairs(raw, label string) map[string]string {
	m := make(map[string]string)
	if raw == "" {
		return m
	}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		idx := strings.Index(entry, ":")
		if idx < 0 {
			log.Printf("⚠️  skipping malformed %s entry: %q", label, entry)
			continue
		}
		email := strings.ToLower(strings.TrimSpace(entry[:idx]))
		val := strings.TrimSpace(entry[idx+1:])
		if email == "" || !strings.Contains(email, "@") || val == "" {
			log.Printf("⚠️  skipping malformed %s entry: %q", label, entry)
			continue
		}
		m[email] = val
	}
	return m
}

// ResolveAccountID returns the Unipile account_id mapped to email, or "".
func (s *Store) ResolveAccountID(email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	if id, ok := s.accountIDs[email]; ok {
		return id
	}
	return ""
}

func (s *Store) Resolve(email, bearer string, legacy bool) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email != "" {
		if key, ok := s.users[email]; ok {
			return key, nil
		}
		if s.sharedKey != "" {
			return s.sharedKey, nil
		}
		return "", ErrNoCredential
	}
	if s.sharedKey != "" {
		return s.sharedKey, nil
	}
	if legacy && bearer != "" {
		return bearer, nil
	}
	return "", ErrNoCredential
}
