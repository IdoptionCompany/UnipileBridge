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
	tokens     map[string]string // bearer token -> email
	sharedKey  string
}

func NewStore(userMap, sharedKey, accountMap, tokenMap string) *Store {
	return &Store{
		users:      parsePairs(userMap, "USER_MAP", true),
		accountIDs: parsePairs(accountMap, "ACCOUNT_MAP", true),
		tokens:     parseTokenMap(tokenMap),
		sharedKey:  strings.TrimSpace(sharedKey),
	}
}

// parsePairs parses a comma-separated list of "key:value" pairs, splitting each
// entry on its first colon. Malformed entries are logged (tagged with label) and
// skipped. When keyIsEmail is true the key is lowercased and required to contain
// "@" (email-keyed maps for case-insensitive lookup); when false the key is kept
// verbatim and only required to be non-empty (e.g. case-sensitive bearer tokens).
func parsePairs(raw, label string, keyIsEmail bool) map[string]string {
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
		key := strings.TrimSpace(entry[:idx])
		val := strings.TrimSpace(entry[idx+1:])
		if keyIsEmail {
			key = strings.ToLower(key)
		}
		if key == "" || val == "" || (keyIsEmail && !strings.Contains(key, "@")) {
			log.Printf("⚠️  skipping malformed %s entry: %q", label, entry)
			continue
		}
		m[key] = val
	}
	return m
}

// parseTokenMap parses TOKEN_MAP ("token:email,...") into a token->email map.
// Tokens are kept verbatim (case-sensitive, may contain no "@"); entries with an
// empty token or email are skipped. Each loaded entry is logged at startup.
func parseTokenMap(raw string) map[string]string {
	m := make(map[string]string)
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		idx := strings.Index(pair, ":")
		if idx <= 0 || idx == len(pair)-1 {
			continue
		}
		token := strings.TrimSpace(pair[:idx])
		email := strings.TrimSpace(pair[idx+1:])
		if token != "" && email != "" {
			m[token] = email
			log.Printf("credentials: TOKEN_MAP loaded token=%q → email=%q", token, email)
		}
	}
	return m
}

// ResolveEmailFromToken returns the email mapped to a per-user bearer token, or "".
func (s *Store) ResolveEmailFromToken(token string) string {
	log.Printf("credentials: looking up token=%q in %d entries", token, len(s.tokens))
	if email, ok := s.tokens[token]; ok {
		return email
	}
	return ""
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
