package bridge

import (
	"errors"
	"log"
	"strings"
)

var ErrNoCredential = errors.New("no Unipile credential for caller")

type Store struct {
	users     map[string]string
	sharedKey string
}

func NewStore(userMap, sharedKey string) *Store {
	s := &Store{
		users:     make(map[string]string),
		sharedKey: strings.TrimSpace(sharedKey),
	}
	if userMap == "" {
		return s
	}
	for _, raw := range strings.Split(userMap, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		idx := strings.Index(raw, ":")
		if idx < 0 {
			log.Printf("⚠️  skipping malformed USER_MAP entry: %q", raw)
			continue
		}
		email := strings.ToLower(strings.TrimSpace(raw[:idx]))
		key := strings.TrimSpace(raw[idx+1:])
		if email == "" || !strings.Contains(email, "@") || key == "" {
			log.Printf("⚠️  skipping malformed USER_MAP entry: %q", raw)
			continue
		}
		s.users[email] = key
	}
	return s
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
