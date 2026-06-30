package oauth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Issuer signs and verifies the bridge's access/refresh tokens (HS256).
type Issuer struct {
	secret     []byte
	issuer     string
	audience   string
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func NewIssuer(secret []byte, issuer, audience string) *Issuer {
	return &Issuer{
		secret:     secret,
		issuer:     issuer,
		audience:   audience,
		accessTTL:  time.Hour,
		refreshTTL: 30 * 24 * time.Hour,
	}
}

var ErrInvalidToken = errors.New("invalid token")

type claims struct {
	Email string `json:"email"`
	Typ   string `json:"typ"`
	jwt.RegisteredClaims
}

func (i *Issuer) sign(email, typ string, ttl time.Duration) (string, error) {
	now := time.Now()
	c := claims{
		Email: email,
		Typ:   typ,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.issuer,
			Subject:   email,
			Audience:  jwt.ClaimStrings{i.audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(i.secret)
}

func (i *Issuer) IssueAccess(email string) (string, error)  { return i.sign(email, "access", i.accessTTL) }
func (i *Issuer) IssueRefresh(email string) (string, error) { return i.sign(email, "refresh", i.refreshTTL) }

func (i *Issuer) verify(token, wantTyp string) (string, error) {
	c := &claims{}
	_, err := jwt.ParseWithClaims(token, c, func(t *jwt.Token) (any, error) {
		return i.secret, nil
	},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(i.issuer),
		jwt.WithAudience(i.audience),
		jwt.WithExpirationRequired(),
	)
	if err != nil || c.Typ != wantTyp || c.Email == "" {
		return "", ErrInvalidToken
	}
	return c.Email, nil
}

func (i *Issuer) VerifyAccess(token string) (string, error)  { return i.verify(token, "access") }
func (i *Issuer) VerifyRefresh(token string) (string, error) { return i.verify(token, "refresh") }
