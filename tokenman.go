package tokenman

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var (
	// ErrInvalidAccessToken is an error that can be returned when verifying a token.
	ErrInvalidAccessToken = errors.New("invalid access token")

	// ErrExpiredAccessToken is an error that can be returned when verifying a token.
	ErrExpiredAccessToken = errors.New("expired access token")

	// ErrTokenCreationFailed  is an error that can be returned when creating a token.
	ErrTokenCreationFailed = errors.New("creating authorization token failed")

	// ErrSigningKeyEmpty  is an error that can be returned when creating a token.
	ErrSigningKeyEmpty = errors.New("JWT signing key cannot be empty")

	// ErrorClaimIssuerEmpty  is an error that can be returned when creating a token.
	ErrorClaimIssuerEmpty = errors.New("JWT claim issuer cannot be empty")

	// ErrorClaimAudienceEmpty is an error that can be returned when creating a token.
	ErrorClaimAudienceEmpty = errors.New("JWT claim audience cannot be empty")
)

const (
	claimIdentityKey = "jti"
	claimIssuerKey   = "iss"
	claimExpiresKey  = "exp"
	claimCreatedKey  = "iat"
)

type AccessToken struct {
	Issuer    string    `json:"issuer"`
	Identity  string    `json:"identity"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type TokenMan struct {
	mutex            *sync.RWMutex
	sharedSigningKey []byte
	cache            map[string]AccessToken
	// ClaimIssuer sets Issuer and is stored in each generated token. Cannot be empty
	ClaimIssuer string
	// ClaimAudience sets Audience and is stored in each generated token. Cannot be empty
	ClaimAudience string
}

// NewTokenMan creates a new JWT token manager.
func NewTokenMan(signingKey string) (*TokenMan, error) {
	if len(signingKey) == 0 {
		return nil, ErrSigningKeyEmpty
	}
	return &TokenMan{
		mutex:            new(sync.RWMutex),
		sharedSigningKey: []byte(signingKey),
		cache:            map[string]AccessToken{},
		ClaimIssuer:      "github.com/emicklei/tokenman",
		ClaimAudience:    "authorization,authentication"}, nil
}

// VerifyToken checks the token and returns the AccessToken.
func (m *TokenMan) VerifyToken(tokenString string) (AccessToken, error) {
	t, err := m.getAccessToken(tokenString)
	if err != nil {
		return AccessToken{}, err
	}
	return t, nil
}

// getAccessToken returns a new or valid cached AccessToken
func (m *TokenMan) getAccessToken(tokenString string) (AccessToken, error) {
	m.mutex.RLock()
	accessToken, ok := m.cache[tokenString]
	m.mutex.RUnlock()
	if ok {
		// check expired
		if accessToken.ExpiresAt.Before(time.Now()) {
			// leave it in the cache
			return AccessToken{}, ErrExpiredAccessToken
		}
		return accessToken, nil
	}
	// parse it
	claims := jwt.MapClaims{}
	jwtToken, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.sharedSigningKey, nil
	})
	if err != nil {
		return AccessToken{}, err
	}
	if !jwtToken.Valid {
		return AccessToken{}, ErrInvalidAccessToken
	}
	// we got a valid unseen token; cache and return it
	accessToken = AccessToken{
		Issuer:    claims[claimIssuerKey].(string),
		Identity:  claims[claimIdentityKey].(string),
		IssuedAt:  timeFromSeconds(claims[claimCreatedKey]),
		ExpiresAt: timeFromSeconds(claims[claimExpiresKey])}
	m.mutex.Lock()
	m.cache[tokenString] = accessToken
	m.mutex.Unlock()
	return accessToken, nil
}

// CreateToken returns a new encoded JWT token using the identity
func (m *TokenMan) CreateToken(identity string, hoursTTL int) (string, error) {
	if len(m.ClaimAudience) == 0 {
		return "", ErrorClaimAudienceEmpty
	}
	if len(m.ClaimIssuer) == 0 {
		return "", ErrorClaimIssuerEmpty
	}
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims = jwt.StandardClaims{
		Audience:  m.ClaimAudience,
		ExpiresAt: time.Now().Add(time.Hour * time.Duration(hoursTTL)).Unix(),
		Issuer:    m.ClaimIssuer,
		Id:        identity,
		IssuedAt:  time.Now().Unix(),
	}
	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString(m.sharedSigningKey)
	if err != nil {
		return "", ErrTokenCreationFailed
	}
	return tokenString, nil
}

// timeFromSeconds converts an untyped float into a Time.
func timeFromSeconds(sec interface{}) time.Time {
	if sec == nil {
		return time.Time{}
	}
	return time.Unix(int64(sec.(float64)), 0)
}
