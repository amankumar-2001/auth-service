package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kharchibook/auth-service/config"
	apperrors "github.com/kharchibook/auth-service/errors"
	"github.com/kharchibook/auth-service/pkg/domain/dto/entity"
	"github.com/kharchibook/auth-service/third_party/platlogger"
	"github.com/kharchibook/auth-service/utils"
)

// ITokenService mints and verifies access JWTs (RS256) and generates opaque
// refresh tokens. The RSA private key never leaves this service; the public key
// is exported (PublicKeyPEM) so a Gateway can verify tokens locally.
type ITokenService interface {
	// GenerateAccessToken signs an RS256 JWT carrying the claims. Returns the
	// token and its lifetime in seconds.
	GenerateAccessToken(claims entity.TokenClaims) (token string, expiresIn int64, err error)
	// ParseAccessToken verifies the signature + expiry and returns the claims.
	ParseAccessToken(token string) (*entity.TokenClaims, error)
	// GenerateRefreshToken returns a high-entropy opaque refresh token (raw).
	GenerateRefreshToken() (string, error)
	// AccessTTL is the configured access-token lifetime.
	AccessTTL() time.Duration
	// RefreshTTL is the configured refresh-token lifetime.
	RefreshTTL() time.Duration
	// PublicKeyPEM returns the PEM-encoded public key for external verification.
	PublicKeyPEM() string
}

// authClaims is the JWT payload (PRD §6 suggested shape).
type authClaims struct {
	Roles    []string `json:"roles"`
	Verified bool     `json:"verified"`
	SID      string   `json:"sid"`
	jwt.RegisteredClaims
}

type tokenService struct {
	cfg        config.Token
	privateKey *rsa.PrivateKey
	publicPEM  string
}

// NewTokenService loads the RSA key pair from configured PEM (path or inline) or,
// for local dev, generates an ephemeral key pair (logged with a warning).
func NewTokenService(cfg config.Token) (ITokenService, error) {
	priv, err := loadOrGenerateKey(cfg)
	if err != nil {
		return nil, err
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	return &tokenService{cfg: cfg, privateKey: priv, publicPEM: string(pubPEM)}, nil
}

func loadOrGenerateKey(cfg config.Token) (*rsa.PrivateKey, error) {
	var pemBytes []byte
	switch {
	case cfg.PrivateKeyPEM != "":
		pemBytes = []byte(cfg.PrivateKeyPEM)
	case cfg.PrivateKeyPath != "":
		b, err := os.ReadFile(cfg.PrivateKeyPath)
		if err == nil {
			pemBytes = b
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("read private key: %w", err)
		}
	}

	if len(pemBytes) > 0 {
		key, err := jwt.ParseRSAPrivateKeyFromPEM(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		return key, nil
	}

	// No key configured/found → generate an ephemeral one for local dev. Tokens
	// won't survive a restart; configure a persistent key for any shared env.
	platlogger.Warn("no JWT signing key configured; generating ephemeral RSA key (dev only)")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}
	return key, nil
}

func (s *tokenService) GenerateAccessToken(claims entity.TokenClaims) (string, int64, error) {
	now := time.Now().UTC()
	exp := now.Add(s.cfg.AccessTokenTTL)
	c := authClaims{
		Roles:    claims.Roles,
		Verified: claims.Verified,
		SID:      strconv.FormatInt(claims.SessionID, 10),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strconv.FormatInt(claims.UserID, 10),
			Issuer:    s.cfg.Issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	signed, err := tok.SignedString(s.privateKey)
	if err != nil {
		return "", 0, fmt.Errorf("sign token: %w", err)
	}
	return signed, int64(s.cfg.AccessTokenTTL.Seconds()), nil
}

func (s *tokenService) ParseAccessToken(token string) (*entity.TokenClaims, error) {
	var c authClaims
	parsed, err := jwt.ParseWithClaims(token, &c, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return &s.privateKey.PublicKey, nil
	}, jwt.WithIssuer(s.cfg.Issuer))
	if err != nil || !parsed.Valid {
		return nil, apperrors.UnauthorizedError("invalid or expired token")
	}

	userID, _ := strconv.ParseInt(c.Subject, 10, 64)
	sid, _ := strconv.ParseInt(c.SID, 10, 64)
	out := &entity.TokenClaims{
		UserID:    userID,
		SessionID: sid,
		Roles:     c.Roles,
		Verified:  c.Verified,
	}
	if c.IssuedAt != nil {
		out.IssuedAt = c.IssuedAt.Time
	}
	if c.ExpiresAt != nil {
		out.ExpiresAt = c.ExpiresAt.Time
	}
	return out, nil
}

func (s *tokenService) GenerateRefreshToken() (string, error) {
	// 32 bytes ≈ 256 bits of entropy — safe to store only as a SHA-256 hash.
	return utils.RandomToken(32)
}

func (s *tokenService) AccessTTL() time.Duration  { return s.cfg.AccessTokenTTL }
func (s *tokenService) RefreshTTL() time.Duration { return s.cfg.RefreshTokenTTL }
func (s *tokenService) PublicKeyPEM() string      { return s.publicPEM }
