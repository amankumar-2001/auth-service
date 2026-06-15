package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	apperrors "github.com/kharchibook/auth-service/errors"
	"github.com/kharchibook/auth-service/pkg/domain/models/dao"
	"github.com/kharchibook/auth-service/pkg/infrastructure/kms"
	"github.com/kharchibook/auth-service/pkg/infrastructure/sqlrepo"
	httptransport "github.com/kharchibook/auth-service/pkg/infrastructure/transport/http"
)

// accessTokenSkew refreshes a little before actual expiry so a token handed to a
// caller stays valid for the duration of its request.
const accessTokenSkew = 2 * time.Minute

// IGmailTokenService manages a user's Gmail OAuth lifecycle: building the consent
// URL (with a tamper-proof state binding the user), storing the tokens returned
// by the callback (encrypted), and vending a currently-valid access token to
// trusted internal callers (mcp-gateway). The client secret and refresh token
// never leave this service.
type IGmailTokenService interface {
	Enabled() bool
	// ConnectURL builds the Google consent URL, binding userID into a signed state.
	ConnectURL(userID int64) (string, error)
	// HandleCallback verifies state, exchanges the code, and stores the tokens.
	// Returns the userID the connection was bound to.
	HandleCallback(ctx context.Context, code, state string) (int64, error)
	// AccessToken returns a valid access token for userID, refreshing + persisting
	// if the stored one has expired.
	AccessToken(ctx context.Context, userID int64) (token string, expiry time.Time, err error)
	// Status reports whether the user has Gmail connected (a stored credential).
	Status(ctx context.Context, userID int64) (connected bool, scope string, err error)
}

type gmailTokenService struct {
	client      httptransport.IGmailOAuthClient
	repo        sqlrepo.IGmailCredentialRepository
	enc         kms.IKMSEncryptor
	stateSecret []byte
}

// NewGmailTokenService constructs the service. stateSecret signs the OAuth state
// parameter (HMAC) so a user cannot connect Gmail to another user's account.
func NewGmailTokenService(
	client httptransport.IGmailOAuthClient,
	repo sqlrepo.IGmailCredentialRepository,
	enc kms.IKMSEncryptor,
	stateSecret string,
) IGmailTokenService {
	if stateSecret == "" {
		stateSecret = "auth-service-local-dev-gmail-state-secret"
	}
	return &gmailTokenService{client: client, repo: repo, enc: enc, stateSecret: []byte(stateSecret)}
}

func (s *gmailTokenService) Enabled() bool { return s.client.Enabled() }

func (s *gmailTokenService) ConnectURL(userID int64) (string, error) {
	if !s.Enabled() {
		return "", apperrors.BadRequestError("gmail connect is not configured")
	}
	return s.client.AuthCodeURL(s.signState(userID)), nil
}

func (s *gmailTokenService) HandleCallback(ctx context.Context, code, state string) (int64, error) {
	userID, err := s.verifyState(state)
	if err != nil {
		return 0, apperrors.BadRequestError("invalid oauth state")
	}

	tok, err := s.client.Exchange(ctx, code)
	if err != nil {
		return 0, apperrors.InternalServerError(err)
	}

	accessEnc, err := s.enc.Encrypt([]byte(tok.AccessToken))
	if err != nil {
		return 0, apperrors.InternalServerError(err)
	}
	refreshEnc, err := s.enc.Encrypt([]byte(tok.RefreshToken))
	if err != nil {
		return 0, apperrors.InternalServerError(err)
	}

	scope, _ := tok.Extra("scope").(string)
	if err := s.repo.Upsert(ctx, &dao.GmailCredential{
		UserID:          userID,
		AccessTokenEnc:  accessEnc,
		RefreshTokenEnc: refreshEnc,
		TokenExpiry:     tok.Expiry,
		Scope:           scope,
	}); err != nil {
		return 0, apperrors.InternalServerError(err)
	}
	return userID, nil
}

func (s *gmailTokenService) AccessToken(ctx context.Context, userID int64) (string, time.Time, error) {
	cred, err := s.repo.GetByUserID(ctx, userID)
	if err != nil {
		if apperrors.Is(err, apperrors.ErrNotFound) {
			return "", time.Time{}, apperrors.NotFoundError("gmail not connected for this user")
		}
		return "", time.Time{}, apperrors.InternalServerError(err)
	}

	// Still valid (with skew)? Decrypt and return the stored access token.
	if time.Now().Add(accessTokenSkew).Before(cred.TokenExpiry) {
		access, err := s.enc.Decrypt(cred.AccessTokenEnc)
		if err != nil {
			return "", time.Time{}, apperrors.InternalServerError(err)
		}
		return string(access), cred.TokenExpiry, nil
	}

	// Expired (or about to): refresh using the stored refresh token, then persist.
	refresh, err := s.enc.Decrypt(cred.RefreshTokenEnc)
	if err != nil {
		return "", time.Time{}, apperrors.InternalServerError(err)
	}
	tok, err := s.client.TokenFromRefresh(ctx, string(refresh))
	if err != nil {
		return "", time.Time{}, apperrors.InternalServerError(err)
	}

	accessEnc, err := s.enc.Encrypt([]byte(tok.AccessToken))
	if err != nil {
		return "", time.Time{}, apperrors.InternalServerError(err)
	}
	cred.AccessTokenEnc = accessEnc
	cred.TokenExpiry = tok.Expiry
	// Google usually keeps the same refresh token; if it rotated, persist the new.
	if tok.RefreshToken != "" && tok.RefreshToken != string(refresh) {
		if refreshEnc, e := s.enc.Encrypt([]byte(tok.RefreshToken)); e == nil {
			cred.RefreshTokenEnc = refreshEnc
		}
	}
	if err := s.repo.Upsert(ctx, cred); err != nil {
		return "", time.Time{}, apperrors.InternalServerError(err)
	}
	return tok.AccessToken, tok.Expiry, nil
}

func (s *gmailTokenService) Status(ctx context.Context, userID int64) (bool, string, error) {
	cred, err := s.repo.GetByUserID(ctx, userID)
	if err != nil {
		if apperrors.Is(err, apperrors.ErrNotFound) {
			return false, "", nil
		}
		return false, "", apperrors.InternalServerError(err)
	}
	return true, cred.Scope, nil
}

// --- signed state (HMAC) -------------------------------------------------------

// signState encodes "<userID>.<unixTime>.<hmac>" base64-url. The HMAC binds the
// userID so the callback can trust it without a server-side state store.
func (s *gmailTokenService) signState(userID int64) string {
	payload := fmt.Sprintf("%d.%d", userID, time.Now().Unix())
	mac := s.mac(payload)
	return base64.RawURLEncoding.EncodeToString([]byte(payload + "." + mac))
}

func (s *gmailTokenService) verifyState(state string) (int64, error) {
	raw, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		return 0, fmt.Errorf("decode state: %w", err)
	}
	parts := strings.Split(string(raw), ".")
	if len(parts) != 3 {
		return 0, fmt.Errorf("malformed state")
	}
	payload := parts[0] + "." + parts[1]
	if !hmac.Equal([]byte(s.mac(payload)), []byte(parts[2])) {
		return 0, fmt.Errorf("bad state signature")
	}
	// Reject stale states (consent older than 15m).
	if ts, err := strconv.ParseInt(parts[1], 10, 64); err != nil || time.Since(time.Unix(ts, 0)) > 15*time.Minute {
		return 0, fmt.Errorf("expired state")
	}
	userID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("bad user id in state")
	}
	return userID, nil
}

func (s *gmailTokenService) mac(payload string) string {
	h := hmac.New(sha256.New, s.stateSecret)
	h.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
