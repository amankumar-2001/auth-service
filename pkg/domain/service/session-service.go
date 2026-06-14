package service

import (
	"context"
	"errors"
	"time"

	apperrors "github.com/kharchibook/auth-service/errors"
	"github.com/kharchibook/auth-service/pkg/domain/dto/entity"
	"github.com/kharchibook/auth-service/pkg/domain/models/dao"
	"github.com/kharchibook/auth-service/pkg/infrastructure/sqlrepo"
	"github.com/kharchibook/auth-service/utils"
)

// ErrRefreshInvalid signals an unknown/expired refresh token.
var ErrRefreshInvalid = errors.New("invalid refresh token")

// ErrRefreshReuse signals replay of an already-rotated (revoked) refresh token —
// a theft indicator. The caller must revoke the whole session family (already
// done here) and surface a 401.
var ErrRefreshReuse = errors.New("refresh token reuse detected")

// RotateResult is returned when a refresh token is successfully rotated.
type RotateResult struct {
	SessionID       int64
	UserID          int64
	RawRefreshToken string
}

// ISessionService manages the refresh-token lifecycle with rotation and theft
// detection. The raw refresh token exists only transiently; only its hash is
// persisted.
type ISessionService interface {
	// Create starts a new session and returns its id plus the raw refresh token
	// (shown to the client once).
	Create(ctx context.Context, userID int64, sc entity.SessionContext) (sessionID int64, rawRefresh string, err error)
	// Rotate validates the presented refresh token and, on success, issues a new
	// one (revoking the old row so replay is detectable).
	Rotate(ctx context.Context, rawRefresh string) (RotateResult, error)
	// RevokeByToken revokes the session a refresh token belongs to (logout).
	RevokeByToken(ctx context.Context, rawRefresh string) (userID int64, err error)
	// RevokeAll revokes every active session for a user (logout-all, reset).
	RevokeAll(ctx context.Context, userID int64) error
}

type sessionService struct {
	repo   sqlrepo.ISessionRepository
	tokens ITokenService
}

// NewSessionService constructs the session service.
func NewSessionService(repo sqlrepo.ISessionRepository, tokens ITokenService) ISessionService {
	return &sessionService{repo: repo, tokens: tokens}
}

func (s *sessionService) Create(ctx context.Context, userID int64, sc entity.SessionContext) (int64, string, error) {
	raw, err := s.tokens.GenerateRefreshToken()
	if err != nil {
		return 0, "", apperrors.InternalServerError(err)
	}
	now := time.Now().UTC()
	sess := &dao.Session{
		UserID:           userID,
		RefreshTokenHash: utils.HashToken(raw),
		DeviceID:         sc.DeviceID,
		IPAddress:        sc.IPAddress,
		UserAgent:        sc.UserAgent,
		ExpiresAt:        now.Add(s.tokens.RefreshTTL()),
		LastUsedAt:       now,
	}
	if err := s.repo.Create(ctx, sess); err != nil {
		return 0, "", apperrors.InternalServerError(err)
	}
	return sess.ID, raw, nil
}

func (s *sessionService) Rotate(ctx context.Context, rawRefresh string) (RotateResult, error) {
	sess, err := s.repo.GetByRefreshHash(ctx, utils.HashToken(rawRefresh))
	if err != nil {
		if apperrors.Is(err, apperrors.ErrNotFound) {
			return RotateResult{}, ErrRefreshInvalid
		}
		return RotateResult{}, apperrors.InternalServerError(err)
	}

	// Replay of a revoked (already-rotated) token → theft. Revoke the family.
	if sess.IsRevoked {
		_, _ = s.repo.RevokeAllForUser(ctx, sess.UserID)
		return RotateResult{}, ErrRefreshReuse
	}

	if time.Now().UTC().After(sess.ExpiresAt) {
		_ = s.repo.Revoke(ctx, sess.ID)
		return RotateResult{}, ErrRefreshInvalid
	}

	// Issue a fresh session row and revoke the old one. Keeping the old row (with
	// its hash) is what makes a future replay detectable above.
	newID, newRaw, err := s.Create(ctx, sess.UserID, entity.SessionContext{
		DeviceID:  sess.DeviceID,
		IPAddress: sess.IPAddress,
		UserAgent: sess.UserAgent,
	})
	if err != nil {
		return RotateResult{}, err
	}
	if err := s.repo.Revoke(ctx, sess.ID); err != nil {
		return RotateResult{}, apperrors.InternalServerError(err)
	}

	return RotateResult{SessionID: newID, UserID: sess.UserID, RawRefreshToken: newRaw}, nil
}

func (s *sessionService) RevokeByToken(ctx context.Context, rawRefresh string) (int64, error) {
	sess, err := s.repo.GetByRefreshHash(ctx, utils.HashToken(rawRefresh))
	if err != nil {
		if apperrors.Is(err, apperrors.ErrNotFound) {
			return 0, ErrRefreshInvalid
		}
		return 0, apperrors.InternalServerError(err)
	}
	if err := s.repo.Revoke(ctx, sess.ID); err != nil {
		return 0, apperrors.InternalServerError(err)
	}
	return sess.UserID, nil
}

func (s *sessionService) RevokeAll(ctx context.Context, userID int64) error {
	if _, err := s.repo.RevokeAllForUser(ctx, userID); err != nil {
		return apperrors.InternalServerError(err)
	}
	return nil
}
