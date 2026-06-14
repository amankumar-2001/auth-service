package sqlrepo

import (
	"context"
	"errors"
	"fmt"
	"time"

	apperrors "github.com/kharchibook/auth-service/errors"
	"github.com/kharchibook/auth-service/pkg/domain/models/dao"
	"gorm.io/gorm"
)

// ISessionRepository is the persistence contract for login sessions and the
// refresh-token lifecycle.
type ISessionRepository interface {
	Create(ctx context.Context, s *dao.Session) error
	GetByRefreshHash(ctx context.Context, hash string) (*dao.Session, error)
	GetByID(ctx context.Context, id int64) (*dao.Session, error)
	Rotate(ctx context.Context, sessionID int64, newHash string, expiresAt time.Time) error
	Revoke(ctx context.Context, sessionID int64) error
	RevokeAllForUser(ctx context.Context, userID int64) (int64, error)
}

type sessionRepository struct {
	db *gorm.DB
}

// NewSessionRepository constructs the GORM session repository.
func NewSessionRepository(db *gorm.DB) ISessionRepository {
	return &sessionRepository{db: db}
}

func (r *sessionRepository) Create(ctx context.Context, s *dao.Session) error {
	if err := r.db.WithContext(ctx).Create(s).Error; err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

func (r *sessionRepository) GetByRefreshHash(ctx context.Context, hash string) (*dao.Session, error) {
	var s dao.Session
	err := r.db.WithContext(ctx).Where("refresh_token_hash = ?", hash).First(&s).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("query session: %w", err)
	}
	return &s, nil
}

func (r *sessionRepository) GetByID(ctx context.Context, id int64) (*dao.Session, error) {
	var s dao.Session
	err := r.db.WithContext(ctx).First(&s, id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("query session: %w", err)
	}
	return &s, nil
}

// Rotate replaces the refresh-token hash and extends expiry, stamping last_used.
func (r *sessionRepository) Rotate(ctx context.Context, sessionID int64, newHash string, expiresAt time.Time) error {
	res := r.db.WithContext(ctx).Model(&dao.Session{}).Where("id = ?", sessionID).Updates(map[string]any{
		"refresh_token_hash": newHash,
		"expires_at":         expiresAt,
		"last_used_at":       time.Now().UTC(),
	})
	if res.Error != nil {
		return fmt.Errorf("rotate session: %w", res.Error)
	}
	return nil
}

func (r *sessionRepository) Revoke(ctx context.Context, sessionID int64) error {
	res := r.db.WithContext(ctx).Model(&dao.Session{}).Where("id = ?", sessionID).
		Update("is_revoked", true)
	if res.Error != nil {
		return fmt.Errorf("revoke session: %w", res.Error)
	}
	return nil
}

// RevokeAllForUser revokes every active session for a user (logout-all, password
// reset, theft response) and returns how many rows were revoked.
func (r *sessionRepository) RevokeAllForUser(ctx context.Context, userID int64) (int64, error) {
	res := r.db.WithContext(ctx).Model(&dao.Session{}).
		Where("user_id = ? AND is_revoked = ?", userID, false).
		Update("is_revoked", true)
	if res.Error != nil {
		return 0, fmt.Errorf("revoke all sessions: %w", res.Error)
	}
	return res.RowsAffected, nil
}
