package sqlrepo

import (
	"context"
	"fmt"

	apperrors "github.com/kharchibook/auth-service/errors"
	"github.com/kharchibook/auth-service/pkg/domain/models/dao"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// IGmailCredentialRepository persists per-user Gmail OAuth credentials (stored
// encrypted by the service layer).
type IGmailCredentialRepository interface {
	// Upsert inserts or replaces the row for cred.UserID.
	Upsert(ctx context.Context, cred *dao.GmailCredential) error
	// GetByUserID returns the credential or apperrors.ErrNotFound.
	GetByUserID(ctx context.Context, userID int64) (*dao.GmailCredential, error)
}

type gmailCredentialRepository struct {
	db *gorm.DB
}

// NewGmailCredentialRepository constructs the GORM repository.
func NewGmailCredentialRepository(db *gorm.DB) IGmailCredentialRepository {
	return &gmailCredentialRepository{db: db}
}

func (r *gmailCredentialRepository) Upsert(ctx context.Context, cred *dao.GmailCredential) error {
	// On conflict (same user_id), overwrite the token columns.
	err := r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "user_id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"access_token_enc", "refresh_token_enc", "token_expiry", "scope", "email", "updated_at",
		}),
	}).Create(cred).Error
	if err != nil {
		return fmt.Errorf("upsert gmail credential: %w", err)
	}
	return nil
}

func (r *gmailCredentialRepository) GetByUserID(ctx context.Context, userID int64) (*dao.GmailCredential, error) {
	var cred dao.GmailCredential
	err := r.db.WithContext(ctx).First(&cred, "user_id = ?", userID).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("query gmail credential: %w", err)
	}
	return &cred, nil
}
