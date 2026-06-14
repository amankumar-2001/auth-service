// Package sqlrepo holds GORM-backed PostgreSQL repositories. Each repository is
// defined as an interface (for DI and testability) plus a concrete impl.
package sqlrepo

import (
	"context"
	"errors"
	"fmt"
	"time"

	apperrors "github.com/kharchibook/auth-service/errors"
	"github.com/kharchibook/auth-service/pkg/domain/models/dao"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// IUserRepository is the persistence contract for user identity records.
type IUserRepository interface {
	Create(ctx context.Context, u *dao.User) error
	GetByEmail(ctx context.Context, email string) (*dao.User, error)
	GetByID(ctx context.Context, id int64) (*dao.User, error)
	GetByProviderUID(ctx context.Context, provider, uid string) (*dao.User, error)
	Update(ctx context.Context, u *dao.User) error
	SetVerified(ctx context.Context, id int64, verified bool) error
	RecordLoginSuccess(ctx context.Context, id int64, at time.Time) error
	IncrementFailedAttempts(ctx context.Context, id int64) (int, error)
	LockAccount(ctx context.Context, id int64, until time.Time) error
	UpdatePassword(ctx context.Context, id int64, passwordHash string) error
}

type userRepository struct {
	db *gorm.DB
}

// NewUserRepository constructs the GORM user repository.
func NewUserRepository(db *gorm.DB) IUserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) Create(ctx context.Context, u *dao.User) error {
	if err := r.db.WithContext(ctx).Create(u).Error; err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

func (r *userRepository) GetByEmail(ctx context.Context, email string) (*dao.User, error) {
	var u dao.User
	err := r.db.WithContext(ctx).Preload("Roles").Where("email = ?", email).First(&u).Error
	return mapUser(&u, err)
}

func (r *userRepository) GetByID(ctx context.Context, id int64) (*dao.User, error) {
	var u dao.User
	err := r.db.WithContext(ctx).Preload("Roles").First(&u, id).Error
	return mapUser(&u, err)
}

func (r *userRepository) GetByProviderUID(ctx context.Context, provider, uid string) (*dao.User, error) {
	var u dao.User
	err := r.db.WithContext(ctx).Preload("Roles").
		Where("provider = ? AND provider_uid = ?", provider, uid).First(&u).Error
	return mapUser(&u, err)
}

func (r *userRepository) Update(ctx context.Context, u *dao.User) error {
	if err := r.db.WithContext(ctx).Save(u).Error; err != nil {
		return fmt.Errorf("update user: %w", err)
	}
	return nil
}

func (r *userRepository) SetVerified(ctx context.Context, id int64, verified bool) error {
	return r.updateColumns(ctx, id, map[string]any{"verified": verified})
}

func (r *userRepository) RecordLoginSuccess(ctx context.Context, id int64, at time.Time) error {
	// Successful login clears the failed-attempt counter and any lock.
	return r.updateColumns(ctx, id, map[string]any{
		"last_login":      at,
		"failed_attempts": 0,
		"locked_until":    nil,
	})
}

// IncrementFailedAttempts atomically bumps the counter and returns the new value,
// so the caller can decide whether the lock threshold is reached.
func (r *userRepository) IncrementFailedAttempts(ctx context.Context, id int64) (int, error) {
	if err := r.db.WithContext(ctx).Model(&dao.User{}).Where("id = ?", id).
		UpdateColumn("failed_attempts", gorm.Expr("failed_attempts + 1")).Error; err != nil {
		return 0, fmt.Errorf("increment failed attempts: %w", err)
	}
	var u dao.User
	if err := r.db.WithContext(ctx).Select("failed_attempts").First(&u, id).Error; err != nil {
		return 0, fmt.Errorf("read failed attempts: %w", err)
	}
	return u.FailedAttempts, nil
}

func (r *userRepository) LockAccount(ctx context.Context, id int64, until time.Time) error {
	return r.updateColumns(ctx, id, map[string]any{"locked_until": until})
}

func (r *userRepository) UpdatePassword(ctx context.Context, id int64, passwordHash string) error {
	return r.updateColumns(ctx, id, map[string]any{"password_hash": passwordHash})
}

func (r *userRepository) updateColumns(ctx context.Context, id int64, cols map[string]any) error {
	res := r.db.WithContext(ctx).Model(&dao.User{}).Where("id = ?", id).Updates(cols)
	if res.Error != nil {
		return fmt.Errorf("update user columns: %w", res.Error)
	}
	return nil
}

// mapUser translates GORM's not-found error into the domain sentinel.
func mapUser(u *dao.User, err error) (*dao.User, error) {
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("query user: %w", err)
	}
	return u, nil
}

// AssignRoleTx assigns a role to a user within an existing transaction, used by
// the account service during signup. Exposed as a helper to keep the join-table
// write idempotent.
func AssignRoleTx(ctx context.Context, tx *gorm.DB, userID, roleID int64) error {
	ur := dao.UserRole{UserID: userID, RoleID: roleID}
	err := tx.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&ur).Error
	if err != nil {
		return fmt.Errorf("assign role: %w", err)
	}
	return nil
}
