package cacherepo

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	apperrors "github.com/kharchibook/auth-service/errors"
)

// IResetTokenRepository stores single-use, hashed password-reset tokens keyed by
// user ID, with a short TTL.
type IResetTokenRepository interface {
	Store(ctx context.Context, userID int64, hashedToken string, ttl time.Duration) error
	Get(ctx context.Context, userID int64) (string, error)
	Delete(ctx context.Context, userID int64) error
}

type resetTokenRepository struct {
	rdb *redis.Client
}

// NewResetTokenRepository constructs the Redis reset-token repository.
func NewResetTokenRepository(rdb *redis.Client) IResetTokenRepository {
	return &resetTokenRepository{rdb: rdb}
}

func resetKey(userID int64) string { return "reset:" + strconv.FormatInt(userID, 10) }

func (r *resetTokenRepository) Store(ctx context.Context, userID int64, hashedToken string, ttl time.Duration) error {
	if err := r.rdb.Set(ctx, resetKey(userID), hashedToken, ttl).Err(); err != nil {
		return fmt.Errorf("store reset token: %w", err)
	}
	return nil
}

func (r *resetTokenRepository) Get(ctx context.Context, userID int64) (string, error) {
	v, err := r.rdb.Get(ctx, resetKey(userID)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", apperrors.ErrNotFound
		}
		return "", fmt.Errorf("get reset token: %w", err)
	}
	return v, nil
}

func (r *resetTokenRepository) Delete(ctx context.Context, userID int64) error {
	if err := r.rdb.Del(ctx, resetKey(userID)).Err(); err != nil {
		return fmt.Errorf("delete reset token: %w", err)
	}
	return nil
}
