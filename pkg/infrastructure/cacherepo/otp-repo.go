// Package cacherepo holds Redis-backed ephemeral stores: OTPs, password-reset
// tokens, and rate-limit counters. Everything here has a TTL and auto-expires.
package cacherepo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	apperrors "github.com/kharchibook/auth-service/errors"
)

// IOTPRepository stores hashed OTPs with a TTL and tracks failed attempts.
type IOTPRepository interface {
	// Store saves the hashed OTP under the email key with the given TTL,
	// overwriting any previous value.
	Store(ctx context.Context, email, hashedOTP string, ttl time.Duration) error
	// Get returns the stored hashed OTP, or ErrNotFound if absent/expired.
	Get(ctx context.Context, email string) (string, error)
	// Delete removes the OTP key (called on successful verification).
	Delete(ctx context.Context, email string) error
	// IncrAttempts increments the wrong-attempt counter within a window and
	// returns the new count.
	IncrAttempts(ctx context.Context, email string, window time.Duration) (int, error)
	// ClearAttempts resets the wrong-attempt counter.
	ClearAttempts(ctx context.Context, email string) error
	// SetResendCooldown sets a short cooldown key; CooldownActive checks it.
	SetResendCooldown(ctx context.Context, email string, cooldown time.Duration) error
	CooldownActive(ctx context.Context, email string) (bool, error)
}

type otpRepository struct {
	rdb *redis.Client
}

// NewOTPRepository constructs the Redis OTP repository.
func NewOTPRepository(rdb *redis.Client) IOTPRepository {
	return &otpRepository{rdb: rdb}
}

func otpKey(email string) string      { return "otp:email:" + email }
func otpFailKey(email string) string  { return "otp:fail:email:" + email }
func cooldownKey(email string) string { return "otp:cooldown:email:" + email }

func (r *otpRepository) Store(ctx context.Context, email, hashedOTP string, ttl time.Duration) error {
	if err := r.rdb.Set(ctx, otpKey(email), hashedOTP, ttl).Err(); err != nil {
		return fmt.Errorf("store otp: %w", err)
	}
	return nil
}

func (r *otpRepository) Get(ctx context.Context, email string) (string, error) {
	v, err := r.rdb.Get(ctx, otpKey(email)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", apperrors.ErrNotFound
		}
		return "", fmt.Errorf("get otp: %w", err)
	}
	return v, nil
}

func (r *otpRepository) Delete(ctx context.Context, email string) error {
	if err := r.rdb.Del(ctx, otpKey(email)).Err(); err != nil {
		return fmt.Errorf("delete otp: %w", err)
	}
	return nil
}

func (r *otpRepository) IncrAttempts(ctx context.Context, email string, window time.Duration) (int, error) {
	key := otpFailKey(email)
	pipe := r.rdb.TxPipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, window) // refreshes window; acceptable for abuse counters
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, fmt.Errorf("incr otp attempts: %w", err)
	}
	return int(incr.Val()), nil
}

func (r *otpRepository) ClearAttempts(ctx context.Context, email string) error {
	if err := r.rdb.Del(ctx, otpFailKey(email)).Err(); err != nil {
		return fmt.Errorf("clear otp attempts: %w", err)
	}
	return nil
}

func (r *otpRepository) SetResendCooldown(ctx context.Context, email string, cooldown time.Duration) error {
	if err := r.rdb.Set(ctx, cooldownKey(email), "1", cooldown).Err(); err != nil {
		return fmt.Errorf("set otp cooldown: %w", err)
	}
	return nil
}

func (r *otpRepository) CooldownActive(ctx context.Context, email string) (bool, error) {
	n, err := r.rdb.Exists(ctx, cooldownKey(email)).Result()
	if err != nil {
		return false, fmt.Errorf("check otp cooldown: %w", err)
	}
	return n > 0, nil
}
