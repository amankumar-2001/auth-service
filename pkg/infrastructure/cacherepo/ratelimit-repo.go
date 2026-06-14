package cacherepo

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// IRateLimitRepository implements a fixed-window counter keyed by an arbitrary
// string (e.g. "login:<ip>", "reset:<email>").
type IRateLimitRepository interface {
	// Incr increments the counter for key and returns the new count. On the
	// first hit in a window it sets the TTL.
	Incr(ctx context.Context, key string, window time.Duration) (int, error)
	// Reset clears the counter (e.g. after a successful login).
	Reset(ctx context.Context, key string) error
}

type rateLimitRepository struct {
	rdb *redis.Client
}

// NewRateLimitRepository constructs the Redis rate-limit repository.
func NewRateLimitRepository(rdb *redis.Client) IRateLimitRepository {
	return &rateLimitRepository{rdb: rdb}
}

func rlKey(key string) string { return "ratelimit:" + key }

func (r *rateLimitRepository) Incr(ctx context.Context, key string, window time.Duration) (int, error) {
	full := rlKey(key)
	n, err := r.rdb.Incr(ctx, full).Result()
	if err != nil {
		return 0, fmt.Errorf("incr rate limit: %w", err)
	}
	// Only the first increment in the window establishes the expiry, so the
	// window is fixed (doesn't slide on every hit).
	if n == 1 {
		if err := r.rdb.Expire(ctx, full, window).Err(); err != nil {
			return 0, fmt.Errorf("set rate-limit ttl: %w", err)
		}
	}
	return int(n), nil
}

func (r *rateLimitRepository) Reset(ctx context.Context, key string) error {
	if err := r.rdb.Del(ctx, rlKey(key)).Err(); err != nil {
		return fmt.Errorf("reset rate limit: %w", err)
	}
	return nil
}
