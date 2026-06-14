package drivers

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/kharchibook/auth-service/config"
	"github.com/redis/go-redis/v9"
)

// NewRedis opens a go-redis client and verifies connectivity with a PING.
func NewRedis(cfg config.Cache) (*redis.Client, error) {
	opts := &redis.Options{
		Addr:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password: cfg.Password,
		DB:       cfg.DB,
	}
	// Managed Redis (Upstash, Redis Cloud) requires TLS; ServerName is taken from
	// the dialed host for SNI / certificate verification.
	if cfg.TLS {
		opts.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: cfg.Host,
		}
	}

	client := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("ping redis: %w", err)
	}
	return client, nil
}
