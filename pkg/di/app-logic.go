// Package di wires the application's dependencies together. AppInterface is the
// central accessor the HTTP layer and middleware use to reach services without
// depending on construction details.
package di

import (
	"context"

	"github.com/redis/go-redis/v9"
	"github.com/kharchibook/auth-service/config"
	"github.com/kharchibook/auth-service/pkg/domain/service"
	"gorm.io/gorm"
)

// AppInterface exposes the services and resources needed across the HTTP layer.
type AppInterface interface {
	Config() *config.Config
	AuthService() service.IAuthService
	TokenService() service.ITokenService
	RBACService() service.IRBACService
	AccountService() service.IAccountService
	// DB and Cache are exposed for health checks and graceful shutdown.
	DB() *gorm.DB
	Cache() *redis.Client
	// Close releases held resources (DB pool, Redis client).
	Close() error
	// HealthCheck pings both datastores; used by the readiness endpoint.
	HealthCheck(ctx context.Context) error
}

// app is the concrete AppInterface implementation produced by the DI container.
type app struct {
	cfg *config.Config

	authSvc    service.IAuthService
	tokenSvc   service.ITokenService
	rbacSvc    service.IRBACService
	accountSvc service.IAccountService

	db  *gorm.DB
	rdb *redis.Client
}

func (a *app) Config() *config.Config                  { return a.cfg }
func (a *app) AuthService() service.IAuthService       { return a.authSvc }
func (a *app) TokenService() service.ITokenService     { return a.tokenSvc }
func (a *app) RBACService() service.IRBACService       { return a.rbacSvc }
func (a *app) AccountService() service.IAccountService { return a.accountSvc }
func (a *app) DB() *gorm.DB                            { return a.db }
func (a *app) Cache() *redis.Client                    { return a.rdb }

func (a *app) Close() error {
	if a.rdb != nil {
		_ = a.rdb.Close()
	}
	if a.db != nil {
		if sqlDB, err := a.db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	}
	return nil
}

// ensure compile-time conformance.
var _ AppInterface = (*app)(nil)

// HealthCheck pings both datastores; used by the readiness endpoint.
func (a *app) HealthCheck(ctx context.Context) error {
	if err := a.rdb.Ping(ctx).Err(); err != nil {
		return err
	}
	sqlDB, err := a.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.PingContext(ctx)
}
