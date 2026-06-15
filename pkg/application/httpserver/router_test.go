package httpserver_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/kharchibook/auth-service/config"
	"github.com/kharchibook/auth-service/pkg/application/httpserver"
	"github.com/kharchibook/auth-service/pkg/domain/dto/entity"
	"github.com/kharchibook/auth-service/pkg/domain/dto/request"
	"github.com/kharchibook/auth-service/pkg/domain/dto/response"
	"github.com/kharchibook/auth-service/pkg/domain/models/dao"
	"github.com/kharchibook/auth-service/pkg/domain/service"
	"gorm.io/gorm"
)

// stubAuth returns canned token responses; only Login is exercised here.
type stubAuth struct{ service.IAuthService }

func (stubAuth) Login(context.Context, request.LoginRequest, entity.SessionContext) (entity.IssuedTokens, error) {
	return entity.IssuedTokens{AccessToken: "access", RefreshToken: "refresh", ExpiresIn: 900}, nil
}

type stubAccount struct{ service.IAccountService }

func (stubAccount) GetByID(_ context.Context, id int64) (*dao.User, error) {
	return &dao.User{ID: id, Email: "u@x.com", Verified: true, Provider: "local"}, nil
}

type stubRBAC struct{ service.IRBACService }

func (stubRBAC) GetUserRoles(context.Context, int64) ([]string, error) { return []string{"user"}, nil }

type stubGmail struct{ service.IGmailTokenService }

// fakeApp implements di.AppInterface for HTTP-layer tests (no real datastores).
type fakeApp struct {
	tokens service.ITokenService
}

func (a *fakeApp) Config() *config.Config                  { return &config.Config{} }
func (a *fakeApp) AuthService() service.IAuthService       { return stubAuth{} }
func (a *fakeApp) TokenService() service.ITokenService     { return a.tokens }
func (a *fakeApp) RBACService() service.IRBACService       { return stubRBAC{} }
func (a *fakeApp) AccountService() service.IAccountService { return stubAccount{} }
func (a *fakeApp) GmailTokenService() service.IGmailTokenService { return stubGmail{} }
func (a *fakeApp) DB() *gorm.DB                            { return nil }
func (a *fakeApp) Cache() *redis.Client                    { return nil }
func (a *fakeApp) Close() error                            { return nil }
func (a *fakeApp) HealthCheck(context.Context) error       { return nil }

func newTestServer(t *testing.T) (*httptest.Server, service.ITokenService) {
	t.Helper()
	tok, err := service.NewTokenService(config.Token{Issuer: "auth-service", AccessTokenTTL: 15 * time.Minute, RefreshTokenTTL: time.Hour})
	if err != nil {
		t.Fatalf("token service: %v", err)
	}
	srv := httptest.NewServer(httpserver.NewRouter(&fakeApp{tokens: tok}))
	t.Cleanup(srv.Close)
	return srv, tok
}

func TestLoginRoute(t *testing.T) {
	srv, _ := newTestServer(t)

	// Invalid body → 400 validation error.
	resp, err := http.Post(srv.URL+"/v1/public/auth/login", "application/json", strings.NewReader(`{"email":"bad"}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid body, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Valid body → 200 token pair.
	resp, err = http.Post(srv.URL+"/v1/public/auth/login", "application/json",
		strings.NewReader(`{"email":"u@x.com","password":"whatever"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var tp response.TokenPairResponse
	decode(t, resp, &tp)
	if tp.AccessToken != "access" || tp.TokenType != "Bearer" {
		t.Fatalf("unexpected token pair: %+v", tp)
	}
}

func TestMeRouteGuard(t *testing.T) {
	srv, tok := newTestServer(t)

	// No token → 401.
	resp, err := http.Get(srv.URL + "/v1/public/auth/me")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Valid token → 200.
	access, _, err := tok.GenerateAccessToken(entity.TokenClaims{UserID: 42, SessionID: 1, Roles: []string{"user"}, Verified: true})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/public/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with valid token, got %d", resp.StatusCode)
	}
}

func decode(t *testing.T, resp *http.Response, dst any) {
	t.Helper()
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		t.Fatalf("decode: %v", err)
	}
}
