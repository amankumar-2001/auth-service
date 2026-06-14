package service

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/kharchibook/auth-service/config"
	apperrors "github.com/kharchibook/auth-service/errors"
	"github.com/kharchibook/auth-service/pkg/domain/dto/entity"
	"github.com/kharchibook/auth-service/pkg/domain/dto/message"
	"github.com/kharchibook/auth-service/pkg/domain/dto/request"
	"github.com/kharchibook/auth-service/pkg/domain/models/dao"
	"github.com/kharchibook/auth-service/pkg/infrastructure/kms"
	httptransport "github.com/kharchibook/auth-service/pkg/infrastructure/transport/http"
)

// ---- in-memory fakes --------------------------------------------------------

type fakeUserRepo struct {
	mu   sync.Mutex
	seq  int64
	byID map[int64]*dao.User
}

func newFakeUserRepo() *fakeUserRepo { return &fakeUserRepo{byID: map[int64]*dao.User{}} }

func (r *fakeUserRepo) Create(_ context.Context, u *dao.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	u.ID = r.seq
	cp := *u
	r.byID[u.ID] = &cp
	return nil
}
func (r *fakeUserRepo) GetByEmail(_ context.Context, email string) (*dao.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range r.byID {
		if u.Email == email {
			cp := *u
			return &cp, nil
		}
	}
	return nil, apperrors.ErrNotFound
}
func (r *fakeUserRepo) GetByID(_ context.Context, id int64) (*dao.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if u, ok := r.byID[id]; ok {
		cp := *u
		return &cp, nil
	}
	return nil, apperrors.ErrNotFound
}
func (r *fakeUserRepo) GetByProviderUID(_ context.Context, provider, uid string) (*dao.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range r.byID {
		if u.Provider == provider && u.ProviderUID != nil && *u.ProviderUID == uid {
			cp := *u
			return &cp, nil
		}
	}
	return nil, apperrors.ErrNotFound
}
func (r *fakeUserRepo) Update(_ context.Context, u *dao.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *u
	r.byID[u.ID] = &cp
	return nil
}
func (r *fakeUserRepo) SetVerified(_ context.Context, id int64, v bool) error {
	return r.patch(id, func(u *dao.User) { u.Verified = v })
}
func (r *fakeUserRepo) RecordLoginSuccess(_ context.Context, id int64, at time.Time) error {
	return r.patch(id, func(u *dao.User) { u.LastLogin = &at; u.FailedAttempts = 0; u.LockedUntil = nil })
}
func (r *fakeUserRepo) IncrementFailedAttempts(_ context.Context, id int64) (int, error) {
	var n int
	err := r.patch(id, func(u *dao.User) { u.FailedAttempts++; n = u.FailedAttempts })
	return n, err
}
func (r *fakeUserRepo) LockAccount(_ context.Context, id int64, until time.Time) error {
	return r.patch(id, func(u *dao.User) { u.LockedUntil = &until })
}
func (r *fakeUserRepo) UpdatePassword(_ context.Context, id int64, h string) error {
	return r.patch(id, func(u *dao.User) { u.PasswordHash = h })
}
func (r *fakeUserRepo) patch(id int64, fn func(*dao.User)) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.byID[id]
	if !ok {
		return apperrors.ErrNotFound
	}
	fn(u)
	return nil
}

type fakeSessionRepo struct {
	mu   sync.Mutex
	seq  int64
	rows map[int64]*dao.Session
}

func newFakeSessionRepo() *fakeSessionRepo { return &fakeSessionRepo{rows: map[int64]*dao.Session{}} }

func (r *fakeSessionRepo) Create(_ context.Context, s *dao.Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	s.ID = r.seq
	cp := *s
	r.rows[s.ID] = &cp
	return nil
}
func (r *fakeSessionRepo) GetByRefreshHash(_ context.Context, hash string) (*dao.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.rows {
		if s.RefreshTokenHash == hash {
			cp := *s
			return &cp, nil
		}
	}
	return nil, apperrors.ErrNotFound
}
func (r *fakeSessionRepo) GetByID(_ context.Context, id int64) (*dao.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.rows[id]; ok {
		cp := *s
		return &cp, nil
	}
	return nil, apperrors.ErrNotFound
}
func (r *fakeSessionRepo) Rotate(_ context.Context, id int64, h string, exp time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.rows[id]; ok {
		s.RefreshTokenHash = h
		s.ExpiresAt = exp
	}
	return nil
}
func (r *fakeSessionRepo) Revoke(_ context.Context, id int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.rows[id]; ok {
		s.IsRevoked = true
	}
	return nil
}
func (r *fakeSessionRepo) RevokeAllForUser(_ context.Context, userID int64) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for _, s := range r.rows {
		if s.UserID == userID && !s.IsRevoked {
			s.IsRevoked = true
			n++
		}
	}
	return n, nil
}

type fakeRBACRepo struct{}

func (fakeRBACRepo) GetRoleByName(_ context.Context, name string) (*dao.Role, error) {
	return &dao.Role{ID: 1, Name: name}, nil
}
func (fakeRBACRepo) AssignRoleToUser(_ context.Context, _, _ int64) error { return nil }
func (fakeRBACRepo) GetUserRoleNames(_ context.Context, _ int64) ([]string, error) {
	return []string{"user"}, nil
}
func (fakeRBACRepo) GetPermissionsForRoles(_ context.Context, _ []string) ([]string, error) {
	return nil, nil
}

type fakeAuditRepo struct{}

func (fakeAuditRepo) Insert(_ context.Context, _ *dao.AuditLog) error { return nil }

type fakeOTPRepo struct {
	mu       sync.Mutex
	otp      map[string]string
	attempts map[string]int
	cooldown map[string]bool
}

func newFakeOTPRepo() *fakeOTPRepo {
	return &fakeOTPRepo{otp: map[string]string{}, attempts: map[string]int{}, cooldown: map[string]bool{}}
}
func (r *fakeOTPRepo) Store(_ context.Context, email, h string, _ time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.otp[email] = h
	return nil
}
func (r *fakeOTPRepo) Get(_ context.Context, email string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := r.otp[email]; ok {
		return v, nil
	}
	return "", apperrors.ErrNotFound
}
func (r *fakeOTPRepo) Delete(_ context.Context, email string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.otp, email)
	return nil
}
func (r *fakeOTPRepo) IncrAttempts(_ context.Context, email string, _ time.Duration) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.attempts[email]++
	return r.attempts[email], nil
}
func (r *fakeOTPRepo) ClearAttempts(_ context.Context, email string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.attempts, email)
	return nil
}
func (r *fakeOTPRepo) SetResendCooldown(_ context.Context, email string, _ time.Duration) error {
	return nil // disabled in tests so resend is immediate
}
func (r *fakeOTPRepo) CooldownActive(_ context.Context, _ string) (bool, error) { return false, nil }

type fakeResetRepo struct {
	mu sync.Mutex
	m  map[int64]string
}

func newFakeResetRepo() *fakeResetRepo { return &fakeResetRepo{m: map[int64]string{}} }
func (r *fakeResetRepo) Store(_ context.Context, id int64, h string, _ time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[id] = h
	return nil
}
func (r *fakeResetRepo) Get(_ context.Context, id int64) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := r.m[id]; ok {
		return v, nil
	}
	return "", apperrors.ErrNotFound
}
func (r *fakeResetRepo) Delete(_ context.Context, id int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, id)
	return nil
}

type fakeRateLimit struct {
	mu sync.Mutex
	m  map[string]int
}

func newFakeRateLimit() *fakeRateLimit { return &fakeRateLimit{m: map[string]int{}} }
func (r *fakeRateLimit) Incr(_ context.Context, key string, _ time.Duration) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[key]++
	return r.m[key], nil
}
func (r *fakeRateLimit) Reset(_ context.Context, key string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, key)
	return nil
}

// capturePublisher records the last OTP/reset so tests can complete the flow.
type capturePublisher struct {
	lastOTP   string
	lastReset string
}

func (p *capturePublisher) PublishOTP(_ context.Context, n message.OTPNotification) error {
	p.lastOTP = n.OTP
	return nil
}
func (p *capturePublisher) PublishPasswordReset(_ context.Context, n message.PasswordResetNotification) error {
	p.lastReset = n.ResetLink
	return nil
}

// ---- harness ----------------------------------------------------------------

func newTestAuthService(t *testing.T) (IAuthService, *capturePublisher) {
	t.Helper()
	enc, err := kms.NewLocalKMS("test-secret")
	if err != nil {
		t.Fatalf("kms: %v", err)
	}
	pub := &capturePublisher{}
	rbac := NewRBACService(fakeRBACRepo{})
	accounts := NewAccountService(newFakeUserRepo(), rbac, enc, 5, 15*time.Minute)
	tokens, err := NewTokenService(config.Token{
		Issuer:          "auth-service-test",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("tokens: %v", err)
	}
	sessions := NewSessionService(newFakeSessionRepo(), tokens)
	otp := NewOTPService(newFakeOTPRepo(), pub, config.OTP{Length: 6, TTL: time.Minute, MaxAttempts: 3, AttemptWindow: time.Minute}, false)
	auth := NewAuthService(AuthDeps{
		Accounts:  accounts,
		Passwords: NewPasswordService(4), // low cost = fast tests
		Tokens:    tokens,
		Sessions:  sessions,
		OTP:       otp,
		RBAC:      rbac,
		Audit:     NewAuditService(fakeAuditRepo{}),
		ResetRepo: newFakeResetRepo(),
		RateLimit: newFakeRateLimit(),
		Publisher: pub,
		Google:    httptransport.NewGoogleOAuthClient(config.GoogleOAuth{}),
		RateCfg:   config.RateLimit{LoginMaxAttempts: 5, LoginWindow: time.Minute, ResetMaxAttempts: 5, ResetWindow: time.Minute},
		ResetURL:  "http://localhost/reset",
		DevMode:   false,
	})
	return auth, pub
}

// ---- tests ------------------------------------------------------------------

func TestSignupVerifyLoginRefreshFlow(t *testing.T) {
	auth, pub := newTestAuthService(t)
	ctx := context.Background()
	sc := entity.SessionContext{IPAddress: "1.2.3.4", DeviceID: "dev1"}

	// Signup issues an OTP.
	signup, err := auth.SignUp(ctx, request.SignUpRequest{Email: "a@b.com", Password: "S3cure!pass", Phone: "+919876543210"})
	if err != nil {
		t.Fatalf("signup: %v", err)
	}
	if signup.Verified {
		t.Fatalf("expected unverified after signup")
	}
	if pub.lastOTP == "" {
		t.Fatalf("expected an OTP to be published")
	}

	// Verify OTP.
	if err := auth.VerifyOTP(ctx, request.OTPVerifyRequest{Email: "a@b.com", OTP: pub.lastOTP}); err != nil {
		t.Fatalf("verify otp: %v", err)
	}

	// Login succeeds and returns a token pair.
	tokens, err := auth.Login(ctx, request.LoginRequest{Email: "a@b.com", Password: "S3cure!pass"}, sc)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatalf("expected non-empty tokens")
	}

	// Refresh rotates the refresh token.
	refreshed, err := auth.RefreshToken(ctx, request.RefreshTokenRequest{RefreshToken: tokens.RefreshToken}, sc)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if refreshed.RefreshToken == tokens.RefreshToken {
		t.Fatalf("expected rotated refresh token to differ")
	}

	// Replaying the OLD refresh token must be detected as reuse (theft).
	_, err = auth.RefreshToken(ctx, request.RefreshTokenRequest{RefreshToken: tokens.RefreshToken}, sc)
	if err == nil {
		t.Fatalf("expected reuse of rotated token to fail")
	}

	// And the family is revoked: the rotated token no longer works either.
	if _, err := auth.RefreshToken(ctx, request.RefreshTokenRequest{RefreshToken: refreshed.RefreshToken}, sc); err == nil {
		t.Fatalf("expected session family to be revoked after reuse detection")
	}
}

func TestLoginWrongPassword(t *testing.T) {
	auth, _ := newTestAuthService(t)
	ctx := context.Background()
	if _, err := auth.SignUp(ctx, request.SignUpRequest{Email: "c@d.com", Password: "S3cure!pass"}); err != nil {
		t.Fatalf("signup: %v", err)
	}
	_, err := auth.Login(ctx, request.LoginRequest{Email: "c@d.com", Password: "WrongPass!9"}, entity.SessionContext{IPAddress: "9.9.9.9"})
	he := apperrors.AsHTTP(err)
	if he == nil || he.StatusCode() != 401 {
		t.Fatalf("expected 401, got %v", err)
	}
}

func TestForgotResetRevokesSessions(t *testing.T) {
	auth, pub := newTestAuthService(t)
	ctx := context.Background()
	sc := entity.SessionContext{IPAddress: "1.1.1.1"}
	if _, err := auth.SignUp(ctx, request.SignUpRequest{Email: "e@f.com", Password: "S3cure!pass"}); err != nil {
		t.Fatalf("signup: %v", err)
	}
	tokens, err := auth.Login(ctx, request.LoginRequest{Email: "e@f.com", Password: "S3cure!pass"}, sc)
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	if err := auth.ForgotPassword(ctx, request.ForgotPasswordRequest{Email: "e@f.com"}); err != nil {
		t.Fatalf("forgot: %v", err)
	}
	// reset link = http://localhost/reset?token=<id>.<secret>
	token := pub.lastReset[len("http://localhost/reset?token="):]
	if token == "" {
		t.Fatalf("expected a reset token to be published")
	}

	if err := auth.ResetPassword(ctx, request.ResetPasswordRequest{ResetToken: token, NewPassword: "BrandN3w!pass"}); err != nil {
		t.Fatalf("reset: %v", err)
	}

	// Old refresh token must be revoked after reset.
	if _, err := auth.RefreshToken(ctx, request.RefreshTokenRequest{RefreshToken: tokens.RefreshToken}, sc); err == nil {
		t.Fatalf("expected sessions revoked after password reset")
	}

	// New password works.
	if _, err := auth.Login(ctx, request.LoginRequest{Email: "e@f.com", Password: "BrandN3w!pass"}, sc); err != nil {
		t.Fatalf("login with new password: %v", err)
	}
}
