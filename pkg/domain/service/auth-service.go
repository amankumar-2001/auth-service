package service

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/kharchibook/auth-service/config"
	"github.com/kharchibook/auth-service/enums/clienttype"
	"github.com/kharchibook/auth-service/enums/eventtype"
	apperrors "github.com/kharchibook/auth-service/errors"
	"github.com/kharchibook/auth-service/pkg/domain/dto/entity"
	"github.com/kharchibook/auth-service/pkg/domain/dto/message"
	"github.com/kharchibook/auth-service/pkg/domain/dto/request"
	"github.com/kharchibook/auth-service/pkg/domain/dto/response"
	"github.com/kharchibook/auth-service/pkg/domain/models/dao"
	"github.com/kharchibook/auth-service/pkg/infrastructure/cacherepo"
	"github.com/kharchibook/auth-service/pkg/infrastructure/msgqueuerepo"
	httptransport "github.com/kharchibook/auth-service/pkg/infrastructure/transport/http"
	"github.com/kharchibook/auth-service/third_party/platlogger"
	"github.com/kharchibook/auth-service/utils"
)

// IAuthService is the orchestration layer the HTTP handlers call. It composes the
// lower-level services into the end-to-end auth flows.
type IAuthService interface {
	SignUp(ctx context.Context, req request.SignUpRequest) (response.SignUpResponse, error)
	Login(ctx context.Context, req request.LoginRequest, sc entity.SessionContext) (entity.IssuedTokens, error)
	VerifyOTP(ctx context.Context, req request.OTPVerifyRequest) error
	ResendOTP(ctx context.Context, req request.OTPResendRequest) error
	RefreshToken(ctx context.Context, req request.RefreshTokenRequest, sc entity.SessionContext) (entity.IssuedTokens, error)
	Logout(ctx context.Context, req request.LogoutRequest) error
	ForgotPassword(ctx context.Context, req request.ForgotPasswordRequest) error
	ResetPassword(ctx context.Context, req request.ResetPasswordRequest) error
	GoogleAuthURL(state string) (string, error)
	GoogleCallback(ctx context.Context, code string, sc entity.SessionContext) (entity.IssuedTokens, error)
}

type authService struct {
	accounts  IAccountService
	passwords IPasswordService
	tokens    ITokenService
	sessions  ISessionService
	otp       IOTPService
	rbac      IRBACService
	audit     IAuditService
	resetRepo cacherepo.IResetTokenRepository
	rateLimit cacherepo.IRateLimitRepository
	publisher msgqueuerepo.INotificationPublisher
	google    httptransport.IGoogleOAuthClient
	rlCfg     config.RateLimit
	resetURL  string
	devMode   bool
}

// AuthDeps bundles the auth service's dependencies (keeps the constructor and the
// DI wiring readable given the breadth of collaborators).
type AuthDeps struct {
	Accounts  IAccountService
	Passwords IPasswordService
	Tokens    ITokenService
	Sessions  ISessionService
	OTP       IOTPService
	RBAC      IRBACService
	Audit     IAuditService
	ResetRepo cacherepo.IResetTokenRepository
	RateLimit cacherepo.IRateLimitRepository
	Publisher msgqueuerepo.INotificationPublisher
	Google    httptransport.IGoogleOAuthClient
	RateCfg   config.RateLimit
	ResetURL  string
	DevMode   bool
}

// NewAuthService constructs the orchestrating auth service.
func NewAuthService(d AuthDeps) IAuthService {
	return &authService{
		accounts:  d.Accounts,
		passwords: d.Passwords,
		tokens:    d.Tokens,
		sessions:  d.Sessions,
		otp:       d.OTP,
		rbac:      d.RBAC,
		audit:     d.Audit,
		resetRepo: d.ResetRepo,
		rateLimit: d.RateLimit,
		publisher: d.Publisher,
		google:    d.Google,
		rlCfg:     d.RateCfg,
		resetURL:  d.ResetURL,
		devMode:   d.DevMode,
	}
}

// ---- Signup -----------------------------------------------------------------

func (s *authService) SignUp(ctx context.Context, req request.SignUpRequest) (response.SignUpResponse, error) {
	hash, err := s.passwords.Hash(req.Password)
	if err != nil {
		return response.SignUpResponse{}, apperrors.InternalServerError(err)
	}

	user, err := s.accounts.CreateLocalUser(ctx, req.Email, hash, req.Phone, req.Name)
	if err != nil {
		return response.SignUpResponse{}, err
	}

	// Kick off OTP email verification (best-effort: the account exists either
	// way and the user can request a resend).
	if err := s.otp.GenerateAndSend(ctx, req.Email, clienttype.Email, "signup_verification"); err != nil {
		platlogger.WithContext(ctx).Error("failed to send signup OTP", "error", err)
	} else {
		s.audit.Log(ctx, eventtype.OTPSent, &user.ID, map[string]any{"medium": "email"})
	}

	s.audit.Log(ctx, eventtype.Signup, &user.ID, map[string]any{"email": req.Email})
	return response.SignUpResponse{
		UserID:   strconv.FormatInt(user.ID, 10),
		Verified: false,
		Message:  "OTP sent",
	}, nil
}

// ---- Login ------------------------------------------------------------------

func (s *authService) Login(ctx context.Context, req request.LoginRequest, sc entity.SessionContext) (entity.IssuedTokens, error) {
	// Per-IP rate limit (defense against credential stuffing).
	if sc.IPAddress != "" {
		count, err := s.rateLimit.Incr(ctx, "login:"+sc.IPAddress, s.rlCfg.LoginWindow)
		if err != nil {
			return entity.IssuedTokens{}, apperrors.InternalServerError(err)
		}
		if count > s.rlCfg.LoginMaxAttempts {
			return entity.IssuedTokens{}, apperrors.LockedError("too many login attempts; try again later")
		}
	}

	user, err := s.accounts.GetByEmail(ctx, req.Email)
	if err != nil {
		if apperrors.Is(err, apperrors.ErrNotFound) {
			// Generic message — don't reveal whether the account exists.
			s.audit.Log(ctx, eventtype.LoginFail, nil, map[string]any{"email": req.Email, "reason": "no_user"})
			return entity.IssuedTokens{}, apperrors.UnauthorizedError("invalid credentials")
		}
		return entity.IssuedTokens{}, err
	}

	if !user.IsActive {
		s.audit.Log(ctx, eventtype.LoginFail, &user.ID, map[string]any{"reason": "inactive"})
		return entity.IssuedTokens{}, apperrors.ForbiddenError("account is inactive")
	}
	if user.LockedUntil != nil && user.LockedUntil.After(time.Now().UTC()) {
		s.audit.Log(ctx, eventtype.LoginFail, &user.ID, map[string]any{"reason": "locked"})
		return entity.IssuedTokens{}, apperrors.LockedError("account temporarily locked")
	}

	if user.PasswordHash == "" || !s.passwords.Verify(req.Password, user.PasswordHash) {
		locked, lerr := s.accounts.RegisterFailedLogin(ctx, user.ID)
		if lerr != nil {
			platlogger.WithContext(ctx).Error("failed to register failed login", "error", lerr)
		}
		if locked {
			s.audit.Log(ctx, eventtype.AccountLocked, &user.ID, nil)
		}
		s.audit.Log(ctx, eventtype.LoginFail, &user.ID, map[string]any{"reason": "bad_password"})
		return entity.IssuedTokens{}, apperrors.UnauthorizedError("invalid credentials")
	}

	// Success — clear counters and rate-limit window, then issue tokens.
	if err := s.accounts.RecordLoginSuccess(ctx, user.ID); err != nil {
		platlogger.WithContext(ctx).Error("failed to record login success", "error", err)
	}
	if sc.IPAddress != "" {
		_ = s.rateLimit.Reset(ctx, "login:"+sc.IPAddress)
	}

	tokens, err := s.issueTokens(ctx, user, sc)
	if err != nil {
		return entity.IssuedTokens{}, err
	}
	s.audit.Log(ctx, eventtype.LoginSuccess, &user.ID, nil)
	return tokens, nil
}

// ---- OTP --------------------------------------------------------------------

func (s *authService) VerifyOTP(ctx context.Context, req request.OTPVerifyRequest) error {
	if err := s.otp.Verify(ctx, req.Email, req.OTP); err != nil {
		s.audit.Log(ctx, eventtype.OTPFail, nil, map[string]any{"email": req.Email})
		return err
	}

	user, err := s.accounts.GetByEmail(ctx, req.Email)
	if err != nil {
		if apperrors.Is(err, apperrors.ErrNotFound) {
			return apperrors.BadRequestError("invalid or expired OTP")
		}
		return err
	}
	if err := s.accounts.MarkVerified(ctx, user.ID); err != nil {
		return apperrors.InternalServerError(err)
	}
	s.audit.Log(ctx, eventtype.OTPVerified, &user.ID, nil)
	return nil
}

func (s *authService) ResendOTP(ctx context.Context, req request.OTPResendRequest) error {
	user, err := s.accounts.GetByEmail(ctx, req.Email)
	if err != nil {
		if apperrors.Is(err, apperrors.ErrNotFound) {
			return nil // non-enumerable: pretend success
		}
		return err
	}
	if user.Verified {
		return nil // nothing to do; don't reveal verification state
	}
	if err := s.otp.GenerateAndSend(ctx, req.Email, clienttype.Email, "signup_verification"); err != nil {
		return err
	}
	s.audit.Log(ctx, eventtype.OTPSent, &user.ID, map[string]any{"medium": "email", "resend": true})
	return nil
}

// ---- Token refresh ----------------------------------------------------------

func (s *authService) RefreshToken(ctx context.Context, req request.RefreshTokenRequest, sc entity.SessionContext) (entity.IssuedTokens, error) {
	res, err := s.sessions.Rotate(ctx, req.RefreshToken)
	if err != nil {
		switch {
		case apperrors.Is(err, ErrRefreshReuse):
			s.audit.Log(ctx, eventtype.TokenReuse, nil, map[string]any{"detail": "rotated token replayed"})
			return entity.IssuedTokens{}, apperrors.UnauthorizedError("refresh token revoked")
		case apperrors.Is(err, ErrRefreshInvalid):
			return entity.IssuedTokens{}, apperrors.UnauthorizedError("invalid or expired refresh token")
		default:
			return entity.IssuedTokens{}, err
		}
	}

	user, err := s.accounts.GetByID(ctx, res.UserID)
	if err != nil {
		return entity.IssuedTokens{}, err
	}
	roles, err := s.rbac.GetUserRoles(ctx, user.ID)
	if err != nil {
		return entity.IssuedTokens{}, err
	}

	access, expiresIn, err := s.tokens.GenerateAccessToken(entity.TokenClaims{
		UserID:    user.ID,
		SessionID: res.SessionID,
		Roles:     roles,
		Verified:  user.Verified,
	})
	if err != nil {
		return entity.IssuedTokens{}, apperrors.InternalServerError(err)
	}

	s.audit.Log(ctx, eventtype.TokenRefresh, &user.ID, nil)
	return entity.IssuedTokens{AccessToken: access, RefreshToken: res.RawRefreshToken, ExpiresIn: expiresIn}, nil
}

// ---- Logout -----------------------------------------------------------------

func (s *authService) Logout(ctx context.Context, req request.LogoutRequest) error {
	userID, err := s.sessions.RevokeByToken(ctx, req.RefreshToken)
	if err != nil {
		if apperrors.Is(err, ErrRefreshInvalid) {
			return nil // idempotent: already logged out / unknown token
		}
		return err
	}
	if req.AllSessions {
		if err := s.sessions.RevokeAll(ctx, userID); err != nil {
			return err
		}
	}
	s.audit.Log(ctx, eventtype.Logout, &userID, map[string]any{"allSessions": req.AllSessions})
	return nil
}

// ---- Password reset ---------------------------------------------------------

func (s *authService) ForgotPassword(ctx context.Context, req request.ForgotPasswordRequest) error {
	user, err := s.accounts.GetByEmail(ctx, req.Email)
	if err != nil {
		if apperrors.Is(err, apperrors.ErrNotFound) {
			return nil // non-enumerable: always report generic success
		}
		return err
	}

	// Rate limit reset requests per email.
	count, err := s.rateLimit.Incr(ctx, "reset:"+req.Email, s.rlCfg.ResetWindow)
	if err != nil {
		return apperrors.InternalServerError(err)
	}
	if count > s.rlCfg.ResetMaxAttempts {
		return nil // silently drop; still non-enumerable
	}

	secret, err := utils.RandomToken(32)
	if err != nil {
		return apperrors.InternalServerError(err)
	}
	if err := s.resetRepo.Store(ctx, user.ID, utils.HashToken(secret), config.ResetTokenTTL); err != nil {
		return apperrors.InternalServerError(err)
	}

	// The token embeds the user id so reset can locate the record from the token
	// alone; only the secret half is hashed and stored.
	token := fmt.Sprintf("%d.%s", user.ID, secret)
	link := fmt.Sprintf("%s?token=%s", s.resetURL, token)
	if err := s.publisher.PublishPasswordReset(ctx, message.PasswordResetNotification{Email: req.Email, ResetLink: link}); err != nil {
		platlogger.WithContext(ctx).Error("failed to publish reset notification", "error", err)
	}
	if s.devMode {
		platlogger.WithContext(ctx).Warn("DEV reset token issued", "email", req.Email, "token", token)
	}

	s.audit.Log(ctx, eventtype.PwdResetRequest, &user.ID, nil)
	return nil
}

func (s *authService) ResetPassword(ctx context.Context, req request.ResetPasswordRequest) error {
	userID, secret, ok := parseResetToken(req.ResetToken)
	if !ok {
		return apperrors.BadRequestError("invalid or expired reset token")
	}

	stored, err := s.resetRepo.Get(ctx, userID)
	if err != nil {
		if apperrors.Is(err, apperrors.ErrNotFound) {
			return apperrors.BadRequestError("invalid or expired reset token")
		}
		return apperrors.InternalServerError(err)
	}
	if !utils.ConstantTimeEqual(stored, utils.HashToken(secret)) {
		return apperrors.BadRequestError("invalid or expired reset token")
	}

	hash, err := s.passwords.Hash(req.NewPassword)
	if err != nil {
		return apperrors.InternalServerError(err)
	}
	if err := s.accounts.UpdatePassword(ctx, userID, hash); err != nil {
		return apperrors.InternalServerError(err)
	}

	// Critical: revoke every session so a thief who triggered the reset (or had
	// stolen tokens) is logged out everywhere.
	if err := s.sessions.RevokeAll(ctx, userID); err != nil {
		return err
	}
	_ = s.resetRepo.Delete(ctx, userID)

	s.audit.Log(ctx, eventtype.PwdResetSuccess, &userID, nil)
	return nil
}

// ---- Social login -----------------------------------------------------------

func (s *authService) GoogleAuthURL(state string) (string, error) {
	if !s.google.Enabled() {
		return "", apperrors.BadRequestError("google login is not configured")
	}
	return s.google.AuthCodeURL(state), nil
}

func (s *authService) GoogleCallback(ctx context.Context, code string, sc entity.SessionContext) (entity.IssuedTokens, error) {
	gu, err := s.google.ExchangeAndVerify(ctx, code)
	if err != nil {
		if apperrors.Is(err, httptransport.ErrOAuthNotConfigured) {
			return entity.IssuedTokens{}, apperrors.BadRequestError("google login is not available")
		}
		return entity.IssuedTokens{}, apperrors.UnauthorizedError("google authentication failed")
	}
	if !gu.EmailVerified {
		return entity.IssuedTokens{}, apperrors.ForbiddenError("google account email is not verified")
	}

	user, created, err := s.accounts.FindOrCreateSocialUser(ctx, "google", gu.Sub, gu.Email)
	if err != nil {
		return entity.IssuedTokens{}, err
	}

	tokens, err := s.issueTokens(ctx, user, sc)
	if err != nil {
		return entity.IssuedTokens{}, err
	}
	s.audit.Log(ctx, eventtype.SocialLogin, &user.ID, map[string]any{"provider": "google", "created": created})
	return tokens, nil
}

// ---- helpers ----------------------------------------------------------------

// issueTokens mints a new session + access/refresh pair for an authenticated user.
func (s *authService) issueTokens(ctx context.Context, user *dao.User, sc entity.SessionContext) (entity.IssuedTokens, error) {
	roles, err := s.rbac.GetUserRoles(ctx, user.ID)
	if err != nil {
		return entity.IssuedTokens{}, err
	}
	sessionID, rawRefresh, err := s.sessions.Create(ctx, user.ID, sc)
	if err != nil {
		return entity.IssuedTokens{}, err
	}
	access, expiresIn, err := s.tokens.GenerateAccessToken(entity.TokenClaims{
		UserID:    user.ID,
		SessionID: sessionID,
		Roles:     roles,
		Verified:  user.Verified,
	})
	if err != nil {
		return entity.IssuedTokens{}, apperrors.InternalServerError(err)
	}
	return entity.IssuedTokens{AccessToken: access, RefreshToken: rawRefresh, ExpiresIn: expiresIn}, nil
}

// parseResetToken splits a "<userID>.<secret>" reset token.
func parseResetToken(token string) (int64, string, bool) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return 0, "", false
	}
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || parts[1] == "" {
		return 0, "", false
	}
	return id, parts[1], true
}
