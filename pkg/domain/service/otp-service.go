package service

import (
	"context"

	"github.com/kharchibook/auth-service/config"
	"github.com/kharchibook/auth-service/enums/clienttype"
	apperrors "github.com/kharchibook/auth-service/errors"
	"github.com/kharchibook/auth-service/pkg/domain/dto/message"
	"github.com/kharchibook/auth-service/pkg/infrastructure/cacherepo"
	"github.com/kharchibook/auth-service/pkg/infrastructure/msgqueuerepo"
	"github.com/kharchibook/auth-service/third_party/platlogger"
	"github.com/kharchibook/auth-service/utils"
)

// IOTPService generates, delivers, and validates one-time passcodes. OTPs are
// stored only as hashes in Redis with a TTL; delivery is fanned out via the
// message queue to a Notification Worker.
type IOTPService interface {
	GenerateAndSend(ctx context.Context, email string, medium clienttype.Medium, purpose string) error
	// Verify checks the submitted OTP, enforcing the wrong-attempt limit. On
	// success the OTP key and attempt counter are cleared.
	Verify(ctx context.Context, email, otp string) error
}

type otpService struct {
	repo      cacherepo.IOTPRepository
	publisher msgqueuerepo.INotificationPublisher
	cfg       config.OTP
	devMode   bool // when true, the generated OTP is logged for local testing
}

// NewOTPService constructs the OTP service. devMode should be true ONLY in local
// development — it surfaces the plaintext OTP in logs.
func NewOTPService(
	repo cacherepo.IOTPRepository,
	publisher msgqueuerepo.INotificationPublisher,
	cfg config.OTP,
	devMode bool,
) IOTPService {
	return &otpService{repo: repo, publisher: publisher, cfg: cfg, devMode: devMode}
}

func (s *otpService) GenerateAndSend(ctx context.Context, email string, medium clienttype.Medium, purpose string) error {
	// Enforce resend cooldown to prevent OTP-spam abuse.
	active, err := s.repo.CooldownActive(ctx, email)
	if err != nil {
		return apperrors.InternalServerError(err)
	}
	if active {
		return apperrors.TooManyRequestsError("please wait before requesting another OTP")
	}

	otp, err := utils.RandomNumericOTP(s.cfg.Length)
	if err != nil {
		return apperrors.InternalServerError(err)
	}

	if err := s.repo.Store(ctx, email, utils.HashToken(otp), s.cfg.TTL); err != nil {
		return apperrors.InternalServerError(err)
	}
	if err := s.repo.SetResendCooldown(ctx, email, s.cfg.ResendCooldown); err != nil {
		return apperrors.InternalServerError(err)
	}

	// Publish the delivery event (Kafka → Notification Worker → provider).
	if err := s.publisher.PublishOTP(ctx, message.OTPNotification{
		Medium:    medium,
		Recipient: email,
		OTP:       otp,
		Purpose:   purpose,
	}); err != nil {
		return apperrors.InternalServerError(err)
	}

	if s.devMode {
		// DEV ONLY: never enabled outside local development (PRD §14 forbids
		// logging OTPs). Lets a developer complete the flow without a provider.
		platlogger.WithContext(ctx).Warn("DEV OTP issued", "email", email, "otp", otp, "purpose", purpose)
	}
	return nil
}

func (s *otpService) Verify(ctx context.Context, email, otp string) error {
	// Block once the wrong-attempt threshold is reached within the window.
	stored, err := s.repo.Get(ctx, email)
	if err != nil {
		if apperrors.Is(err, apperrors.ErrNotFound) {
			return apperrors.BadRequestError("invalid or expired OTP")
		}
		return apperrors.InternalServerError(err)
	}

	if !utils.ConstantTimeEqual(stored, utils.HashToken(otp)) {
		count, incErr := s.repo.IncrAttempts(ctx, email, s.cfg.AttemptWindow)
		if incErr != nil {
			return apperrors.InternalServerError(incErr)
		}
		if count >= s.cfg.MaxAttempts {
			// Burn the OTP so a locked-out attacker can't keep guessing it.
			_ = s.repo.Delete(ctx, email)
			return apperrors.TooManyRequestsError("too many incorrect attempts; request a new OTP")
		}
		return apperrors.BadRequestError("invalid or expired OTP")
	}

	// Success: single-use — delete the key and clear the attempt counter.
	_ = s.repo.Delete(ctx, email)
	_ = s.repo.ClearAttempts(ctx, email)
	return nil
}
