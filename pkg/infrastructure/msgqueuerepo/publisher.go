// Package msgqueuerepo publishes notification/audit events to the message queue
// (Kafka). This build ships a logging stub; a franz-go backed publisher can be
// dropped in behind the same interface without touching callers.
package msgqueuerepo

import (
	"context"

	"github.com/kharchibook/auth-service/pkg/domain/dto/message"
	"github.com/kharchibook/auth-service/third_party/platlogger"
)

// INotificationPublisher publishes notification events for the Notification
// Worker to fan out to SMS/Email providers.
type INotificationPublisher interface {
	PublishOTP(ctx context.Context, n message.OTPNotification) error
	PublishPasswordReset(ctx context.Context, n message.PasswordResetNotification) error
}

// stubPublisher is a no-op publisher used when Kafka is disabled. It logs that an
// event would be published, but NEVER logs the OTP, reset link, or other secret
// payload (PRD §14 observability rule). For local end-to-end testing, the secret
// is surfaced separately via the OTP service's dev sink, not here.
type stubPublisher struct{}

// NewStubPublisher returns the logging stub publisher.
func NewStubPublisher() INotificationPublisher {
	return &stubPublisher{}
}

func (p *stubPublisher) PublishOTP(ctx context.Context, n message.OTPNotification) error {
	platlogger.WithContext(ctx).Info("otp notification queued (stub)",
		"medium", n.Medium, "purpose", n.Purpose, "recipient", mask(n.Recipient))
	return nil
}

func (p *stubPublisher) PublishPasswordReset(ctx context.Context, n message.PasswordResetNotification) error {
	platlogger.WithContext(ctx).Info("password-reset notification queued (stub)",
		"recipient", mask(n.Email))
	return nil
}

// mask redacts the local part of an email/phone for safe logging.
func mask(s string) string {
	if len(s) <= 3 {
		return "***"
	}
	return s[:2] + "***" + s[len(s)-1:]
}
