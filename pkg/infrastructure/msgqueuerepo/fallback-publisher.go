package msgqueuerepo

import (
	"context"
	"errors"

	"github.com/kharchibook/auth-service/pkg/domain/dto/message"
	"github.com/kharchibook/auth-service/third_party/platlogger"
)

// fallbackPublisher tries an ordered list of publishers and returns as soon as
// one succeeds. It exists so a primary transport (e.g. Resend over HTTPS) can be
// backed by a secondary (e.g. SMTP) without callers knowing: if the primary
// errors, the next is tried. Order matters — put the most-likely-to-work
// transport first (on Render, Resend, since SMTP is blocked).
type fallbackPublisher struct {
	publishers []INotificationPublisher
}

// NewFallbackPublisher chains publishers in priority order. With a single
// publisher it behaves identically to that publisher; with none it is a no-op
// that errors on every call (callers should pass at least one).
func NewFallbackPublisher(publishers ...INotificationPublisher) INotificationPublisher {
	return &fallbackPublisher{publishers: publishers}
}

func (p *fallbackPublisher) PublishOTP(ctx context.Context, n message.OTPNotification) error {
	return p.try(ctx, func(pub INotificationPublisher) error {
		return pub.PublishOTP(ctx, n)
	})
}

func (p *fallbackPublisher) PublishPasswordReset(ctx context.Context, n message.PasswordResetNotification) error {
	return p.try(ctx, func(pub INotificationPublisher) error {
		return pub.PublishPasswordReset(ctx, n)
	})
}

// try runs publish against each publisher in order, returning on the first
// success. Each failure is logged (with its index) and the next is tried; if all
// fail the joined error is returned.
func (p *fallbackPublisher) try(ctx context.Context, publish func(INotificationPublisher) error) error {
	if len(p.publishers) == 0 {
		return errors.New("no notification publisher configured")
	}
	var errs []error
	for i, pub := range p.publishers {
		err := publish(pub)
		if err == nil {
			return nil
		}
		errs = append(errs, err)
		if i < len(p.publishers)-1 {
			platlogger.WithContext(ctx).Warn("notification publisher failed, trying fallback", "index", i, "error", err)
		}
	}
	return errors.Join(errs...)
}
