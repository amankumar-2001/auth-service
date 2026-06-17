package msgqueuerepo

import (
	"context"
	"fmt"
	"net/smtp"
	"strings"

	"github.com/kharchibook/auth-service/config"
	"github.com/kharchibook/auth-service/pkg/domain/dto/message"
	"github.com/kharchibook/auth-service/third_party/platlogger"
)

// smtpPublisher delivers notifications by sending email directly over SMTP. It
// implements INotificationPublisher, so it drops in behind the same interface as
// the Kafka stub — the OTP/auth services are unaware of the delivery mechanism.
//
// This is the synchronous, no-worker delivery path suitable for a single-service
// deployment. At scale, swap back to a queue publisher + a dedicated Notification
// Worker without touching callers.
type smtpPublisher struct {
	host     string
	addr     string
	auth     smtp.Auth
	from     string
	fromName string
}

// NewSMTPPublisher builds an SMTP-backed publisher. PlainAuth is used when a
// username is set (e.g. Gmail app password); for a local catcher (Mailpit) with
// no auth, leave Username empty and auth stays nil.
func NewSMTPPublisher(cfg config.Email) INotificationPublisher {
	from := cfg.From
	if from == "" {
		from = cfg.Username
	}
	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}
	return &smtpPublisher{
		host:     cfg.Host,
		addr:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		auth:     auth,
		from:     from,
		fromName: cfg.FromName,
	}
}

func (p *smtpPublisher) PublishOTP(ctx context.Context, n message.OTPNotification) error {
	subject, body := otpEmailContent(n.OTP)
	if err := p.send(n.Recipient, subject, body); err != nil {
		platlogger.WithContext(ctx).Error("failed to send OTP email", "recipient", mask(n.Recipient), "error", err)
		return err
	}
	platlogger.WithContext(ctx).Info("otp email sent", "purpose", n.Purpose, "recipient", mask(n.Recipient))
	return nil
}

func (p *smtpPublisher) PublishPasswordReset(ctx context.Context, n message.PasswordResetNotification) error {
	subject, body := passwordResetEmailContent(n.ResetLink)
	if err := p.send(n.Email, subject, body); err != nil {
		platlogger.WithContext(ctx).Error("failed to send reset email", "recipient", mask(n.Email), "error", err)
		return err
	}
	platlogger.WithContext(ctx).Info("password-reset email sent", "recipient", mask(n.Email))
	return nil
}

// send composes a minimal MIME HTML message and delivers it. net/smtp.SendMail
// performs STARTTLS automatically when the server advertises it (e.g. Gmail:587).
func (p *smtpPublisher) send(to, subject, htmlBody string) error {
	fromHeader := p.from
	if p.fromName != "" {
		fromHeader = fmt.Sprintf("%s <%s>", p.fromName, p.from)
	}
	headers := []string{
		"From: " + fromHeader,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		`Content-Type: text/html; charset="UTF-8"`,
	}
	msg := strings.Join(headers, "\r\n") + "\r\n\r\n" + htmlBody
	return smtp.SendMail(p.addr, p.auth, p.from, []string{to}, []byte(msg))
}
