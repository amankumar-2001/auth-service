package msgqueuerepo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kharchibook/auth-service/config"
	"github.com/kharchibook/auth-service/pkg/domain/dto/message"
	"github.com/kharchibook/auth-service/third_party/platlogger"
)

// resendEndpoint is Resend's transactional-email API. Delivery is over HTTPS
// (443), so it works on hosts that block outbound SMTP (e.g. Render free).
const resendEndpoint = "https://api.resend.com/emails"

// resendPublisher delivers notifications via the Resend HTTP API. It implements
// INotificationPublisher, so it drops in behind the same interface as the SMTP
// and stub publishers — callers are unaware of the transport.
type resendPublisher struct {
	client *http.Client
	apiKey string
	from   string // header form, e.g. "KharchiBook <noreply@yourdomain.com>"
}

// NewResendPublisher builds a Resend-backed publisher. From defaults to the
// Resend sandbox sender when unset (which only delivers to the account owner).
func NewResendPublisher(cfg config.Resend) INotificationPublisher {
	from := cfg.From
	if from == "" {
		from = "onboarding@resend.dev"
	}
	if cfg.FromName != "" {
		from = fmt.Sprintf("%s <%s>", cfg.FromName, from)
	}
	return &resendPublisher{
		client: &http.Client{Timeout: 15 * time.Second},
		apiKey: cfg.APIKey,
		from:   from,
	}
}

func (p *resendPublisher) PublishOTP(ctx context.Context, n message.OTPNotification) error {
	subject, html := otpEmailContent(n.OTP)
	if err := p.send(ctx, n.Recipient, subject, html); err != nil {
		platlogger.WithContext(ctx).Error("failed to send OTP email (resend)", "recipient", mask(n.Recipient), "error", err)
		return err
	}
	platlogger.WithContext(ctx).Info("otp email sent (resend)", "purpose", n.Purpose, "recipient", mask(n.Recipient))
	return nil
}

func (p *resendPublisher) PublishPasswordReset(ctx context.Context, n message.PasswordResetNotification) error {
	subject, html := passwordResetEmailContent(n.ResetLink)
	if err := p.send(ctx, n.Email, subject, html); err != nil {
		platlogger.WithContext(ctx).Error("failed to send reset email (resend)", "recipient", mask(n.Email), "error", err)
		return err
	}
	platlogger.WithContext(ctx).Info("password-reset email sent (resend)", "recipient", mask(n.Email))
	return nil
}

// send POSTs one email to the Resend API. A non-2xx response becomes an error
// carrying the status and a trimmed body so callers (and the fallback chain) can
// react.
func (p *resendPublisher) send(ctx context.Context, to, subject, html string) error {
	body, err := json.Marshal(map[string]any{
		"from":    p.from,
		"to":      []string{to},
		"subject": subject,
		"html":    html,
	})
	if err != nil {
		return fmt.Errorf("marshal resend payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, resendEndpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("call resend api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("resend api returned %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}
