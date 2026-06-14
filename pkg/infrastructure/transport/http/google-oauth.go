// Package httptransport holds resilient HTTP clients for downstream services and
// identity providers.
package httptransport

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/kharchibook/auth-service/config"
)

// ErrOAuthNotConfigured is returned when a Google OAuth call is attempted but no
// client credentials are configured.
var ErrOAuthNotConfigured = errors.New("google oauth not configured")

// GoogleUser is the identity extracted from a verified Google ID token.
type GoogleUser struct {
	Sub           string // Google's stable user id
	Email         string
	EmailVerified bool
	Name          string
}

// IGoogleOAuthClient performs the Google OAuth 2.0 authorization-code flow:
// build the consent URL, exchange the code, and verify the returned ID token via
// Google's JWKS. The verification result is the app's proof of identity — the
// app then mints its OWN tokens (never reuses Google's).
type IGoogleOAuthClient interface {
	// AuthCodeURL builds the redirect URL to Google's consent screen.
	AuthCodeURL(state string) string
	// ExchangeAndVerify exchanges the auth code and returns the verified user.
	ExchangeAndVerify(ctx context.Context, code string) (*GoogleUser, error)
	// Enabled reports whether OAuth credentials are configured.
	Enabled() bool
}

type googleOAuthClient struct {
	cfg config.GoogleOAuth
}

// NewGoogleOAuthClient constructs the Google OAuth client.
func NewGoogleOAuthClient(cfg config.GoogleOAuth) IGoogleOAuthClient {
	return &googleOAuthClient{cfg: cfg}
}

func (c *googleOAuthClient) Enabled() bool { return c.cfg.ClientID != "" }

func (c *googleOAuthClient) AuthCodeURL(state string) string {
	q := url.Values{}
	q.Set("client_id", c.cfg.ClientID)
	q.Set("redirect_uri", c.cfg.RedirectURL)
	q.Set("response_type", "code")
	q.Set("scope", "openid email profile")
	q.Set("state", state)
	q.Set("access_type", "offline")
	return "https://accounts.google.com/o/oauth2/v2/auth?" + q.Encode()
}

// ExchangeAndVerify is the real integration point. Wiring the live token exchange
// + JWKS verification is left as the production task; until credentials are
// configured this returns ErrOAuthNotConfigured so the flow fails cleanly rather
// than silently trusting an unverified token.
func (c *googleOAuthClient) ExchangeAndVerify(ctx context.Context, code string) (*GoogleUser, error) {
	if !c.Enabled() {
		return nil, ErrOAuthNotConfigured
	}
	// TODO(prod): POST code to https://oauth2.googleapis.com/token, then verify
	// the returned id_token against https://www.googleapis.com/oauth2/v3/certs
	// (JWKS) before trusting its claims.
	return nil, fmt.Errorf("%w: live token exchange not implemented in this build", ErrOAuthNotConfigured)
}
