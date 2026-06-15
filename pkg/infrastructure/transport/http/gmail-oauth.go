package httptransport

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/kharchibook/auth-service/config"
)

// GmailReadonlyScope is the only Gmail scope requested — read-only mailbox access.
const GmailReadonlyScope = "https://www.googleapis.com/auth/gmail.readonly"

// IGmailOAuthClient performs the Gmail-connect OAuth flow and token lifecycle:
// build the consent URL, exchange the code for tokens, and refresh an access
// token from a stored refresh token. Unlike the login client, this requests the
// gmail.readonly scope and keeps the resulting tokens (the gateway uses them).
type IGmailOAuthClient interface {
	AuthCodeURL(state string) string
	Exchange(ctx context.Context, code string) (*oauth2.Token, error)
	// TokenFromRefresh returns a fresh, valid token derived from refreshToken,
	// performing a refresh against Google. The returned token's AccessToken/Expiry
	// are current; its RefreshToken may be unchanged.
	TokenFromRefresh(ctx context.Context, refreshToken string) (*oauth2.Token, error)
	Enabled() bool
}

type gmailOAuthClient struct {
	cfg config.GoogleOAuth
}

// NewGmailOAuthClient constructs the Gmail OAuth client from the shared Google
// client credentials plus the Gmail-specific redirect URL.
func NewGmailOAuthClient(cfg config.GoogleOAuth) IGmailOAuthClient {
	return &gmailOAuthClient{cfg: cfg}
}

func (c *gmailOAuthClient) Enabled() bool {
	return c.cfg.ClientID != "" && c.cfg.ClientSecret != ""
}

func (c *gmailOAuthClient) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.cfg.ClientID,
		ClientSecret: c.cfg.ClientSecret,
		RedirectURL:  c.cfg.GmailRedirectURL,
		Scopes:       []string{GmailReadonlyScope},
		Endpoint:     google.Endpoint,
	}
}

func (c *gmailOAuthClient) AuthCodeURL(state string) string {
	// AccessTypeOffline + prompt=consent ensures Google returns a refresh token.
	return c.oauthConfig().AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("prompt", "consent"),
	)
}

func (c *gmailOAuthClient) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	if !c.Enabled() {
		return nil, ErrOAuthNotConfigured
	}
	tok, err := c.oauthConfig().Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("exchange gmail auth code: %w", err)
	}
	if tok.RefreshToken == "" {
		return nil, fmt.Errorf("google did not return a refresh token (re-consent required)")
	}
	return tok, nil
}

func (c *gmailOAuthClient) TokenFromRefresh(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	if !c.Enabled() {
		return nil, ErrOAuthNotConfigured
	}
	// A TokenSource seeded with only a refresh token refreshes on demand.
	src := c.oauthConfig().TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken})
	tok, err := src.Token()
	if err != nil {
		return nil, fmt.Errorf("refresh gmail access token: %w", err)
	}
	return tok, nil
}
