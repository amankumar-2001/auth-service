package config

import "time"

// Config is the root configuration object loaded from the active env JSON file
// (overlaid with environment variables via Viper).
type Config struct {
	App       App       `mapstructure:"app"`
	Server    Server    `mapstructure:"server"`
	Store     Store     `mapstructure:"store"`
	Cache     Cache     `mapstructure:"cache"`
	Token     Token     `mapstructure:"token"`
	Security  Security  `mapstructure:"security"`
	OTP       OTP       `mapstructure:"otp"`
	RateLimit RateLimit `mapstructure:"rateLimit"`
	MsgQueue  MsgQueue  `mapstructure:"msgQueue"`
	Email     Email     `mapstructure:"email"`
	Resend    Resend    `mapstructure:"resend"`
	OAuth     OAuth     `mapstructure:"oauth"`
	Internal  Internal  `mapstructure:"internal"`
}

// Internal holds service-to-service settings: the shared secret guarding the
// /v1/internal routes, and the key for the phone blind index. Both are secrets
// supplied via env overrides (INTERNAL_APIKEY, INTERNAL_PHONEHASHKEY) — never the
// JSON config. Empty values fall back to fixed dev defaults.
type Internal struct {
	APIKey       string `mapstructure:"apiKey"`
	PhoneHashKey string `mapstructure:"phoneHashKey"`
}

// App holds high-level service metadata.
type App struct {
	Name string `mapstructure:"name"`
	Env  string `mapstructure:"env"`
	// ResetPasswordURL is the frontend page the password-reset link points to;
	// the reset token is appended as a query parameter.
	ResetPasswordURL string `mapstructure:"resetPasswordURL"`
}

// Server holds HTTP server tuning.
type Server struct {
	Port            int           `mapstructure:"port"`
	ReadTimeout     time.Duration `mapstructure:"readTimeout"`
	WriteTimeout    time.Duration `mapstructure:"writeTimeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdownTimeout"`
}

// Store holds the primary SQL (PostgreSQL) connection settings.
type Store struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	User            string        `mapstructure:"user"`
	Password        string        `mapstructure:"password"`
	Name            string        `mapstructure:"name"`
	SSLMode         string        `mapstructure:"sslMode"`
	MaxOpenConns    int           `mapstructure:"maxOpenConns"`
	MaxIdleConns    int           `mapstructure:"maxIdleConns"`
	ConnMaxLifetime time.Duration `mapstructure:"connMaxLifetime"`
	AutoMigrate     bool          `mapstructure:"autoMigrate"`
}

// Cache holds the Redis connection settings.
type Cache struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
	// TLS enables an encrypted connection — required by managed Redis providers
	// (Upstash, Redis Cloud). Leave false for a local plaintext Redis.
	TLS bool `mapstructure:"tls"`
}

// Token holds JWT + refresh-token lifecycle settings.
type Token struct {
	Issuer          string        `mapstructure:"issuer"`
	AccessTokenTTL  time.Duration `mapstructure:"accessTokenTTL"`
	RefreshTokenTTL time.Duration `mapstructure:"refreshTokenTTL"`
	PrivateKeyPath  string        `mapstructure:"privateKeyPath"`
	PublicKeyPath   string        `mapstructure:"publicKeyPath"`
	PrivateKeyPEM   string        `mapstructure:"privateKeyPEM"`
	PublicKeyPEM    string        `mapstructure:"publicKeyPEM"`
}

// Security holds credential-hashing and lockout policy.
type Security struct {
	BcryptCost          int           `mapstructure:"bcryptCost"`
	MaxFailedAttempts   int           `mapstructure:"maxFailedAttempts"`
	AccountLockDuration time.Duration `mapstructure:"accountLockDuration"`
}

// OTP holds one-time-passcode generation/validation policy.
type OTP struct {
	Length         int           `mapstructure:"length"`
	TTL            time.Duration `mapstructure:"ttl"`
	MaxAttempts    int           `mapstructure:"maxAttempts"`
	AttemptWindow  time.Duration `mapstructure:"attemptWindow"`
	ResendCooldown time.Duration `mapstructure:"resendCooldown"`
}

// RateLimit holds abuse-prevention windows.
type RateLimit struct {
	LoginMaxAttempts int           `mapstructure:"loginMaxAttempts"`
	LoginWindow      time.Duration `mapstructure:"loginWindow"`
	ResetMaxAttempts int           `mapstructure:"resetMaxAttempts"`
	ResetWindow      time.Duration `mapstructure:"resetWindow"`
}

// MsgQueue holds Kafka/notification-fanout settings.
type MsgQueue struct {
	Brokers    []string `mapstructure:"brokers"`
	OTPTopic   string   `mapstructure:"otpTopic"`
	AuditTopic string   `mapstructure:"auditTopic"`
	Enabled    bool     `mapstructure:"enabled"`
}

// Email holds SMTP settings for transactional delivery (OTP, password reset).
// Secrets (username/password) come from environment overrides, never the JSON
// config. When Username is empty the service falls back to the logging stub
// publisher, so local dev works with no provider configured.
type Email struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	// From is the envelope/header sender address. Defaults to Username if empty.
	From     string `mapstructure:"from"`
	FromName string `mapstructure:"fromName"`
}

// Resend configures the Resend transactional-email API (https://resend.com),
// delivered over HTTPS. This is the preferred sender on hosts that block
// outbound SMTP (e.g. Render free instances block ports 25/465/587). When APIKey
// is set the service prefers Resend and falls back to SMTP; APIKey is a secret
// supplied via env (RESEND_APIKEY), never committed.
type Resend struct {
	APIKey string `mapstructure:"apiKey"`
	// From is the sender address; its domain must be verified in Resend (or use
	// the shared onboarding@resend.dev sandbox sender for first tests).
	From     string `mapstructure:"from"`
	FromName string `mapstructure:"fromName"`
}

// OAuth holds social-login provider settings.
type OAuth struct {
	Google GoogleOAuth `mapstructure:"google"`
}

// GoogleOAuth holds Google OAuth 2.0 client settings. The same client is used
// for social login and for Gmail connect (a separate, incremental consent with
// the gmail.readonly scope and its own redirect/callback).
type GoogleOAuth struct {
	ClientID     string `mapstructure:"clientID"`
	ClientSecret string `mapstructure:"clientSecret"`
	RedirectURL  string `mapstructure:"redirectURL"`
	// GmailRedirectURL is the callback Google returns to after the Gmail-connect
	// consent (distinct from the login RedirectURL).
	GmailRedirectURL string `mapstructure:"gmailRedirectURL"`
	// GmailConnectedURL is where the browser is sent after a successful connect
	// (the web app). Empty renders a plain success page instead.
	GmailConnectedURL string `mapstructure:"gmailConnectedURL"`
}

// ResetTokenTTL is a fixed policy value (single-use password reset link lifetime).
const ResetTokenTTL = 10 * time.Minute
