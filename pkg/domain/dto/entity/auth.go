// Package entity holds internal value objects passed between domain services.
package entity

import "time"

// TokenClaims is the verified payload of an access JWT, attached to the request
// context by the JWT guard.
type TokenClaims struct {
	UserID    int64
	SessionID int64
	Roles     []string
	Verified  bool
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// IssuedTokens is the result of minting a new access+refresh pair.
type IssuedTokens struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64 // access-token lifetime in seconds
}

// SessionContext carries the request metadata captured at login time.
type SessionContext struct {
	DeviceID  string
	IPAddress string
	UserAgent string
}
