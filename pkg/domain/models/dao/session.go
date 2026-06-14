package dao

import "time"

// Session tracks an active login. The refresh token is stored only as a hash;
// the raw token lives only on the client. Rotation replaces RefreshTokenHash and
// theft of an already-rotated token is detected via IsRevoked.
type Session struct {
	ID               int64     `gorm:"column:id;primaryKey;autoIncrement"`
	UserID           int64     `gorm:"column:user_id;index;not null"`
	RefreshTokenHash string    `gorm:"column:refresh_token_hash;index;not null"`
	DeviceID         string    `gorm:"column:device_id"`
	IPAddress        string    `gorm:"column:ip_address"`
	UserAgent        string    `gorm:"column:user_agent"`
	IsRevoked        bool      `gorm:"column:is_revoked;not null;default:false"`
	CreatedAt        time.Time `gorm:"column:created_at;autoCreateTime"`
	ExpiresAt        time.Time `gorm:"column:expires_at;index"`
	LastUsedAt       time.Time `gorm:"column:last_used_at"`
}

func (Session) TableName() string { return "sessions" }
