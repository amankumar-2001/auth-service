package dao

import "time"

// GmailCredential stores a user's Gmail OAuth tokens, encrypted at rest. The
// access/refresh tokens are AES-256-GCM ciphertext (via the KMS); the service
// layer encrypts on write and decrypts on read. One row per user.
type GmailCredential struct {
	UserID          int64     `gorm:"column:user_id;primaryKey"`
	AccessTokenEnc  []byte    `gorm:"column:access_token_enc;not null"`
	RefreshTokenEnc []byte    `gorm:"column:refresh_token_enc;not null"`
	TokenExpiry     time.Time `gorm:"column:token_expiry;not null"`
	Scope           string    `gorm:"column:scope;not null;default:''"`
	Email           string    `gorm:"column:email;not null;default:''"`
	CreatedAt       time.Time `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt       time.Time `gorm:"column:updated_at;autoUpdateTime"`
}

// TableName overrides the default GORM table name.
func (GmailCredential) TableName() string { return "gmail_credentials" }
