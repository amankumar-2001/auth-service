// Package dao holds GORM-mapped database entities (data access objects).
package dao

import "time"

// User is the account-service identity record. It stores only a salted password
// hash — never the plaintext password — and keeps phone as encrypted bytes.
type User struct {
	ID             int64      `gorm:"column:id;primaryKey;autoIncrement"`
	Email          string     `gorm:"column:email;uniqueIndex;not null"`
	Name           string     `gorm:"column:name;not null;default:''"`
	PhoneEncrypted []byte     `gorm:"column:phone_encrypted"`
	// PhoneHash is a keyed HMAC of the normalized phone (blind index). The phone
	// itself is encrypted with a random nonce and cannot be queried; this column
	// is what phone lookups (e.g. the WhatsApp worker) match against.
	PhoneHash      string     `gorm:"column:phone_hash;index"`
	PasswordHash   string     `gorm:"column:password_hash"`
	Verified       bool       `gorm:"column:verified;not null;default:false"`
	IsActive       bool       `gorm:"column:is_active;not null;default:true"`
	FailedAttempts int        `gorm:"column:failed_attempts;not null;default:0"`
	LockedUntil    *time.Time `gorm:"column:locked_until"`
	Provider       string     `gorm:"column:provider;not null;default:'local'"`
	ProviderUID    *string    `gorm:"column:provider_uid;index"`
	LastLogin      *time.Time `gorm:"column:last_login"`
	CreatedAt      time.Time  `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt      time.Time  `gorm:"column:updated_at;autoUpdateTime"`

	Roles []Role `gorm:"many2many:user_roles;joinForeignKey:user_id;joinReferences:role_id"`
}

// TableName overrides the default GORM table name.
func (User) TableName() string { return "users" }
