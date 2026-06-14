package dao

import (
	"time"

	"github.com/kharchibook/auth-service/enums/eventtype"
	"gorm.io/datatypes"
)

// AuditLog is an append-only record of a security-relevant event. Rows are never
// updated or deleted, providing an immutable trail for compliance.
type AuditLog struct {
	ID        int64               `gorm:"column:id;primaryKey;autoIncrement"`
	UserID    *int64              `gorm:"column:user_id;index"`
	EventType eventtype.EventType `gorm:"column:event_type;index;not null"`
	IPAddress string              `gorm:"column:ip_address"`
	DeviceID  string              `gorm:"column:device_id"`
	Metadata  datatypes.JSON      `gorm:"column:metadata;type:jsonb"`
	CreatedAt time.Time           `gorm:"column:created_at;autoCreateTime;index"`
}

func (AuditLog) TableName() string { return "audit_logs" }
