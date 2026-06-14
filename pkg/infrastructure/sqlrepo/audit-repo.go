package sqlrepo

import (
	"context"
	"fmt"

	"github.com/kharchibook/auth-service/pkg/domain/models/dao"
	"gorm.io/gorm"
)

// IAuditRepository appends immutable security-audit rows. Only Insert is exposed
// — the table is append-only (enforced by a DB trigger in the DDL).
type IAuditRepository interface {
	Insert(ctx context.Context, entry *dao.AuditLog) error
}

type auditRepository struct {
	db *gorm.DB
}

// NewAuditRepository constructs the GORM audit-log repository.
func NewAuditRepository(db *gorm.DB) IAuditRepository {
	return &auditRepository{db: db}
}

func (r *auditRepository) Insert(ctx context.Context, entry *dao.AuditLog) error {
	if err := r.db.WithContext(ctx).Create(entry).Error; err != nil {
		return fmt.Errorf("insert audit log: %w", err)
	}
	return nil
}
