package service

import (
	"context"
	"encoding/json"

	"github.com/kharchibook/auth-service/constants"
	"github.com/kharchibook/auth-service/enums/eventtype"
	"github.com/kharchibook/auth-service/pkg/domain/models/dao"
	"github.com/kharchibook/auth-service/pkg/infrastructure/sqlrepo"
	"github.com/kharchibook/auth-service/third_party/platlogger"
	"github.com/kharchibook/auth-service/utils"
	"gorm.io/datatypes"
)

// IAuditService records security-relevant events to the immutable audit trail. It
// pulls IP/device from the request context automatically.
type IAuditService interface {
	// Log writes an audit entry. userID may be nil for pre-auth events. A
	// failure to write is logged but never propagated — auditing must not break
	// the primary flow.
	Log(ctx context.Context, event eventtype.EventType, userID *int64, metadata map[string]any)
}

type auditService struct {
	repo sqlrepo.IAuditRepository
}

// NewAuditService constructs the audit service.
func NewAuditService(repo sqlrepo.IAuditRepository) IAuditService {
	return &auditService{repo: repo}
}

func (s *auditService) Log(ctx context.Context, event eventtype.EventType, userID *int64, metadata map[string]any) {
	entry := &dao.AuditLog{
		UserID:    userID,
		EventType: event,
		IPAddress: utils.GetFromContext(ctx, constants.CtxIPAddress),
		DeviceID:  utils.GetFromContext(ctx, constants.CtxDeviceID),
	}
	if metadata != nil {
		if b, err := json.Marshal(metadata); err == nil {
			entry.Metadata = datatypes.JSON(b)
		}
	}
	if err := s.repo.Insert(ctx, entry); err != nil {
		platlogger.WithContext(ctx).Error("failed to write audit log", "event", event, "error", err)
	}
}
