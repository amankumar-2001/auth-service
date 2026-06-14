package sqlrepo

import (
	"context"
	"errors"
	"fmt"

	apperrors "github.com/kharchibook/auth-service/errors"
	"github.com/kharchibook/auth-service/pkg/domain/models/dao"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// IRBACRepository is the persistence contract for roles, permissions, and their
// assignment to users.
type IRBACRepository interface {
	GetRoleByName(ctx context.Context, name string) (*dao.Role, error)
	AssignRoleToUser(ctx context.Context, userID, roleID int64) error
	GetUserRoleNames(ctx context.Context, userID int64) ([]string, error)
	GetPermissionsForRoles(ctx context.Context, roleNames []string) ([]string, error)
}

type rbacRepository struct {
	db *gorm.DB
}

// NewRBACRepository constructs the GORM RBAC repository.
func NewRBACRepository(db *gorm.DB) IRBACRepository {
	return &rbacRepository{db: db}
}

func (r *rbacRepository) GetRoleByName(ctx context.Context, name string) (*dao.Role, error) {
	var role dao.Role
	err := r.db.WithContext(ctx).Where("name = ?", name).First(&role).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("query role: %w", err)
	}
	return &role, nil
}

func (r *rbacRepository) AssignRoleToUser(ctx context.Context, userID, roleID int64) error {
	ur := dao.UserRole{UserID: userID, RoleID: roleID}
	err := r.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&ur).Error
	if err != nil {
		return fmt.Errorf("assign role to user: %w", err)
	}
	return nil
}

func (r *rbacRepository) GetUserRoleNames(ctx context.Context, userID int64) ([]string, error) {
	var names []string
	err := r.db.WithContext(ctx).
		Table("roles").
		Joins("JOIN user_roles ur ON ur.role_id = roles.id").
		Where("ur.user_id = ?", userID).
		Pluck("roles.name", &names).Error
	if err != nil {
		return nil, fmt.Errorf("query user roles: %w", err)
	}
	return names, nil
}

func (r *rbacRepository) GetPermissionsForRoles(ctx context.Context, roleNames []string) ([]string, error) {
	if len(roleNames) == 0 {
		return nil, nil
	}
	var perms []string
	err := r.db.WithContext(ctx).
		Table("permissions").
		Distinct("permissions.name").
		Joins("JOIN role_permissions rp ON rp.permission_id = permissions.id").
		Joins("JOIN roles ON roles.id = rp.role_id").
		Where("roles.name IN ?", roleNames).
		Pluck("permissions.name", &perms).Error
	if err != nil {
		return nil, fmt.Errorf("query permissions: %w", err)
	}
	return perms, nil
}
