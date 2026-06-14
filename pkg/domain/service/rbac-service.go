package service

import (
	"context"
	"fmt"

	apperrors "github.com/kharchibook/auth-service/errors"
	"github.com/kharchibook/auth-service/pkg/infrastructure/sqlrepo"
)

// IRBACService resolves a user's roles/permissions and assigns roles.
type IRBACService interface {
	GetUserRoles(ctx context.Context, userID int64) ([]string, error)
	AssignRole(ctx context.Context, userID int64, roleName string) error
	// HasPermission reports whether any of the given role names grants the
	// permission. Used by the role guard for sensitive routes.
	HasPermission(ctx context.Context, roleNames []string, permission string) (bool, error)
}

type rbacService struct {
	repo sqlrepo.IRBACRepository
}

// NewRBACService constructs the RBAC service.
func NewRBACService(repo sqlrepo.IRBACRepository) IRBACService {
	return &rbacService{repo: repo}
}

func (s *rbacService) GetUserRoles(ctx context.Context, userID int64) ([]string, error) {
	return s.repo.GetUserRoleNames(ctx, userID)
}

func (s *rbacService) AssignRole(ctx context.Context, userID int64, roleName string) error {
	role, err := s.repo.GetRoleByName(ctx, roleName)
	if err != nil {
		if apperrors.Is(err, apperrors.ErrNotFound) {
			return apperrors.BadRequestError(fmt.Sprintf("unknown role %q", roleName))
		}
		return err
	}
	return s.repo.AssignRoleToUser(ctx, userID, role.ID)
}

func (s *rbacService) HasPermission(ctx context.Context, roleNames []string, permission string) (bool, error) {
	perms, err := s.repo.GetPermissionsForRoles(ctx, roleNames)
	if err != nil {
		return false, err
	}
	for _, p := range perms {
		if p == permission {
			return true, nil
		}
	}
	return false, nil
}
