package middleware

import (
	"context"
	"crypto/subtle"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/kharchibook/auth-service/constants"
	apperrors "github.com/kharchibook/auth-service/errors"
	"github.com/kharchibook/auth-service/pkg/domain/service"
	"github.com/kharchibook/auth-service/utils"
)

// Guard holds the dependencies for the auth guards.
type Guard struct {
	tokens service.ITokenService
	rbac   service.IRBACService
}

// NewGuard constructs the auth guard middleware factory.
func NewGuard(tokens service.ITokenService, rbac service.IRBACService) *Guard {
	return &Guard{tokens: tokens, rbac: rbac}
}

// JWT verifies the Bearer access token locally (signature + expiry, no DB call)
// and attaches userID, roles, sessionID, and verified to the request context.
// This is the defense-in-depth equivalent of the API Gateway's global check.
func (g *Guard) JWT(c *gin.Context) {
	header := c.Request.Header.Get(constants.HeaderAuthorization)
	if !strings.HasPrefix(header, constants.BearerPrefix) {
		utils.WriteError(c.Writer, apperrors.UnauthorizedError("missing or malformed Authorization header"))
		c.Abort()
		return
	}
	raw := strings.TrimPrefix(header, constants.BearerPrefix)

	claims, err := g.tokens.ParseAccessToken(raw)
	if err != nil {
		utils.WriteError(c.Writer, err)
		c.Abort()
		return
	}

	ctx := c.Request.Context()
	ctx = context.WithValue(ctx, constants.CtxUserID, claims.UserID)
	ctx = context.WithValue(ctx, constants.CtxSessionID, claims.SessionID)
	ctx = context.WithValue(ctx, constants.CtxRoles, claims.Roles)
	ctx = context.WithValue(ctx, constants.CtxVerified, claims.Verified)
	c.Request = c.Request.WithContext(ctx)
	c.Next()
}

// ServiceAuth returns middleware that authenticates trusted service-to-service
// callers (e.g. expense-service's WhatsApp worker) via a shared secret in the
// X-Internal-Key header, compared in constant time. An empty configured key
// rejects all callers, so the internal routes fail closed if misconfigured.
func (g *Guard) ServiceAuth(expectedKey string) gin.HandlerFunc {
	want := []byte(expectedKey)
	return func(c *gin.Context) {
		got := []byte(c.Request.Header.Get(constants.HeaderInternalKey))
		if len(want) == 0 || subtle.ConstantTimeCompare(got, want) != 1 {
			utils.WriteError(c.Writer, apperrors.UnauthorizedError("invalid service credentials"))
			c.Abort()
			return
		}
		c.Next()
	}
}

// RequireVerified rejects users that have not completed OTP/email verification.
// Place after JWT for sensitive routes.
func (g *Guard) RequireVerified(c *gin.Context) {
	if !utils.GetVerifiedFromContext(c.Request.Context()) {
		utils.WriteError(c.Writer, apperrors.ForbiddenError("account verification required"))
		c.Abort()
		return
	}
	c.Next()
}

// RequireRole returns middleware that requires the caller to hold at least one of
// the given roles (read from the JWT — fast, no DB call).
func (g *Guard) RequireRole(roles ...string) gin.HandlerFunc {
	want := make(map[string]struct{}, len(roles))
	for _, r := range roles {
		want[r] = struct{}{}
	}
	return func(c *gin.Context) {
		for _, have := range utils.GetRolesFromContext(c.Request.Context()) {
			if _, ok := want[have]; ok {
				c.Next()
				return
			}
		}
		utils.WriteError(c.Writer, apperrors.ForbiddenError("insufficient role"))
		c.Abort()
	}
}

// RequirePermission returns middleware that re-checks a granular permission
// against the DB (RBAC service). Use for sensitive admin actions where the
// JWT-embedded roles aren't trusted enough on their own.
func (g *Guard) RequirePermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		roles := utils.GetRolesFromContext(c.Request.Context())
		ok, err := g.rbac.HasPermission(c.Request.Context(), roles, permission)
		if err != nil {
			utils.WriteError(c.Writer, err)
			c.Abort()
			return
		}
		if !ok {
			utils.WriteError(c.Writer, apperrors.ForbiddenError("insufficient permission"))
			c.Abort()
			return
		}
		c.Next()
	}
}
