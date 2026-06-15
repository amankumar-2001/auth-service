package publicrouter

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/kharchibook/auth-service/constants"
	apperrors "github.com/kharchibook/auth-service/errors"
	"github.com/kharchibook/auth-service/pkg/di"
	"github.com/kharchibook/auth-service/utils"
)

// ProfileHandler serves endpoints about the authenticated user. Its routes must
// be mounted behind the JWT guard.
type ProfileHandler struct {
	app di.AppInterface
}

// NewProfileHandler constructs the profile handler.
func NewProfileHandler(app di.AppInterface) *ProfileHandler {
	return &ProfileHandler{app: app}
}

type meResponse struct {
	UserID   int64    `json:"userId"`
	Email    string   `json:"email"`
	Name     string   `json:"name"`
	Verified bool     `json:"verified"`
	Provider string   `json:"provider"`
	Roles    []string `json:"roles"`
}

// Me returns the current user's identity, derived from the validated JWT plus a
// fresh account lookup.
func (h *ProfileHandler) Me(c *gin.Context) {
	ctx := c.Request.Context()
	uid, ok := ctx.Value(constants.CtxUserID).(int64)
	if !ok || uid == 0 {
		utils.WriteError(c.Writer, apperrors.UnauthorizedError("unauthenticated"))
		return
	}
	user, err := h.app.AccountService().GetByID(ctx, uid)
	if err != nil {
		if apperrors.Is(err, apperrors.ErrNotFound) {
			utils.WriteError(c.Writer, apperrors.NotFoundError("user not found"))
			return
		}
		utils.WriteError(c.Writer, err)
		return
	}
	roles, err := h.app.RBACService().GetUserRoles(ctx, uid)
	if err != nil {
		utils.WriteError(c.Writer, err)
		return
	}
	utils.WriteJSON(c.Writer, http.StatusOK, meResponse{
		UserID:   user.ID,
		Email:    user.Email,
		Name:     user.Name,
		Verified: user.Verified,
		Provider: user.Provider,
		Roles:    roles,
	})
}

// PublicKey exposes the JWT verification public key (PEM). A gateway or
// downstream service fetches this once to verify access tokens locally with no
// per-request call back to auth-service.
func (h *ProfileHandler) PublicKey(c *gin.Context) {
	pem := h.app.TokenService().PublicKeyPEM()
	c.Writer.Header().Set("Content-Type", "application/x-pem-file")
	c.Writer.Header().Set("Content-Length", strconv.Itoa(len(pem)))
	c.Writer.WriteHeader(http.StatusOK)
	_, _ = c.Writer.Write([]byte(pem))
}
