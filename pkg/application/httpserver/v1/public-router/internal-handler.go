package publicrouter

import (
	"net/http"

	"github.com/gin-gonic/gin"
	apperrors "github.com/kharchibook/auth-service/errors"
	"github.com/kharchibook/auth-service/pkg/di"
	"github.com/kharchibook/auth-service/utils"
)

// InternalHandler serves service-to-service endpoints under /v1/internal. Its
// routes must be mounted behind the ServiceAuth guard (shared-secret header),
// never exposed publicly.
type InternalHandler struct {
	app di.AppInterface
}

// NewInternalHandler constructs the internal handler.
func NewInternalHandler(app di.AppInterface) *InternalHandler {
	return &InternalHandler{app: app}
}

type userByPhoneResponse struct {
	UserID int64  `json:"userId"`
	Name   string `json:"name"`
}

// UserByPhone resolves a user by phone number for trusted callers (the WhatsApp
// worker). Returns 404 when the phone is not registered. The phone is matched via
// the phone_hash blind index, normalized to E.164 first.
func (h *InternalHandler) UserByPhone(c *gin.Context) {
	phone := c.Query("phone")
	if phone == "" {
		utils.WriteError(c.Writer, apperrors.BadRequestError("phone is required"))
		return
	}
	user, err := h.app.AccountService().GetByPhone(c.Request.Context(), phone)
	if err != nil {
		if apperrors.Is(err, apperrors.ErrNotFound) {
			utils.WriteError(c.Writer, apperrors.NotFoundError("phone not registered"))
			return
		}
		utils.WriteError(c.Writer, err)
		return
	}
	utils.WriteJSON(c.Writer, http.StatusOK, userByPhoneResponse{
		UserID: user.ID,
		Name:   user.Name,
	})
}
