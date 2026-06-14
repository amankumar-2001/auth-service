package publicrouter

import (
	"net/http"

	"github.com/gin-gonic/gin"
	apperrors "github.com/kharchibook/auth-service/errors"
	"github.com/kharchibook/auth-service/pkg/domain/dto/request"
	"github.com/kharchibook/auth-service/pkg/domain/dto/response"
	"github.com/kharchibook/auth-service/utils"
)

func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var ctx = c.Request.Context()
	var req request.ForgotPasswordRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.WriteError(c.Writer, apperrors.BadRequestError("invalid JSON body"))
		return
	}
	if err := req.Validate(); err != nil {
		utils.WriteError(c.Writer, apperrors.ValidationError(err))
		return
	}

	if err := h.app.AuthService().ForgotPassword(ctx, req); err != nil {
		utils.WriteError(c.Writer, err)
		return
	}
	// Always non-enumerable.
	utils.WriteJSON(c.Writer, http.StatusOK, response.MessageResponse{Message: "If the account exists, a reset link was sent"})
}
