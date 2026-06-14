package publicrouter

import (
	"net/http"

	"github.com/gin-gonic/gin"
	apperrors "github.com/kharchibook/auth-service/errors"
	"github.com/kharchibook/auth-service/pkg/domain/dto/request"
	"github.com/kharchibook/auth-service/utils"
)

func (h *AuthHandler) SignUp(c *gin.Context) {
	var ctx = c.Request.Context()
	var req request.SignUpRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.WriteError(c.Writer, apperrors.BadRequestError("invalid JSON body"))
		return
	}
	if err := req.Validate(); err != nil {
		utils.WriteError(c.Writer, apperrors.ValidationError(err))
		return
	}

	svc := h.app.AuthService()
	res, err := svc.SignUp(ctx, req)

	if err != nil {
		utils.WriteError(c.Writer, err)
		return
	}
	utils.WriteJSON(c.Writer, http.StatusCreated, res)
}
