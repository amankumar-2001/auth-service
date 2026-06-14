package publicrouter

import (
	"net/http"

	"github.com/gin-gonic/gin"
	apperrors "github.com/kharchibook/auth-service/errors"
	"github.com/kharchibook/auth-service/pkg/domain/dto/request"
	"github.com/kharchibook/auth-service/utils"
)

func (h *AuthHandler) Login(c *gin.Context) {
	var ctx = c.Request.Context()
	var req request.LoginRequest
	
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.WriteError(c.Writer, apperrors.BadRequestError("invalid JSON body"))
		return
	}
	if err := req.Validate(); err != nil {
		utils.WriteError(c.Writer, apperrors.ValidationError(err))
		return
	}

	tokens, err := h.app.AuthService().Login(ctx, req, sessionContext(c))
	if err != nil {
		utils.WriteError(c.Writer, err)
		return
	}
	utils.WriteJSON(c.Writer, http.StatusOK, toTokenPair(tokens))
}
