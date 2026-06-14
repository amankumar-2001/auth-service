package publicrouter

import (
	"net/http"

	"github.com/gin-gonic/gin"
	apperrors "github.com/kharchibook/auth-service/errors"
	"github.com/kharchibook/auth-service/utils"
)

func (h *AuthHandler) GoogleCallback(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		utils.WriteError(c.Writer, apperrors.BadRequestError("missing authorization code"))
		return
	}
	tokens, err := h.app.AuthService().GoogleCallback(c.Request.Context(), code, sessionContext(c))
	if err != nil {
		utils.WriteError(c.Writer, err)
		return
	}
	utils.WriteJSON(c.Writer, http.StatusOK, toTokenPair(tokens))
}
