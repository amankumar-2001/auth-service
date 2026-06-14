package publicrouter

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/kharchibook/auth-service/utils"
)

func (h *AuthHandler) GoogleRedirect(c *gin.Context) {
	// state should be a CSRF token bound to the session; a static placeholder is
	// used here as the demo build has no server-side OAuth state store.
	url, err := h.app.AuthService().GoogleAuthURL("state")
	if err != nil {
		utils.WriteError(c.Writer, err)
		return
	}
	c.Redirect(http.StatusFound, url)
}
