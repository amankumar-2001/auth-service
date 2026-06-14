// Package publicrouter holds the V1 public (client-facing) HTTP handlers.
package publicrouter

import (
	"github.com/gin-gonic/gin"
	"github.com/kharchibook/auth-service/constants"
	"github.com/kharchibook/auth-service/pkg/di"
	"github.com/kharchibook/auth-service/pkg/domain/dto/entity"
	"github.com/kharchibook/auth-service/pkg/domain/dto/response"
	"github.com/kharchibook/auth-service/utils"
)

// AuthHandler serves the /auth/* endpoints.
type AuthHandler struct {
	app di.AppInterface
}

// NewAuthHandler constructs the auth handler.
func NewAuthHandler(app di.AppInterface) *AuthHandler {
	return &AuthHandler{app: app}
}

// Routes mounts the auth routes onto the given router group.
func (h *AuthHandler) Routes(r gin.IRouter) {
	r.POST("/signup", h.SignUp)
	r.POST("/login", h.Login)
	r.POST("/otp/verify", h.VerifyOTP)
	r.POST("/otp/resend", h.ResendOTP)
	r.POST("/token/refresh", h.RefreshToken)
	r.POST("/logout", h.Logout)
	r.POST("/password/forgot", h.ForgotPassword)
	r.POST("/password/reset", h.ResetPassword)
	r.GET("/oauth/google", h.GoogleRedirect)
	r.GET("/oauth/google/callback", h.GoogleCallback)
}

// ---- shared helpers ---------------------------------------------------------

// sessionContext pulls the request metadata captured by the RequestInfo
// middleware into the value object services expect.
func sessionContext(c *gin.Context) entity.SessionContext {
	ctx := c.Request.Context()
	return entity.SessionContext{
		DeviceID:  utils.GetFromContext(ctx, constants.CtxDeviceID),
		IPAddress: utils.GetFromContext(ctx, constants.CtxIPAddress),
		UserAgent: utils.GetFromContext(ctx, constants.CtxUserAgent),
	}
}

func toTokenPair(t entity.IssuedTokens) response.TokenPairResponse {
	return response.TokenPairResponse{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		ExpiresIn:    t.ExpiresIn,
		TokenType:    "Bearer",
	}
}
