// Package httpserver builds the application's HTTP handler: the global
// middleware chain plus the per-version route mounts.
package httpserver

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/kharchibook/auth-service/middleware"
	publicrouter "github.com/kharchibook/auth-service/pkg/application/httpserver/v1/public-router"
	"github.com/kharchibook/auth-service/pkg/di"
	"github.com/kharchibook/auth-service/utils"
)

// NewRouter assembles the HTTP handler from the application container.
func NewRouter(app di.AppInterface) http.Handler {
	// Quiet, production-friendly mode unless running the dev env.
	if app.Config().App.Env == "dev" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// Reject request bodies with unknown fields (matches the prior strict decoder).
	gin.EnableJsonDecoderDisallowUnknownFields()

	r := gin.New()

	// Global middleware chain (outermost first). RequestInfo derives the client
	// IP from X-Forwarded-For/X-Real-Ip for logging and the audit trail.
	r.Use(middleware.RequestInfo())
	r.Use(middleware.Recovery())
	r.Use(middleware.CORS())

	guard := middleware.NewGuard(app.TokenService(), app.RBACService())

	// Liveness/readiness.
	r.GET("/healthz", func(c *gin.Context) {
		utils.WriteJSON(c.Writer, http.StatusOK, map[string]string{"status": "ok"})
	})
	r.GET("/readyz", func(c *gin.Context) {
		if err := app.HealthCheck(c.Request.Context()); err != nil {
			utils.WriteJSON(c.Writer, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
			return
		}
		utils.WriteJSON(c.Writer, http.StatusOK, map[string]string{"status": "ready"})
	})

	// V1 routes.
	mountV1(r.Group("/v1"), app, guard)

	return r
}

// mountV1 wires the V1 public router. Internal/admin routers (V2+) mount here as
// the service grows.
func mountV1(r *gin.RouterGroup, app di.AppInterface, guard *middleware.Guard) {
	authHandler := publicrouter.NewAuthHandler(app)
	profileHandler := publicrouter.NewProfileHandler(app)
	internalHandler := publicrouter.NewInternalHandler(app)
	gmailHandler := publicrouter.NewGmailHandler(app)

	auth := r.Group("/public/auth")

	// Public, unauthenticated endpoints.
	authHandler.Routes(auth)

	// JWT verification key for gateways/services.
	auth.GET("/.well-known/public-key", profileHandler.PublicKey)

	// Protected endpoints (require a valid access token — guard stays visible here).
	auth.GET("/me", guard.JWT, profileHandler.Me)

	// Gmail connect: the user starts the flow authenticated (JWT); Google's
	// callback is public (no JWT) but trusted via the signed state.
	auth.GET("/google/gmail/connect", guard.JWT, gmailHandler.Connect)
	auth.GET("/google/gmail/status", guard.JWT, gmailHandler.Status)
	auth.GET("/google/gmail/callback", gmailHandler.Callback)

	// Service-to-service endpoints, authenticated by the shared internal key.
	internal := r.Group("/internal", guard.ServiceAuth(app.Config().Internal.APIKey))
	internal.GET("/users/by-phone", internalHandler.UserByPhone)
	internal.GET("/gmail/access-token", gmailHandler.InternalAccessToken)
}
