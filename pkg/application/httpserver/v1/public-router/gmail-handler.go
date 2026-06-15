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

// GmailHandler serves the Gmail-connect OAuth flow (public, user-facing) and the
// internal access-token endpoint (service-to-service).
type GmailHandler struct {
	app di.AppInterface
}

// NewGmailHandler constructs the Gmail handler.
func NewGmailHandler(app di.AppInterface) *GmailHandler {
	return &GmailHandler{app: app}
}

type gmailConnectResponse struct {
	AuthURL string `json:"authUrl"`
}

// Connect (JWT-guarded) returns the Google consent URL for the authenticated
// user (with their id bound into a signed state). It returns JSON rather than a
// 302 because the SPA carries its JWT in the Authorization header — it performs
// the redirect client-side.
func (h *GmailHandler) Connect(c *gin.Context) {
	ctx := c.Request.Context()
	uid, ok := ctx.Value(constants.CtxUserID).(int64)
	if !ok || uid == 0 {
		utils.WriteError(c.Writer, apperrors.UnauthorizedError("unauthenticated"))
		return
	}
	url, err := h.app.GmailTokenService().ConnectURL(uid)
	if err != nil {
		utils.WriteError(c.Writer, err)
		return
	}
	utils.WriteJSON(c.Writer, http.StatusOK, gmailConnectResponse{AuthURL: url})
}

type gmailStatusResponse struct {
	Connected bool   `json:"connected"`
	Scope     string `json:"scope,omitempty"`
}

// Status (JWT-guarded) reports whether the current user has Gmail connected.
// This is the read-back that confirms a token was actually stored.
func (h *GmailHandler) Status(c *gin.Context) {
	ctx := c.Request.Context()
	uid, ok := ctx.Value(constants.CtxUserID).(int64)
	if !ok || uid == 0 {
		utils.WriteError(c.Writer, apperrors.UnauthorizedError("unauthenticated"))
		return
	}
	connected, scope, err := h.app.GmailTokenService().Status(ctx, uid)
	if err != nil {
		utils.WriteError(c.Writer, err)
		return
	}
	utils.WriteJSON(c.Writer, http.StatusOK, gmailStatusResponse{Connected: connected, Scope: scope})
}

// Callback (public) is where Google returns after consent. It verifies the
// signed state, stores the tokens, then sends the browser to the configured web
// URL (or renders a plain success page).
func (h *GmailHandler) Callback(c *gin.Context) {
	if e := c.Query("error"); e != "" {
		utils.WriteError(c.Writer, apperrors.BadRequestError("authorization denied: "+e))
		return
	}
	code := c.Query("code")
	state := c.Query("state")
	if code == "" || state == "" {
		utils.WriteError(c.Writer, apperrors.BadRequestError("missing code or state"))
		return
	}
	if _, err := h.app.GmailTokenService().HandleCallback(c.Request.Context(), code, state); err != nil {
		utils.WriteError(c.Writer, err)
		return
	}

	if dest := h.app.Config().OAuth.Google.GmailConnectedURL; dest != "" {
		c.Redirect(http.StatusFound, dest)
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8",
		[]byte("<h2>Gmail connected ✓</h2>You can close this tab."))
}

type gmailAccessTokenResponse struct {
	AccessToken string `json:"accessToken"`
	Expiry      string `json:"expiry"`
}

// InternalAccessToken (ServiceAuth-guarded) returns a currently-valid Gmail
// access token for the given user, refreshing transparently. Consumed by
// mcp-gateway. Query: ?userId=<id>.
func (h *GmailHandler) InternalAccessToken(c *gin.Context) {
	uid, err := strconv.ParseInt(c.Query("userId"), 10, 64)
	if err != nil || uid <= 0 {
		utils.WriteError(c.Writer, apperrors.BadRequestError("valid userId is required"))
		return
	}
	token, expiry, err := h.app.GmailTokenService().AccessToken(c.Request.Context(), uid)
	if err != nil {
		utils.WriteError(c.Writer, err)
		return
	}
	utils.WriteJSON(c.Writer, http.StatusOK, gmailAccessTokenResponse{
		AccessToken: token,
		Expiry:      expiry.UTC().Format("2006-01-02T15:04:05Z07:00"),
	})
}
