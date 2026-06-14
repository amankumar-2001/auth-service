// Package middleware holds the HTTP middleware chain: request metadata
// extraction, panic recovery, CORS, and the auth guards.
package middleware

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/kharchibook/auth-service/constants"
)

// RequestInfo extracts correlation + client metadata (request ID, device ID, IP,
// user agent) from headers into the request context, so downstream services and
// the audit logger can read them via utils.GetFromContext.
func RequestInfo() gin.HandlerFunc {
	return func(c *gin.Context) {
		r := c.Request
		reqID := r.Header.Get(constants.HeaderRequestID)
		if reqID == "" {
			reqID = uuid.NewString()
		}
		c.Writer.Header().Set(constants.HeaderRequestID, reqID)

		ctx := r.Context()
		ctx = context.WithValue(ctx, constants.CtxRequestID, reqID)
		ctx = context.WithValue(ctx, constants.CtxDeviceID, r.Header.Get(constants.HeaderDeviceID))
		ctx = context.WithValue(ctx, constants.CtxUserAgent, r.Header.Get(constants.HeaderUserAgent))
		ctx = context.WithValue(ctx, constants.CtxIPAddress, clientIP(r))

		c.Request = r.WithContext(ctx)
		c.Next()
	}
}

// clientIP resolves the originating client IP, trusting X-Forwarded-For /
// X-Real-Ip (set by the gateway/load balancer) before falling back to the socket.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get(constants.HeaderForwardedFor); xff != "" {
		// First entry is the original client.
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if rip := r.Header.Get(constants.HeaderRealIP); rip != "" {
		return rip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
