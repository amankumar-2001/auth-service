package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// CORS applies permissive cross-origin headers suitable for local development.
// In production the allowed origin should be restricted via configuration.
func CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Request-Id, X-Device-Id")
		h.Set("Access-Control-Max-Age", "300")

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
