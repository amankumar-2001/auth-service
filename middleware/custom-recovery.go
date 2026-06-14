package middleware

import (
	"runtime/debug"

	"github.com/gin-gonic/gin"
	apperrors "github.com/kharchibook/auth-service/errors"
	"github.com/kharchibook/auth-service/third_party/platlogger"
	"github.com/kharchibook/auth-service/utils"
)

// Recovery converts any panic in a downstream handler into a 500 response,
// logging the stack trace so a single bad request can't take the server down.
func Recovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if rec := recover(); rec != nil {
				platlogger.WithContext(c.Request.Context()).Error("panic recovered",
					"panic", rec, "stack", string(debug.Stack()))
				utils.WriteError(c.Writer, apperrors.InternalServerError(nil))
				c.Abort()
			}
		}()
		c.Next()
	}
}
