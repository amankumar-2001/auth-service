// Package platlogger is a thin wrapper around the standard library slog,
// mirroring the internal platform-logger interface used across services. It
// provides structured logging with a request-correlation field and is the only
// logging entry point the rest of the codebase imports.
package platlogger

import (
	"context"
	"log/slog"
	"os"

	"github.com/kharchibook/auth-service/constants"
)

var logger *slog.Logger

func init() {
	// Default to JSON structured logs at info level. Init replaces this once
	// config is available.
	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// Init configures the global logger. level is one of debug|info|warn|error.
func Init(serviceName, level string) {
	lvl := slog.LevelInfo
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}
	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})
	logger = slog.New(h).With("service", serviceName)
}

func Debug(msg string, args ...any) { logger.Debug(msg, args...) }
func Info(msg string, args ...any)  { logger.Info(msg, args...) }
func Warn(msg string, args ...any)  { logger.Warn(msg, args...) }
func Error(msg string, args ...any) { logger.Error(msg, args...) }

// WithContext returns a logger enriched with the request ID from the context,
// so every log line during a request is correlatable.
func WithContext(ctx context.Context) *slog.Logger {
	if rid, ok := ctx.Value(constants.CtxRequestID).(string); ok && rid != "" {
		return logger.With("requestID", rid)
	}
	return logger
}
