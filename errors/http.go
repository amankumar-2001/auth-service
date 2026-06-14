// Package errors provides a typed HTTP error with factory functions, so handlers
// can return errors that carry the right status code and a safe client message.
package errors

import (
	"errors"
	"fmt"
	"net/http"
)

// IHttpError is an error that knows its HTTP status code and a client-safe message.
type IHttpError interface {
	error
	StatusCode() int
	// Message is the client-safe message (never leaks internal detail).
	Message() string
	// Code is a short machine-readable error code.
	Code() string
}

type httpError struct {
	status  int
	code    string
	message string
	// wrapped is the underlying cause; logged server-side, never sent to clients.
	wrapped error
}

func (e *httpError) Error() string {
	if e.wrapped != nil {
		return fmt.Sprintf("%s (%d): %s: %v", e.code, e.status, e.message, e.wrapped)
	}
	return fmt.Sprintf("%s (%d): %s", e.code, e.status, e.message)
}

func (e *httpError) StatusCode() int { return e.status }
func (e *httpError) Message() string { return e.message }
func (e *httpError) Code() string    { return e.code }
func (e *httpError) Unwrap() error   { return e.wrapped }

func newError(status int, code, message string, wrapped error) IHttpError {
	return &httpError{status: status, code: code, message: message, wrapped: wrapped}
}

// BadRequestError → 400.
func BadRequestError(message string) IHttpError {
	return newError(http.StatusBadRequest, "BAD_REQUEST", message, nil)
}

// ValidationError → 400 for invalid input, wrapping the validation cause.
func ValidationError(err error) IHttpError {
	return newError(http.StatusBadRequest, "VALIDATION_ERROR", err.Error(), err)
}

// UnauthorizedError → 401.
func UnauthorizedError(message string) IHttpError {
	return newError(http.StatusUnauthorized, "UNAUTHORIZED", message, nil)
}

// ForbiddenError → 403.
func ForbiddenError(message string) IHttpError {
	return newError(http.StatusForbidden, "FORBIDDEN", message, nil)
}

// NotFoundError → 404.
func NotFoundError(message string) IHttpError {
	return newError(http.StatusNotFound, "NOT_FOUND", message, nil)
}

// ConflictError → 409.
func ConflictError(message string) IHttpError {
	return newError(http.StatusConflict, "CONFLICT", message, nil)
}

// LockedError → 423 (account/credential temporarily locked).
func LockedError(message string) IHttpError {
	return newError(http.StatusLocked, "LOCKED", message, nil)
}

// TooManyRequestsError → 429.
func TooManyRequestsError(message string) IHttpError {
	return newError(http.StatusTooManyRequests, "TOO_MANY_REQUESTS", message, nil)
}

// InternalServerError → 500. The cause is logged, never sent to the client.
func InternalServerError(cause error) IHttpError {
	return newError(http.StatusInternalServerError, "INTERNAL_ERROR", "something went wrong", cause)
}

// AsHTTP coerces any error into an IHttpError, defaulting to 500.
func AsHTTP(err error) IHttpError {
	if err == nil {
		return nil
	}
	var he IHttpError
	if errors.As(err, &he) {
		return he
	}
	return InternalServerError(err)
}
