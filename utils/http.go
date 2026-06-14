package utils

import (
	"encoding/json"
	"net/http"

	apperrors "github.com/kharchibook/auth-service/errors"
	"github.com/kharchibook/auth-service/third_party/platlogger"
)

// envelope is the uniform JSON error shape returned to clients.
type envelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// WriteJSON writes v as a JSON response with the given status code.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		platlogger.Error("failed to encode response", "error", err)
	}
}

// WriteError maps any error to its HTTP status + client-safe body, logging the
// underlying cause server-side for 5xx errors.
func WriteError(w http.ResponseWriter, err error) {
	he := apperrors.AsHTTP(err)
	if he.StatusCode() >= http.StatusInternalServerError {
		platlogger.Error("request failed", "code", he.Code(), "error", he.Error())
	}
	var body envelope
	body.Error.Code = he.Code()
	body.Error.Message = he.Message()
	WriteJSON(w, he.StatusCode(), body)
}
