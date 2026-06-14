package request

import (
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

// ForgotPasswordRequest is the POST /auth/password/forgot body.
type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

func (r ForgotPasswordRequest) Validate() error {
	return validation.ValidateStruct(&r,
		validation.Field(&r.Email, validation.Required, is.Email),
	)
}
