package request

import (
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

// OTPResendRequest is the POST /auth/otp/resend body.
type OTPResendRequest struct {
	Email string `json:"email"`
}

func (r OTPResendRequest) Validate() error {
	return validation.ValidateStruct(&r,
		validation.Field(&r.Email, validation.Required, is.Email),
	)
}
