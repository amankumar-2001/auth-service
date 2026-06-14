package request

import (
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

// OTPVerifyRequest is the POST /auth/otp/verify body.
type OTPVerifyRequest struct {
	Email string `json:"email"`
	OTP   string `json:"otp"`
}

func (r OTPVerifyRequest) Validate() error {
	return validation.ValidateStruct(&r,
		validation.Field(&r.Email, validation.Required, is.Email),
		validation.Field(&r.OTP, validation.Required, validation.Length(4, 8), is.Digit),
	)
}
