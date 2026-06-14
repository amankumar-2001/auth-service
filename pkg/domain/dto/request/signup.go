package request

import (
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

// SignUpRequest is the POST /auth/signup body.
type SignUpRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Phone    string `json:"phone"`
}

func (r SignUpRequest) Validate() error {
	return validation.ValidateStruct(&r,
		validation.Field(&r.Email, validation.Required, is.Email),
		validation.Field(&r.Password, passwordRules()...),
		validation.Field(&r.Phone, validation.When(r.Phone != "", is.E164.Error("must be E.164 format, e.g. +919876543210"))),
	)
}
