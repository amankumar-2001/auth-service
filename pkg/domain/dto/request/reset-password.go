package request

import validation "github.com/go-ozzo/ozzo-validation/v4"

// ResetPasswordRequest is the POST /auth/password/reset body.
type ResetPasswordRequest struct {
	ResetToken  string `json:"resetToken"`
	NewPassword string `json:"newPassword"`
}

func (r ResetPasswordRequest) Validate() error {
	return validation.ValidateStruct(&r,
		validation.Field(&r.ResetToken, validation.Required),
		validation.Field(&r.NewPassword, passwordRules()...),
	)
}
