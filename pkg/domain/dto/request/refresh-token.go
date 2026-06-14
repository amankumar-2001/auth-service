package request

import validation "github.com/go-ozzo/ozzo-validation/v4"

// RefreshTokenRequest is the POST /auth/token/refresh body.
type RefreshTokenRequest struct {
	RefreshToken string `json:"refreshToken"`
}

func (r RefreshTokenRequest) Validate() error {
	return validation.ValidateStruct(&r,
		validation.Field(&r.RefreshToken, validation.Required),
	)
}
