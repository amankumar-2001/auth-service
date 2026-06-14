package request

import validation "github.com/go-ozzo/ozzo-validation/v4"

// LogoutRequest is the POST /auth/logout body.
type LogoutRequest struct {
	RefreshToken string `json:"refreshToken"`
	AllSessions  bool   `json:"allSessions"`
}

func (r LogoutRequest) Validate() error {
	return validation.ValidateStruct(&r,
		validation.Field(&r.RefreshToken, validation.Required),
	)
}
