// Package response holds outbound response DTOs — one file per API response,
// plus the shared bodies (TokenPairResponse, Message) reused across several endpoints.
package response

// TokenPairResponse is the standard token-issuance body (login, refresh, social login).
type TokenPairResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    int64  `json:"expiresIn"` // access-token lifetime in seconds
	TokenType    string `json:"tokenType"`
}
