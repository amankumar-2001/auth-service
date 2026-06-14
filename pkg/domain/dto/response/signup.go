package response

// SignUpResponse is the 201 body for POST /auth/signup.
type SignUpResponse struct {
	UserID   string `json:"userId"`
	Verified bool   `json:"verified"`
	Message  string `json:"message"`
}
