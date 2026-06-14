package response

// OTPVerifyResponse is the 200 body for POST /auth/otp/verify.
type OTPVerifyResponse struct {
	Verified bool `json:"verified"`
}
