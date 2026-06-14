package response

// MessageResponse is a generic single-field message body (resend OTP, forgot/reset
// password) where the response is just human-readable confirmation text.
type MessageResponse struct {
	Message string `json:"message"`
}
