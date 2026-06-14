// Package eventtype enumerates the security-relevant audit event types.
package eventtype

// EventType is a security-audit event classifier.
type EventType string

const (
	LoginSuccess    EventType = "LOGIN_SUCCESS"
	LoginFail       EventType = "LOGIN_FAIL"
	Logout          EventType = "LOGOUT"
	Signup          EventType = "SIGNUP"
	OTPSent         EventType = "OTP_SENT"
	OTPVerified     EventType = "OTP_VERIFIED"
	OTPFail         EventType = "OTP_FAIL"
	PwdResetRequest EventType = "PWD_RESET_REQUEST"
	PwdResetSuccess EventType = "PWD_RESET_SUCCESS"
	TokenRefresh    EventType = "TOKEN_REFRESH"
	TokenReuse      EventType = "TOKEN_REUSE_DETECTED"
	SessionRevoked  EventType = "SESSION_REVOKED"
	RoleChange      EventType = "ROLE_CHANGE"
	AccountLocked   EventType = "ACCOUNT_LOCKED"
	SocialLogin     EventType = "SOCIAL_LOGIN"
)

func (e EventType) String() string { return string(e) }
