// Package message holds the event payloads published to the message queue.
package message

import "github.com/kharchibook/auth-service/enums/clienttype"

// OTPNotification is the event published to Kafka for the Notification Worker to
// deliver an OTP via an SMS/Email provider.
type OTPNotification struct {
	Medium    clienttype.Medium `json:"medium"`
	Recipient string            `json:"recipient"`
	OTP       string            `json:"otp"`
	Purpose   string            `json:"purpose"`
}

// PasswordResetNotification is the event published to deliver a reset link.
type PasswordResetNotification struct {
	Email     string `json:"email"`
	ResetLink string `json:"resetLink"`
}
