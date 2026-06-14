// Package clienttype enumerates the OTP delivery channels.
package clienttype

// Medium is the channel an OTP / notification is delivered over.
type Medium string

const (
	Email Medium = "email"
	SMS   Medium = "sms"
)

func (m Medium) String() string { return string(m) }
