package msgqueuerepo

import "fmt"

// Shared email subject + HTML body builders, used by every email-backed
// publisher (SMTP, Resend) so the wire format stays identical regardless of the
// delivery transport.

// otpEmailContent renders the OTP verification email.
func otpEmailContent(otp string) (subject, html string) {
	subject = "Your KharchiBook verification code"
	html = fmt.Sprintf(
		`<div style="font-family:system-ui,Arial,sans-serif;max-width:440px;margin:auto">`+
			`<h2 style="color:#059669">KharchiBook</h2>`+
			`<p>Your verification code is:</p>`+
			`<p style="font-size:32px;font-weight:700;letter-spacing:6px">%s</p>`+
			`<p style="color:#78716c">This code expires in a few minutes. If you didn't request it, ignore this email.</p>`+
			`</div>`, otp)
	return subject, html
}

// passwordResetEmailContent renders the password-reset email.
func passwordResetEmailContent(resetLink string) (subject, html string) {
	subject = "Reset your KharchiBook password"
	html = fmt.Sprintf(
		`<div style="font-family:system-ui,Arial,sans-serif;max-width:440px;margin:auto">`+
			`<h2 style="color:#059669">KharchiBook</h2>`+
			`<p>Click below to reset your password:</p>`+
			`<p><a href="%s" style="background:#059669;color:#fff;padding:10px 18px;border-radius:8px;text-decoration:none">Reset password</a></p>`+
			`<p style="color:#78716c">This link expires shortly. If you didn't request it, ignore this email.</p>`+
			`</div>`, resetLink)
	return subject, html
}
