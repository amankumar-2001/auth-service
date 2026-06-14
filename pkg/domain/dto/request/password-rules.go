// Package request holds inbound request DTOs with ozzo-validation rules — one
// file per API endpoint (matching the handler filenames), plus this shared
// password policy used by the signup and password-reset DTOs.
package request

import (
	"regexp"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

// passwordRules enforces a strong-password policy: 8+ chars with at least one
// lower, upper, digit, and symbol. Defeats rainbow tables / trivial brute force.
var (
	hasLower  = regexp.MustCompile(`[a-z]`)
	hasUpper  = regexp.MustCompile(`[A-Z]`)
	hasDigit  = regexp.MustCompile(`[0-9]`)
	hasSymbol = regexp.MustCompile(`[^a-zA-Z0-9]`)
)

func passwordRules() []validation.Rule {
	return []validation.Rule{
		validation.Required,
		validation.Length(8, 128),
		validation.Match(hasLower).Error("must contain a lowercase letter"),
		validation.Match(hasUpper).Error("must contain an uppercase letter"),
		validation.Match(hasDigit).Error("must contain a digit"),
		validation.Match(hasSymbol).Error("must contain a symbol"),
	}
}
