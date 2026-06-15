// Package blindindex computes deterministic, keyed hashes used as searchable
// "blind indexes" over encrypted PII. The phone column is encrypted with a random
// nonce (see kms), so it cannot be queried directly; we store a keyed HMAC of the
// normalized phone alongside it and query by that instead. HMAC (not a bare hash)
// is used so the small phone-number space can't be brute-forced from a leaked
// index without the key.
package blindindex

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// IHasher produces a stable hex digest for a plaintext value.
type IHasher interface {
	// Hash returns the keyed digest, or "" for empty input.
	Hash(plaintext string) string
}

type hmacHasher struct {
	key []byte
}

// New returns an HMAC-SHA256 hasher. An empty secret falls back to a fixed dev
// default so the service runs without external config; it MUST be overridden in
// staging/production via INTERNAL_PHONEHASHKEY.
func New(secret string) IHasher {
	if secret == "" {
		secret = "auth-service-local-dev-phone-hash-key"
	}
	return &hmacHasher{key: []byte(secret)}
}

func (h *hmacHasher) Hash(plaintext string) string {
	if plaintext == "" {
		return ""
	}
	mac := hmac.New(sha256.New, h.key)
	mac.Write([]byte(plaintext))
	return hex.EncodeToString(mac.Sum(nil))
}

var nonDigit = regexp.MustCompile(`[^0-9]`)

// NormalizePhone canonicalizes a phone to E.164 ("+" + digits) so the same number
// hashes identically whether it arrives as "+91 98765 43210" (signup, E.164) or
// "919876543210" (a WhatsApp wa_id). Returns "" for empty input.
func NormalizePhone(phone string) string {
	phone = strings.TrimSpace(phone)
	if phone == "" {
		return ""
	}
	digits := nonDigit.ReplaceAllString(phone, "")
	if digits == "" {
		return ""
	}
	return "+" + digits
}
