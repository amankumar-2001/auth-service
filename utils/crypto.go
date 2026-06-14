package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
)

// HashToken returns a hex-encoded SHA-256 hash of an opaque token (refresh
// token, OTP, reset token). These are high-entropy random values, so a fast
// hash is sufficient — bcrypt is reserved for low-entropy user passwords.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ConstantTimeEqual compares two strings without leaking timing information.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// RandomToken returns a URL-safe random token with nBytes of entropy.
func RandomToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// RandomNumericOTP returns a cryptographically-secure numeric OTP of the given
// length using crypto/rand (never math/rand, which is predictable).
func RandomNumericOTP(length int) (string, error) {
	const digits = "0123456789"
	out := make([]byte, length)
	for i := range out {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			return "", fmt.Errorf("read random otp: %w", err)
		}
		out[i] = digits[n.Int64()]
	}
	return string(out), nil
}
