// Package service holds the business-logic services. Each capability is exposed
// as an IXxxService interface plus a concrete implementation, so the DI layer can
// wire dependencies and tests can substitute fakes.
package service

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// IPasswordService hashes and verifies user passwords.
//
// Note on salt: bcrypt generates and embeds a unique per-hash salt inside the
// output string, satisfying the PRD's "per-user salt" requirement without a
// separate salt column. The schema keeps a salt column only for compatibility
// with alternative hashers; it is unused by this bcrypt implementation.
type IPasswordService interface {
	Hash(plaintext string) (string, error)
	Verify(plaintext, hash string) bool
}

type passwordService struct {
	cost int
}

// NewPasswordService constructs the bcrypt password service. cost is clamped to
// bcrypt's valid range.
func NewPasswordService(cost int) IPasswordService {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		cost = bcrypt.DefaultCost
	}
	return &passwordService{cost: cost}
}

func (s *passwordService) Hash(plaintext string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plaintext), s.cost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(b), nil
}

// Verify reports whether plaintext matches hash. A constant-time comparison is
// performed inside bcrypt. Returns false (not an error) on mismatch so callers
// treat all failures uniformly as "invalid credentials".
func (s *passwordService) Verify(plaintext, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext))
	if err != nil && !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		// Malformed hash, etc. — treat as failure but it indicates data issues.
		return false
	}
	return err == nil
}
