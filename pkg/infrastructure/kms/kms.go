// Package kms provides PII encryption. In production this fronts a cloud KMS
// (AWS/GCP/Azure) that holds the key in tamper-proof hardware. This build ships a
// local AES-256-GCM implementation behind the same interface so PII (phone, etc.)
// is still encrypted at rest during development.
package kms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

// IKMSEncryptor encrypts/decrypts sensitive PII. Every Decrypt is a point where a
// real KMS would emit an audit record (PRD §13 KEY_DECRYPT).
type IKMSEncryptor interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

type localKMS struct {
	gcm cipher.AEAD
}

// NewLocalKMS derives a 256-bit AES-GCM key from the provided secret material.
// In production, swap this constructor for one that fetches a data key from the
// cloud KMS; callers depend only on IKMSEncryptor.
func NewLocalKMS(secret string) (IKMSEncryptor, error) {
	if secret == "" {
		// A fixed dev default so the service runs without external config; MUST
		// be overridden in staging/production via the KMS-backed implementation.
		secret = "auth-service-local-dev-kms-master-secret"
	}
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("new aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}
	return &localKMS{gcm: gcm}, nil
}

// Encrypt returns nonce||ciphertext using AES-256-GCM (authenticated encryption).
func (k *localKMS) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, nil
	}
	nonce := make([]byte, k.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}
	return k.gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt reverses Encrypt, verifying the GCM auth tag.
func (k *localKMS) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, nil
	}
	ns := k.gcm.NonceSize()
	if len(ciphertext) < ns {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := ciphertext[:ns], ciphertext[ns:]
	plaintext, err := k.gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("gcm open: %w", err)
	}
	return plaintext, nil
}
