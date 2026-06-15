package service

import (
	"context"
	"testing"
	"time"

	apperrors "github.com/kharchibook/auth-service/errors"
	"github.com/kharchibook/auth-service/pkg/infrastructure/blindindex"
	"github.com/kharchibook/auth-service/pkg/infrastructure/kms"
)

// newTestAccountService wires the account service with in-memory fakes (reused
// from auth_flow_test.go) plus a real KMS + phone hasher.
func newTestAccountService(t *testing.T) IAccountService {
	t.Helper()
	enc, err := kms.NewLocalKMS("test-secret")
	if err != nil {
		t.Fatalf("kms: %v", err)
	}
	rbac := NewRBACService(fakeRBACRepo{})
	return NewAccountService(newFakeUserRepo(), rbac, enc, blindindex.New("test-phone-key"), 5, 15*time.Minute)
}

func TestGetByPhoneRoundTrip(t *testing.T) {
	ctx := context.Background()
	acc := newTestAccountService(t)

	created, err := acc.CreateLocalUser(ctx, "ramesh@example.com", "hash", "+919876543210", "Ramesh")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Looked up by the wa_id form (no "+"), which must normalize to the same hash.
	got, err := acc.GetByPhone(ctx, "919876543210")
	if err != nil {
		t.Fatalf("get by phone: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("id = %d, want %d", got.ID, created.ID)
	}
	if got.Name != "Ramesh" {
		t.Errorf("name = %q, want Ramesh", got.Name)
	}
}

func TestGetByPhoneUnregistered(t *testing.T) {
	ctx := context.Background()
	acc := newTestAccountService(t)

	if _, err := acc.GetByPhone(ctx, "+910000000000"); !apperrors.Is(err, apperrors.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
	// Empty phone is treated as not registered.
	if _, err := acc.GetByPhone(ctx, ""); !apperrors.Is(err, apperrors.ErrNotFound) {
		t.Errorf("empty phone err = %v, want ErrNotFound", err)
	}
}
