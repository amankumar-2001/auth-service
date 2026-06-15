package service

import (
	"context"
	"time"

	"github.com/kharchibook/auth-service/constants"
	apperrors "github.com/kharchibook/auth-service/errors"
	"github.com/kharchibook/auth-service/pkg/domain/models/dao"
	"github.com/kharchibook/auth-service/pkg/infrastructure/blindindex"
	"github.com/kharchibook/auth-service/pkg/infrastructure/kms"
	"github.com/kharchibook/auth-service/pkg/infrastructure/sqlrepo"
	"github.com/kharchibook/auth-service/third_party/platlogger"
)

// IAccountService owns user identity records: creation, lookup, verification
// state, password rotation, and PII (phone) encryption. It is the only service
// that talks to the user repository.
type IAccountService interface {
	CreateLocalUser(ctx context.Context, email, passwordHash, phone, name string) (*dao.User, error)
	GetByEmail(ctx context.Context, email string) (*dao.User, error)
	GetByID(ctx context.Context, id int64) (*dao.User, error)
	// GetByPhone resolves a user by phone number (normalized to E.164 then matched
	// against the phone_hash blind index). Returns ErrNotFound if unregistered.
	GetByPhone(ctx context.Context, phone string) (*dao.User, error)
	FindOrCreateSocialUser(ctx context.Context, provider, providerUID, email string) (user *dao.User, created bool, err error)
	MarkVerified(ctx context.Context, id int64) error
	UpdatePassword(ctx context.Context, id int64, passwordHash string) error
	RecordLoginSuccess(ctx context.Context, id int64) error
	// RegisterFailedLogin increments the counter and locks the account once the
	// threshold is hit. Returns whether the account is now locked.
	RegisterFailedLogin(ctx context.Context, id int64) (locked bool, err error)
	// DecryptPhone returns the plaintext phone for a user (logged as KEY_DECRYPT
	// by a real KMS).
	DecryptPhone(u *dao.User) (string, error)
	// BackfillPhoneHashes populates the phone_hash blind index for rows that
	// predate the column. Idempotent; returns the number of rows updated.
	BackfillPhoneHashes(ctx context.Context) (int, error)
}

type accountService struct {
	users    sqlrepo.IUserRepository
	rbac     IRBACService
	kms      kms.IKMSEncryptor
	phone    blindindex.IHasher
	maxFails int
	lockFor  time.Duration
}

// NewAccountService constructs the account service.
func NewAccountService(
	users sqlrepo.IUserRepository,
	rbac IRBACService,
	enc kms.IKMSEncryptor,
	phone blindindex.IHasher,
	maxFails int,
	lockFor time.Duration,
) IAccountService {
	return &accountService{users: users, rbac: rbac, kms: enc, phone: phone, maxFails: maxFails, lockFor: lockFor}
}

func (s *accountService) CreateLocalUser(ctx context.Context, email, passwordHash, phone, name string) (*dao.User, error) {
	// Reject duplicates up front (the unique index is the ultimate guard).
	if _, err := s.users.GetByEmail(ctx, email); err == nil {
		return nil, apperrors.ConflictError("user already exists")
	} else if !apperrors.Is(err, apperrors.ErrNotFound) {
		return nil, err
	}

	encPhone, err := s.kms.Encrypt([]byte(phone))
	if err != nil {
		return nil, apperrors.InternalServerError(err)
	}

	u := &dao.User{
		Email:          email,
		Name:           name,
		PhoneEncrypted: encPhone,
		PhoneHash:      s.phone.Hash(blindindex.NormalizePhone(phone)),
		PasswordHash:   passwordHash,
		Verified:       false,
		IsActive:       true,
		Provider:       constants.ProviderLocal,
	}
	if err := s.users.Create(ctx, u); err != nil {
		return nil, apperrors.InternalServerError(err)
	}

	// Every new account gets the baseline "user" role.
	if err := s.rbac.AssignRole(ctx, u.ID, constants.RoleUser); err != nil {
		return nil, err
	}
	return u, nil
}

func (s *accountService) GetByEmail(ctx context.Context, email string) (*dao.User, error) {
	return s.users.GetByEmail(ctx, email)
}

func (s *accountService) GetByID(ctx context.Context, id int64) (*dao.User, error) {
	return s.users.GetByID(ctx, id)
}

func (s *accountService) GetByPhone(ctx context.Context, phone string) (*dao.User, error) {
	hash := s.phone.Hash(blindindex.NormalizePhone(phone))
	if hash == "" {
		return nil, apperrors.ErrNotFound
	}
	return s.users.GetByPhoneHash(ctx, hash)
}

// BackfillPhoneHashes computes the phone_hash blind index for any existing rows
// that predate the column. Safe to run on every startup: it's a no-op once all
// rows are populated. Best-effort — a single failure is logged and skipped.
func (s *accountService) BackfillPhoneHashes(ctx context.Context) (int, error) {
	pending, err := s.users.ListNeedingPhoneHash(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for i := range pending {
		plain, err := s.DecryptPhone(&pending[i])
		if err != nil || plain == "" {
			platlogger.WithContext(ctx).Warn("backfill: skip user", "userID", pending[i].ID)
			continue
		}
		hash := s.phone.Hash(blindindex.NormalizePhone(plain))
		if err := s.users.SetPhoneHash(ctx, pending[i].ID, hash); err != nil {
			platlogger.WithContext(ctx).Warn("backfill: set hash failed", "userID", pending[i].ID, "error", err)
			continue
		}
		n++
	}
	return n, nil
}

func (s *accountService) FindOrCreateSocialUser(ctx context.Context, provider, providerUID, email string) (*dao.User, bool, error) {
	// Returning user via this provider?
	if u, err := s.users.GetByProviderUID(ctx, provider, providerUID); err == nil {
		return u, false, nil
	} else if !apperrors.Is(err, apperrors.ErrNotFound) {
		return nil, false, err
	}

	// Existing local account with same email → link the provider to it.
	if u, err := s.users.GetByEmail(ctx, email); err == nil {
		u.Provider = provider
		u.ProviderUID = &providerUID
		u.Verified = true // provider already verified the email
		if err := s.users.Update(ctx, u); err != nil {
			return nil, false, apperrors.InternalServerError(err)
		}
		return u, false, nil
	} else if !apperrors.Is(err, apperrors.ErrNotFound) {
		return nil, false, err
	}

	// First-time social user → create a verified, password-less account.
	u := &dao.User{
		Email:       email,
		Verified:    true,
		IsActive:    true,
		Provider:    provider,
		ProviderUID: &providerUID,
	}
	if err := s.users.Create(ctx, u); err != nil {
		return nil, false, apperrors.InternalServerError(err)
	}
	if err := s.rbac.AssignRole(ctx, u.ID, constants.RoleUser); err != nil {
		return nil, false, err
	}
	return u, true, nil
}

func (s *accountService) MarkVerified(ctx context.Context, id int64) error {
	return s.users.SetVerified(ctx, id, true)
}

func (s *accountService) UpdatePassword(ctx context.Context, id int64, passwordHash string) error {
	return s.users.UpdatePassword(ctx, id, passwordHash)
}

func (s *accountService) RecordLoginSuccess(ctx context.Context, id int64) error {
	return s.users.RecordLoginSuccess(ctx, id, time.Now().UTC())
}

func (s *accountService) RegisterFailedLogin(ctx context.Context, id int64) (bool, error) {
	count, err := s.users.IncrementFailedAttempts(ctx, id)
	if err != nil {
		return false, err
	}
	if count >= s.maxFails {
		if err := s.users.LockAccount(ctx, id, time.Now().UTC().Add(s.lockFor)); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func (s *accountService) DecryptPhone(u *dao.User) (string, error) {
	if len(u.PhoneEncrypted) == 0 {
		return "", nil
	}
	b, err := s.kms.Decrypt(u.PhoneEncrypted)
	if err != nil {
		return "", apperrors.InternalServerError(err)
	}
	return string(b), nil
}
