package service

import (
	"context"
	"testing"
	"time"

	apperrors "github.com/kharchibook/auth-service/errors"
	"github.com/kharchibook/auth-service/pkg/domain/models/dao"
	"golang.org/x/oauth2"
)

// --- fakes ---------------------------------------------------------------------

type fakeGmailClient struct {
	exchangeTok *oauth2.Token
	refreshTok  *oauth2.Token
}

func (f *fakeGmailClient) Enabled() bool                { return true }
func (f *fakeGmailClient) AuthCodeURL(state string) string { return "https://consent?state=" + state }
func (f *fakeGmailClient) Exchange(_ context.Context, _ string) (*oauth2.Token, error) {
	return f.exchangeTok, nil
}
func (f *fakeGmailClient) TokenFromRefresh(_ context.Context, _ string) (*oauth2.Token, error) {
	return f.refreshTok, nil
}

type fakeCredRepo struct{ rows map[int64]*dao.GmailCredential }

func (r *fakeCredRepo) Upsert(_ context.Context, c *dao.GmailCredential) error {
	r.rows[c.UserID] = c
	return nil
}
func (r *fakeCredRepo) GetByUserID(_ context.Context, id int64) (*dao.GmailCredential, error) {
	if c, ok := r.rows[id]; ok {
		return c, nil
	}
	return nil, apperrors.ErrNotFound
}

// identityKMS is a no-op encryptor for tests (plaintext in == out).
type identityKMS struct{}

func (identityKMS) Encrypt(b []byte) ([]byte, error) { return b, nil }
func (identityKMS) Decrypt(b []byte) ([]byte, error) { return b, nil }

func newTestService(client *fakeGmailClient) (*gmailTokenService, *fakeCredRepo) {
	repo := &fakeCredRepo{rows: map[int64]*dao.GmailCredential{}}
	svc := NewGmailTokenService(client, repo, identityKMS{}, "test-secret").(*gmailTokenService)
	return svc, repo
}

// --- tests ---------------------------------------------------------------------

func TestSignedState_RoundTripAndTamper(t *testing.T) {
	svc, _ := newTestService(&fakeGmailClient{})

	state := svc.signState(42)
	uid, err := svc.verifyState(state)
	if err != nil || uid != 42 {
		t.Fatalf("round trip: uid=%d err=%v", uid, err)
	}

	// Tampering invalidates the signature.
	if _, err := svc.verifyState(state + "x"); err == nil {
		t.Error("tampered state should fail verification")
	}
	// A state signed with a different secret must not verify here.
	other := NewGmailTokenService(&fakeGmailClient{}, &fakeCredRepo{rows: map[int64]*dao.GmailCredential{}}, identityKMS{}, "a-different-secret").(*gmailTokenService)
	if _, err := svc.verifyState(other.signState(42)); err == nil {
		t.Error("state from a different secret should fail verification")
	}
}

func TestHandleCallback_StoresEncryptedTokens(t *testing.T) {
	client := &fakeGmailClient{exchangeTok: &oauth2.Token{
		AccessToken:  "access-1",
		RefreshToken: "refresh-1",
		Expiry:       time.Now().Add(time.Hour),
	}}
	svc, repo := newTestService(client)

	uid, err := svc.HandleCallback(context.Background(), "code", svc.signState(7))
	if err != nil || uid != 7 {
		t.Fatalf("HandleCallback: uid=%d err=%v", uid, err)
	}
	row := repo.rows[7]
	if row == nil || string(row.RefreshTokenEnc) != "refresh-1" {
		t.Fatalf("credential not stored: %+v", row)
	}
}

func TestAccessToken_RefreshesWhenExpired(t *testing.T) {
	client := &fakeGmailClient{
		refreshTok: &oauth2.Token{AccessToken: "fresh-access", Expiry: time.Now().Add(time.Hour)},
	}
	svc, repo := newTestService(client)
	// Seed an already-expired credential.
	repo.rows[9] = &dao.GmailCredential{
		UserID:          9,
		AccessTokenEnc:  []byte("stale-access"),
		RefreshTokenEnc: []byte("refresh-9"),
		TokenExpiry:     time.Now().Add(-time.Minute),
	}

	tok, _, err := svc.AccessToken(context.Background(), 9)
	if err != nil {
		t.Fatalf("AccessToken: %v", err)
	}
	if tok != "fresh-access" {
		t.Errorf("expected refreshed token, got %q", tok)
	}
	// The refreshed access token is persisted.
	if string(repo.rows[9].AccessTokenEnc) != "fresh-access" {
		t.Errorf("refreshed token not persisted: %s", repo.rows[9].AccessTokenEnc)
	}
}

func TestAccessToken_NotConnected(t *testing.T) {
	svc, _ := newTestService(&fakeGmailClient{})
	if _, _, err := svc.AccessToken(context.Background(), 123); err == nil {
		t.Error("expected NotFound for a user who never connected Gmail")
	}
}
