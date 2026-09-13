package asset

import (
	"context"
	"errors"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"sync"
	"testing"

	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/stretchr/testify/require"
)

type materialTrace struct {
	material.BytesColumnCodec
	mu      sync.Mutex
	buffers [][]byte
	calls   int
	failAt  int
}

func (c *materialTrace) DecryptBytesFor(ctx context.Context, ref crypto.CipherRef, ciphertext string) (*material.Secret, error) {
	c.mu.Lock()
	c.calls++
	fail := c.calls == c.failAt
	c.mu.Unlock()
	if fail {
		return nil, errors.New("injected second field failure")
	}
	owner, err := c.BytesColumnCodec.DecryptBytesFor(ctx, ref, ciphertext)
	if err != nil {
		return nil, err
	}
	err = owner.Borrow(func(raw []byte) error {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.buffers = append(c.buffers, raw)
		return nil
	})
	if err != nil {
		owner.Destroy()
		return nil, err
	}
	return owner, nil
}
func (c *materialTrace) zero(t *testing.T) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	require.NotEmpty(t, c.buffers)
	for _, raw := range c.buffers {
		require.Equal(t, make([]byte, len(raw)), raw, "original allocation must be zero")
	}
}
func (c *materialTrace) live(t *testing.T) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	require.NotEmpty(t, c.buffers)
	for _, raw := range c.buffers {
		require.NotEqual(t, make([]byte, len(raw)), raw, "material still needed for remote operation")
	}
}
func tracedAssets(t *testing.T) (*AssetService, *materialTrace, uint, uint) {
	t.Helper()
	db := setupAccountDB(t)
	assets, _ := newAccountServices(t)
	row, err := assets.Create(&CreateAssetRequest{Name: "owned", Protocol: model.ProtocolSSH, Host: "127.0.0.1", Port: 22, Username: "ops", Password: "password-fixture", PrivateKey: "key-fixture", CreatedBy: 1})
	require.NoError(t, err)
	var account model.AssetAccount
	require.NoError(t, db.Where("asset_id = ?", row.ID).First(&account).Error)
	trace := &materialTrace{BytesColumnCodec: assets.bytesCrypto}
	assets.bytesCrypto = trace
	assets.resolver.crypto = trace
	return assets, trace, row.ID, account.ID
}
func TestResolveForBindingZeroize(t *testing.T) {
	for _, mode := range []string{"success_transfer", "second_field_failure", "foreign_account"} {
		t.Run(mode, func(t *testing.T) {
			svc, trace, assetID, accountID := tracedAssets(t)
			if mode == "second_field_failure" {
				trace.failAt = 2
			}
			if mode == "foreign_account" {
				out, err := svc.resolver.ResolveForBinding(context.Background(), assetID+1, accountID)
				require.ErrorIs(t, err, ErrAssetAccountNotFound)
				require.Nil(t, out)
				require.Zero(t, trace.calls)
				return
			}
			out, err := svc.GetWithCredentialsForAccount(assetID, accountID)
			if mode == "second_field_failure" {
				require.ErrorContains(t, err, "injected second field failure")
				require.Nil(t, out)
			} else {
				require.NoError(t, err)
				trace.live(t)
				require.NoError(t, out.Password.Borrow(func(raw []byte) error { require.Equal(t, []byte("password-fixture"), raw); return nil }))
				out.Destroy()
			}
			trace.zero(t)
		})
	}
}
func TestResolveVersionZeroize(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending_version", true: "second_field_failure"}[fail], func(t *testing.T) {
			svc, trace, _, _ := tracedAssets(t)
			db := database.DB
			credID, _, _, pending := seedCredentialWithVersions(t, db, svc, "ops", "effective", "current", "pending")
			key, err := svc.crypto.EncryptFor(context.Background(), keyvault.RefCredentialVersionPrivateKey, "key-fixture")
			require.NoError(t, err)
			require.NoError(t, db.Model(&model.CredentialSecretVersion{}).Where("id = ?", pending).Update("private_key_enc", key).Error)
			if fail {
				trace.failAt = 2
			}
			out, err := svc.resolver.ResolveVersion(context.Background(), credID, pending)
			if fail {
				require.Error(t, err)
				require.Nil(t, out)
			} else {
				require.NoError(t, err)
				require.Equal(t, pending, out.VersionID)
				require.NoError(t, out.Password.Borrow(func(raw []byte) error { require.Equal(t, []byte("pending"), raw); return nil }))
				trace.live(t)
				out.Destroy()
			}
			trace.zero(t)
		})
	}
}
