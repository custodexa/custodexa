package database

import (
	"context"
	"errors"
	"testing"

	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/stretchr/testify/require"
)

type conversionBytesCodec struct {
	buffers [][]byte
	calls   int
	failAt  int
}

func (c *conversionBytesCodec) EncryptBytesFor(context.Context, crypto.CipherRef, []byte) (string, error) {
	return "", errors.New("comparison must preserve ciphertext")
}

func (c *conversionBytesCodec) DecryptBytesFor(_ context.Context, _ crypto.CipherRef, ciphertext string) (*material.Secret, error) {
	c.calls++
	if c.calls == c.failAt {
		return nil, errors.New("injected column failure")
	}
	raw := []byte(ciphertext)
	c.buffers = append(c.buffers, raw)
	return material.Adopt(raw), nil
}

func testConversionMaterial(t *testing.T, privateKey bool) {
	t.Helper()
	for _, scenario := range []struct {
		name             string
		different, empty bool
		failAt           int
	}{
		{name: "equal"}, {name: "different", different: true}, {name: "empty", empty: true},
		{name: "first_password_failure", failAt: 1}, {name: "first_key_failure", failAt: 2},
		{name: "later_password_failure", failAt: 3}, {name: "later_key_failure", failAt: 4},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			codec := &conversionBytesCodec{failAt: scenario.failAt}
			first := credentialGroupMember{AccountID: 1, VersionID: 1, PasswordEnc: "password", PrivateKeyEnc: "key"}
			if scenario.empty {
				if privateKey {
					first.PrivateKeyEnc = ""
				} else {
					first.PasswordEnc = ""
				}
			}
			second := first
			second.AccountID = 2
			if scenario.different {
				if privateKey {
					second.PrivateKeyEnc = "different"
				} else {
					second.PasswordEnc = "different"
				}
			}
			verdict, err := evaluateGroupForMerge(codec, credentialGroup{Members: []credentialGroupMember{first, second}})
			if scenario.failAt != 0 {
				require.ErrorContains(t, err, "injected column failure")
			} else {
				require.NoError(t, err)
				require.Equal(t, !scenario.different, verdict.Merge)
			}
			for _, raw := range codec.buffers {
				require.Equal(t, make([]byte, len(raw)), raw, "every original buffer must be zero")
			}
		})
	}
}

func TestConversionPasswordZeroize(t *testing.T) {
	testConversionMaterial(t, false)
	t.Run("merge_preserves_ciphertext", func(t *testing.T) {
		db := newCredentialLibraryDB(t)
		km := newCredentialLibraryKM(t, db)
		a := seedAsset(t, db, "owned-a", model.ProtocolSSH)
		b := seedAsset(t, db, "owned-b", model.ProtocolSSH)
		seedAccount(t, db, km, a, "ops", "fixture", "owned-group")
		seedAccount(t, db, km, b, "ops", "fixture", "owned-group")
		_, err := convertAccountsToDedicatedCredentials(db)
		require.NoError(t, err)
		_, err = rebindMigratedVersionCiphertext(db, km)
		require.NoError(t, err)
		groups, err := credentialGroupsForMerge(db)
		require.NoError(t, err)
		require.Len(t, groups, 1)
		first := groups[0].Members[0]
		verdict, err := evaluateGroupForMerge(km, groups[0])
		require.NoError(t, err)
		require.True(t, verdict.Merge)
		require.NoError(t, mergeGroupIntoSharedCredential(db, groups[0], 1))
		var version model.CredentialSecretVersion
		require.NoError(t, db.First(&version).Error)
		require.Equal(t, first.PasswordEnc, version.PasswordEnc)
		require.Equal(t, first.PrivateKeyEnc, version.PrivateKeyEnc)
	})
}
func TestConversionPrivateKeyZeroize(t *testing.T) { testConversionMaterial(t, true) }
