package asset

import (
	"context"
	"errors"
	"testing"

	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/stretchr/testify/require"
)

type trackedMaterialCodec struct {
	buffers [][]byte
	calls   int
	failAt  int
}

func (c *trackedMaterialCodec) EncryptBytesFor(context.Context, crypto.CipherRef, []byte) (string, error) {
	return "", errors.New("unexpected encryption")
}
func (c *trackedMaterialCodec) DecryptBytesFor(_ context.Context, _ crypto.CipherRef, ciphertext string) (*material.Secret, error) {
	c.calls++
	if c.calls == c.failAt {
		return nil, errors.New("injected decrypt failure")
	}
	raw := []byte(ciphertext)
	c.buffers = append(c.buffers, raw)
	return material.Adopt(raw), nil
}
func TestGetSftpPasswordZeroize(t *testing.T) {
	for _, mode := range []string{"success", "decrypt_failure", "disabled", "empty"} {
		t.Run(mode, func(t *testing.T) {
			codec := &trackedMaterialCodec{}
			svc := &AssetService{bytesCrypto: codec}
			row := &model.Asset{SftpEnabled: true, SftpPasswordEnc: "fixture"}
			if mode == "decrypt_failure" {
				codec.failAt = 1
			}
			if mode == "disabled" {
				row.SftpEnabled = false
			}
			if mode == "empty" {
				row.SftpPasswordEnc = ""
			}
			owner, err := svc.GetSftpPassword(row)
			if mode == "decrypt_failure" {
				require.ErrorContains(t, err, "解密 SFTP 密碼失敗")
				require.Nil(t, owner)
			} else {
				require.NoError(t, err)
				require.NoError(t, owner.Borrow(func(raw []byte) error {
					if mode == "success" {
						require.Equal(t, []byte("fixture"), raw)
					} else {
						require.Empty(t, raw)
					}
					return nil
				}))
				owner.Destroy()
			}
			for _, raw := range codec.buffers {
				require.Equal(t, make([]byte, len(raw)), raw)
			}
			if mode == "disabled" || mode == "empty" {
				require.Zero(t, codec.calls)
			}
		})
	}
}

func secretText(t *testing.T, owner *material.Secret) string {
	t.Helper()
	t.Cleanup(owner.Destroy)
	value, err := material.Use(owner, func(raw []byte) (string, error) { return string(raw), nil })
	require.NoError(t, err)
	return value
}
