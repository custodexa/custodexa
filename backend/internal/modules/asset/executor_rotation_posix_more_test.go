package asset

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// Windows 通道的資產即使設了專用帳號，密碼型改密仍是自改（本版只有 POSIX 通道有代改）。
func TestDelegatedRotationWindowsChannelIsSelf(t *testing.T) {
	for _, channel := range []string{model.RotationChannelWindowsWinRM, model.RotationChannelWindowsSSH} {
		t.Run(channel, func(t *testing.T) {
			e := newDelegEnv(t)
			e.srv.addAccount(delegExecutorUser, delegExecutorSecret, fakeSudoNopasswd)
			e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
			require.NoError(t, e.db.Model(&model.Asset{}).Where("id = ?", e.assetID).
				Update("rotation_channel", channel).Error)
			job := rotationJob{planID: 1, scope: model.AccountScope{model.AccountScopeAll}, secretType: model.ChangeSecretTypePassword}
			targets, skip := e.runner.resolveTargets(job, e.assetID)
			require.Nil(t, skip)
			require.Len(t, targets, 1)
			assert.Nil(t, targets[0].executorPin, "Windows 通道維持自改")
			assert.Equal(t, channel, targets[0].channel)
		})
	}
}

// 取專用帳號秘密的邊界（逐案）：掛載被清除、不可用的三種成因、未驗證候選、帳號名取掛載的名字。
func TestResolveExecutorCredentialsBoundaries(t *testing.T) {
	ctx := context.Background()
	t.Run("mount_cleared_is_changed", func(t *testing.T) {
		e := newDelegEnv(t)
		e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
		pin, err := readExecutorPin(e.db, e.assetID)
		require.NoError(t, err)
		require.NoError(t, e.db.Delete(&model.AssetAccount{}, pin.AccountID).Error)
		_, err = e.assets.ResolveExecutorCredentials(ctx, e.assetID, *pin)
		assert.ErrorIs(t, err, ErrExecutorChanged)
	})
	t.Run("no_effective_version_is_unavailable", func(t *testing.T) {
		e := newDelegEnv(t)
		e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
		require.NoError(t, e.db.Model(&model.AssetAccount{}).
			Where("asset_id = ? AND purpose = ?", e.assetID, model.AccountPurposeExecutor).
			Update("effective_version_id", nil).Error)
		pin, err := readExecutorPin(e.db, e.assetID)
		require.NoError(t, err)
		require.Zero(t, pin.EffectiveVersionID)
		_, err = e.assets.ResolveExecutorCredentials(ctx, e.assetID, *pin)
		assert.ErrorIs(t, err, ErrExecutorUnavailable)
	})
	t.Run("password_with_newline_is_unavailable", func(t *testing.T) {
		e := newDelegEnv(t)
		e.setExecutor(t, delegExecutorUser, "bad\npw", "")
		pin, err := readExecutorPin(e.db, e.assetID)
		require.NoError(t, err)
		_, err = e.assets.ResolveExecutorCredentials(ctx, e.assetID, *pin)
		require.ErrorIs(t, err, ErrExecutorUnavailable)
		assert.NotContains(t, err.Error(), "bad")
	})
	t.Run("unverified_candidate_is_busy", func(t *testing.T) {
		e := newDelegEnv(t)
		e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
		pin, err := readExecutorPin(e.db, e.assetID)
		require.NoError(t, err)
		require.NoError(t, e.db.Create(&model.ChangeSecretCandidate{
			AccountID: pin.AccountID, AssetID: e.assetID, SecretType: model.ChangeSecretTypePassword,
		}).Error)
		_, err = e.assets.ResolveExecutorCredentials(ctx, e.assetID, *pin)
		assert.ErrorIs(t, err, ErrExecutorBusy)
	})
	t.Run("username_comes_from_mount_not_credential", func(t *testing.T) {
		e := newDelegEnv(t)
		e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
		pin, err := readExecutorPin(e.db, e.assetID)
		require.NoError(t, err)
		require.NoError(t, e.db.Model(&model.Credential{}).Where("id = ?", pin.CredentialID).
			Update("username", "credential-side-name").Error)
		got, err := e.assets.ResolveExecutorCredentials(ctx, e.assetID, *pin)
		require.NoError(t, err)
		defer got.Destroy()
		assert.Equal(t, delegExecutorUser, got.Username, "帳號名取掛載的名字")
	})
}
