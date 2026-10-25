package asset

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// OwnershipDetachAndBatchPathsForTest 脫離與批次整組建立的歸屬寫入（外部測試 TestCredentialOwnershipAssignment 的子測試）。
//
// 兩條路徑都要遠端執行替身與套件內夾具，故放在套件內：脫離產生的專用憑證隨資產、原共用歸屬不變；
// 批次整組模式未帶歸屬、發起者為全域主體時新共用憑證為全域。
func OwnershipDetachAndBatchPathsForTest(t *testing.T) {
	t.Run("脫離產生隨資產的專用憑證", func(t *testing.T) {
		f := setupRotationFixture(t)
		// 三台：脫離一台後原憑證仍有兩個掛載、維持共用（剩一台時會收斂成專用，歸屬改隨資產）
		credID, accounts := f.sharedOn(t, "歸屬脫離", "ops", "co-shared-fixture", "10.13.9.1", "10.13.9.2", "10.13.9.3")
		before := f.credential(t, credID)
		require.NotNil(t, before.OwnerKind)

		_, err := f.rotations.Detach(adminCtx(), credID, accounts[1], DetachCredentialRequest{
			Source: DetachSourceCustom, Password: "co-detach-fixture-1",
		})
		require.NoError(t, err)

		detached := f.credential(t, f.binding(t, accounts[1]).CredentialID)
		require.NotEqual(t, credID, detached.ID)
		assert.Equal(t, model.CredentialScopeDedicated, detached.Scope)
		require.NotNil(t, detached.OwnerKind)
		assert.Equal(t, model.CredentialOwnerAsset, *detached.OwnerKind)
		assert.Nil(t, detached.OwnerNodeID)

		after := f.credential(t, credID)
		require.NotNil(t, after.OwnerKind)
		assert.Equal(t, *before.OwnerKind, *after.OwnerKind, "原共用歸屬不變")
		assert.Equal(t, before.OwnerNodeID, after.OwnerNodeID)
	})

	t.Run("批次整組建立未帶歸屬為全域", func(t *testing.T) {
		f := setupBatchFixture(t)
		f.addHost(t, "co-h1", "10.2.9.1", "ops")
		f.addHost(t, "co-h2", "10.2.9.2", "ops")
		f.useExecutor(newSecretRecorder())

		batch, assetIDs, err := f.batches.Create(sharedBatchRequest("ops", "歸屬批次"), 1, "admin")
		require.NoError(t, err)
		records := f.runner.RunBatch(batch, assetIDs)
		require.Len(t, records, 2)
		require.NotZero(t, batch.SharedCredentialID)
		cred := f.credentialOf(t, batch.SharedCredentialID)
		require.NotNil(t, cred.OwnerKind)
		assert.Equal(t, model.CredentialOwnerGlobal, *cred.OwnerKind)
		assert.Nil(t, cred.OwnerNodeID)
	})
}
