package asset

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// 批次 runner 依帳號名查掛載的兩處（未收斂略過、共用成員拆分）只看登入掛載：
// 同名的執行身分掛載不得被當成批次目標略過或拆分。先以登入用途證明兩條路徑
// 確實會命中，再把同一組掛載改為執行身分，斷言兩處都查不到。
func TestBatchRunnerAccountLookupsIgnoreExecutorMounts(t *testing.T) {
	f := setupBatchFixture(t)
	credID, accountIDs := f.sharedOn(t, "共用執行", "ops", "old-shared", "10.2.11.1", "10.2.11.2")
	f.runner.rotations = nil

	assetIDs := make([]uint, 0, len(accountIDs))
	for _, id := range accountIDs {
		assetIDs = append(assetIDs, f.bindingOf(t, id).AssetID)
	}
	job := rotationJob{batchID: 1, scope: model.AccountScope{"ops"}}

	// 對照：登入掛載時兩條路徑都會命中
	recs, routed := f.runner.runSharedMembersSplit(job, assetIDs)
	require.Len(t, recs, 2, "登入用途的共用成員應走拆分路徑（輪替引擎未接線時逐台略過）")
	require.Len(t, routed, 2)

	pending := uint(999)
	require.NoError(t, f.db.Model(&model.Credential{}).Where("id = ?", credID).
		Update("pending_version_id", pending).Error)
	recs, blocked := f.runner.skipOutOfSyncBindings(job, assetIDs)
	require.Len(t, recs, 2, "登入用途且憑證未收斂時應逐台略過")
	require.Len(t, blocked, 2)

	// 同一組掛載改為執行身分後，兩處都不得查到
	require.NoError(t, f.db.Model(&model.AssetAccount{}).Where("id IN ?", accountIDs).
		Update("purpose", model.AccountPurposeExecutor).Error)

	recs, blocked = f.runner.skipOutOfSyncBindings(job, assetIDs)
	assert.Empty(t, recs, "執行身分掛載不得被未收斂略過路徑當成批次目標")
	assert.Empty(t, blocked)

	require.NoError(t, f.db.Model(&model.Credential{}).Where("id = ?", credID).
		Update("pending_version_id", nil).Error)
	recs, routed = f.runner.runSharedMembersSplit(job, assetIDs)
	assert.Empty(t, recs, "執行身分掛載不得被共用成員拆分路徑接手")
	assert.Empty(t, routed)
}
