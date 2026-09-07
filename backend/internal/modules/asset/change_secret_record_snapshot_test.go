package asset

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// 改密記錄與候選的憑證快照：執行當下這台用的是哪一筆憑證、哪一版。
//
// 快照的存在理由是「事後回頭 join 會讀到現況」——掛載可以被改綁到另一筆憑證，
// 而稽核問的是當時。故本檔的每一支都在改綁之後再驗一次快照沒被覆蓋。

// 記錄帶憑證識別、名稱與目標版本；掛載改綁之後舊記錄的快照不被覆蓋
func TestRecordCarriesCredentialAndVersionSnapshot(t *testing.T) {
	f := setupBatchFixture(t)
	credID, accounts := f.sharedOn(t, "快照共用", "ops", "old-shared", "192.0.2.11", "192.0.2.12")
	rec := newSecretRecorder()
	f.useExecutor(rec)
	f.rotations.executors = func(string) rotationExecutor { return rec }

	req := planRequest("整組留記錄", []uint{f.bindingOf(t, accounts[0]).AssetID}, "ops")
	req.TargetKind = model.PlanTargetCredential
	req.TargetCredentialID = credID
	plan, err := f.plans.Create(req)
	require.NoError(t, err)

	records := f.runner.RunPlan(plan)
	require.Len(t, records, 2)
	pendingVersion := records[0].TargetVersionID
	require.NotZero(t, pendingVersion)
	for _, r := range records {
		assert.Equal(t, credID, r.CredentialID)
		assert.Equal(t, "快照共用", r.CredentialName)
		assert.Equal(t, pendingVersion, r.TargetVersionID, "整組改密的成員就位同一版")
	}

	// 之後把兩台拆開：掛載改指各自的新專用憑證
	batch, assetIDs, err := f.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, true), 1, "admin")
	require.NoError(t, err)
	splitRecords := f.runner.RunBatch(batch, assetIDs)
	require.Len(t, splitRecords, 2)
	for _, accountID := range accounts {
		assert.NotEqual(t, credID, f.bindingOf(t, accountID).CredentialID, "掛載已改綁")
	}

	// 改綁後回頭讀當初那兩筆記錄：憑證與版本快照必須維持當時的值
	for _, before := range records {
		var stored model.ChangeSecretRecord
		require.NoError(t, f.db.Where("id = ?", before.ID).First(&stored).Error)
		assert.Equal(t, credID, stored.CredentialID, "舊記錄的憑證快照未被改綁後的憑證覆蓋")
		assert.Equal(t, "快照共用", stored.CredentialName)
		assert.Equal(t, pendingVersion, stored.TargetVersionID)
	}
}

// 候選帶憑證識別、名稱與轉正後要就位的版本；改綁之後快照不變
func TestCandidateCarriesCredentialAndVersionSnapshot(t *testing.T) {
	f := setupBatchFixture(t)
	f.addHost(t, "h1", "192.0.2.21", "ops")
	_, acc2 := f.addHost(t, "h2", "192.0.2.22", "ops")
	rec := newSecretRecorder()
	rec.verifyErr["192.0.2.22"] = errRemoteDropped
	f.useExecutor(rec)

	batch, assetIDs, err := f.batches.Create(sharedBatchRequest("ops", "候選快照批次"), 1, "admin")
	require.NoError(t, err)
	f.runner.RunBatch(batch, assetIDs)

	var cand model.ChangeSecretCandidate
	require.NoError(t, f.db.Where("account_id = ?", acc2).First(&cand).Error)
	assert.Equal(t, batch.SharedCredentialID, cand.CredentialID, "候選帶轉正後要落到的憑證")
	assert.Equal(t, "候選快照批次", cand.CredentialName)
	assert.NotZero(t, cand.TargetVersionID, "候選帶轉正後要就位的版本")
	beforeCredential, beforeVersion := cand.CredentialID, cand.TargetVersionID

	// 未決期間把該掛載改綁到另一筆共用憑證
	other, err := f.creds.Create(adminCtx(), &CreateCredentialRequest{
		Name: "另一筆共用", Username: "ops", ProtocolFamily: model.ProtocolFamilySSH, Password: "pw",
	})
	require.NoError(t, err)
	binding := f.bindingOf(t, acc2)
	_, err = f.creds.Rebind(adminCtx(), binding.AssetID, acc2, other.ID)
	require.NoError(t, err)

	var after model.ChangeSecretCandidate
	require.NoError(t, f.db.Where("id = ?", cand.ID).First(&after).Error)
	assert.Equal(t, beforeCredential, after.CredentialID, "候選快照不隨改綁改變")
	assert.Equal(t, beforeVersion, after.TargetVersionID)
	assert.Equal(t, "候選快照批次", after.CredentialName)
}

// 以憑證識別為軸的記錄查詢：只回該憑證的記錄，新到舊
func TestRecordsByCredentialQuery(t *testing.T) {
	f := setupBatchFixture(t)
	a1, acc1 := f.addHost(t, "h1", "192.0.2.31", "ops")
	a2, acc2 := f.addHost(t, "h2", "192.0.2.32", "ops")
	cred1 := f.bindingOf(t, acc1).CredentialID
	cred2 := f.bindingOf(t, acc2).CredentialID
	require.NotEqual(t, cred1, cred2)
	rec := newSecretRecorder()
	f.useExecutor(rec)

	plan, err := f.plans.Create(planRequest("兩台各自", []uint{a1, a2}, "ops"))
	require.NoError(t, err)
	records := f.runner.RunPlan(plan)
	require.Len(t, records, 2)

	got, err := f.plans.RecordsByCredential(cred1, 0)
	require.NoError(t, err)
	require.Len(t, got, 1, "只回該憑證的記錄")
	assert.Equal(t, acc1, got[0].AccountID)
	assert.Equal(t, cred1, got[0].CredentialID)

	got2, err := f.plans.RecordsByCredential(cred2, 0)
	require.NoError(t, err)
	require.Len(t, got2, 1)
	assert.Equal(t, acc2, got2[0].AccountID)

	// 同一憑證再跑一次：新到舊
	second := f.runner.RunPlan(plan)
	require.Len(t, second, 2)
	got, err = f.plans.RecordsByCredential(cred1, 0)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Greater(t, got[0].ID, got[1].ID, "新到舊")

	none, err := f.plans.RecordsByCredential(0, 0)
	require.NoError(t, err)
	assert.Empty(t, none, "沒有憑證識別就沒有查詢對象")
}
