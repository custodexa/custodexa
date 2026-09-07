package asset

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// 改密計劃的目標種類：以帳號為目標時擋下共用憑證的成員（儲存時與執行時兩層），
// 以憑證為目標時走整組改密。
//
// 遠端協定不是本檔的責任：以可換的執行器注入，不連任何目標機。

// planRequest 一份最小可用的計劃請求
func planRequest(name string, assetIDs []uint, accounts ...string) *ChangeSecretPlanRequest {
	return &ChangeSecretPlanRequest{Name: name, AssetIDs: assetIDs, Accounts: accounts}
}

// 儲存時擋：計劃的帳號範圍命中共用憑證的成員即整筆拒絕
func TestPlanRejectsSharedCredentialTargetOnSave(t *testing.T) {
	f := setupBatchFixture(t)
	// 兩台掛同一筆共用憑證（恰好兩個成員：擋門條件若被放寬成「掛載數大於 2」，本例即漏擋）
	_, accounts := f.sharedOn(t, "共用甲", "ops", "old-shared", "10.3.0.1", "10.3.0.2")
	require.Len(t, accounts, 2)
	sharedAssets := []uint{f.bindingOf(t, accounts[0]).AssetID, f.bindingOf(t, accounts[1]).AssetID}
	dedicatedAsset, _ := f.addHost(t, "h9", "10.3.0.9", "ops")

	_, err := f.plans.Create(planRequest("擋下共用", sharedAssets, "ops"))
	assert.ErrorIs(t, err, ErrPlanSharedCredentialTarget, "明列帳號名命中共用成員即拒絕")

	_, err = f.plans.Create(planRequest("擋下共用-全帳號", sharedAssets))
	assert.ErrorIs(t, err, ErrPlanSharedCredentialTarget, "@ALL 範圍同樣命中")

	_, err = f.plans.Create(planRequest("擋下共用-混合", append([]uint{dedicatedAsset}, sharedAssets...), "ops"))
	assert.ErrorIs(t, err, ErrPlanSharedCredentialTarget, "只要有一台命中就整筆拒絕")

	var stored int64
	require.NoError(t, f.db.Model(&model.ChangeSecretPlan{}).Count(&stored).Error)
	assert.Zero(t, stored, "被拒的建立不得留下計劃列")

	// 只涵蓋專用憑證的計劃照常建立；建立後改成共用範圍即被更新擋下
	plan, err := f.plans.Create(planRequest("只有專用", []uint{dedicatedAsset}, "ops"))
	require.NoError(t, err)
	assert.Equal(t, model.PlanTargetAccount, plan.TargetKind, "預設目標種類為帳號")

	_, err = f.plans.Update(plan.ID, planRequest("只有專用", append([]uint{dedicatedAsset}, sharedAssets...), "ops"))
	assert.ErrorIs(t, err, ErrPlanSharedCredentialTarget, "更新同樣經過前置驗證")
}

// 執行時擋：計劃存檔後才被改綁到共用憑證的目標記為略過，遠端不被觸碰
func TestPlanSkipsSharedCredentialTargetAtRun(t *testing.T) {
	f := setupBatchFixture(t)
	a1, acc1 := f.addHost(t, "h1", "10.3.1.1", "ops")
	a2, _ := f.addHost(t, "h2", "10.3.1.2", "ops")
	rec := newSecretRecorder()
	f.useExecutor(rec)

	plan, err := f.plans.Create(planRequest("存檔時全是專用", []uint{a1, a2}, "ops"))
	require.NoError(t, err)

	// 存檔之後才改綁到共用憑證
	shared, err := f.creds.Create(adminCtx(), &CreateCredentialRequest{
		Name: "事後才共用", Username: "ops", ProtocolFamily: model.ProtocolFamilySSH, Password: "shared-pw",
	})
	require.NoError(t, err)
	_, err = f.creds.Rebind(adminCtx(), a1, acc1, shared.ID)
	require.NoError(t, err)

	records := f.runner.RunPlan(plan)
	require.Len(t, records, 2)
	skipped := recordByAsset(records, a1)
	require.NotNil(t, skipped)
	assert.Equal(t, model.ChangeSecretSkipped, skipped.Status)
	assert.Equal(t, model.ChangeSecretReasonSharedCredentialTargetRequired, skipped.Error)
	assert.Equal(t, shared.ID, skipped.CredentialID, "略過的記錄仍帶憑證快照")

	done := recordByAsset(records, a2)
	require.NotNil(t, done)
	assert.Equal(t, model.ChangeSecretSuccess, done.Status, "其餘目標照常執行")

	assert.Empty(t, rec.secretOf("10.3.1.1"), "被擋的目標遠端不被觸碰")
	assert.NotEmpty(t, rec.secretOf("10.3.1.2"))
	assert.EqualValues(t, 1, f.versionCountOf(t, shared.ID), "共用憑證不得被追加版本")
	var cands int64
	require.NoError(t, f.db.Model(&model.ChangeSecretCandidate{}).
		Where("account_id = ?", acc1).Count(&cands).Error)
	assert.Zero(t, cands, "被擋的目標不留候選")
}

// 以憑證為目標：成員集合＝該憑證當下的全部掛載，全部走整組改密
func TestPlanCredentialTargetCoversAllBindings(t *testing.T) {
	f := setupBatchFixture(t)
	credID, accounts := f.sharedOn(t, "整組目標", "ops", "old-shared", "10.3.2.1", "10.3.2.2", "10.3.2.3")
	require.Len(t, accounts, 3)
	rec := newSecretRecorder()
	f.useExecutor(rec)
	f.rotations.executors = func(string) rotationExecutor { return rec }

	req := planRequest("整組改密", []uint{f.bindingOf(t, accounts[0]).AssetID}, "ops")
	req.TargetKind = model.PlanTargetCredential
	req.TargetCredentialID = credID
	plan, err := f.plans.Create(req)
	require.NoError(t, err)
	require.NotNil(t, plan.TargetCredentialID)
	assert.Equal(t, credID, *plan.TargetCredentialID)

	records := f.runner.RunPlan(plan)
	require.Len(t, records, 3, "成員集合等於該憑證當下的全部掛載")
	for _, r := range records {
		assert.Equal(t, model.ChangeSecretSuccess, r.Status, "錯誤: %s", r.Error)
		assert.Equal(t, plan.ID, r.PlanID, "整組改密的記錄掛回該計劃")
		assert.Equal(t, credID, r.CredentialID)
		assert.Equal(t, "整組目標", r.CredentialName)
		assert.NotZero(t, r.TargetVersionID)
	}

	cred := f.credentialOf(t, credID)
	require.NotNil(t, cred.CurrentVersionID)
	assert.Nil(t, cred.PendingVersionID, "全部就位後收斂")
	assert.Nil(t, cred.ActiveRotationID)
	for _, accountID := range accounts {
		binding := f.bindingOf(t, accountID)
		require.NotNil(t, binding.EffectiveVersionID)
		assert.Equal(t, *cred.CurrentVersionID, *binding.EffectiveVersionID)
	}
	assert.EqualValues(t, 2, f.versionCountOf(t, credID), "整輪只產生一個新版本")

	pushed := rec.secretOf("10.3.2.1")
	require.NotEmpty(t, pushed)
	assert.Equal(t, pushed, rec.secretOf("10.3.2.2"), "整組換的是同一組秘密")
	assert.Equal(t, pushed, rec.secretOf("10.3.2.3"))

	// 整組改密的逐成員結果要在輪替證據報告的區間明細裡看得見
	now := time.Now()
	rep, err := f.reports.Build(ReportScope{Kind: model.RotationScopeAll},
		now.Add(-time.Hour), now.Add(time.Hour), now.Add(time.Hour), "zh-TW")
	require.NoError(t, err)
	seen := 0
	for _, r := range rep.Records {
		if r.CredentialName != "整組目標" {
			continue
		}
		seen++
		assert.Equal(t, model.ChangeSecretSuccess, r.Status)
		assert.Equal(t, 2, r.VersionNo, "明細帶執行當下的版本快照")
	}
	assert.Equal(t, 3, seen, "三台的成員記錄都要出現在區間明細")
}

// 目標為專用憑證：逐帳號輪替的行為與本能力引入前逐項相同
func TestPlanDedicatedTargetUnchanged(t *testing.T) {
	f := setupBatchFixture(t)
	a1, acc1 := f.addHost(t, "h1", "10.3.3.1", "ops")
	a2, acc2 := f.addHost(t, "h2", "10.3.3.2", "ops")
	before1 := f.bindingOf(t, acc1).CredentialID
	rec := newSecretRecorder()
	f.useExecutor(rec)

	plan, err := f.plans.Create(planRequest("全專用", []uint{a1, a2}, "ops"))
	require.NoError(t, err)
	records := f.runner.RunPlan(plan)
	require.Len(t, records, 2)
	for _, r := range records {
		assert.Equal(t, model.ChangeSecretSuccess, r.Status, "錯誤: %s", r.Error)
		assert.Equal(t, plan.ID, r.PlanID)
		assert.Zero(t, r.BatchID)
	}
	p1, p2 := rec.secretOf("10.3.3.1"), rec.secretOf("10.3.3.2")
	require.NotEmpty(t, p1)
	assert.NotEqual(t, p1, p2, "各自隨機")
	assert.Equal(t, before1, f.bindingOf(t, acc1).CredentialID, "專用憑證不改綁")
	assert.EqualValues(t, 2, f.versionCountOf(t, before1), "提交後憑證多一版")
	assert.Zero(t, f.candidateCount(t), "成功後候選清除")

	rows, err := f.reports.AccountRows(model.AccountScope{"ops"}, time.Now())
	require.NoError(t, err)
	require.Len(t, rows, 2)
	for _, row := range rows {
		assert.False(t, row.SharedCredential)
	}
	_ = acc2
}
