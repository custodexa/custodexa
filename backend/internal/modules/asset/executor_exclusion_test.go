package asset

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
)

// 執行身分掛載不進人員連線、帳號列表、申請、批次與帳號目標計劃；預設帳號不變式只計登入掛載。
// 執行身分以直接改寫掛載用途的方式布置（與執行身分服務產生的狀態相同：非預設、用途 executor）。

// markExecutor 把既有掛載改為執行身分（非預設）。
func markExecutor(t *testing.T, ids ...uint) {
	t.Helper()
	for _, id := range ids {
		require.NoError(t, database.DB.Model(&model.AssetAccount{}).Where("id = ?", id).
			Updates(map[string]any{"purpose": model.AccountPurposeExecutor, "is_default": false}).Error)
	}
}

// executorHost 一台 ssh 資產：登入帳號 app（預設）與執行身分 cx-exec（專用憑證）。
func executorHost(t *testing.T, assets *AssetService, accounts *AssetAccountService, name, host string) (assetID, appID, execID uint) {
	t.Helper()
	a, err := assets.Create(WithSystemCaller(context.Background()), &CreateAssetRequest{
		Name: name, Protocol: model.ProtocolSSH, Host: host, Port: 22,
		Username: "app", Password: "app-pw", CreatedBy: 1,
	})
	require.NoError(t, err)
	list, err := accounts.List(a.ID)
	require.NoError(t, err)
	require.Len(t, list, 1)
	exec, err := accounts.Create(WithSystemCaller(adminCtx()), a.ID, &CreateAssetAccountRequest{Username: "cx-exec", Password: "exec-pw"})
	require.NoError(t, err)
	markExecutor(t, exec.ID)
	return a.ID, list[0].ID, exec.ID
}

func TestExecutorOnlyAssetIsZeroLoginAccounts(t *testing.T) {
	db := setupAccountDB(t)
	assets, accounts := newAccountServices(t)
	a, err := assets.Create(WithSystemCaller(context.Background()), &CreateAssetRequest{
		Name: "exec-only", Protocol: model.ProtocolSSH, Host: "10.9.0.1", Port: 22,
		Username: "cx-exec", Password: "exec-pw", CreatedBy: 1,
	})
	require.NoError(t, err)
	var only model.AssetAccount
	require.NoError(t, db.Where("asset_id = ?", a.ID).First(&only).Error)
	markExecutor(t, only.ID)

	got, err := resolveAssetAccount(db, a.ID, 0)
	require.NoError(t, err, "只有執行身分的資產不是「有帳號無預設」")
	assert.Nil(t, got)

	// 待配憑證判準與零帳號閘一致：只有執行身分仍算待配憑證（旗標與篩選兩處）
	pending, err := assets.List(&AssetFilter{CredentialPending: true})
	require.NoError(t, err)
	require.Len(t, pending.Data, 1, "只有執行身分的資產列在待配憑證篩選")
	assert.Equal(t, a.ID, pending.Data[0].ID)
	assert.True(t, pending.Data[0].CredentialPending, "只有執行身分的資產旗標為待配憑證")

	created, err := accounts.Create(WithSystemCaller(adminCtx()), a.ID, &CreateAssetAccountRequest{Username: "app", Password: "app-pw"})
	require.NoError(t, err)
	assert.True(t, created.IsDefault, "第一筆登入帳號自動成為預設")

	list, err := accounts.List(a.ID)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "app", list[0].Username, "列表不含執行身分")

	pending, err = assets.List(&AssetFilter{CredentialPending: true})
	require.NoError(t, err)
	assert.Empty(t, pending.Data, "有登入帳號後不再待配憑證")
}

func TestExecutorHiddenFromConnectionExits(t *testing.T) {
	_ = setupAccountDB(t)
	assets, accounts := newAccountServices(t)
	assetID, appID, execID := executorHost(t, assets, accounts, "exec-conn", "10.9.0.2")
	trace := &materialTrace{BytesColumnCodec: assets.bytesCrypto}
	assets.bytesCrypto = trace
	assets.resolver.crypto = trace

	t.Run("ResolveAccountIdentity", func(t *testing.T) {
		_, err := assets.ResolveAccountIdentity(assetID, execID)
		assert.ErrorIs(t, err, ErrAssetAccountNotFound)
		_, missing := assets.ResolveAccountIdentity(assetID, 999999)
		assert.Equal(t, missing, err, "與帳號不存在同形")
	})
	t.Run("VerifyAccountBinding", func(t *testing.T) {
		assert.ErrorIs(t, assets.VerifyAccountBinding(assetID, execID), ErrAssetAccountNotFound)
	})
	t.Run("GetWithCredentialsForAccount", func(t *testing.T) {
		before := trace.calls
		_, err := assets.GetWithCredentialsForAccount(assetID, execID)
		assert.ErrorIs(t, err, ErrAssetAccountNotFound)
		assert.Equal(t, before, trace.calls, "判定在任何解封之前")
	})
	t.Run("login account still works", func(t *testing.T) {
		creds, err := assets.GetWithCredentialsForAccount(assetID, appID)
		require.NoError(t, err)
		defer creds.Destroy()
		assert.Equal(t, "app", creds.Username)
	})
}

func TestExecutorExcludedFromRequestAndBatch(t *testing.T) {
	f := setupBatchFixture(t)
	assetID, _, _ := executorHost(t, f.assets, f.accounts, "exec-batch", "10.9.0.3")

	t.Run("RequestAccountPresent", func(t *testing.T) {
		ok, err := RequestAccountPresent(f.db, assetID, "cx-exec")
		require.NoError(t, err)
		assert.False(t, ok, "指名執行身分與沒有這個帳號相同")
		ok, err = RequestAccountPresent(f.db, assetID, "app")
		require.NoError(t, err)
		assert.True(t, ok)
	})
	t.Run("Usernames", func(t *testing.T) {
		names, err := f.batches.Usernames()
		require.NoError(t, err)
		for _, n := range names {
			assert.NotEqual(t, "cx-exec", n.Username)
		}
	})
	t.Run("Targets", func(t *testing.T) {
		targets, err := f.batches.Targets("cx-exec", time.Now())
		require.NoError(t, err)
		assert.Empty(t, targets)
	})
	t.Run("selectTargets", func(t *testing.T) {
		_, _, err := f.batches.Create(batchRequest("cx-exec", model.BatchPasswordPerTarget, true), 7, "admin")
		require.Error(t, err, "批次以執行身分帳號名展開不到任何目標")
		var n int64
		require.NoError(t, f.db.Model(&model.ChangeSecretBatch{}).Count(&n).Error)
		assert.Zero(t, n)
	})
}

func TestExecutorExcludedFromAccountTargetPlans(t *testing.T) {
	f := setupBatchFixture(t)
	assetID, appID, execID := executorHost(t, f.assets, f.accounts, "exec-plan", "10.9.0.4")
	rec := newSecretRecorder()
	f.useExecutor(rec)
	execBefore := *f.bindingOf(t, execID).EffectiveVersionID

	t.Run("run @ALL", func(t *testing.T) {
		plan, err := f.plans.Create(adminCtx(), planRequest("全帳號", []uint{assetID}))
		require.NoError(t, err)
		records := f.runner.RunPlan(plan)
		require.Len(t, records, 1)
		assert.Equal(t, appID, records[0].AccountID)
		assert.Equal(t, execBefore, *f.bindingOf(t, execID).EffectiveVersionID, "執行身分就位版本不變")
	})
	t.Run("run named executor", func(t *testing.T) {
		plan, err := f.plans.Create(adminCtx(), planRequest("只指名執行身分", []uint{assetID}, "cx-exec"))
		require.NoError(t, err)
		records := f.runner.RunPlan(plan)
		require.Len(t, records, 1)
		assert.Equal(t, model.ChangeSecretReasonNoAccountInScope, records[0].Error)
	})
}

func TestSharedExecutorDoesNotBlockAccountPlanSave(t *testing.T) {
	f := setupBatchFixture(t)
	// 共用憑證 ops 掛在兩台：兩台另有登入帳號 seed（專用、預設）
	credID, mounts := f.sharedOn(t, "共用執行身分", "ops", "shared-pw", "10.9.1.1", "10.9.1.2")
	markExecutor(t, mounts...)
	assetIDs := []uint{f.bindingOf(t, mounts[0]).AssetID, f.bindingOf(t, mounts[1]).AssetID}

	plan, err := f.plans.Create(adminCtx(), planRequest("涵蓋共用執行身分", assetIDs))
	require.NoError(t, err, "執行身分引用共用憑證不擋帳號目標計劃存檔")
	_, err = f.plans.Update(adminCtx(), plan.ID, planRequest("涵蓋共用執行身分", assetIDs))
	require.NoError(t, err)

	// 對照：登入帳號引用共用憑證照舊擋
	other, err := f.creds.Create(adminCtx(), &CreateCredentialRequest{
		Name: "共用登入", Username: "lg", ProtocolFamily: model.ProtocolFamilySSH, Password: "lg-pw",
	})
	require.NoError(t, err)
	_, err = f.creds.Bind(adminCtx(), other.ID, &BindCredentialRequest{AssetID: assetIDs[0]})
	require.NoError(t, err)
	_, err = f.plans.Create(adminCtx(), planRequest("涵蓋共用登入", assetIDs))
	assert.ErrorIs(t, err, ErrPlanSharedCredentialTarget)
	_ = credID
}

func TestRotationReportDoesNotCoverExecutorWithAccountPlan(t *testing.T) {
	f := setupBatchFixture(t)
	assetID, appID, execID := executorHost(t, f.assets, f.accounts, "exec-report", "10.9.0.5")
	plan, err := f.plans.Create(adminCtx(), planRequest("報告涵蓋", []uint{assetID}))
	require.NoError(t, err)
	require.True(t, plan.Enabled)

	rows, err := f.reports.AccountRowsIn(nil, []uint{assetID}, nil, time.Now())
	require.NoError(t, err)
	byID := map[uint]AccountRow{}
	for _, r := range rows {
		byID[r.AccountID] = r
	}
	require.Contains(t, byID, execID, "報告母體含執行身分")
	require.Contains(t, byID, appID)
	assert.Empty(t, byID[execID].Plans, "帳號目標計劃不算涵蓋執行身分")
	assert.Equal(t, []string{"報告涵蓋"}, byID[appID].Plans)
}
