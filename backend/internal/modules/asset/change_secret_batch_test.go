package asset

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 以帳號名為軸的批次改密：目標解析、兩種密碼模式、逐目標隔離，
// 以及「整批同一組」模式所建共用憑證的改綁與收尾（掛載不足兩台即轉專用）。
//
// 遠端協定不是本檔的責任：以 fake executor 注入，不連任何目標機。
// 兩條執行器路徑的真連線行為由各自的 reliability 測試承擔。

type batchFixture struct {
	db         *gorm.DB
	assets     *AssetService
	accounts   *AssetAccountService
	creds      *CredentialService
	candidates *ChangeSecretCandidateService
	rotations  *CredentialRotationService
	runner     *ChangeSecretRunner
	retry      *ChangeSecretRetryRunner
	plans      *ChangeSecretPlanService
	reports    *RotationReportBuilder
	batches    *ChangeSecretBatchService
}

func setupBatchFixture(t *testing.T) *batchFixture {
	t.Helper()
	db := setupAccountDB(t)
	require.NoError(t, db.AutoMigrate(
		&model.AssetHostKey{}, &model.ChangeSecretPlan{}, &model.ChangeSecretRecord{},
		&model.ChangeSecretCandidate{}, &model.ChangeSecretBatch{},
		&model.CredentialRotation{}, &model.CredentialRotationMember{},
	))
	assets, accounts := newAccountServices(t)
	codec := aesColumnCodec(t, make([]byte, 32))
	creds := NewCredentialService(assets, codec, audit.NewTxSink())
	candidates, err := NewChangeSecretCandidateService(db, codec, assets, audit.NewTxSink())
	require.NoError(t, err)
	hostKeys := NewHostKeyService(db)
	plans := NewChangeSecretPlanService(db)
	reports := NewRotationReportBuilder(db, plans, func() int { return 0 })
	rotations := NewCredentialRotationService(db, assets, candidates, hostKeys, codec,
		audit.NewTxSink(), &fakePermissionChecker{defaultAllow: true})
	return &batchFixture{
		db: db, assets: assets, accounts: accounts, creds: creds, candidates: candidates,
		rotations: rotations,
		runner:    NewChangeSecretRunner(db, assets, candidates, hostKeys, nil).WithRotationService(rotations),
		retry:     NewChangeSecretRetryRunner(db, candidates, assets, hostKeys, nil).WithRotationService(rotations),
		plans:     plans,
		reports:   reports,
		batches:   NewChangeSecretBatchService(db, reports),
	}
}

// sharedOn 建一筆共用憑證並掛到指定的幾台 SSH 資產上，回傳憑證 id 與逐台掛載 id。
func (f *batchFixture) sharedOn(t *testing.T, name, username, secret string, hosts ...string) (uint, []uint) {
	t.Helper()
	cred, err := f.creds.Create(adminCtx(), &CreateCredentialRequest{
		Name: name, Username: username, ProtocolFamily: model.ProtocolFamilySSH, Password: secret,
	})
	require.NoError(t, err)
	accountIDs := make([]uint, 0, len(hosts))
	for _, host := range hosts {
		asset := newSSHAsset(t, f.assets, host, host)
		binding, berr := f.creds.Bind(adminCtx(), cred.ID, &BindCredentialRequest{AssetID: asset.ID})
		require.NoError(t, berr)
		accountIDs = append(accountIDs, binding.ID)
	}
	return cred.ID, accountIDs
}

// credentialOf 取一筆憑證列（含軟刪，供斷言回收）。
func (f *batchFixture) credentialOf(t *testing.T, id uint) *model.Credential {
	t.Helper()
	var cred model.Credential
	require.NoError(t, f.db.Unscoped().Where("id = ?", id).First(&cred).Error)
	return &cred
}

// bindingOf 取一筆掛載列。
func (f *batchFixture) bindingOf(t *testing.T, accountID uint) *model.AssetAccount {
	t.Helper()
	var acc model.AssetAccount
	require.NoError(t, f.db.Where("id = ?", accountID).First(&acc).Error)
	return &acc
}

// sharedBatchRequest 整批同一組的請求（含必填的共用憑證名稱）
func sharedBatchRequest(username, credentialName string, ids ...uint) *ChangeSecretBatchRequest {
	req := batchRequest(username, model.BatchPasswordShared, len(ids) == 0, ids...)
	req.CredentialName = credentialName
	return req
}

// addHost 建一台 ssh 資產（含預設帳號憑證），回傳資產 id 與帳號 id
func (f *batchFixture) addHost(t *testing.T, name, host, username string) (uint, uint) {
	t.Helper()
	a, err := f.assets.Create(&CreateAssetRequest{
		Name: name, Protocol: model.ProtocolSSH, Host: host, Port: 22,
		Username: username, Password: "old-" + name, CreatedBy: 1,
	})
	require.NoError(t, err)
	list, err := f.accounts.List(a.ID)
	require.NoError(t, err)
	require.Len(t, list, 1)
	return a.ID, list[0].ID
}

func (f *batchFixture) reload(t *testing.T, id uint) *model.ChangeSecretBatch {
	t.Helper()
	b, err := f.batches.Get(id)
	require.NoError(t, err)
	return b
}

func (f *batchFixture) candidateCount(t *testing.T) int64 {
	t.Helper()
	var n int64
	require.NoError(t, f.db.Model(&model.ChangeSecretCandidate{}).Count(&n).Error)
	return n
}

// secretRecorder 記下每台主機收到的新密碼，並依主機回傳指定錯誤。
type secretRecorder struct {
	mu          sync.Mutex
	rotated     map[string]string
	rotateErr   map[string]error
	verifyErr   map[string]error
	rotateCalls map[string]int
	verifyCalls map[string]int
}

func newSecretRecorder() *secretRecorder {
	return &secretRecorder{
		rotated: map[string]string{}, rotateErr: map[string]error{}, verifyErr: map[string]error{},
		rotateCalls: map[string]int{}, verifyCalls: map[string]int{},
	}
}

func (s *secretRecorder) Rotate(_ context.Context, t rotationTarget, _, newSecret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rotateCalls[t.asset.Host]++
	if err := s.rotateErr[t.asset.Host]; err != nil {
		return err
	}
	s.rotated[t.asset.Host] = newSecret
	return nil
}

func (s *secretRecorder) Verify(_ context.Context, t rotationTarget, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verifyCalls[t.asset.Host]++
	return s.verifyErr[t.asset.Host]
}

// snapshotCalls 每台的改密與驗證呼叫次數（推進與否要看得出「有沒有真的再打一次」）
func (s *secretRecorder) snapshotCalls() (map[string]string, map[string]int, map[string]int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pushed := map[string]string{}
	for k, v := range s.rotated {
		pushed[k] = v
	}
	rc := map[string]int{}
	for k, v := range s.rotateCalls {
		rc[k] = v
	}
	vc := map[string]int{}
	for k, v := range s.verifyCalls {
		vc[k] = v
	}
	return pushed, rc, vc
}

func (s *secretRecorder) secretOf(host string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rotated[host]
}

func (f *batchFixture) useExecutor(rec *secretRecorder) {
	factory := func(string) rotationExecutor { return rec }
	f.runner.executors = factory
	f.retry.executors = factory
}

func batchRequest(username, mode string, all bool, ids ...uint) *ChangeSecretBatchRequest {
	return &ChangeSecretBatchRequest{Username: username, PasswordMode: mode, All: all, AccountIDs: ids}
}

func assetIDsOf(targets []BatchTarget) []uint {
	out := make([]uint, 0, len(targets))
	for i := range targets {
		out = append(out, targets[i].AssetID)
	}
	return out
}

// 目標集合＝掛在未刪除資產上、名為該帳號名的帳號；已刪除資產與其他帳號名都不在名單上
func TestBatchTargetsOnlyUndeletedAssetsWithUsername(t *testing.T) {
	f := setupBatchFixture(t)
	a1, _ := f.addHost(t, "h1", "10.2.0.1", "ops")
	a2, _ := f.addHost(t, "h2", "10.2.0.2", "ops")
	a3, _ := f.addHost(t, "h3", "10.2.0.3", "ops")
	f.addHost(t, "h4", "10.2.0.4", "root")
	// 直接軟刪資產列：本測試驗的是目標查詢的母體條件，不是刪除的級聯面
	require.NoError(t, f.db.Delete(&model.Asset{}, a3).Error)

	targets, err := f.batches.Targets("ops", time.Now())
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint{a1, a2}, assetIDsOf(targets), "已刪除資產不得入列")
	for _, tgt := range targets {
		assert.Equal(t, "ops", tgt.Username)
		assert.NotEmpty(t, tgt.Bucket, "每個目標帶報告的狀態桶")
		assert.Equal(t, model.RotationChannelPosixSSH, tgt.RotationChannel)
		assert.Empty(t, tgt.IneligibleReason, "有密碼憑證的 ssh 帳號可改密")
	}

	names, err := f.batches.Usernames()
	require.NoError(t, err)
	assert.Equal(t, []BatchUsername{{Username: "ops", AssetCount: 2}, {Username: "root", AssetCount: 1}}, names)

	_, err = f.batches.Targets("  ", time.Now())
	assert.ErrorIs(t, err, ErrBatchUsernameRequired)
}

// 每台各自隨機：兩台的新密碼互異，成功後各自提交為該掛載的憑證
func TestBatchPerTargetModeUsesDistinctPasswords(t *testing.T) {
	f := setupBatchFixture(t)
	a1, acc1 := f.addHost(t, "h1", "10.2.1.1", "ops")
	a2, _ := f.addHost(t, "h2", "10.2.1.2", "ops")
	rec := newSecretRecorder()
	f.useExecutor(rec)

	batch, assetIDs, err := f.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, true), 7, "admin")
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint{a1, a2}, assetIDs)

	records := f.runner.RunBatch(batch, assetIDs)
	require.Len(t, records, 2)
	for _, r := range records {
		assert.Equal(t, model.ChangeSecretSuccess, r.Status, "錯誤: %s", r.Error)
		assert.Equal(t, batch.ID, r.BatchID)
		assert.Zero(t, r.PlanID, "批次記錄不掛在任何計劃上")
	}
	p1, p2 := rec.secretOf("10.2.1.1"), rec.secretOf("10.2.1.2")
	require.NotEmpty(t, p1)
	require.NotEmpty(t, p2)
	assert.NotEqual(t, p1, p2, "每台各自隨機的新密碼不得相同")

	creds1, err := f.assets.GetWithCredentialsForAccount(a1, acc1)
	require.NoError(t, err)
	assert.Equal(t, p1, creds1.Password, "成功後提交為帳號憑證")

	got := f.reload(t, batch.ID)
	assert.Equal(t, model.ChangeSecretBatchCompleted, got.Status)
	assert.Equal(t, 2, got.TargetCount)
	assert.Equal(t, 2, got.SuccessCount)
	assert.NotNil(t, got.FinishedAt)
	assert.Equal(t, uint(7), got.RequestedBy)
}

// 整批同一組：系統建立一筆具名共用憑證，兩台改綁到它並就位同一版本；
// 那組密碼不進審計列、改密記錄與批次列
func TestBatchSharedModeCreatesNamedSharedCredential(t *testing.T) {
	f := setupBatchFixture(t)
	_, acc1 := f.addHost(t, "h1", "10.2.2.1", "ops")
	_, acc2 := f.addHost(t, "h2", "10.2.2.2", "ops")
	oldCred1 := f.bindingOf(t, acc1).CredentialID
	rec := newSecretRecorder()
	f.useExecutor(rec)

	batch, assetIDs, err := f.batches.Create(sharedBatchRequest("ops", "維運批次 2026-09-06"), 1, "admin")
	require.NoError(t, err)

	records := f.runner.RunBatch(batch, assetIDs)
	require.Len(t, records, 2)
	for _, r := range records {
		assert.Equal(t, model.ChangeSecretSuccess, r.Status, "錯誤: %s", r.Error)
	}
	shared := rec.secretOf("10.2.2.1")
	require.NotEmpty(t, shared)
	assert.Equal(t, shared, rec.secretOf("10.2.2.2"), "整批同一組：兩台收到同一組新密碼")

	require.NotZero(t, batch.SharedCredentialID, "整批同一組須建立一筆共用憑證")
	cred := f.credentialOf(t, batch.SharedCredentialID)
	assert.Equal(t, model.CredentialScopeShared, cred.Scope)
	require.NotNil(t, cred.Name)
	assert.Equal(t, "維運批次 2026-09-06", *cred.Name, "名稱取自操作者提供的值")
	require.NotNil(t, cred.CurrentVersionID)

	for _, accountID := range []uint{acc1, acc2} {
		binding := f.bindingOf(t, accountID)
		assert.Equal(t, cred.ID, binding.CredentialID, "成功的目標改綁到該共用憑證")
		require.NotNil(t, binding.EffectiveVersionID)
		assert.Equal(t, *cred.CurrentVersionID, *binding.EffectiveVersionID, "就位同一密文版本")
	}
	var versions int64
	require.NoError(t, f.db.Model(&model.CredentialSecretVersion{}).
		Where("credential_id = ?", cred.ID).Count(&versions).Error)
	assert.EqualValues(t, 1, versions, "同一組密文只存一份，不複製到多筆憑證")
	var orphan int64
	require.NoError(t, f.db.Model(&model.Credential{}).Where("id = ?", oldCred1).Count(&orphan).Error)
	assert.EqualValues(t, 0, orphan, "改綁後零掛載的專用憑證同交易回收")

	for _, r := range records {
		assert.Equal(t, cred.ID, r.CredentialID, "記錄帶憑證快照")
		assert.Equal(t, "維運批次 2026-09-06", r.CredentialName)
		assert.Equal(t, *cred.CurrentVersionID, r.TargetVersionID, "記錄帶目標版本快照")
	}

	rows, err := f.reports.AccountRows(model.AccountScope{"ops"}, time.Now())
	require.NoError(t, err)
	require.Len(t, rows, 2)
	for _, row := range rows {
		assert.True(t, row.SharedCredential, "報告據憑證範圍標示共用")
		assert.Equal(t, "維運批次 2026-09-06", row.CredentialName)
	}
	assert.Equal(t, 2, f.reload(t, batch.ID).SuccessCount)

	// 那組密碼只能存在於執行期記憶體與憑證版本的密文：審計列、改密記錄、批次列都不得含它
	var audits []model.AuditLog
	require.NoError(t, f.db.Find(&audits).Error)
	require.NotEmpty(t, audits, "改密提交必有審計列，否則本斷言由空資料假綠")
	for _, a := range audits {
		raw, _ := json.Marshal(a)
		assert.NotContains(t, string(raw), shared, "審計列不得含整批共用的密碼")
	}
	var stored []model.ChangeSecretRecord
	require.NoError(t, f.db.Find(&stored).Error)
	for _, r := range stored {
		raw, _ := json.Marshal(r)
		assert.NotContains(t, string(raw), shared)
	}
	raw, _ := json.Marshal(f.reload(t, batch.ID))
	assert.NotContains(t, string(raw), shared)
}

// 三台目標、一台失敗：成功的兩台改綁新共用憑證且就位，失敗那台留在原憑證，
// 掛載數仍達 2 故維持共用
func TestBatchSharedModeThreeTargetsPartialSuccess(t *testing.T) {
	f := setupBatchFixture(t)
	_, acc1 := f.addHost(t, "h1", "10.2.11.1", "ops")
	_, acc2 := f.addHost(t, "h2", "10.2.11.2", "ops")
	a3, acc3 := f.addHost(t, "h3", "10.2.11.3", "ops")
	originalOfThree := f.bindingOf(t, acc3).CredentialID
	rec := newSecretRecorder()
	rec.rotateErr["10.2.11.3"] = &remoteRejectedError{reason: model.ChangeSecretReasonRemoteRejected}
	f.useExecutor(rec)

	batch, assetIDs, err := f.batches.Create(sharedBatchRequest("ops", "三台去二"), 1, "admin")
	require.NoError(t, err)
	records := f.runner.RunBatch(batch, assetIDs)
	require.Len(t, records, 3)
	assert.Equal(t, model.ChangeSecretFailed, recordByAsset(records, a3).Status)

	cred := f.credentialOf(t, batch.SharedCredentialID)
	assert.Equal(t, model.CredentialScopeShared, cred.Scope, "掛載達 2 即維持共用")
	require.NotNil(t, cred.Name)
	assert.Equal(t, "三台去二", *cred.Name, "維持共用時名稱不清空")
	require.NotNil(t, cred.CurrentVersionID)
	for _, accountID := range []uint{acc1, acc2} {
		binding := f.bindingOf(t, accountID)
		assert.Equal(t, cred.ID, binding.CredentialID)
		require.NotNil(t, binding.EffectiveVersionID)
		assert.Equal(t, *cred.CurrentVersionID, *binding.EffectiveVersionID)
	}
	failed := f.bindingOf(t, acc3)
	assert.Equal(t, originalOfThree, failed.CredentialID, "失敗那台留在原憑證")
	assert.Empty(t, rec.secretOf("10.2.11.3"), "遠端確定拒絕，密碼沒換上去")

	got := f.reload(t, batch.ID)
	assert.Equal(t, [4]int{2, 1, 0, 0},
		[4]int{got.SuccessCount, got.FailedCount, got.UnverifiedCount, got.SkippedCount})
}

// 整批同一組模式必須提供憑證名稱，且名稱依共用唯一性檢核
func TestBatchSharedModeRequiresCredentialName(t *testing.T) {
	f := setupBatchFixture(t)
	f.addHost(t, "h1", "10.2.7.1", "ops")

	_, _, err := f.batches.Create(batchRequest("ops", model.BatchPasswordShared, true), 1, "admin")
	assert.ErrorIs(t, err, ErrBatchCredentialNameRequired)

	_, err = f.creds.Create(adminCtx(), &CreateCredentialRequest{
		Name: "已存在", Username: "ops", ProtocolFamily: model.ProtocolFamilySSH, Password: "x",
	})
	require.NoError(t, err)
	_, _, err = f.batches.Create(sharedBatchRequest("ops", "已存在"), 1, "admin")
	assert.ErrorIs(t, err, ErrCredentialNameExists, "名稱撞名在送出前就擋下")

	var n int64
	require.NoError(t, f.db.Model(&model.ChangeSecretBatch{}).Count(&n).Error)
	assert.Zero(t, n, "被拒的建立不得留下批次列")
}

// 同一批內成功、確定拒絕、狀態不可知三種結果各自落記錄，互不影響；批次計數與之相符
func TestBatchResultsIsolatedPerTarget(t *testing.T) {
	f := setupBatchFixture(t)
	a1, _ := f.addHost(t, "h1", "10.2.3.1", "ops")
	a2, _ := f.addHost(t, "h2", "10.2.3.2", "ops")
	a3, _ := f.addHost(t, "h3", "10.2.3.3", "ops")
	rec := newSecretRecorder()
	rec.rotateErr["10.2.3.2"] = &remoteRejectedError{reason: model.ChangeSecretReasonRemoteRejected, cause: errors.New("denied")}
	rec.rotateErr["10.2.3.3"] = errors.New("connection reset by peer")
	f.useExecutor(rec)

	batch, assetIDs, err := f.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, true), 1, "admin")
	require.NoError(t, err)
	records := f.runner.RunBatch(batch, assetIDs)
	require.Len(t, records, 3)

	byAsset := map[uint]model.ChangeSecretRecord{}
	for _, r := range records {
		assert.Equal(t, batch.ID, r.BatchID)
		byAsset[r.AssetID] = r
	}
	assert.Equal(t, model.ChangeSecretSuccess, byAsset[a1].Status)
	assert.Equal(t, model.ChangeSecretFailed, byAsset[a2].Status)
	assert.Equal(t, model.ChangeSecretReasonRemoteRejected, byAsset[a2].Error)
	assert.Equal(t, model.ChangeSecretUnverified, byAsset[a3].Status)
	assert.Equal(t, model.ChangeSecretReasonRemoteStateUnknown, byAsset[a3].Error)

	// 候選只剩狀態不可知那台；確定拒絕的已清除、成功的已提交
	var cands []model.ChangeSecretCandidate
	require.NoError(t, f.db.Find(&cands).Error)
	require.Len(t, cands, 1)
	assert.Equal(t, a3, cands[0].AssetID)
	assert.Equal(t, batch.ID, cands[0].BatchID)

	got := f.reload(t, batch.ID)
	assert.Equal(t, model.ChangeSecretBatchCompleted, got.Status)
	assert.Equal(t, [4]int{1, 1, 1, 0},
		[4]int{got.SuccessCount, got.FailedCount, got.UnverifiedCount, got.SkippedCount})
}

// 整批同一組但只有一台成功、另一台確定拒絕：沒有第二個成員，該憑證於批次結束時
// 轉為專用並清空名稱、不再標示共用
func TestBatchSharedCredentialBecomesDedicatedWithoutSecondMember(t *testing.T) {
	f := setupBatchFixture(t)
	_, acc1 := f.addHost(t, "h1", "10.2.4.1", "ops")
	_, acc2 := f.addHost(t, "h2", "10.2.4.2", "ops")
	rec := newSecretRecorder()
	rec.rotateErr["10.2.4.2"] = &remoteRejectedError{reason: model.ChangeSecretReasonRemoteRejected, cause: errors.New("denied")}
	f.useExecutor(rec)

	batch, assetIDs, err := f.batches.Create(sharedBatchRequest("ops", "只剩一員的批次"), 1, "admin")
	require.NoError(t, err)
	records := f.runner.RunBatch(batch, assetIDs)
	require.Len(t, records, 2)
	assert.Zero(t, f.candidateCount(t), "確定拒絕的候選已清除，批次無待驗證候選")

	cred := f.credentialOf(t, batch.SharedCredentialID)
	assert.Equal(t, model.CredentialScopeDedicated, cred.Scope, "一個人的共用不是共用")
	assert.Nil(t, cred.Name, "轉專用時清空名稱")
	assert.Equal(t, cred.ID, f.bindingOf(t, acc1).CredentialID, "成功那台仍掛在它上面")
	assert.NotEqual(t, cred.ID, f.bindingOf(t, acc2).CredentialID, "失敗那台留在原憑證")

	rows, err := f.reports.AccountRows(model.AccountScope{"ops"}, time.Now())
	require.NoError(t, err)
	require.Len(t, rows, 2)
	for _, row := range rows {
		assert.False(t, row.SharedCredential)
	}
}

// 明列的帳號識別若非該帳號名的目標，整筆拒絕且不留批次列；其他輸入錯誤各回專屬 sentinel
func TestBatchCreateRejectsMismatchedAccount(t *testing.T) {
	f := setupBatchFixture(t)
	_, opsAcc := f.addHost(t, "h1", "10.2.5.1", "ops")
	_, rootAcc := f.addHost(t, "h2", "10.2.5.2", "root")

	_, _, err := f.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, false, opsAcc, rootAcc), 1, "admin")
	assert.ErrorIs(t, err, ErrBatchTargetMismatch)

	_, _, err = f.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, false), 1, "admin")
	assert.ErrorIs(t, err, ErrBatchNoTargets)

	_, _, err = f.batches.Create(batchRequest("ops", "rotate", true), 1, "admin")
	assert.ErrorIs(t, err, ErrBatchBadPasswordMode)

	_, _, err = f.batches.Create(batchRequest("", model.BatchPasswordShared, true), 1, "admin")
	assert.ErrorIs(t, err, ErrBatchUsernameRequired)

	bad := batchRequest("ops", model.BatchPasswordShared, true)
	bad.PasswordLength = 8
	_, _, err = f.batches.Create(bad, 1, "admin")
	assert.ErrorIs(t, err, ErrPasswordLengthOutOfRange)

	var n int64
	require.NoError(t, f.db.Model(&model.ChangeSecretBatch{}).Count(&n).Error)
	assert.Zero(t, n, "被拒的建立不得留下批次列")

	// 明列一個合法目標即建立成功，且目標數只算被明列的那一台
	batch, assetIDs, err := f.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, false, opsAcc, opsAcc), 1, "admin")
	require.NoError(t, err)
	assert.Len(t, assetIDs, 1, "重複的識別只算一次")
	assert.Equal(t, 1, batch.TargetCount)
	assert.Equal(t, model.ChangeSecretBatchRunning, batch.Status)
}

// 整批同一組：一台成功、一台驗證未過留候選；批次結束時憑證不轉專用（仍有待驗證候選），
// 候選經重試轉正後改綁到同一筆共用憑證
func TestRetryPromotionRebindsToSharedCredential(t *testing.T) {
	f := setupBatchFixture(t)
	_, acc1 := f.addHost(t, "h1", "10.2.6.1", "ops")
	a2, acc2 := f.addHost(t, "h2", "10.2.6.2", "ops")
	rec := newSecretRecorder()
	rec.verifyErr["10.2.6.2"] = errors.New("verify timeout")
	f.useExecutor(rec)

	batch, assetIDs, err := f.batches.Create(sharedBatchRequest("ops", "分兩次到齊"), 1, "admin")
	require.NoError(t, err)
	records := f.runner.RunBatch(batch, assetIDs)
	require.Len(t, records, 2)
	assert.Equal(t, model.ChangeSecretUnverified, recordByAsset(records, a2).Status)

	credID := batch.SharedCredentialID
	require.NotZero(t, credID)
	assert.Equal(t, model.CredentialScopeShared, f.credentialOf(t, credID).Scope,
		"仍有待驗證候選時不轉專用")
	assert.Equal(t, credID, f.bindingOf(t, acc1).CredentialID)
	assert.NotEqual(t, credID, f.bindingOf(t, acc2).CredentialID, "未轉正前不改綁")

	var cand model.ChangeSecretCandidate
	require.NoError(t, f.db.Where("account_id = ?", acc2).First(&cand).Error)
	assert.Equal(t, batch.ID, cand.BatchID)
	assert.Equal(t, credID, cand.CredentialID, "候選自帶轉正後要落到哪一筆憑證")
	assert.NotZero(t, cand.TargetVersionID, "候選自帶轉正後要就位的版本")

	// 遠端恢復：重試轉正
	rec.mu.Lock()
	delete(rec.verifyErr, "10.2.6.2")
	rec.mu.Unlock()
	require.True(t, f.retry.RetryOne(&cand), "驗證通過即轉正")

	cred := f.credentialOf(t, credID)
	assert.Equal(t, model.CredentialScopeShared, cred.Scope, "兩員同組，維持共用")
	require.NotNil(t, cred.CurrentVersionID)
	binding := f.bindingOf(t, acc2)
	assert.Equal(t, credID, binding.CredentialID, "轉正後改綁到該批次的共用憑證")
	require.NotNil(t, binding.EffectiveVersionID)
	assert.Equal(t, *cred.CurrentVersionID, *binding.EffectiveVersionID, "就位同一密文版本")
	assert.Zero(t, f.candidateCount(t))

	var versions int64
	require.NoError(t, f.db.Model(&model.CredentialSecretVersion{}).
		Where("credential_id = ?", credID).Count(&versions).Error)
	assert.EqualValues(t, 1, versions, "轉正不另開版本")

	var promoted model.ChangeSecretRecord
	require.NoError(t, f.db.Where("account_id = ? AND status = ?", acc2, model.ChangeSecretSuccess).First(&promoted).Error)
	assert.Equal(t, batch.ID, promoted.BatchID, "轉正記錄帶批次識別")
	assert.Equal(t, credID, promoted.CredentialID, "轉正記錄帶憑證快照")
	assert.True(t, strings.HasPrefix(promoted.Error, "CHANGE_SECRET_RETRY"), "轉正記錄的原因碼為重試轉正")
}

// 最後一筆候選由重試轉正時，掛載數仍少於 2 即在該次轉正後轉為專用
func TestRetryPromotionSettlesSharedCredentialToDedicated(t *testing.T) {
	f := setupBatchFixture(t)
	_, acc1 := f.addHost(t, "h1", "10.2.8.1", "ops")
	a2, acc2 := f.addHost(t, "h2", "10.2.8.2", "ops")
	rec := newSecretRecorder()
	rec.rotateErr["10.2.8.1"] = &remoteRejectedError{reason: model.ChangeSecretReasonRemoteRejected, cause: errors.New("denied")}
	rec.verifyErr["10.2.8.2"] = errors.New("verify timeout")
	f.useExecutor(rec)

	batch, assetIDs, err := f.batches.Create(sharedBatchRequest("ops", "只有一台到齊"), 1, "admin")
	require.NoError(t, err)
	records := f.runner.RunBatch(batch, assetIDs)
	require.Len(t, records, 2)
	assert.Equal(t, model.ChangeSecretUnverified, recordByAsset(records, a2).Status)
	credID := batch.SharedCredentialID
	assert.Equal(t, model.CredentialScopeShared, f.credentialOf(t, credID).Scope,
		"仍有待驗證候選時不轉專用")

	rec.mu.Lock()
	delete(rec.verifyErr, "10.2.8.2")
	rec.mu.Unlock()
	var cand model.ChangeSecretCandidate
	require.NoError(t, f.db.Where("account_id = ?", acc2).First(&cand).Error)
	require.True(t, f.retry.RetryOne(&cand))

	cred := f.credentialOf(t, credID)
	assert.Equal(t, model.CredentialScopeDedicated, cred.Scope, "轉正後重估：只剩一個掛載即轉專用")
	assert.Nil(t, cred.Name)
	assert.Equal(t, credID, f.bindingOf(t, acc2).CredentialID)
	assert.NotEqual(t, credID, f.bindingOf(t, acc1).CredentialID)
}

// 每台各自隨機：目標為共用憑證成員者走拆分輪替，成功者改綁各自的新專用憑證
func TestBatchPerTargetSharedMembersUseSplitRotation(t *testing.T) {
	f := setupBatchFixture(t)
	credID, accounts := f.sharedOn(t, "原共用", "ops", "old-shared", "10.2.9.1", "10.2.9.2")
	accA, accB := accounts[0], accounts[1]
	rec := newSecretRecorder()
	f.useExecutor(rec)
	f.rotations.executors = func(string) rotationExecutor { return rec }

	batch, assetIDs, err := f.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, true), 1, "admin")
	require.NoError(t, err)
	records := f.runner.RunBatch(batch, assetIDs)
	require.Len(t, records, 2)
	for _, r := range records {
		assert.Equal(t, model.ChangeSecretSuccess, r.Status, "錯誤: %s", r.Error)
		assert.Equal(t, batch.ID, r.BatchID, "拆分產生的記錄掛回本批次")
	}

	p1, p2 := rec.secretOf("10.2.9.1"), rec.secretOf("10.2.9.2")
	require.NotEmpty(t, p1)
	require.NotEmpty(t, p2)
	assert.NotEqual(t, p1, p2, "每台各自隨機的新密碼不得相同")

	bindA, bindB := f.bindingOf(t, accA), f.bindingOf(t, accB)
	assert.NotEqual(t, credID, bindA.CredentialID, "成功者改綁各自的新專用憑證")
	assert.NotEqual(t, credID, bindB.CredentialID)
	assert.NotEqual(t, bindA.CredentialID, bindB.CredentialID)
	for _, id := range []uint{bindA.CredentialID, bindB.CredentialID} {
		assert.Equal(t, model.CredentialScopeDedicated, f.credentialOf(t, id).Scope)
	}
	var live int64
	require.NoError(t, f.db.Model(&model.Credential{}).Where("id = ?", credID).Count(&live).Error)
	assert.EqualValues(t, 0, live, "零掛載且無未決候選的原共用憑證同交易回收")

	got := f.reload(t, batch.ID)
	assert.Equal(t, model.ChangeSecretBatchCompleted, got.Status)
	assert.Equal(t, 2, got.SuccessCount)
}

// 輪替引擎未接線時，共用憑證成員一律略過而非退回單帳號路徑
func TestBatchPerTargetSharedMembersSkippedWithoutRotationEngine(t *testing.T) {
	f := setupBatchFixture(t)
	credID, _ := f.sharedOn(t, "原共用", "ops", "old-shared", "10.2.10.1", "10.2.10.2")
	rec := newSecretRecorder()
	f.useExecutor(rec)
	f.runner.rotations = nil

	batch, assetIDs, err := f.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, true), 1, "admin")
	require.NoError(t, err)
	records := f.runner.RunBatch(batch, assetIDs)
	require.Len(t, records, 2)
	for _, r := range records {
		assert.Equal(t, model.ChangeSecretSkipped, r.Status)
		assert.Equal(t, model.ChangeSecretReasonSharedCredentialTargetRequired, r.Error)
	}
	assert.EqualValues(t, 1, f.versionCountOf(t, credID), "原共用憑證不得被追加版本")
	assert.Empty(t, rec.secretOf("10.2.10.1"), "遠端不被觸碰")
}

// versionCountOf 憑證的密文版本數
func (f *batchFixture) versionCountOf(t *testing.T, credentialID uint) int64 {
	t.Helper()
	var n int64
	require.NoError(t, f.db.Model(&model.CredentialSecretVersion{}).
		Where("credential_id = ?", credentialID).Count(&n).Error)
	return n
}
