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

// 以帳號名為軸的批次改密：目標解析、兩種密碼模式、逐目標隔離、共用群組的歸組與解散。
//
// 遠端協定不是本檔的責任：以 fake executor 注入，不連任何目標機。
// 兩條執行器路徑的真連線行為由各自的 reliability 測試承擔。

type batchFixture struct {
	db         *gorm.DB
	assets     *AssetService
	accounts   *AssetAccountService
	candidates *ChangeSecretCandidateService
	runner     *ChangeSecretRunner
	retry      *ChangeSecretRetryRunner
	reports    *RotationReportBuilder
	batches    *ChangeSecretBatchService
}

func setupBatchFixture(t *testing.T) *batchFixture {
	t.Helper()
	db := setupAccountDB(t)
	require.NoError(t, db.AutoMigrate(
		&model.AssetHostKey{}, &model.ChangeSecretPlan{}, &model.ChangeSecretRecord{},
		&model.ChangeSecretCandidate{}, &model.ChangeSecretBatch{},
	))
	assets, accounts := newAccountServices(t)
	codec := aesColumnCodec(t, make([]byte, 32))
	candidates, err := NewChangeSecretCandidateService(db, codec, assets, audit.NewTxSink())
	require.NoError(t, err)
	hostKeys := NewHostKeyService(db)
	plans := NewChangeSecretPlanService(db)
	reports := NewRotationReportBuilder(db, plans, func() int { return 0 })
	return &batchFixture{
		db: db, assets: assets, accounts: accounts, candidates: candidates,
		runner:  NewChangeSecretRunner(db, assets, candidates, hostKeys, nil),
		retry:   NewChangeSecretRetryRunner(db, candidates, assets, hostKeys, nil),
		reports: reports,
		batches: NewChangeSecretBatchService(db, reports),
	}
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
	mu        sync.Mutex
	rotated   map[string]string
	rotateErr map[string]error
	verifyErr map[string]error
}

func newSecretRecorder() *secretRecorder {
	return &secretRecorder{
		rotated: map[string]string{}, rotateErr: map[string]error{}, verifyErr: map[string]error{},
	}
}

func (s *secretRecorder) Rotate(_ context.Context, t rotationTarget, _, newSecret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.rotateErr[t.asset.Host]; err != nil {
		return err
	}
	s.rotated[t.asset.Host] = newSecret
	return nil
}

func (s *secretRecorder) Verify(_ context.Context, t rotationTarget, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.verifyErr[t.asset.Host]
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

// 每台各自隨機：兩台的新密碼互異，成功後皆不屬於任何憑證群組
func TestBatchPerTargetModeUsesDistinctPasswords(t *testing.T) {
	f := setupBatchFixture(t)
	a1, acc1 := f.addHost(t, "h1", "10.2.1.1", "ops")
	a2, acc2 := f.addHost(t, "h2", "10.2.1.2", "ops")
	rec := newSecretRecorder()
	f.useExecutor(rec)

	batch, assetIDs, err := f.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, true), 7, "admin")
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint{a1, a2}, assetIDs)
	assert.Empty(t, batch.SharedGroup, "各自隨機模式不產生群組識別")

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
	assert.Empty(t, groupOf(t, f.db, acc1))
	assert.Empty(t, groupOf(t, f.db, acc2))

	got := f.reload(t, batch.ID)
	assert.Equal(t, model.ChangeSecretBatchCompleted, got.Status)
	assert.Equal(t, 2, got.TargetCount)
	assert.Equal(t, 2, got.SuccessCount)
	assert.NotNil(t, got.FinishedAt)
	assert.Equal(t, uint(7), got.RequestedBy)
}

// 整批同一組：兩台的新密碼相同、同屬批次群組、報告標示共用；那組密碼不進審計列與記錄
func TestBatchSharedModeJoinsCredentialGroup(t *testing.T) {
	f := setupBatchFixture(t)
	_, acc1 := f.addHost(t, "h1", "10.2.2.1", "ops")
	_, acc2 := f.addHost(t, "h2", "10.2.2.2", "ops")
	rec := newSecretRecorder()
	f.useExecutor(rec)

	batch, assetIDs, err := f.batches.Create(batchRequest("ops", model.BatchPasswordShared, true), 1, "admin")
	require.NoError(t, err)
	require.NotEmpty(t, batch.SharedGroup)

	records := f.runner.RunBatch(batch, assetIDs)
	require.Len(t, records, 2)
	for _, r := range records {
		assert.Equal(t, model.ChangeSecretSuccess, r.Status, "錯誤: %s", r.Error)
	}
	shared := rec.secretOf("10.2.2.1")
	require.NotEmpty(t, shared)
	assert.Equal(t, shared, rec.secretOf("10.2.2.2"), "整批同一組：兩台收到同一組新密碼")

	assert.Equal(t, batch.SharedGroup, groupOf(t, f.db, acc1))
	assert.Equal(t, batch.SharedGroup, groupOf(t, f.db, acc2))

	rows, err := f.reports.AccountRows(model.AccountScope{"ops"}, time.Now())
	require.NoError(t, err)
	require.Len(t, rows, 2)
	for _, row := range rows {
		assert.True(t, row.SharedCredential, "報告須把整批同一組的帳號標為共用憑證")
	}
	assert.Equal(t, 2, f.reload(t, batch.ID).SuccessCount)

	// 那組密碼只能存在於執行期記憶體與帳號憑證的密文：審計列、改密記錄、批次列都不得含它
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
	assert.NotContains(t, string(raw), batch.SharedGroup, "群組識別不出站")
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

// 整批同一組但只有一台成功、另一台確定拒絕：沒有第二個成員，群組解散、不標共用
func TestBatchSharedGroupDissolvesWithoutSecondMember(t *testing.T) {
	f := setupBatchFixture(t)
	_, acc1 := f.addHost(t, "h1", "10.2.4.1", "ops")
	_, acc2 := f.addHost(t, "h2", "10.2.4.2", "ops")
	rec := newSecretRecorder()
	rec.rotateErr["10.2.4.2"] = &remoteRejectedError{reason: model.ChangeSecretReasonRemoteRejected, cause: errors.New("denied")}
	f.useExecutor(rec)

	batch, assetIDs, err := f.batches.Create(batchRequest("ops", model.BatchPasswordShared, true), 1, "admin")
	require.NoError(t, err)
	records := f.runner.RunBatch(batch, assetIDs)
	require.Len(t, records, 2)
	assert.Zero(t, f.candidateCount(t), "確定拒絕的候選已清除，批次無待驗證候選")

	assert.Empty(t, groupOf(t, f.db, acc1), "一個人的共用不是共用")
	assert.Empty(t, groupOf(t, f.db, acc2))
	rows, err := f.reports.AccountRows(model.AccountScope{"ops"}, time.Now())
	require.NoError(t, err)
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

// 整批同一組：一台成功、一台驗證未過留候選；批次結束時群組不解散（仍有待驗證候選），
// 候選經重試轉正後歸入同一群組
func TestRetryPromotionJoinsSharedGroup(t *testing.T) {
	f := setupBatchFixture(t)
	_, acc1 := f.addHost(t, "h1", "10.2.6.1", "ops")
	a2, acc2 := f.addHost(t, "h2", "10.2.6.2", "ops")
	rec := newSecretRecorder()
	rec.verifyErr["10.2.6.2"] = errors.New("verify timeout")
	f.useExecutor(rec)

	batch, assetIDs, err := f.batches.Create(batchRequest("ops", model.BatchPasswordShared, true), 1, "admin")
	require.NoError(t, err)
	records := f.runner.RunBatch(batch, assetIDs)
	require.Len(t, records, 2)
	assert.Equal(t, model.ChangeSecretUnverified, recordByAsset(records, a2).Status)

	assert.Equal(t, batch.SharedGroup, groupOf(t, f.db, acc1), "仍有待驗證候選時群組不解散")
	assert.Empty(t, groupOf(t, f.db, acc2), "未轉正前不歸組")

	var cand model.ChangeSecretCandidate
	require.NoError(t, f.db.Where("account_id = ?", acc2).First(&cand).Error)
	assert.Equal(t, batch.ID, cand.BatchID)
	assert.Equal(t, batch.SharedGroup, cand.SharedGroup, "候選自帶轉正後要歸入的群組")

	// 遠端恢復：重試轉正
	rec.mu.Lock()
	delete(rec.verifyErr, "10.2.6.2")
	rec.mu.Unlock()
	require.True(t, f.retry.RetryOne(&cand), "驗證通過即轉正")

	assert.Equal(t, batch.SharedGroup, groupOf(t, f.db, acc2), "轉正後歸入批次群組")
	assert.Equal(t, batch.SharedGroup, groupOf(t, f.db, acc1), "兩員同組，不解散")
	assert.Zero(t, f.candidateCount(t))

	var promoted model.ChangeSecretRecord
	require.NoError(t, f.db.Where("account_id = ? AND status = ?", acc2, model.ChangeSecretSuccess).First(&promoted).Error)
	assert.Equal(t, batch.ID, promoted.BatchID, "轉正記錄帶批次識別")
	assert.True(t, strings.HasPrefix(promoted.Error, "CHANGE_SECRET_RETRY"), "轉正記錄的原因碼為重試轉正")
}
