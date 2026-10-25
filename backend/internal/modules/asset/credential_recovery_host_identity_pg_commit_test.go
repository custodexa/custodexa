package asset

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 本檔承接 TestCredentialRecoveryHostIdentityPG 的第三批子測試（M-6A-c）：
// verify_vs_local_commit、commit_phase_evidence（本檔），manual_confirm_vs_adopt、confirm_crash_barrier
// （見 *_pg_confirm_test.go）。注入的重置一律從實例二的連線池與服務發出，提交交易跑在實例一。

// pgBatchEnv 批次／輪替夾具（batchFixture）的 PG 版：同一個 schema 內兩條獨立連線池。
type pgBatchEnv struct {
	f       *batchFixture
	db2     *gorm.DB
	svc2    *HostKeyService
	appName string
}

// newPGBatchEnv 與 setupBatchFixture 同構，但資料庫是 PG 的獨立 schema；兩條池帶 application_name。
func newPGBatchEnv(t *testing.T, dsn string) *pgBatchEnv {
	t.Helper()
	schema := fmt.Sprintf("hid_pgb_%d", time.Now().UnixNano())
	appName := "p2m6aa_" + schema
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA " + schema + " CASCADE").Error
		if sqlDB, err := admin.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	db := openPGIdentityPool(t, dsn, schema, appName)
	db2 := openPGIdentityPool(t, dsn, schema, appName)
	require.NoError(t, db.AutoMigrate(
		&model.Asset{}, &model.AssetAccount{}, &model.Credential{}, &model.CredentialSecretVersion{}, &model.AuditLog{},
		&model.AssetGroup{}, &model.AssetNode{}, &model.CredentialJobAuthorization{},
		&model.AssetHostKey{}, &model.AssetHostKeyMismatch{}, &model.ChangeSecretPlan{}, &model.ChangeSecretRecord{},
		&model.ChangeSecretCandidate{}, &model.ChangeSecretBatch{},
		&model.CredentialRotation{}, &model.CredentialRotationMember{},
	))
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	assets, accounts := newAccountServices(t)
	codec := aesColumnCodec(t, make([]byte, 32))
	creds := NewCredentialService(assets, codec, audit.NewTxSink()).WithOwnershipScope(globalOwnershipScopeForTest{}).WithManagementAuthorizer(newAllowAllAuthorizer()).WithSystemAlertSink(newFakeAlertSink())
	candidates, err := NewChangeSecretCandidateService(db, codec, assets, audit.NewTxSink())
	require.NoError(t, err)
	hostKeys := NewHostKeyService(db)
	hostKeys.SetAuditTxSink(audit.NewTxSink())
	hostKeys.SetSystemAlertSink(newFakeAlertSink())
	az := newAllowAllAuthorizer()
	plans := NewChangeSecretPlanService(db).WithAuthorizer(az).WithAuditSink(audit.NewTxSink())
	reports := NewRotationReportBuilder(db, plans, func() int { return 0 })
	rotations := NewCredentialRotationService(db, assets, candidates, hostKeys, codec,
		audit.NewTxSink(), az).WithSystemAlertSink(newFakeAlertSink())
	f := &batchFixture{
		db: db, assets: assets, accounts: accounts, creds: creds, candidates: candidates,
		rotations: rotations,
		runner: NewChangeSecretRunner(db, assets, candidates, hostKeys, nil).WithOwnershipScope(globalOwnershipScopeForTest{}).WithRotationService(rotations).
			WithManagementAuthorizer(az),
		retry: NewChangeSecretRetryRunner(db, candidates, assets, hostKeys, nil).WithRotationService(rotations).
			WithManagementAuthorizer(az),
		plans: plans, reports: reports,
		batches: NewChangeSecretBatchService(db, reports).WithManagementAuthorizer(az).WithOwnershipScope(globalOwnershipScopeForTest{}),
		authz:   az,
	}
	svc2 := NewHostKeyService(db2)
	svc2.SetAuditTxSink(audit.NewTxSink())
	svc2.SetSystemAlertSink(newFakeAlertSink())
	return &pgBatchEnv{f: f, db2: db2, svc2: svc2, appName: appName}
}

// --- verify_vs_local_commit ---

// barrierEnv2 注入用的環境：資料面操作走實例二的連線池與服務。
func (e *pgIdentityEnv) barrierEnv2(t *testing.T) *barrierEnv {
	t.Helper()
	return newBarrierEnv(t, e.db2, e.svc2, e.f.assetID, e.f.server.currentHostKey().PublicKey())
}

// 一般候選 Promote：已綁定、已下達的候選重試，驗證成功之後、轉正交易之前由實例二注入重置。
func runVerifyVsCommitPromote(t *testing.T, e *pgIdentityEnv, form barrierForm) {
	s := newPGRetryScenario(t, e)
	versions := credentialVersionCount(t, s.f)
	be, p := e.barrierEnv2(t), &barrierProbe{}
	s.f.retry.executors = wrapCSExecutors(t, s.f, s.f.retry.executors, be, form, p)

	assert.False(t, s.retry(t, false))
	requireBarrierReached(t, p, be, 1)
	assert.EqualValues(t, 1, p.authDelta.Load(), "驗證階段靶機認證嘗試恰一次")
	assert.EqualValues(t, s.baseAuth+1, s.f.server.authAttempts.Load(), "重試全程只有驗證那一次登入")
	assert.EqualValues(t, 1, s.f.candidateCount(t), "不提交：候選保留")
	assert.Equal(t, "oldpass123", s.f.storedPassword(t), "正式憑證不變")
	assert.Equal(t, versions, credentialVersionCount(t, s.f), "不新增版本")
	assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, candidateOfAccount(t, s.f).LastError)
	requireStopSeq(t, stopAuditDetails(t, s.f), barrierCommitStop)
	requireOwnUntouched(t, p, be)
}

// 帶目標憑證候選 promoteToCredential：同輪另一台（h1）已完成，不受影響。
func runVerifyVsCommitPromoteToCredential(t *testing.T, e *pgBatchEnv, form barrierForm) {
	f := e.f
	f.runner.WithAuditSink(audit.NewTxSink())
	f.retry.WithAuditSink(audit.NewTxSink())
	_, acc1 := f.addHost(t, "h1", "10.38.3.1", "ops")
	a2, acc2 := f.addHost(t, "h2", "10.38.3.2", "ops")
	rec := newSecretRecorder()
	rec.verifyErr["10.38.3.2"] = errors.New("verify timeout")
	f.useExecutor(rec)
	batch, assetIDs, err := f.batches.Create(sharedBatchRequest("ops", "重置注入"), 1, "admin")
	require.NoError(t, err)
	records := f.runner.RunBatch(batch, assetIDs)
	require.Equal(t, model.ChangeSecretUnverified, recordByAsset(records, a2).Status)
	var cand model.ChangeSecretCandidate
	require.NoError(t, f.db.Where("account_id = ?", acc2).First(&cand).Error)
	require.NotZero(t, cand.CredentialID, "帶目標憑證的候選")
	require.Equal(t, model.HostKeyBindingBound, cand.HostKeyBinding)
	credBefore := f.bindingOf(t, acc2).CredentialID
	otherCredBefore := f.bindingOf(t, acc1).CredentialID

	be, p := newBarrierEnv(t, e.db2, e.svc2, a2, rec.hostKey), &barrierProbe{}
	_, _, vc := rec.snapshotCalls()
	baseVerifies := int32(vc["10.38.3.2"])
	rec.mu.Lock()
	delete(rec.verifyErr, "10.38.3.2")
	rec.afterVerify = func(h string) {
		if h != "10.38.3.2" {
			return
		}
		p.fired.Add(1)
		p.verifies.Store(int32(rec.verifyCalls[h]) - baseVerifies) // 替身持鎖呼叫，直接讀
		p.inject(t, be, form)
	}
	rec.mu.Unlock()

	assert.False(t, f.retry.RetryOneAs(context.Background(), &cand), "身分不符：不轉正")
	requireBarrierReached(t, p, be, 1)
	kept := f.candidateOf(t, cand.ID)
	assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, kept.LastError, "原因碼不是提交失敗")
	assert.Equal(t, credBefore, f.bindingOf(t, acc2).CredentialID, "未改綁，正式憑證不變")
	assert.EqualValues(t, 1, f.candidateCountFor(t, acc2), "候選保留")
	assert.Equal(t, otherCredBefore, f.bindingOf(t, acc1).CredentialID, "同輪另一台不受影響")
	requireStopSeq(t, memberStops(t, f.db), barrierCommitStop)
	requireOwnUntouched(t, p, be)
}

// 輪替成員 commitGroupApplied／commitSplitApplied：第二台驗證之後注入重置；第一台維持 applied。
func runVerifyVsCommitMember(t *testing.T, e *pgBatchEnv, form barrierForm, split bool) {
	f := e.f
	host1, host2 := "10.38.1.1", "10.38.1.2"
	if split {
		host1, host2 = "10.38.2.1", "10.38.2.2"
	}
	credID, accounts := f.sharedOn(t, "重置注入", "ops", "old-shared", host1, host2)
	assetID := f.bindingOf(t, accounts[1]).AssetID
	effBefore := f.bindingOf(t, accounts[1]).EffectiveVersionID
	rec := newSecretRecorder()
	be, p := newBarrierEnv(t, e.db2, e.svc2, assetID, rec.hostKey), &barrierProbe{}
	rec.afterVerify = func(h string) {
		if h != host2 {
			return
		}
		p.fired.Add(1)
		p.verifies.Store(int32(rec.verifyCalls[h])) // 替身持鎖呼叫，直接讀
		p.inject(t, be, form)
	}
	f.useRotationExecutor(rec)

	var rot *model.CredentialRotation
	var err error
	if split {
		rot, err = f.rotations.StartSplit(adminCtx(), credID, StartRotationRequest{})
	} else {
		rot, err = f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
	}
	require.NoError(t, err)
	require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))

	requireBarrierReached(t, p, be, 1)
	_, _, vc := rec.snapshotCalls()
	assert.Equal(t, 1, vc[host2], "該台驗證恰一次，之後沒有再打")
	bad := f.memberOf(t, rot.ID, accounts[1])
	require.Equal(t, model.HostKeyBindingBound, bad.HostKeyBinding)
	assert.Equal(t, model.CredentialMemberChangedUnverified, bad.State, "不提交：停在已下達未驗證")
	assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, bad.LastError)
	assert.EqualValues(t, 1, f.candidateCountFor(t, accounts[1]), "候選保留")
	assert.Equal(t, effBefore, f.bindingOf(t, accounts[1]).EffectiveVersionID, "就位版本不動")
	if split {
		assert.Equal(t, credID, f.bindingOf(t, accounts[1]).CredentialID, "未改綁到專用憑證")
	}
	assert.Equal(t, model.CredentialMemberApplied, f.memberOf(t, rot.ID, accounts[0]).State, "同輪另一成員不受影響")
	stops := memberStops(t, f.db)
	requireStopSeq(t, stops, barrierCommitStop)
	assert.EqualValues(t, bad.ID, stops[0]["member_id"])
	requireOwnUntouched(t, p, be)
}

// --- commit_phase_evidence ---

// 提交階段的停止審計照實記 phase=commit、verification_sent=true（秘密已送出、驗證已通過）；
// 靶機認證嘗試在驗證階段恰一次。兩條真 SSH 路徑：一般密碼 rotatePassword 與重試 Promote。
func runCommitPhaseEvidenceRotate(t *testing.T, e *pgIdentityEnv) {
	f := e.f
	wireStopAudit(f)
	form := barrierForms()[0]
	be, p := e.barrierEnv2(t), &barrierProbe{}
	f.runner.executors = wrapCSExecutors(t, f, f.runner.executors, be, form, p)
	records := f.runner.RunPlan(f.plan(t, nil))
	require.Len(t, records, 1)
	requireBarrierReached(t, p, be, 1)
	assert.EqualValues(t, 1, p.authDelta.Load(), "替身 authAttempts：驗證階段恰一次")
	assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, records[0].Error)
	stops := stopAuditDetails(t, f)
	requireStopSeq(t, stops, barrierCommitStop)
	assert.Equal(t, hostIdentityPhaseCommit, stops[0]["phase"])
	assert.Equal(t, verificationSentTrue, stops[0]["verification_sent"])
}

func runCommitPhaseEvidenceRetry(t *testing.T, e *pgIdentityEnv) {
	s := newPGRetryScenario(t, e)
	form := barrierForms()[0]
	be, p := e.barrierEnv2(t), &barrierProbe{}
	s.f.retry.executors = wrapCSExecutors(t, s.f, s.f.retry.executors, be, form, p)
	assert.False(t, s.retry(t, false))
	requireBarrierReached(t, p, be, 1)
	assert.EqualValues(t, 1, p.authDelta.Load(), "替身 authAttempts：驗證階段恰一次")
	assert.EqualValues(t, s.baseAuth+1, s.f.server.authAttempts.Load(), "重試全程 authAttempts 只增加 1")
	stops := stopAuditDetails(t, s.f)
	requireStopSeq(t, stops, barrierCommitStop)
	assert.Equal(t, hostIdentityPhaseCommit, stops[0]["phase"])
	assert.Equal(t, verificationSentTrue, stops[0]["verification_sent"])
}
