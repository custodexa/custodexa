package asset

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 提交交易的「真 Verify 之後、提交之前」重置注入（root：TestCredentialRecoveryHostIdentityPin，前綴 3.4/提交注入/）。
// 注入點是替身執行器的 Verify 成功之後（秘密已送出、驗證已通過），三種重置形態各自走四個提交交易的所有到達路徑：
// 一般密碼 rotatePassword、一般金鑰 rotateKey、重試 RetryOneAs（一般候選與帶目標憑證候選兩種轉正交易）、
// 整組與拆分輪替的 commitApplied。夾具的綁定與主機金鑰記錄都經正式回呼建立，注入只動資料面的記錄列。

// barrierEnv 注入重置所需的服務與資產位址。
type barrierEnv struct {
	db       *gorm.DB
	hostKeys *HostKeyService
	assetID  uint
	host     string
	port     int
	key      ssh.PublicKey
}

func newBarrierEnv(t *testing.T, db *gorm.DB, hk *HostKeyService, assetID uint, key ssh.PublicKey) *barrierEnv {
	t.Helper()
	require.NoError(t, db.AutoMigrate(&model.AssetHostKeyMismatch{}))
	hk.SetAuditTxSink(audit.NewTxSink())
	hk.SetSystemAlertSink(newFakeAlertSink())
	var asset model.Asset
	require.NoError(t, db.First(&asset, assetID).Error)
	return &barrierEnv{db: db, hostKeys: hk, assetID: assetID, host: asset.Host, port: asset.Port, key: key}
}

func (e *barrierEnv) own(t *testing.T) (model.AssetHostKey, bool) {
	t.Helper()
	var own model.AssetHostKey
	err := e.db.Where("asset_id = ?", e.assetID).First(&own).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return own, false
	}
	require.NoError(t, err)
	return own, true
}

// barrierForm 一種重置形態；apply 在 Verify 成功之後被呼叫（可能在非測試 goroutine，只用 t.Errorf）。
type barrierForm struct {
	name  string
	apply func(t *testing.T, e *barrierEnv)
}

func barrierForms() []barrierForm {
	actor := HostKeyActor{UserID: 1, Username: "super"}
	reset := func(t *testing.T, e *barrierEnv) {
		existed, err := e.hostKeys.Reset(e.assetID, actor)
		if err != nil || !existed {
			t.Errorf("重置注入失敗 existed=%v err=%v", existed, err)
		}
	}
	rerecord := func(t *testing.T, e *barrierEnv) {
		if _, err := e.hostKeys.Evaluate(e.assetID, e.host, e.port, e.key); err != nil {
			t.Errorf("重新記錄失敗: %v", err)
		}
	}
	return []barrierForm{
		{"重置待記錄", reset},
		{"重置後重新記錄", func(t *testing.T, e *barrierEnv) { reset(t, e); rerecord(t, e) }},
		{"刪列重建到同世代", func(t *testing.T, e *barrierEnv) {
			var before model.AssetHostKey
			if err := e.db.Where("asset_id = ?", e.assetID).First(&before).Error; err != nil {
				t.Errorf("讀自身列失敗: %v", err)
				return
			}
			if err := e.db.Where("asset_id = ?", e.assetID).Delete(&model.AssetHostKey{}).Error; err != nil {
				t.Errorf("刪列失敗: %v", err)
				return
			}
			rerecord(t, e)
			var after model.AssetHostKey
			if err := e.db.Where("asset_id = ?", e.assetID).First(&after).Error; err != nil {
				t.Errorf("重建後讀列失敗: %v", err)
				return
			}
			if after.ID == before.ID || after.TrustGeneration != before.TrustGeneration {
				t.Errorf("重建須為新列且世代相同: id %d->%d gen %d->%d", before.ID, after.ID, before.TrustGeneration, after.TrustGeneration)
			}
		}},
	}
}

// barrierProbe 記錄注入點的觀察：觸發次數、Verify 次數、到達注入點時的靶機認證嘗試差值，以及注入後的自身列快照。
type barrierProbe struct {
	fired     atomic.Int32
	verifies  atomic.Int32
	authDelta atomic.Int32
	afterOwn  model.AssetHostKey
	hadOwn    bool
}

// inject 套用一種重置形態，並在 apply 返回後、控制權交回產品碼之前立刻快照自身列，
// 作為「守衛不改寫記錄」的比較基線（基線若取在流程結束後，守衛在途的改寫會被當成基線而放過）。
// 可能在非測試 goroutine 呼叫，只用 t.Errorf。
func (p *barrierProbe) inject(t *testing.T, e *barrierEnv, form barrierForm) {
	form.apply(t, e)
	var own model.AssetHostKey
	err := e.db.Where("asset_id = ?", e.assetID).First(&own).Error
	switch {
	case err == nil:
		p.afterOwn, p.hadOwn = own, true
	case errors.Is(err, gorm.ErrRecordNotFound):
		p.afterOwn, p.hadOwn = model.AssetHostKey{}, false
	default:
		t.Errorf("注入後讀自身列失敗: %v", err)
	}
}

// wrapCSExecutors 把靶機（真 SSH 替身）路徑的執行器換成：Verify 前記下認證嘗試基準、Verify 成功後注入重置。
func wrapCSExecutors(t *testing.T, f *csFixture, orig func(string) rotationExecutor, e *barrierEnv, form barrierForm, p *barrierProbe) func(string) rotationExecutor {
	var before atomic.Int32
	return func(ch string) rotationExecutor {
		hooked := verifyHookExecutor{orig(ch), func() {
			p.verifies.Add(1)
			before.Store(f.server.authAttempts.Load())
		}}
		return verifyAfterExecutor{hooked, func() {
			p.fired.Add(1)
			p.authDelta.Store(f.server.authAttempts.Load() - before.Load())
			p.inject(t, e, form)
		}}
	}
}

func csBarrierEnv(t *testing.T, f *csFixture) *barrierEnv {
	return newBarrierEnv(t, f.db, f.hostKeys, f.assetID, f.server.currentHostKey().PublicKey())
}

// requireBarrierReached 證明注入點真的在驗證之後：觸發一次、Verify 一次、驗證階段恰一次認證嘗試。
func requireBarrierReached(t *testing.T, p *barrierProbe, e *barrierEnv, wantVerifies int32) {
	t.Helper()
	require.EqualValues(t, 1, p.fired.Load(), "注入器必須真的觸發（否則為假綠）")
	require.EqualValues(t, wantVerifies, p.verifies.Load(), "Verify 恰一次")
}

// requireOwnUntouched 提交被擋下之後，自身列與注入剛返回時（inject 的快照）逐欄相同（守衛不改寫記錄）。
func requireOwnUntouched(t *testing.T, p *barrierProbe, e *barrierEnv) {
	t.Helper()
	now, ok := e.own(t)
	require.Equal(t, p.hadOwn, ok)
	if ok {
		assert.Equal(t, p.afterOwn.ID, now.ID)
		assert.Equal(t, p.afterOwn.TrustGeneration, now.TrustGeneration)
		assert.Equal(t, p.afterOwn.ResetPending, now.ResetPending)
		assert.Equal(t, p.afterOwn.Fingerprint, now.Fingerprint)
	}
}

var barrierCommitStop = [3]string{hostIdentityCommitGenerationChanged, hostIdentityPhaseCommit, verificationSentTrue}

// runCommitResetBarrier 三種重置形態 x 六條提交到達路徑。
func runCommitResetBarrier(t *testing.T) {
	for _, form := range barrierForms() {
		t.Run(form.name, func(t *testing.T) {
			t.Run("一般密碼rotatePassword", func(t *testing.T) { barrierRotatePassword(t, form) })
			t.Run("一般SSH金鑰rotateKey", func(t *testing.T) { barrierRotateKey(t, form) })
			t.Run("retry轉正RetryOneAs的Promote", func(t *testing.T) { barrierRetryPromote(t, form) })
			t.Run("帶目標憑證候選RetryOneAs的promoteToCredential", func(t *testing.T) { barrierRetryPromoteToCredential(t, form) })
			t.Run("整組commitGroupApplied", func(t *testing.T) { barrierMemberCommit(t, form, false) })
			t.Run("拆分commitSplitApplied", func(t *testing.T) { barrierMemberCommit(t, form, true) })
		})
	}
}

func barrierRotatePassword(t *testing.T, form barrierForm) {
	f := setupChangeSecretFixture(t, "root", "oldpass123")
	wireStopAudit(f)
	versions := credentialVersionCount(t, f)
	e, p := csBarrierEnv(t, f), &barrierProbe{}
	f.runner.executors = wrapCSExecutors(t, f, f.runner.executors, e, form, p)

	records := f.runner.RunPlan(f.plan(t, nil))
	require.Len(t, records, 1)
	requireBarrierReached(t, p, e, 1)
	assert.EqualValues(t, 1, p.authDelta.Load(), "驗證階段靶機認證嘗試恰一次")
	assert.Equal(t, model.ChangeSecretUnverified, records[0].Status)
	assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, records[0].Error)
	assert.EqualValues(t, 1, f.candidateCount(t), "不提交：候選保留")
	assert.Equal(t, "oldpass123", f.storedPassword(t), "正式憑證不變")
	assert.Equal(t, versions, credentialVersionCount(t, f), "不新增版本")
	assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, candidateOfAccount(t, f).LastError)
	requireStopSeq(t, stopAuditDetails(t, f), barrierCommitStop)
	requireOwnUntouched(t, p, e)
}

func barrierRotateKey(t *testing.T, form barrierForm) {
	f := keyRotationFixture(t)
	wireStopAudit(f)
	origKey := f.storedPrivateKey(t)
	versions := credentialVersionCount(t, f)
	e, p := csBarrierEnv(t, f), &barrierProbe{}
	f.runner.executors = wrapCSExecutors(t, f, f.runner.executors, e, form, p)

	records := f.runner.RunPlan(f.keyPlan(t))
	require.Len(t, records, 1)
	requireBarrierReached(t, p, e, 1)
	assert.EqualValues(t, 1, p.authDelta.Load(), "驗證階段靶機認證嘗試恰一次")
	assert.Equal(t, model.ChangeSecretUnverified, records[0].Status)
	assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, records[0].Error)
	assert.EqualValues(t, 1, f.candidateCount(t), "不提交：候選保留")
	assert.Equal(t, origKey, f.storedPrivateKey(t), "正式私鑰不變")
	assert.Equal(t, versions, credentialVersionCount(t, f), "不新增版本")
	assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, candidateOfAccount(t, f).LastError)
	requireStopSeq(t, stopAuditDetails(t, f), barrierCommitStop)
	requireOwnUntouched(t, p, e)
}

func barrierRetryPromote(t *testing.T, form barrierForm) {
	s := newRetryScenario(t)
	versions := credentialVersionCount(t, s.f)
	e, p := csBarrierEnv(t, s.f), &barrierProbe{}
	s.f.retry.executors = wrapCSExecutors(t, s.f, s.f.retry.executors, e, form, p)

	assert.False(t, s.retry(t, false))
	requireBarrierReached(t, p, e, 1)
	assert.EqualValues(t, 1, p.authDelta.Load(), "驗證階段靶機認證嘗試恰一次")
	assert.EqualValues(t, s.baseAuth+1, s.f.server.authAttempts.Load(), "重試全程只有驗證那一次登入")
	assert.EqualValues(t, 1, s.f.candidateCount(t), "不提交：候選保留")
	assert.Equal(t, "oldpass123", s.f.storedPassword(t), "正式憑證不變")
	assert.Equal(t, versions, credentialVersionCount(t, s.f), "不新增版本")
	assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, candidateOfAccount(t, s.f).LastError)
	requireStopSeq(t, stopAuditDetails(t, s.f), barrierCommitStop)
	requireOwnUntouched(t, p, e)
}

func barrierRetryPromoteToCredential(t *testing.T, form barrierForm) {
	f := setupBatchFixture(t)
	f.runner.WithAuditSink(audit.NewTxSink())
	f.retry.WithAuditSink(audit.NewTxSink())
	_, _ = f.addHost(t, "h1", "10.38.3.1", "ops")
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

	e, p := newBarrierEnv(t, f.db, f.rotations.hostKeys, a2, rec.hostKey), &barrierProbe{}
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
		p.inject(t, e, form)
	}
	rec.mu.Unlock()

	assert.False(t, f.retry.RetryOneAs(context.Background(), &cand), "身分不符：不轉正")
	requireBarrierReached(t, p, e, 1)
	kept := f.candidateOf(t, cand.ID)
	assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, kept.LastError, "原因碼不是提交失敗")
	assert.Equal(t, credBefore, f.bindingOf(t, acc2).CredentialID, "未改綁，正式憑證不變")
	assert.EqualValues(t, 1, f.candidateCountFor(t, acc2), "候選保留")
	requireStopSeq(t, memberStops(t, f.db), barrierCommitStop)
	requireOwnUntouched(t, p, e)
}

func barrierMemberCommit(t *testing.T, form barrierForm, split bool) {
	f := setupBatchFixture(t)
	host1, host2 := "10.38.1.1", "10.38.1.2"
	if split {
		host1, host2 = "10.38.2.1", "10.38.2.2"
	}
	credID, accounts := f.sharedOn(t, "重置注入", "ops", "old-shared", host1, host2)
	assetID := f.bindingOf(t, accounts[1]).AssetID
	effBefore := f.bindingOf(t, accounts[1]).EffectiveVersionID
	rec := newSecretRecorder()
	e, p := newBarrierEnv(t, f.db, f.rotations.hostKeys, assetID, rec.hostKey), &barrierProbe{}
	rec.afterVerify = func(h string) {
		if h != host2 {
			return
		}
		p.fired.Add(1)
		p.verifies.Store(int32(rec.verifyCalls[h])) // 替身持鎖呼叫，直接讀
		p.inject(t, e, form)
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

	requireBarrierReached(t, p, e, 1)
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
	assert.Equal(t, model.CredentialMemberApplied, f.memberOf(t, rot.ID, accounts[0]).State, "另一台不受影響")
	stops := memberStops(t, f.db)
	requireStopSeq(t, stops, barrierCommitStop)
	assert.EqualValues(t, bad.ID, stops[0]["member_id"])
	requireOwnUntouched(t, p, e)
}
