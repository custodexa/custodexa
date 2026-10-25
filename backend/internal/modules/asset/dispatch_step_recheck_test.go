package asset

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 金鑰三段式的每一次遠端寫入前重驗（輪替成員與單帳號路徑同一套），以及判定交易未提交時的停止射程。

// stepKeyApplier 金鑰三段式的替身：照正式 helper 的順序（首次寫入前重驗 → 寫入 → 下達標記 → 驗新 →
// 刪舊鑰前重驗 → 寫入）執行，逐台計數 authorized_keys 寫入次數；before 在每次重驗之前呼叫。
type stepKeyApplier struct {
	rec    *secretRecorder
	mu     sync.Mutex
	writes map[string]int
	before func(stage string, rt rotationTarget)
}

func newStepKeyApplier(rec *secretRecorder) *stepKeyApplier {
	return &stepKeyApplier{rec: rec, writes: map[string]int{}}
}

func (a *stepKeyApplier) writeCount(host string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.writes[host]
}

func (a *stepKeyApplier) gate(stage string, rt rotationTarget, recheck func(string) string, delivered bool) error {
	if a.before != nil {
		a.before(stage, rt)
	}
	if recheck == nil {
		return nil
	}
	if reason := recheck(stage); reason != "" {
		return &dispatchStoppedError{reason: reason, delivered: delivered}
	}
	return nil
}

func (a *stepKeyApplier) write(host string) {
	a.mu.Lock()
	a.writes[host]++
	a.mu.Unlock()
}

func (a *stepKeyApplier) apply(ctx context.Context, exec rotationExecutor, rt rotationTarget,
	_ changeSecretTarget, _, _, newPrivate []byte, _, previousLine, _ string,
	onDelivered func() error, recheck func(string) string) error {

	if err := presentHostKeyTo(rt, a.rec.hostKey); err != nil {
		return err
	}
	if err := a.gate(dispatchStageKeyWrite, rt, recheck, false); err != nil {
		return err
	}
	a.write(rt.asset.Host)
	if onDelivered != nil {
		_ = onDelivered()
	}
	verifyRT := rt
	if rt.verifyHostKeyCB != nil {
		cb, err := rt.verifyHostKeyCB()
		if err != nil {
			return &remoteStateUnknownError{reason: precheckStopReason(err), cause: err}
		}
		verifyRT.hostKeyCB = cb
	}
	if err := exec.Verify(ctx, verifyRT, newPrivate); err != nil {
		return err
	}
	if previousLine == "" {
		return nil
	}
	if err := a.gate(dispatchStageKeyPrune, rt, recheck, true); err != nil {
		return err
	}
	a.write(rt.asset.Host)
	return nil
}

// stKeySplitSetup 金鑰型共用憑證掛兩台（都在 in），以資產上界拆分；回傳輪替與「資產 → 主機」。
func stKeySplitSetup(t *testing.T, g *rtFixture, h1, h2 string) (*model.CredentialRotation, map[uint]string) {
	t.Helper()
	grantRtSplit(g)
	oldPrivate, _, err := GenerateSSHKeyPair("st-key-seed")
	require.NoError(t, err)
	cred, err := g.creds.Create(adminCtx(), &CreateCredentialRequest{
		Name: "st-key-" + h1, Username: "ops", ProtocolFamily: model.ProtocolFamilySSH,
		SecretType: model.ChangeSecretTypeSSHKey, PrivateKey: oldPrivate,
	})
	require.NoError(t, err)
	hosts := map[uint]string{}
	var accounts []uint
	for _, h := range []string{h1, h2} {
		asset := newSSHAsset(t, g.assets, h, h)
		binding, berr := g.creds.Bind(adminCtx(), cred.ID, &BindCredentialRequest{AssetID: asset.ID})
		require.NoError(t, berr)
		g.place(t, asset.ID, g.in)
		hosts[asset.ID] = h
		accounts = append(accounts, binding.ID)
	}
	ctx := contextWithInitiator(context.Background(), rtScopedUser, "rt-scoped")
	rot, err := g.rotations.startSplitForBatch(ctx, cred.ID, accounts, StartRotationRequest{},
		&splitAssetBound{caps: []string{CredCapAccountRotate}})
	require.NoError(t, err)
	return rot, hosts
}

// stMemberKeyStop 第一台走到 stage 的重驗之前移出範圍：該台在這一步停下，另一台照常完成三段式。
func stMemberKeyStop(t *testing.T, stage string, h1, h2 string) (*rtFixture, *stepKeyApplier, uint, string) {
	g := newRtFixture(t)
	rot, hosts := stKeySplitSetup(t, g, h1, h2)
	applier := newStepKeyApplier(g.rec)
	var first uint
	applier.before = func(s string, rt rotationTarget) {
		if first == 0 {
			first = rt.asset.ID
		}
		if s == stage && rt.asset.ID == first {
			g.place(t, first, g.out)
		}
	}
	g.rotations.keyApplier = applier.apply
	require.NoError(t, g.rotations.Run(context.Background(), rot.ID))
	require.NotZero(t, first, "走到金鑰三段式")
	other := otherKey(hosts, first)
	assert.Equal(t, 2, applier.writeCount(hosts[other]), "另一台照常：加新與刪舊各寫一次")
	assert.Equal(t, model.CredentialMemberApplied, g.memberOnAsset(t, other).State)
	return g, applier, first, hosts[first]
}

func testMemberKeyRecheckBeforeFirstWrite(t *testing.T) {
	g, applier, first, host := stMemberKeyStop(t, dispatchStageKeyWrite, "10.3.40.1", "10.3.40.2")
	assert.Equal(t, 0, applier.writeCount(host), "首次寫入前重驗未通過：authorized_keys 零寫入")
	m := g.memberOnAsset(t, first)
	assert.Equal(t, model.CredentialMemberAbandoned, m.State, "遠端未改動：成員停止")
	assert.Equal(t, model.ChangeSecretReasonAuthzRevoked, m.LastError)
	var cands int64
	require.NoError(t, g.db.Model(&model.ChangeSecretCandidate{}).Where("account_id = ?", m.AccountID).Count(&cands).Error)
	assert.EqualValues(t, 1, cands, "拆分的候選是該台唯一的目標秘密副本：保留")
}

func testMemberKeyRecheckBeforePrune(t *testing.T) {
	g, applier, first, host := stMemberKeyStop(t, dispatchStageKeyPrune, "10.3.41.1", "10.3.41.2")
	assert.Equal(t, 1, applier.writeCount(host), "刪舊鑰前重驗未通過：只有加新那一次寫入，舊鑰不刪")
	m := g.memberOnAsset(t, first)
	assert.Equal(t, model.CredentialMemberChangedUnverified, m.State, "新鑰已寫入：停在已下達未驗證")
	assert.Equal(t, model.ChangeSecretReasonAuthzRevoked, m.LastError)
	var cand model.ChangeSecretCandidate
	require.NoError(t, g.db.Where("account_id = ?", m.AccountID).First(&cand).Error, "候選保留")
	assert.True(t, cand.Applied, "候選記為已下達")
}

// 單台範圍拒絕之後同一判定交易提交失敗：最終原因是無從判定，停止整個工作，下一台不被處理。
func testJudgeCommitFailureStopsJob(t *testing.T) {
	g := newRtFixture(t)
	batch, assetIDs, hosts := stRunnerSetup(t, g, "10.3.42.1", "10.3.42.2", rtScopedUser)
	var first uint
	armed := false
	g.runner.dispatchHook = func(stage string, acc uint) {
		if stage == dispatchStageCandidate && first == 0 {
			first, armed = acc, true
			g.place(t, g.accountAsset(t, acc), g.out)
		}
	}
	g.runner.judgeTxHook = func(tx *gorm.DB, accs []uint) {
		if armed && len(accs) == 1 && accs[0] == first {
			armed = false
			// 交易內判出範圍拒絕後令提交失敗（交易已結束，Commit 回錯）
			tx.Rollback()
		}
	}
	records := g.runner.RunBatch(batch, assetIDs)
	require.NotZero(t, first, "走到候選落庫後的判定點")
	if rec := recordOf(records, first); assert.NotNil(t, rec) {
		assert.Equal(t, model.ChangeSecretSkipped, rec.Status)
		assert.Equal(t, model.ChangeSecretReasonAuthzUnavailable, rec.Error)
	}
	other := uint(0)
	for acc := range hosts {
		if acc != first {
			other = acc
		}
	}
	assert.Equal(t, 0, g.rotateCalls(hosts[other]), "判定交易未提交：停止整個工作，下一台遠端 0")
	assert.Nil(t, recordOf(records, other), "下一台不被處理")
}

// 只略過一台時，告警內文如實描述射程：不稱整個工作停止，新秘密已寫入時不稱遠端未被觸碰。
func testTargetOnlyStopAlertText(t *testing.T) {
	job := rotationJob{source: "batch=7"}
	tgt := changeSecretTarget{assetID: 11, username: "ops"}
	reason := model.ChangeSecretReasonAuthzRevoked

	skip := stopAlertText(job, reason, &targetStop{tgt: tgt, targetOnly: true})
	pruned := stopAlertText(job, reason, &targetStop{tgt: tgt, targetOnly: true, delivered: true})
	for _, msg := range []string{skip, pruned} {
		assert.Contains(t, msg, "asset_id=11")
		assert.Contains(t, msg, "account=ops")
		assert.Contains(t, msg, "reason="+reason)
		assert.Contains(t, msg, "僅略過此目標")
		assert.Contains(t, msg, "其他目標照常")
		assert.NotContains(t, msg, "停止")
		assert.NotContains(t, msg, "不再處理")
		assert.NotContains(t, msg, "重新授權")
	}
	assert.NotContains(t, pruned, "未被觸碰", "新秘密已寫入：不稱遠端未被觸碰")
	assert.NotContains(t, pruned, "未對其遠端做任何變更")
	assert.Contains(t, pruned, "候選保留")

	whole := stopAlertText(job, reason, &targetStop{tgt: tgt})
	assert.Contains(t, whole, "其後的目標")
	assert.NotContains(t, whole, "僅略過")
	wholeDelivered := stopAlertText(job, reason, &targetStop{tgt: tgt, delivered: true})
	assert.NotContains(t, wholeDelivered, "未被觸碰")
	assert.Contains(t, wholeDelivered, "不再處理")
}

func TestDispatchStepRecheck(t *testing.T) {
	t.Run("member_key_recheck_before_first_write", testMemberKeyRecheckBeforeFirstWrite)
	t.Run("member_key_recheck_before_prune", testMemberKeyRecheckBeforePrune)
	t.Run("judge_commit_failure_stops_job", testJudgeCommitFailureStopsJob)
	t.Run("target_only_stop_alert_text", testTargetOnlyStopAlertText)
}
