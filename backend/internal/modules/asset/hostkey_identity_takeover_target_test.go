package asset

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 目標變更的補強子案例（root：TestCredentialRecoveryHostIdentityTakeover，前綴 目標變更/）。
// 共同原則：核對的就是要撥號的目標，提交的就是驗證過的目標。目標改變回 CHANGE_SECRET_AUTHZ_TARGET_CHANGED
// （不是身分異動），傳輸改變而目標指紋相同時走既有的身分衝突出口。

// winrmVerifyCounter WinRM 執行器替身：不看主機金鑰回呼，只計數 Verify 與記下撥號位址。
type winrmVerifyCounter struct {
	mu      sync.Mutex
	verify  int
	rotate  int
	targets []string
}

func (w *winrmVerifyCounter) Rotate(context.Context, rotationTarget, []byte, []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.rotate++
	return nil
}

func (w *winrmVerifyCounter) Verify(_ context.Context, rt rotationTarget, _ []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.verify++
	w.targets = append(w.targets, rt.addr)
	return nil
}

func (w *winrmVerifyCounter) calls() (int, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.verify, w.rotate
}

// countingVerifyExecutor 包住既有執行器，計數 Verify 呼叫（不論成敗）。
type countingVerifyExecutor struct {
	rotationExecutor
	n *int
}

func (c countingVerifyExecutor) Verify(ctx context.Context, rt rotationTarget, secret []byte) error {
	*c.n++
	return c.rotationExecutor.Verify(ctx, rt, secret)
}

// memberExecutors 成員的執行器：WinRM 走替身，其餘走夾具原本的執行器並計數 Verify。
func memberExecutors(v memberVerifyTarget) (*winrmVerifyCounter, *int) {
	w := &winrmVerifyCounter{}
	n := new(int)
	inner := v.f.rotations.executors
	v.f.rotations.executors = func(ch string) rotationExecutor {
		if ch == model.RotationChannelWindowsWinRM {
			return w
		}
		return countingVerifyExecutor{inner(ch), n}
	}
	return w, n
}

// restampMemberFingerprint 把成員記下的目標指紋改成當下的值（模擬目標指紋相同、只有傳輸不同）。
func restampMemberFingerprint(t *testing.T, v memberVerifyTarget) {
	t.Helper()
	tf, err := loadTargetFingerprint(v.db, v.f.accountID)
	require.NoError(t, err)
	require.NoError(t, v.db.Model(&model.CredentialRotationMember{}).Where("id = ?", v.jobID).
		Update("target_fingerprint", tf).Error)
}

// setRotationChannel 改資產的改密通道：空字串＝SSH。
func setRotationChannel(t *testing.T, v memberVerifyTarget, channel string) {
	t.Helper()
	if channel == model.RotationChannelWindowsWinRM {
		useWinRMChannel(t, v.db, v.f.assetID)
		return
	}
	require.NoError(t, v.db.Model(&model.Asset{}).Where("id = ?", v.f.assetID).
		Update("rotation_channel", channel).Error)
}

// memberOnWinRM 已下達未驗證的成員改成升級前（legacy）、資產走 WinRM，成員記下的目標指紋是 WinRM 下的值。
func memberOnWinRM(t *testing.T, v memberVerifyTarget) {
	t.Helper()
	setRotationChannel(t, v, model.RotationChannelWindowsWinRM)
	require.NoError(t, v.db.Model(&model.CredentialRotationMember{}).Where("id = ?", v.jobID).Updates(map[string]any{
		"host_key_binding": model.HostKeyBindingLegacy, "host_key_transport": "", "host_key_record_id": 0,
		"host_key_algorithm": "", "host_key_fingerprint": "", "host_key_generation": 0, "host_key_bound_at": nil}).Error)
	restampMemberFingerprint(t, v)
}

func runTakeoverTargetReview(t *testing.T) {
	const p = "目標變更/"
	winrmReq := HostIdentityConfirmRequest{Transport: model.HostKeyTransportWinRM}

	// requireTargetChanged 目標變更的出口：不是驗證失敗、不是身分衝突
	requireTargetChanged := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, ErrHostIdentityConfirmTargetChanged)
		assert.NotErrorIs(t, err, ErrHostIdentityVerifyFailed, "候選 handler 先判驗證失敗，目標變更不得被包成它")
		assert.NotErrorIs(t, err, ErrHostIdentityMoved, "目標變更不得對映成身分衝突")
	}

	t.Run(p+"通道切換/對照/WinRM成員正常承接成功", func(t *testing.T) {
		v := newMemberVerifyTarget(t, false)
		memberOnWinRM(t, v)
		w, sshVerifies := memberExecutors(v)
		attBase := v.attempts()
		err := v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, winrmReq)
		require.NoError(t, err)
		ver, rot := w.calls()
		assert.Equal(t, 1, ver, "WinRM 單次驗證")
		assert.Zero(t, rot)
		assert.Zero(t, *sshVerifies)
		assert.Equal(t, attBase, v.attempts(), "SSH 認證 0")
		assert.Equal(t, model.CredentialMemberApplied, v.row(t).State)
		assert.Equal(t, takeoverOutcomeVerified, onlyRecord(t, v.takeoverTarget).Outcome)
	})

	// 通道切換：第一次身分檢查之後、prepareMember 重讀資產之前切通道（目標指紋含通道，故回目標變更）；
	// 以及目標指紋被同步成切換後的值（只有傳輸不同）時，撥號前的傳輸核對仍擋下（回身分衝突）
	type h1Case struct {
		name     string
		from, to string
		// restamp 在入口判定之後、執行器讀成員列之前把成員記下的指紋同步成切換後的值，並同時切通道
		restamp bool
	}
	for _, c := range []h1Case{
		{"身分檢查後重讀前SSH切WinRM_回目標變更", "", model.RotationChannelWindowsWinRM, false},
		{"身分檢查後重讀前WinRM切SSH_回目標變更", model.RotationChannelWindowsWinRM, "", false},
		{"目標指紋同步下SSH切WinRM_回身分衝突", "", model.RotationChannelWindowsWinRM, true},
		{"目標指紋同步下WinRM切SSH_回身分衝突", model.RotationChannelWindowsWinRM, "", true},
	} {
		t.Run(p+"通道切換/成員/"+c.name+"_Verify0_認證0_不就位", func(t *testing.T) {
			v := newMemberVerifyTarget(t, false)
			req := acceptDifferent(v.req)
			if c.from == model.RotationChannelWindowsWinRM {
				memberOnWinRM(t, v)
				req = winrmReq
			}
			w, sshVerifies := memberExecutors(v)
			before := v.row(t)
			attBase := v.attempts()
			fired := 0
			if c.restamp {
				v.svc.crashAfterRecord = func() error {
					fired++
					setRotationChannel(t, v, c.to)
					restampMemberFingerprint(t, v)
					return nil
				}
			} else {
				v.f.rotations.verifyPrecheckHook = func() {
					fired++
					setRotationChannel(t, v, c.to)
				}
			}
			err := v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, req)
			require.Equal(t, 1, fired, "注入點必須真的觸發")
			rec := onlyRecord(t, v.takeoverTarget)
			if c.restamp {
				require.ErrorIs(t, err, ErrHostIdentityMoved)
				assert.Equal(t, takeoverOutcomeMoved, rec.Outcome)
			} else {
				requireTargetChanged(t, err)
				assert.Equal(t, takeoverOutcomeVerifyFailed, rec.Outcome, "撥號前發現目標改變：沒有送出認證")
			}
			assert.NotEqual(t, takeoverOutcomeVerified, rec.Outcome)
			require.NotNil(t, rec.ConsumedAt)
			ver, rot := w.calls()
			assert.Zero(t, ver, "WinRM Verify 0")
			assert.Zero(t, rot)
			assert.Zero(t, *sshVerifies, "SSH Verify 0")
			assert.Equal(t, attBase, v.attempts(), "認證嘗試 0")
			after := v.row(t)
			assert.NotEqual(t, model.CredentialMemberApplied, after.State, "無就位")
			if !c.restamp {
				assert.Equal(t, before, after, "成員整列不變")
			}
			assert.EqualValues(t, 1, memberCandidateCount(t, v.f, &after), "候選保留")
		})
	}

	t.Run(p+"通道切換/成員/SSH驗證後提交前切WinRM且目標指紋同步_提交交易擋下不就位", func(t *testing.T) {
		v := newMemberVerifyTarget(t, false)
		before := v.row(t)
		fired := 0
		v.f.rotations.crashAfterVerify = func() error {
			fired++
			setRotationChannel(t, v, model.RotationChannelWindowsWinRM)
			restampMemberFingerprint(t, v)
			return nil
		}
		err := v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, acceptDifferent(v.req))
		require.Equal(t, 1, fired)
		require.ErrorIs(t, err, ErrHostIdentityMoved)
		assert.Equal(t, takeoverOutcomeMoved, onlyRecord(t, v.takeoverTarget).Outcome)
		after := v.row(t)
		assert.Equal(t, before.State, after.State, "不就位")
		assert.Nil(t, after.AppliedAt)
		assert.EqualValues(t, 1, memberCandidateCount(t, v.f, &after), "候選保留")
	})

	// 同傳輸改址：同傳輸改址
	moveTo := func(t *testing.T, v memberVerifyTarget) {
		t.Helper()
		require.NoError(t, v.db.Model(&model.Asset{}).Where("id = ?", v.f.assetID).
			Updates(map[string]any{"host": "10.77.0.9", "port": 2299}).Error)
	}

	t.Run(p+"同傳輸改址/候選/WinRM入口檢查後Verify前改址_Verify0_回目標變更", func(t *testing.T) {
		w := newWinRMTakeover(t)
		require.NoError(t, w.f.db.Model(&model.ChangeSecretCandidate{}).Where("id = ?", w.cand.ID).Updates(map[string]any{
			"host_key_binding": model.HostKeyBindingLegacy, "host_key_transport": "", "host_key_record_id": 0,
			"host_key_algorithm": "", "host_key_fingerprint": "", "host_key_generation": 0}).Error)
		local := w.f.storedPassword(t)
		beforeVerify := w.verifyTotal()
		fired := 0
		w.svc.crashAfterRecord = func() error {
			fired++
			require.NoError(t, w.f.db.Model(&model.Asset{}).Where("id = ?", w.f.assetID).
				Update("host", "10.77.0.9").Error)
			return nil
		}
		err := w.svc.ConfirmHostIdentityAndVerify(adminCtx(), takeoverKindCandidate, w.cand.ID, winrmReq)
		require.Equal(t, 1, fired, "注入點在入口檢查之後")
		requireTargetChanged(t, err)
		assert.Equal(t, beforeVerify, w.verifyTotal(), "Verify 0")
		assert.EqualValues(t, 1, w.f.candidateCount(t), "候選保留")
		assert.Equal(t, local, w.f.storedPassword(t), "本地憑證不變")
		var rows []model.CredentialHostIdentityConfirmation
		require.NoError(t, w.f.db.Where("kind = ? AND job_id = ?", takeoverKindCandidate, w.cand.ID).Find(&rows).Error)
		require.Len(t, rows, 1)
		assert.Equal(t, takeoverOutcomeVerifyFailed, rows[0].Outcome)
	})

	for _, at := range []string{"入口檢查後", "身分預檢後"} {
		t.Run(p+"同傳輸改址/成員/"+at+"Verify前同傳輸改址_Verify0_回目標變更", func(t *testing.T) {
			v := newMemberVerifyTarget(t, false)
			w, sshVerifies := memberExecutors(v)
			before := v.row(t)
			attBase := v.attempts()
			fired := 0
			move := func() { fired++; moveTo(t, v) }
			if at == "入口檢查後" {
				v.svc.crashAfterRecord = func() error { move(); return nil }
			} else {
				v.f.rotations.verifyPrecheckHook = move
			}
			err := v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, acceptDifferent(v.req))
			require.Equal(t, 1, fired)
			requireTargetChanged(t, err)
			ver, _ := w.calls()
			assert.Zero(t, ver)
			assert.Zero(t, *sshVerifies, "Verify 0")
			assert.Equal(t, attBase, v.attempts(), "認證嘗試 0")
			assert.Equal(t, before, v.row(t), "成員整列不變")
			assert.Equal(t, takeoverOutcomeVerifyFailed, onlyRecord(t, v.takeoverTarget).Outcome)
		})
	}

	t.Run(p+"同傳輸改址/候選/Verify成功後提交前改址_不轉正_記commit_failed", func(t *testing.T) {
		v := newVerifyTarget(t, false)
		local := v.localSecret(t)
		attBase := v.attempts()
		fired := 0
		v.f.retry.crashAfterVerify = func() error {
			fired++
			require.NoError(t, v.db.Model(&model.Asset{}).Where("id = ?", v.f.assetID).
				Updates(map[string]any{"host": "10.77.0.9", "port": 2299}).Error)
			return nil
		}
		err := v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, v.request())
		require.Equal(t, 1, fired)
		requireTargetChanged(t, err)
		assert.EqualValues(t, attBase+1, v.attempts(), "驗證在原目標做了一次")
		assert.EqualValues(t, 1, v.f.candidateCount(t), "候選保留：不被當成新目標的就位憑證")
		assert.Equal(t, local, v.localSecret(t), "本地憑證不變")
		rec := onlyRecord(t, v.takeoverTarget)
		require.NotNil(t, rec.ConsumedAt)
		assert.Equal(t, takeoverOutcomeCommitFailed, rec.Outcome)
	})

	for _, split := range []bool{false, true} {
		name := "整組"
		if split {
			name = "拆分"
		}
		t.Run(p+"同傳輸改址/成員/"+name+"Verify成功後提交前改址_不就位_記commit_failed", func(t *testing.T) {
			v := newMemberVerifyTarget(t, split)
			before := v.row(t)
			var bindingBefore model.AssetAccount
			require.NoError(t, v.db.First(&bindingBefore, v.f.accountID).Error)
			attBase := v.attempts()
			fired := 0
			v.f.rotations.crashAfterVerify = func() error { fired++; moveTo(t, v); return nil }
			err := v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, acceptDifferent(v.req))
			require.Equal(t, 1, fired)
			requireTargetChanged(t, err)
			assert.EqualValues(t, attBase+1, v.attempts(), "驗證在原目標做了一次")
			after := v.row(t)
			assert.NotEqual(t, model.CredentialMemberApplied, after.State, "不就位")
			assert.Equal(t, before, after, "成員整列不變")
			assert.EqualValues(t, 1, memberCandidateCount(t, v.f, &after), "候選保留")
			var bindingAfter model.AssetAccount
			require.NoError(t, v.db.First(&bindingAfter, v.f.accountID).Error)
			assert.Equal(t, bindingBefore.CredentialID, bindingAfter.CredentialID, "掛載未改綁")
			assert.Equal(t, bindingBefore.EffectiveVersionID, bindingAfter.EffectiveVersionID, "就位版本未變")
			rec := onlyRecord(t, v.takeoverTarget)
			require.NotNil(t, rec.ConsumedAt)
			assert.Equal(t, takeoverOutcomeCommitFailed, rec.Outcome)
		})
	}
}

// failTableReads 讓指定表的讀取失敗並計數（armed 為 true 時才注入）；回傳命中次數的讀取函式與還原函式。
func failTableReads(t *testing.T, db *gorm.DB, table string, armed *atomic.Bool) (func() int32, func()) {
	t.Helper()
	var hits atomic.Int32
	name := "p2m:recheck-fail-" + table
	require.NoError(t, db.Callback().Query().Before("gorm:query").Register(name, func(tx *gorm.DB) {
		if tx.Statement.Table != table || !armed.Load() {
			return
		}
		hits.Add(1)
		_ = tx.AddError(errors.New("injected read failure"))
	}))
	return hits.Load, func() { require.NoError(t, db.Callback().Query().Remove(name)) }
}

// 複查修正的子案例（root：TestCredentialRecoveryHostIdentityTakeover，前綴 4.4/複查/R1、4.4/複查/R2）。
func runTakeoverRecheck(t *testing.T) {
	const p = "4.4/複查/"

	// R1：入口讀目標指紋時的資料庫錯誤不是目標變更：無法判定（fail closed），保留原因，不建確認紀錄、不 Verify
	for _, k := range []struct {
		name string
		make func(*testing.T) takeoverTarget
	}{{"候選", candidateTakeoverTarget}, {"成員", memberTakeoverTarget}} {
		for _, table := range []string{"asset_accounts", "assets"} {
			t.Run(p+"R1/"+k.name+"/讀"+table+"失敗_無法判定_不是目標變更_紀錄0_Verify0", func(t *testing.T) {
				tg := k.make(t)
				tr := newTakeoverTrace(t, tg.db, tg.attempts)
				var armed atomic.Bool
				hits, restore := failTableReads(t, tg.db, table, &armed)
				defer restore()
				armed.Store(true)
				err := tg.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg.kind, tg.jobID, acceptDifferent(tg.req))
				require.Positive(t, hits(), "注入點必須真的命中")
				require.ErrorIs(t, err, ErrCredentialAuthzUnavailable)
				assert.NotErrorIs(t, err, ErrHostIdentityConfirmTargetChanged)
				assert.NotErrorIs(t, err, ErrHostIdentityMoved)
				assert.Contains(t, err.Error(), "injected read failure", "原因保留")
				tr.requireUntouched(t)
			})
		}
	}

	// R2：第一道預檢之後通道被改成 none，或帳號名被改：準備流程提前返回也要回目標變更
	type r2Case struct {
		name   string
		mutate func(t *testing.T, v memberVerifyTarget)
	}
	for _, c := range []r2Case{
		{"通道改none", func(t *testing.T, v memberVerifyTarget) { setRotationChannel(t, v, model.RotationChannelNone) }},
		{"改帳號名", func(t *testing.T, v memberVerifyTarget) {
			// 帳號名取自憑證時不隨掛載改名：憑證不帶帳號名時才採掛載帳號名，改名才會讓準備流程提前返回
			var b model.AssetAccount
			require.NoError(t, v.db.First(&b, v.f.accountID).Error)
			require.NoError(t, v.db.Model(&model.Credential{}).Where("id = ?", b.CredentialID).
				Update("username", "").Error)
			require.NoError(t, v.db.Model(&model.AssetAccount{}).Where("id = ?", v.f.accountID).
				Update("username", "renamed-account").Error)
		}},
	} {
		for _, split := range []bool{false, true} {
			mode := "整組"
			if split {
				mode = "拆分"
			}
			t.Run(p+"R2/成員/"+mode+"/預檢後"+c.name+"_回目標變更_Verify0_認證0_不就位", func(t *testing.T) {
				v := newMemberVerifyTarget(t, split)
				w, sshVerifies := memberExecutors(v)
				before := v.row(t)
				attBase := v.attempts()
				fired := 0
				v.f.rotations.verifyPrecheckHook = func() { fired++; c.mutate(t, v) }
				err := v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, acceptDifferent(v.req))
				require.Equal(t, 1, fired, "注入點必須真的觸發")
				require.ErrorIs(t, err, ErrHostIdentityConfirmTargetChanged)
				assert.NotErrorIs(t, err, ErrHostIdentityVerifyFailed, "不得被包成一般驗證未通過")
				assert.NotErrorIs(t, err, ErrHostIdentityMoved)
				ver, _ := w.calls()
				assert.Zero(t, ver)
				assert.Zero(t, *sshVerifies, "Verify 0")
				assert.Equal(t, attBase, v.attempts(), "認證嘗試 0")
				after := v.row(t)
				assert.NotEqual(t, model.CredentialMemberApplied, after.State, "不就位")
				assert.Equal(t, before, after, "成員整列不變")
				rec := onlyRecord(t, v.takeoverTarget)
				require.NotNil(t, rec.ConsumedAt, "確認紀錄消耗")
				assert.Equal(t, takeoverOutcomeVerifyFailed, rec.Outcome)
			})
		}
	}
}
