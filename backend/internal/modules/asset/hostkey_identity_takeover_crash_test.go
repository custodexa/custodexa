package asset

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// 人工承接的崩潰點與啟動收束子案例
// （root：TestCredentialRecoveryHostIdentityTakeover，前綴 4.1/崩潰/ 與 4.1/啟動收束/）。
// 以測試掛點模擬行程在該點結束：掛點回錯誤即原樣返回，不寫任何結果、不再撥號。

// countingExecutor 計 Verify 與 Rotate 的呼叫次數（驗證「重啟後不重放」的計數器）。
type countingExecutor struct {
	rotationExecutor
	verifies, rotates *atomic.Int32
}

func (c countingExecutor) Verify(ctx context.Context, rt rotationTarget, secret []byte) error {
	c.verifies.Add(1)
	return c.rotationExecutor.Verify(ctx, rt, secret)
}

func (c countingExecutor) Rotate(ctx context.Context, rt rotationTarget, oldSecret, newSecret []byte) error {
	c.rotates.Add(1)
	return c.rotationExecutor.Rotate(ctx, rt, oldSecret, newSecret)
}

// crashRig 一種工作的崩潰夾具。
type crashRig struct {
	takeoverTarget
	verifies, rotates *atomic.Int32
	// crashAt 設定崩潰點（"record"＝紀錄提交後、Verify 前；"verify"＝Verify 成功後、本地提交前）
	crashAt func(point string, fn func() error)
	// restart 模擬行程重啟的啟動收束
	restart func(t *testing.T)
	// intact 工作仍停在原處（未被推進）
	intact func(t *testing.T)
	// done 重新確認成功後工作已完成
	done func(t *testing.T)
}

func newCandidateCrashRig(t *testing.T) crashRig {
	t.Helper()
	v := newVerifyTarget(t, false)
	rig := crashRig{takeoverTarget: v.takeoverTarget, verifies: &atomic.Int32{}, rotates: &atomic.Int32{}}
	orig := v.f.retry.executors
	v.f.retry.executors = func(ch string) rotationExecutor {
		return countingExecutor{orig(ch), rig.verifies, rig.rotates}
	}
	secretBefore := v.localSecret(t)
	rig.crashAt = func(point string, fn func() error) {
		if point == "record" {
			v.svc.crashAfterRecord = fn
		} else {
			v.f.retry.crashAfterVerify = fn
		}
	}
	rig.restart = func(t *testing.T) {
		n, err := recoverInterruptedConfirmations(v.db)
		require.NoError(t, err)
		assert.EqualValues(t, 1, n)
	}
	rig.intact = func(t *testing.T) {
		assert.EqualValues(t, 1, v.f.candidateCount(t), "候選保留")
		assert.Equal(t, secretBefore, v.localSecret(t), "本地憑證不動")
	}
	rig.done = func(t *testing.T) {
		assert.EqualValues(t, 0, v.f.candidateCount(t), "候選轉正後刪除")
		assert.NotEqual(t, secretBefore, v.localSecret(t))
	}
	return rig
}

func newMemberCrashRig(t *testing.T) crashRig {
	t.Helper()
	v := newMemberVerifyTarget(t, false)
	rig := crashRig{takeoverTarget: v.takeoverTarget, verifies: &atomic.Int32{}, rotates: &atomic.Int32{}}
	orig := v.f.rotations.executors
	v.f.rotations.executors = func(ch string) rotationExecutor {
		return countingExecutor{orig(ch), rig.verifies, rig.rotates}
	}
	rig.crashAt = func(point string, fn func() error) {
		if point == "record" {
			v.svc.crashAfterRecord = fn
		} else {
			v.f.rotations.crashAfterVerify = fn
		}
	}
	rig.restart = func(t *testing.T) {
		_, err := v.f.rotations.RecoverInterruptedMembers()
		require.NoError(t, err)
	}
	rig.intact = func(t *testing.T) {
		assert.Equal(t, model.CredentialMemberChangedUnverified, v.row(t).State, "成員仍停在已下達未驗證")
		assert.EqualValues(t, 1, memberCandidateCount(t, v.f, ptrMember(v.row(t))), "候選保留")
	}
	rig.done = func(t *testing.T) {
		assert.Equal(t, model.CredentialMemberApplied, v.row(t).State)
	}
	return rig
}

func ptrMember(m model.CredentialRotationMember) *model.CredentialRotationMember { return &m }

func runTakeoverCrash(t *testing.T) {
	rigs := []struct {
		name string
		make func(t *testing.T) crashRig
	}{{"候選", newCandidateCrashRig}, {"成員", newMemberCrashRig}}
	points := []struct {
		key, name       string
		verifies, auths int32
	}{
		{"record", "(ii)紀錄提交後_Verify前", 0, 0},
		{"verify", "(iii)Verify成功後_本地提交前", 1, 1},
	}

	for _, r := range rigs {
		for _, pt := range points {
			t.Run("4.1/崩潰/"+r.name+"/"+pt.name+"/重啟收束為unknown_不重放_新確認建revision2", func(t *testing.T) {
				rig := r.make(t)
				crash := errors.New("simulated process end")
				rig.crashAt(pt.key, func() error { return crash })
				attBase, auditBase := rig.attempts(), confirmAuditCount(t, rig.db)

				err := rig.svc.ConfirmHostIdentityAndVerify(adminCtx(), rig.kind, rig.jobID, acceptDifferent(rig.req))
				require.ErrorIs(t, err, crash, "掛點必須真的觸發（否則為假綠）")

				// 崩潰當下：紀錄與審計已提交、紀錄未消耗；遠端動作只到崩潰點為止
				rows := confirmRecords(t, rig.takeoverTarget)
				require.Len(t, rows, 1)
				assert.Nil(t, rows[0].ConsumedAt, "崩潰：不寫任何結果")
				assert.Equal(t, "", rows[0].Outcome)
				assert.EqualValues(t, 1, rows[0].Revision)
				assert.Equal(t, auditBase+1, confirmAuditCount(t, rig.db), "建立時的一筆承接審計已提交")
				assert.Equal(t, pt.verifies, rig.verifies.Load(), "Verify 次數只到崩潰點")
				assert.Equal(t, attBase+pt.auths, rig.attempts())
				assert.EqualValues(t, 0, rig.rotates.Load(), "從不下達")
				rig.intact(t)

				// 重啟收束
				verifiesAtCrash, attAtCrash := rig.verifies.Load(), rig.attempts()
				rig.restart(t)
				rows = confirmRecords(t, rig.takeoverTarget)
				require.Len(t, rows, 1)
				assert.Equal(t, takeoverOutcomeUnknown, rows[0].Outcome)
				require.NotNil(t, rows[0].ConsumedAt, "consumed_at 非空")
				assert.WithinDuration(t, time.Now(), *rows[0].ConsumedAt, time.Minute)
				assert.Equal(t, verifiesAtCrash, rig.verifies.Load(), "重啟後 Verify 次數不增（不重放）")
				assert.EqualValues(t, 0, rig.rotates.Load())
				assert.Equal(t, attAtCrash, rig.attempts(), "重啟後 authAttempts 不增")
				assert.Equal(t, auditBase+1, confirmAuditCount(t, rig.db), "收束不另寫承接審計")
				rig.intact(t)
				unknownAt := *rows[0].ConsumedAt

				// 具權者重新明示確認：建 revision 2，舊紀錄不再被使用
				rig.crashAt(pt.key, nil)
				require.NoError(t, rig.svc.ConfirmHostIdentityAndVerify(adminCtx(), rig.kind, rig.jobID, acceptDifferent(rig.req)))
				rows = confirmRecords(t, rig.takeoverTarget)
				require.Len(t, rows, 2)
				assert.EqualValues(t, 1, rows[0].Revision)
				assert.Equal(t, takeoverOutcomeUnknown, rows[0].Outcome, "舊紀錄維持 unknown，不被改寫或消耗")
				assert.True(t, unknownAt.Equal(*rows[0].ConsumedAt))
				assert.EqualValues(t, 2, rows[1].Revision)
				assert.Equal(t, takeoverOutcomeVerified, rows[1].Outcome, "被消耗的是 revision 2")
				require.NotNil(t, rows[1].ConsumedAt)
				assert.Equal(t, verifiesAtCrash+1, rig.verifies.Load(), "新確認恰一次邏輯驗證")
				assert.EqualValues(t, 0, rig.rotates.Load())
				rig.done(t)
			})
		}
	}

	t.Run("4.1/崩潰/候選/(iii)重啟前同一確認不可再被消耗", func(t *testing.T) {
		// 收束之後，仍在飛行中的舊確認其條件式消耗落空，不會把舊紀錄寫成 verified
		rig := newCandidateCrashRig(t)
		crash := errors.New("simulated process end")
		rig.crashAt("verify", func() error { return crash })
		require.ErrorIs(t, rig.svc.ConfirmHostIdentityAndVerify(adminCtx(), rig.kind, rig.jobID, acceptDifferent(rig.req)), crash)
		rig.restart(t)
		rows := confirmRecords(t, rig.takeoverTarget)
		require.Len(t, rows, 1)
		err := consumeConfirmation(rig.db, &rows[0], takeoverOutcomeVerified)
		require.ErrorIs(t, err, ErrConfirmationNotConsumable)
		after := confirmRecords(t, rig.takeoverTarget)
		assert.Equal(t, takeoverOutcomeUnknown, after[0].Outcome)
	})

	// 啟動收束的雙向：已消耗的紀錄不被改寫，未消耗的全部收束
	t.Run("4.1/啟動收束/已消耗不改寫_未消耗全收束_兩種工作種類_重複執行不變", func(t *testing.T) {
		rig := newMemberCrashRig(t)
		consumedOutcomes := []string{takeoverOutcomeVerified, takeoverOutcomeVerifyFailed,
			takeoverOutcomeMoved, takeoverOutcomeCommitFailed}
		earlier := time.Now().Add(-48 * time.Hour).UTC().Truncate(time.Second)
		var ids []uint
		for i, oc := range consumedOutcomes {
			consumed := earlier.Add(time.Duration(i) * time.Minute)
			rec := model.CredentialHostIdentityConfirmation{Kind: takeoverKindCandidate, JobID: uint(9100 + i),
				Revision: 1, AssetID: 1, ConfirmedBy: 1, ConfirmedTransport: model.HostKeyTransportSSH,
				ConfirmedFingerprint: "fp-" + oc, CreatedAt: earlier, StartedAt: &earlier,
				ConsumedAt: &consumed, Outcome: oc}
			require.NoError(t, rig.db.Create(&rec).Error)
			ids = append(ids, rec.ID)
		}
		snapshot := func() []string {
			var out []string
			for _, id := range ids {
				var r model.CredentialHostIdentityConfirmation
				require.NoError(t, rig.db.First(&r, id).Error)
				out = append(out, fmt.Sprintf("%d|%s|%d|%s|%s|%d", r.JobID, r.Kind, r.Revision, r.Outcome,
					r.ConfirmedFingerprint, r.ConsumedAt.UTC().UnixNano()))
			}
			return out
		}
		before := snapshot()

		// 未消耗：候選種類一筆（直接建）、成員種類一筆（走正式確認入口後在 Verify 前崩潰）
		pendingCand := model.CredentialHostIdentityConfirmation{Kind: takeoverKindCandidate, JobID: 9200,
			Revision: 1, AssetID: 1, ConfirmedBy: 1, ConfirmedTransport: model.HostKeyTransportSSH,
			CreatedAt: earlier, StartedAt: &earlier}
		require.NoError(t, rig.db.Create(&pendingCand).Error)
		crash := errors.New("simulated process end")
		rig.crashAt("record", func() error { return crash })
		require.ErrorIs(t, rig.svc.ConfirmHostIdentityAndVerify(adminCtx(), rig.kind, rig.jobID, acceptDifferent(rig.req)), crash)
		verifiesBase, attBase := rig.verifies.Load(), rig.attempts()

		rig.restart(t)

		assert.Equal(t, before, snapshot(), "已消耗的四種結果逐欄不變")
		var open int64
		require.NoError(t, rig.db.Model(&model.CredentialHostIdentityConfirmation{}).Where("consumed_at IS NULL").Count(&open).Error)
		assert.EqualValues(t, 0, open, "未消耗者全數收束")
		var unknown []model.CredentialHostIdentityConfirmation
		require.NoError(t, rig.db.Where("outcome = ?", takeoverOutcomeUnknown).Find(&unknown).Error)
		assert.Len(t, unknown, 2)
		for _, u := range unknown {
			require.NotNil(t, u.ConsumedAt)
		}
		assert.Equal(t, verifiesBase, rig.verifies.Load())
		assert.Equal(t, attBase, rig.attempts())

		// 再跑一次：沒有任何列再被改動
		again := snapshot()
		rig.restart(t)
		assert.Equal(t, again, snapshot())
		n, err := recoverInterruptedConfirmations(rig.db)
		require.NoError(t, err)
		assert.EqualValues(t, 0, n, "沒有未消耗者：不動任何列")
	})
}
