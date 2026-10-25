package asset

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 4.1 驗句逐條核對時補的子案例（root：TestCredentialRecoveryHostIdentityTakeover）：
// 建立紀錄的語句層證據，以及輪替成員在「確認到執行之間身分被換」與
// 「消耗之後、提交之前失敗」兩種情形下的行為（候選側已有同型子案例）。
func runTakeoverGaps(t *testing.T) {
	kinds := []struct {
		name string
		make func(*testing.T) takeoverTarget
	}{{"候選", candidateTakeoverTarget}, {"成員", memberTakeoverTarget}}
	for _, k := range kinds {
		t.Run("4.1/建立/"+k.name+"/started_at由建立紀錄的同一筆INSERT寫入_無獨立UPDATE_紀錄與審計同交易", func(t *testing.T) {
			tg := k.make(t)
			newCreateBase(t, tg)
			wr := &writeRecorder{}
			wr.install(t, tg.db)
			err := tg.svc.ConfirmHostIdentityAndVerify(adminCtx(), tg.kind, tg.jobID, acceptDifferent(tg.req))
			require.ErrorIs(t, err, ErrHostIdentityConfirmIncomplete)

			creates := wr.of("credential_host_identity_confirmations", "create")
			require.Len(t, creates, 1, "紀錄恰由一筆 INSERT 建立")
			assert.True(t, creates[0].inTx)
			assert.Empty(t, wr.of("credential_host_identity_confirmations", "update"),
				"建立階段沒有獨立的 started UPDATE")
			rows := confirmRecords(t, tg)
			require.Len(t, rows, 1)
			assert.NotNil(t, rows[0].StartedAt, "started_at 隨 INSERT 寫入")
			audits := wr.of("audit_logs", "create")
			require.NotEmpty(t, audits, "承接審計有寫入")
			for _, a := range audits {
				assert.True(t, a.pool == creates[0].pool, "審計與承接紀錄在同一個交易")
			}
		})
	}

	const p = "4.1/驗證/成員/"
	for _, split := range []bool{false, true} {
		name := "整組"
		if split {
			name = "拆分"
		}
		t.Run(p+name+"消耗後提交前注入失敗_消耗與就位一起回滾", func(t *testing.T) {
			v := newMemberVerifyTarget(t, split)
			before := v.row(t)
			boom := errors.New("injected failure before commit")
			var sawConsumed atomic.Int32
			v.f.rotations.confirmedCommitHook = func(tx *gorm.DB) error {
				var n int64
				require.NoError(t, tx.Model(&model.CredentialHostIdentityConfirmation{}).
					Where("kind = ? AND job_id = ? AND outcome = ?", v.kind, v.jobID, takeoverOutcomeVerified).
					Count(&n).Error)
				sawConsumed.Store(int32(n))
				return boom
			}
			chBase := v.f.server.chpasswdCalls.Load()
			err := v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, acceptDifferent(v.req))
			require.Equal(t, int32(1), sawConsumed.Load(), "掛點觸發時交易內消耗已寫入：回滾的是真東西")
			require.Error(t, err)
			assert.Equal(t, before, v.row(t), "成員整列不變：不就位")
			assert.EqualValues(t, 1, memberCandidateCount(t, v.f, &before), "候選保留")
			assert.Equal(t, takeoverOutcomeCommitFailed, onlyRecord(t, v.takeoverTarget).Outcome,
				"回滾後另寫 commit_failed，不是 verified")
			assert.Equal(t, chBase, v.f.server.chpasswdCalls.Load(), "Rotate 0")
		})

		t.Run(p+name+"確認到執行之間採用_得identity_moved_不提交", func(t *testing.T) {
			for _, phase := range []string{"撥號前", "驗證後提交前"} {
				v := newMemberVerifyTarget(t, split)
				before := v.row(t)
				attBase := v.attempts()
				var fired atomic.Int32
				swap := func() {
					fired.Add(1)
					adoptRemoteKey(t, v.f.server, v.f.db, v.f.assetID, true)
				}
				v.f.wrapExecutors(func(e rotationExecutor) rotationExecutor {
					if phase == "撥號前" {
						return verifyHookExecutor{e, swap}
					}
					return verifyAfterExecutor{e, swap}
				})
				err := v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, acceptDifferent(v.req))
				require.EqualValues(t, 1, fired.Load(), phase+"：注入器必須真的觸發")
				requireConflict(t, err, "")
				rec := onlyRecord(t, v.takeoverTarget)
				assert.Equal(t, takeoverOutcomeMoved, rec.Outcome, phase)
				assert.NotNil(t, rec.ConsumedAt, phase)
				assert.Equal(t, before, v.row(t), phase+"：成員不就位")
				assert.EqualValues(t, 1, memberCandidateCount(t, v.f, &before), phase+"：候選保留")
				if phase == "撥號前" {
					assert.Equal(t, attBase, v.attempts(), "握手即拒絕：沒有送出任何認證")
				} else {
					assert.EqualValues(t, attBase+1, v.attempts(), "驗證已通過一次才在提交交易內被擋下")
				}
			}
		})
	}
}
