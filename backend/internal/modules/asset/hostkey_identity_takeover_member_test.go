package asset

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 輪替成員（未逾期、已下達未驗證）的承接驗證子案例
// （root：TestCredentialRecoveryHostIdentityTakeover，前綴 4.1/驗證/成員/）。
// 夾具的綁定與主機金鑰記錄都經正式回呼建立；審計列與去重鍵不刪，一律用基線差值。

type memberVerifyTarget struct {
	takeoverTarget
	f     *memberBindFixture
	rot   *model.CredentialRotation
	split bool
}

func newMemberVerifyTarget(t *testing.T, split bool) memberVerifyTarget {
	t.Helper()
	f, rot, m := sentUnverified(t, split)
	require.EqualValues(t, 1, memberCandidateCount(t, f, m), "前置：成員掛載的候選存在")
	adoptRemoteKey(t, f.server, f.db, f.assetID, true)
	svc := NewHostIdentityTakeoverService(f.db, f.perms).WithMemberRunner(f.rotations)
	svc.SetAuditTxSink(audit.NewTxSink())
	require.NoError(t, f.db.AutoMigrate(&model.CredentialHostIdentityConfirmation{}))
	tg := takeoverTarget{kind: takeoverKindMember, jobID: m.ID, svc: svc, db: f.db, authz: f.perms,
		capKey: CredCapRotate, assetID: f.assetID,
		req: validConfirmRequest(t, f.db, f.assetID), attempts: f.server.authAttempts.Load}
	return memberVerifyTarget{takeoverTarget: tg, f: f, rot: rot, split: split}
}

func memberCandidateCount(t *testing.T, f *memberBindFixture, m *model.CredentialRotationMember) int64 {
	t.Helper()
	var n int64
	require.NoError(t, f.db.Model(&model.ChangeSecretCandidate{}).Where("account_id = ?", m.AccountID).Count(&n).Error)
	return n
}

func (v memberVerifyTarget) clearCandidate(t *testing.T) {
	t.Helper()
	require.NoError(t, v.db.Where("account_id = ?", v.f.accountID).Delete(&model.ChangeSecretCandidate{}).Error)
}

func (v memberVerifyTarget) row(t *testing.T) model.CredentialRotationMember {
	t.Helper()
	return *v.f.member(t, v.rot.ID)
}

func (v memberVerifyTarget) rotation(t *testing.T) model.CredentialRotation {
	t.Helper()
	var r model.CredentialRotation
	require.NoError(t, v.db.First(&r, v.rot.ID).Error)
	return r
}

func runTakeoverMember(t *testing.T) {
	const p = "4.1/驗證/成員/"

	for _, split := range []bool{false, true} {
		name := "整組"
		if split {
			name = "拆分"
		}
		t.Run(p+name+"成員成功就位_消耗與就位同交易_只Verify不Rotate", func(t *testing.T) {
			v := newMemberVerifyTarget(t, split)
			chBase, attBase := v.f.server.chpasswdCalls.Load(), v.attempts()
			auditBase := confirmAuditCount(t, v.db)
			stopsBase := len(memberStops(t, v.db))
			wr := &writeRecorder{}
			wr.install(t, v.db)

			err := v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, acceptDifferent(v.req))
			require.NoError(t, err)

			after := v.row(t)
			assert.Equal(t, model.CredentialMemberApplied, after.State, "錯誤: %s", after.LastError)
			assert.EqualValues(t, 0, memberCandidateCount(t, v.f, &after), "就位後候選刪除")
			assert.EqualValues(t, attBase+1, v.attempts(), "恰一次邏輯驗證")
			assert.Equal(t, chBase, v.f.server.chpasswdCalls.Load(), "改密指令 0：只 Verify 不 Rotate")
			assert.Equal(t, auditBase+1, confirmAuditCount(t, v.db), "只有建立時的一筆承接審計")
			assert.Len(t, memberStops(t, v.db), stopsBase, "承接路徑不新增停止審計")

			rec := onlyRecord(t, v.takeoverTarget)
			require.NotNil(t, rec.ConsumedAt)
			assert.Equal(t, takeoverOutcomeVerified, rec.Outcome)

			// SQL 攔截：消耗紀錄、成員就位與刪候選在同一個交易連線上
			consume := wr.of("credential_host_identity_confirmations", "update")
			require.Len(t, consume, 1, "成功路徑只有一次條件式消耗更新")
			require.True(t, consume[0].inTx, "消耗在交易內")
			for _, tc := range []struct{ table, kind string }{
				{"credential_rotation_members", "update"}, {"change_secret_candidates", "delete"}} {
				got := wr.of(tc.table, tc.kind)
				require.NotEmpty(t, got, tc.table)
				for _, s := range got {
					assert.True(t, s.pool == consume[0].pool, "%s 的 %s 與消耗在同一個交易", tc.table, tc.kind)
				}
			}
			if split {
				got := wr.of("asset_accounts", "update")
				require.NotEmpty(t, got, "拆分就位改綁掛載")
				for _, s := range got {
					assert.True(t, s.pool == consume[0].pool, "改綁與消耗在同一個交易")
				}
			}
		})

		t.Run(p+name+"消耗受影響0列_整筆回滾_成員不就位", func(t *testing.T) {
			v := newMemberVerifyTarget(t, split)
			before := v.row(t)
			var fired int
			v.f.wrapExecutors(func(e rotationExecutor) rotationExecutor {
				return verifyAfterExecutor{e, func() {
					fired++
					// 驗證成功之後、提交之前，紀錄被別處消耗（例如啟動收束）
					res := v.db.Model(&model.CredentialHostIdentityConfirmation{}).
						Where("kind = ? AND job_id = ?", v.kind, v.jobID).
						Updates(map[string]any{"consumed_at": gorm.Expr("CURRENT_TIMESTAMP"), "outcome": "unknown"})
					if res.Error != nil || res.RowsAffected != 1 {
						t.Errorf("前置消耗失敗 err=%v rows=%d", res.Error, res.RowsAffected)
					}
				}}
			})
			err := v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, acceptDifferent(v.req))
			require.Equal(t, 1, fired, "注入器必須真的觸發")
			require.ErrorIs(t, err, ErrConfirmationNotConsumable)
			assert.Equal(t, before, v.row(t), "成員整列不變：不就位")
			assert.EqualValues(t, 1, memberCandidateCount(t, v.f, &before), "候選保留")
			assert.Equal(t, "unknown", onlyRecord(t, v.takeoverTarget).Outcome, "別處已寫的結果不被覆蓋")
		})
	}

	t.Run(p+"整組成員候選副本已清除_以目標版本驗證一次_成功就位", func(t *testing.T) {
		v := newMemberVerifyTarget(t, false)
		v.clearCandidate(t)
		attBase := v.attempts()
		err := v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, acceptDifferent(v.req))
		require.NoError(t, err)
		after := v.row(t)
		assert.Equal(t, model.CredentialMemberApplied, after.State, "錯誤: %s", after.LastError)
		assert.EqualValues(t, attBase+1, v.attempts(), "以目標版本取秘密，恰驗證一次")
		assert.Equal(t, takeoverOutcomeVerified, onlyRecord(t, v.takeoverTarget).Outcome)
	})

	t.Run(p+"拆分成員候選已清除_verify_failed_authAttempts為0", func(t *testing.T) {
		v := newMemberVerifyTarget(t, true)
		v.clearCandidate(t)
		before := v.row(t)
		attBase := v.attempts()
		err := v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, acceptDifferent(v.req))
		require.ErrorIs(t, err, ErrHostIdentityVerifyFailed)
		assert.Contains(t, err.Error(), model.ChangeSecretReasonNoCredential)
		assert.Equal(t, attBase, v.attempts(), "authAttempts 0：沒有候選就沒有網路")
		assert.Equal(t, takeoverOutcomeVerifyFailed, onlyRecord(t, v.takeoverTarget).Outcome)
		assert.Equal(t, before, v.row(t), "成員整列不變")
	})

	t.Run(p+"成員的原期限不重設", func(t *testing.T) {
		v := newMemberVerifyTarget(t, false)
		before, rotBefore := v.row(t), v.rotation(t)
		v.f.setRejectVerify(true) // 純驗證失敗，與主機身分無關
		err := v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, acceptDifferent(v.req))
		require.ErrorIs(t, err, ErrHostIdentityVerifyFailed)
		assert.Equal(t, takeoverOutcomeVerifyFailed, onlyRecord(t, v.takeoverTarget).Outcome)
		assert.Equal(t, before, v.row(t), "next_attempt_at、次數、原因碼與狀態都不變")
		assert.Equal(t, rotBefore.StartedAt, v.rotation(t).StartedAt, "截止時間基準不重設")
		assert.Equal(t, rotBefore, v.rotation(t))

		// 再次確認並成功：輪替的起算時間仍不變
		v.f.setRejectVerify(false)
		err = v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, acceptDifferent(v.req))
		require.NoError(t, err)
		assert.Equal(t, rotBefore.StartedAt, v.rotation(t).StartedAt)
		rows := confirmRecords(t, v.takeoverTarget)
		require.Len(t, rows, 2)
		assert.Equal(t, takeoverOutcomeVerified, rows[1].Outcome)
	})
}
