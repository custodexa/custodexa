package asset

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 逾期承接子案例（root：TestCredentialRecoveryHostIdentityTakeover，前綴 4.1/逾期/）。
// 逾期成員一律經正式補跑路徑走到終局失敗（回退輪替起算時間後讓驗證失敗），不直接寫狀態。

// newExpiredMemberTarget 成員已逾期轉為終局失敗，之後主機身分被採用為新鑰並可承接。
func newExpiredMemberTarget(t *testing.T, split bool) memberVerifyTarget {
	t.Helper()
	f, rot, m := sentUnverified(t, split)
	require.NoError(t, f.db.Model(&model.CredentialRotation{}).Where("id = ?", rot.ID).
		Update("started_at", time.Now().Add(-25*time.Hour)).Error)
	f.setRejectVerify(true)
	require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, m.ID))
	f.setRejectVerify(false)
	require.Equal(t, model.CredentialMemberTerminalFailed, f.member(t, rot.ID).State, "前置：成員已逾期轉終局失敗")
	adoptRemoteKey(t, f.server, f.db, f.assetID, true)
	svc := NewHostIdentityTakeoverService(f.db, f.perms).WithMemberRunner(f.rotations)
	svc.SetAuditTxSink(audit.NewTxSink())
	require.NoError(t, f.db.AutoMigrate(&model.CredentialHostIdentityConfirmation{}))
	tg := takeoverTarget{kind: takeoverKindMember, jobID: m.ID, svc: svc, db: f.db, authz: f.perms,
		capKey: CredCapRotate, assetID: f.assetID,
		req: validConfirmRequest(t, f.db, f.assetID), attempts: f.server.authAttempts.Load}
	return memberVerifyTarget{takeoverTarget: tg, f: f, rot: rot, split: split}
}

func memberStateName(split bool) string {
	if split {
		return "拆分"
	}
	return "整組"
}

func runTakeoverExpired(t *testing.T) {
	const p = "4.1/逾期/"

	t.Run(p+"候選/單次驗證_消耗_expired為真_Rotate為0", func(t *testing.T) {
		v := newVerifyTarget(t, false)
		require.NoError(t, v.db.Model(&model.ChangeSecretCandidate{}).Where("id = ?", v.jobID).
			Updates(map[string]any{"created_at": time.Now().Add(-25 * time.Hour), "abandoned": true}).Error)
		chBase, attBase := v.f.server.chpasswdCalls.Load(), v.attempts()
		require.NoError(t, v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, v.request()))
		assert.EqualValues(t, 0, v.f.candidateCount(t), "逾期候選轉正後刪除")
		assert.EqualValues(t, attBase+1, v.attempts(), "恰一次邏輯驗證")
		assert.Equal(t, chBase, v.f.server.chpasswdCalls.Load(), "Rotate 0")
		rec := onlyRecord(t, v.takeoverTarget)
		require.NotNil(t, rec.ConsumedAt)
		assert.Equal(t, takeoverOutcomeVerified, rec.Outcome)
		assert.Equal(t, true, lastConfirmAudit(t, v.db)["expired"])
		assert.Equal(t, false, lastConfirmAudit(t, v.db)["deadline_reset"])
	})

	for _, split := range []bool{false, true} {
		name := memberStateName(split)
		t.Run(p+name+"成員/終局失敗直接就位_單次驗證_消耗_不恢復背景_Rotate為0", func(t *testing.T) {
			v := newExpiredMemberTarget(t, split)
			before, rotBefore := v.row(t), v.rotation(t)
			chBase, attBase := v.f.server.chpasswdCalls.Load(), v.attempts()
			wr := &writeRecorder{}
			wr.install(t, v.db)

			require.NoError(t, v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, acceptDifferent(v.req)))

			after := v.row(t)
			assert.Equal(t, model.CredentialMemberApplied, after.State, "錯誤: %s", after.LastError)
			assert.Equal(t, before.AttemptCount, after.AttemptCount, "不經 queued／changing，次數不動")
			assert.Equal(t, rotBefore.StartedAt, v.rotation(t).StartedAt, "原期限不重設")
			assert.EqualValues(t, attBase+1, v.attempts(), "恰一次邏輯驗證")
			assert.Equal(t, chBase, v.f.server.chpasswdCalls.Load(), "Rotate 0")
			assert.EqualValues(t, 0, memberCandidateCount(t, v.f, &before), "就位後候選刪除")
			rec := onlyRecord(t, v.takeoverTarget)
			require.NotNil(t, rec.ConsumedAt)
			assert.Equal(t, takeoverOutcomeVerified, rec.Outcome)
			assert.Equal(t, true, lastConfirmAudit(t, v.db)["expired"])

			consume := wr.of("credential_host_identity_confirmations", "update")
			require.Len(t, consume, 1, "只有一次條件式消耗更新（由就位轉移承擔）")
			require.True(t, consume[0].inTx)
			states := wr.of("credential_rotation_members", "update")
			require.NotEmpty(t, states)
			for _, s := range states {
				assert.True(t, s.pool == consume[0].pool, "成員就位與消耗在同一個交易")
			}

			// 背景不恢復：再補跑不會重新下達
			chAfter := v.f.server.chpasswdCalls.Load()
			_ = v.f.rotations.RunMember(adminCtx(), v.rot.ID, v.jobID)
			assert.Equal(t, chAfter, v.f.server.chpasswdCalls.Load(), "之後沒有任何改密指令")
		})

		t.Run(p+name+"成員/失敗則回滾_狀態不變_背景不重啟", func(t *testing.T) {
			v := newExpiredMemberTarget(t, split)
			before, rotBefore := v.row(t), v.rotation(t)
			chBase := v.f.server.chpasswdCalls.Load()

			// 驗證失敗：成員整列不變
			v.f.setRejectVerify(true)
			err := v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, acceptDifferent(v.req))
			require.ErrorIs(t, err, ErrHostIdentityVerifyFailed)
			assert.Equal(t, before, v.row(t))
			assert.Equal(t, rotBefore, v.rotation(t))
			assert.Equal(t, takeoverOutcomeVerifyFailed, onlyRecord(t, v.takeoverTarget).Outcome)
			v.f.setRejectVerify(false)

			// 就位交易內消耗之後注入失敗：就位、消耗、刪候選一起回滾
			var fired int
			v.f.rotations.confirmedCommitHook = func(*gorm.DB) error { fired++; return errors.New("inject") }
			err = v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, acceptDifferent(v.req))
			require.Equal(t, 1, fired, "注入器必須真的觸發")
			require.Error(t, err)
			assert.Equal(t, before, v.row(t), "成員整列不變：不就位")
			assert.EqualValues(t, 1, memberCandidateCount(t, v.f, &before), "候選保留")
			rows := confirmRecords(t, v.takeoverTarget)
			require.Len(t, rows, 2)
			assert.Equal(t, takeoverOutcomeCommitFailed, rows[1].Outcome, "回滾後另寫結果")
			assert.Equal(t, chBase, v.f.server.chpasswdCalls.Load(), "背景沒有重啟：Rotate 0")
		})
	}

	runTakeoverExpiredRejections(t, p)
}

// runTakeoverExpiredRejections 四種就位轉移被拒：成員狀態與就位版本不變。
func runTakeoverExpiredRejections(t *testing.T, p string) {
	type applyEnv struct {
		v    memberVerifyTarget
		m    model.CredentialRotationMember
		rec  model.CredentialHostIdentityConfirmation
		eff0 any
	}
	// 以建立紀錄但不注入執行器的服務停在建立紀錄：紀錄存在、未消耗、沒有任何驗證
	newEnv := func(t *testing.T, state string) applyEnv {
		v := newExpiredMemberTarget(t, false)
		if state != model.CredentialMemberTerminalFailed {
			require.NoError(t, v.db.Model(&model.CredentialRotationMember{}).Where("id = ?", v.jobID).
				Update("state", state).Error)
		}
		bare := NewHostIdentityTakeoverService(v.db, v.f.perms)
		bare.SetAuditTxSink(audit.NewTxSink())
		err := bare.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, acceptDifferent(v.req))
		require.ErrorIs(t, err, ErrHostIdentityConfirmIncomplete, "停在建立紀錄")
		var acct model.AssetAccount
		require.NoError(t, v.db.First(&acct, v.f.accountID).Error)
		return applyEnv{v: v, m: v.row(t), rec: onlyRecord(t, v.takeoverTarget), eff0: acct.EffectiveVersionID}
	}
	apply := func(env applyEnv, opt memberTransition) error {
		return env.v.db.Transaction(func(tx *gorm.DB) error {
			m := env.m
			return transitionMember(tx, &m, model.CredentialMemberApplied, opt)
		})
	}
	requireUntouched := func(t *testing.T, env applyEnv) {
		t.Helper()
		assert.Equal(t, env.m, env.v.row(t), "成員狀態不變")
		var acct model.AssetAccount
		require.NoError(t, env.v.db.First(&acct, env.v.f.accountID).Error)
		assert.Equal(t, env.eff0, acct.EffectiveVersionID, "就位版本不變")
		rows := confirmRecords(t, env.v.takeoverTarget)
		require.Len(t, rows, 1)
		assert.Equal(t, env.rec.ConsumedAt, rows[0].ConsumedAt)
		assert.Equal(t, env.rec.Outcome, rows[0].Outcome)
	}
	good := func(env applyEnv) verifiedConfirmation {
		return verifiedConfirmation{kind: env.rec.Kind, jobID: env.rec.JobID, confirmationID: env.rec.ID,
			revision: env.rec.Revision}
	}

	for _, state := range []string{model.CredentialMemberTerminalFailed, model.CredentialMemberAbandoned} {
		t.Run(p+"就位轉移被拒/"+state+"/沒有結果物件", func(t *testing.T) {
			env := newEnv(t, state)
			require.ErrorIs(t, apply(env, memberTransition{}), ErrVerifiedConfirmationRequired)
			requireUntouched(t, env)
		})
		t.Run(p+"就位轉移被拒/"+state+"/紀錄存在但驗證未成功或尚未執行", func(t *testing.T) {
			env := newEnv(t, state)
			// 紀錄存在且未消耗，但沒有本次驗證成功產生的結果物件
			require.Nil(t, memberTransition{}.Verified)
			require.ErrorIs(t, apply(env, memberTransition{LastError: "verify_pending"}), ErrVerifiedConfirmationRequired)
			requireUntouched(t, env)
		})
		t.Run(p+"就位轉移被拒/"+state+"/錯誤job或revision與零值", func(t *testing.T) {
			env := newEnv(t, state)
			cases := map[string]func(*verifiedConfirmation){
				"錯誤job":      func(g *verifiedConfirmation) { g.jobID++ },
				"錯誤revision": func(g *verifiedConfirmation) { g.revision++ },
				"錯誤種類":       func(g *verifiedConfirmation) { g.kind = takeoverKindCandidate },
				"零值紀錄ID":     func(g *verifiedConfirmation) { g.confirmationID = 0 },
				"零值job":      func(g *verifiedConfirmation) { g.jobID = 0 },
				"零值revision": func(g *verifiedConfirmation) { g.revision = 0 },
			}
			for name, mutate := range cases {
				g := good(env)
				mutate(&g)
				require.ErrorIs(t, apply(env, memberTransition{Verified: &g}), ErrVerifiedConfirmationInvalid, name)
				requireUntouched(t, env)
			}
		})
		t.Run(p+"就位轉移被拒/"+state+"/紀錄已消耗", func(t *testing.T) {
			env := newEnv(t, state)
			require.NoError(t, env.v.db.Model(&model.CredentialHostIdentityConfirmation{}).Where("id = ?", env.rec.ID).
				Updates(map[string]any{"consumed_at": time.Now(), "outcome": "unknown"}).Error)
			g := good(env)
			require.ErrorIs(t, apply(env, memberTransition{Verified: &g}), ErrVerifiedConfirmationInvalid)
			assert.Equal(t, env.m, env.v.row(t), "成員狀態不變")
		})
		t.Run(p+"就位轉移被拒/"+state+"/對照_正確結果物件放行並同交易消耗", func(t *testing.T) {
			env := newEnv(t, state)
			g := good(env)
			require.NoError(t, apply(env, memberTransition{Verified: &g}))
			assert.Equal(t, model.CredentialMemberApplied, env.v.row(t).State)
			assert.Equal(t, takeoverOutcomeVerified, onlyRecord(t, env.v.takeoverTarget).Outcome)
			// 同一結果物件不能第二次使用
			assert.Error(t, apply(env, memberTransition{Verified: &g}))
		})
	}
}
