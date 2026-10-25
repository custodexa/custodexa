package asset

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// upgradeShapeMember 把已送出未驗證的成員改成實際升級後的形狀：目標指紋為空、主機身分綁定為 legacy（無快照）、
// 送出標記保留。
func upgradeShapeMember(t *testing.T, v memberVerifyTarget) {
	t.Helper()
	require.NoError(t, v.db.Model(&model.CredentialRotationMember{}).Where("id = ?", v.jobID).Updates(map[string]any{
		"target_fingerprint": "",
		"host_key_binding":   model.HostKeyBindingLegacy, "host_key_transport": "", "host_key_record_id": 0,
		"host_key_algorithm": "", "host_key_fingerprint": "", "host_key_generation": 0, "host_key_bound_at": nil}).Error)
	m := v.row(t)
	require.Empty(t, m.TargetFingerprint)
	require.NotNil(t, m.SecretSentAt, "前置：帶送出標記")
}

// confirmAuditPinned 最新一筆承接審計 details 的補記布林；欄位缺席視為 false。
func confirmAuditPinned(t *testing.T, v memberVerifyTarget) bool {
	t.Helper()
	var logs []model.AuditLog
	require.NoError(t, v.db.Where("details LIKE ?", `%host_identity_confirm%`).Order("id desc").Find(&logs).Error)
	require.NotEmpty(t, logs)
	var d map[string]any
	require.NoError(t, json.Unmarshal([]byte(logs[0].Details), &d))
	b, _ := d["target_pinned_at_confirm"].(bool)
	return b
}

func runTakeoverMemberPin(t *testing.T) {
	const p = "4.4/升級前成員/"
	for _, split := range []bool{false, true} {
		mode := "整組"
		if split {
			mode = "拆分"
		}

		t.Run(p+mode+"/空指紋成員確認成功_補記當下值_審計帶布林_Verify1次_就位", func(t *testing.T) {
			v := newMemberVerifyTarget(t, split)
			upgradeShapeMember(t, v)
			_, sshVerifies := memberExecutors(v)
			want, err := loadTargetFingerprint(v.db, v.f.accountID)
			require.NoError(t, err)
			attBase := v.attempts()
			chBase := v.f.server.chpasswdCalls.Load()

			require.NoError(t, v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, v.req))

			after := v.row(t)
			assert.Equal(t, model.CredentialMemberApplied, after.State, "錯誤: %s", after.LastError)
			assert.Equal(t, want, after.TargetFingerprint, "補記為當下值")
			assert.True(t, confirmAuditPinned(t, v), "審計帶補記布林")
			assert.Equal(t, 1, *sshVerifies, "Verify 1 次")
			assert.EqualValues(t, attBase+1, v.attempts(), "恰一次邏輯驗證")
			assert.Equal(t, chBase, v.f.server.chpasswdCalls.Load(), "改密指令 0")
			assert.Equal(t, takeoverOutcomeVerified, onlyRecord(t, v.takeoverTarget).Outcome)
		})

		for _, c := range []struct {
			name   string
			mutate func(t *testing.T, v memberVerifyTarget)
		}{
			{"改位址", func(t *testing.T, v memberVerifyTarget) {
				require.NoError(t, v.db.Model(&model.Asset{}).Where("id = ?", v.f.assetID).
					Update("host", "10.77.0.9").Error)
			}},
			{"改帳號", func(t *testing.T, v memberVerifyTarget) {
				require.NoError(t, v.db.Model(&model.AssetAccount{}).Where("id = ?", v.f.accountID).
					Update("username", "renamed-account").Error)
			}},
		} {
			t.Run(p+mode+"/補記後提交前"+c.name+"_回目標變更_不就位", func(t *testing.T) {
				v := newMemberVerifyTarget(t, split)
				upgradeShapeMember(t, v)
				_, sshVerifies := memberExecutors(v)
				pinned, err := loadTargetFingerprint(v.db, v.f.accountID)
				require.NoError(t, err)
				attBase := v.attempts()
				fired := 0
				v.f.rotations.verifyPrecheckHook = func() { fired++; c.mutate(t, v) }

				err = v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, v.req)
				require.Equal(t, 1, fired, "注入點必須真的觸發")
				require.ErrorIs(t, err, ErrHostIdentityConfirmTargetChanged)
				assert.NotErrorIs(t, err, ErrHostIdentityVerifyFailed)
				assert.Zero(t, *sshVerifies, "Verify 0")
				assert.Equal(t, attBase, v.attempts(), "認證 0")
				after := v.row(t)
				assert.NotEqual(t, model.CredentialMemberApplied, after.State, "不就位")
				assert.Equal(t, pinned, after.TargetFingerprint, "補記的是確認當下的值，不隨後來的變動改寫")
				rec := onlyRecord(t, v.takeoverTarget)
				require.NotNil(t, rec.ConsumedAt)
				assert.Equal(t, takeoverOutcomeVerifyFailed, rec.Outcome)
			})
		}

		t.Run(p+mode+"/審計注入失敗整筆回滾_指紋仍為空", func(t *testing.T) {
			v := newMemberVerifyTarget(t, split)
			upgradeShapeMember(t, v)
			base := newCreateBase(t, v.takeoverTarget)
			v.svc.SetAuditTxSink(failingTxSink{err: errors.New("audit down")})

			err := v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, v.req)
			require.Error(t, err)
			assert.NotErrorIs(t, err, ErrHostIdentityConfirmIncomplete)
			base.requireNoCreate(t, v.takeoverTarget)
			assert.Empty(t, v.row(t).TargetFingerprint, "補記隨交易回滾")
		})

		t.Run(p+mode+"/指紋非空成員_審計不帶補記布林", func(t *testing.T) {
			v := newMemberVerifyTarget(t, split)
			require.NotEmpty(t, v.row(t).TargetFingerprint, "前置：建立時已記指紋")
			before := v.row(t).TargetFingerprint
			require.NoError(t, v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, acceptDifferent(v.req)))
			assert.False(t, confirmAuditPinned(t, v))
			assert.Equal(t, before, v.row(t).TargetFingerprint, "既有指紋不被覆蓋")
			assert.Equal(t, model.CredentialMemberApplied, v.row(t).State)
		})
	}

	// 升級前成員的補記只在確認者通過授權之後發生：無權者與背景主體都不能讓指紋被寫入
	for _, c := range []struct {
		name string
		ctx  func() context.Context
		deny bool
	}{
		{"無權確認者", adminCtx, true},
		{"背景主體", context.Background, false},
	} {
		t.Run(p+c.name+"確認空指紋成員_被拒_指紋仍空_無承接紀錄", func(t *testing.T) {
			v := newMemberVerifyTarget(t, false)
			upgradeShapeMember(t, v)
			if c.deny {
				v.authz.deny(v.capKey)
			}
			tr := newTakeoverTrace(t, v.db, v.attempts)
			err := v.svc.ConfirmHostIdentityAndVerify(c.ctx(), v.kind, v.jobID, v.req)
			require.ErrorIs(t, err, ErrCredentialBindForbidden)
			assert.Empty(t, v.row(t).TargetFingerprint, "被拒時不補記")
			tr.requireUntouched(t)
			var n int64
			require.NoError(t, v.db.Model(&model.CredentialHostIdentityConfirmation{}).Count(&n).Error)
			assert.Zero(t, n, "無承接紀錄")
		})
	}
}

// 成員建立點一律寫入非空目標指紋：空指紋被當成升級前成員補記，漏寫的新建立路徑會因此被靜默放行。
func TestRotationMembersAlwaysCarryTargetFingerprint(t *testing.T) {
	for _, split := range []bool{false, true} {
		mode := "整組"
		if split {
			mode = "拆分"
		}
		t.Run(mode, func(t *testing.T) {
			f := setupMemberBindFixture(t, "")
			rot := f.start(t, split)
			var members []model.CredentialRotationMember
			require.NoError(t, f.db.Where("rotation_id = ?", rot.ID).Find(&members).Error)
			require.NotEmpty(t, members, "前置：建立路徑產生了成員列")
			want, err := loadTargetFingerprint(f.db, f.accountID)
			require.NoError(t, err)
			for _, m := range members {
				assert.NotEmpty(t, m.TargetFingerprint, "成員 %d 建立時必須記錄目標指紋", m.ID)
				if m.AccountID == f.accountID {
					assert.Equal(t, want, m.TargetFingerprint)
				}
			}
		})
	}
}
