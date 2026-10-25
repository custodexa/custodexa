package asset

import (
	"encoding/json"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 一般候選承接驗證的變體子案例（root：TestCredentialRecoveryHostIdentityTakeover，前綴 4.1/驗證/候選/）：
// Windows SSH 通道、派送標記曾失敗、公鑰不同。採用 B 一律走正式不符觀察加 Adopt。

// lastConfirmAudit 取最後一筆承接審計的 details。
func lastConfirmAudit(t *testing.T, db *gorm.DB) map[string]any {
	t.Helper()
	var rows []model.AuditLog
	require.NoError(t, db.Where("details LIKE ?", `%host_identity_confirm%`).Order("id").Find(&rows).Error)
	require.NotEmpty(t, rows)
	var out map[string]any
	require.NoError(t, json.Unmarshal([]byte(rows[len(rows)-1].Details), &out))
	return out
}

// windowsVerifyTarget 一個走 windows_ssh 通道、已綁定、驗證三次皆失而保留的候選；
// 靶機已換成 B 並經正式路徑採用。execSeen 為建置期間靶機看過的 exec 數。
type windowsVerifyTarget struct {
	verifyTarget
	srv      *testSSHServer
	execSeen *atomic.Int32
	acctID   uint
}

func newWindowsVerifyTarget(t *testing.T) windowsVerifyTarget {
	t.Helper()
	fx := setupChangeSecretFixture(t, "root", "oldpass123")
	authz := newAllowAllAuthorizer()
	fx.retry.WithManagementAuthorizer(authz)
	fx.retry.WithAuditSink(audit.NewTxSink())
	require.NoError(t, fx.db.AutoMigrate(&model.AssetHostKeyMismatch{}))
	fx.hostKeys.SetAuditTxSink(audit.NewTxSink())
	fx.hostKeys.SetSystemAlertSink(newFakeAlertSink())
	wireStopAudit(fx)

	srv := newTestSSHServer(t, "Administrator", "winoldpass")
	seen := &atomic.Int32{}
	srv.mu.Lock()
	srv.windowsApplyStdinPassword = true
	srv.execExitByCall = map[int32]int{2: 1, 3: 1, 4: 1} // 改密之後三次驗證皆失敗
	srv.onExec = func(n int32) { seen.Store(n) }
	srv.mu.Unlock()
	id := addWindowsSSHAsset(t, fx, srv)
	winExec := func(string) rotationExecutor { return testWindowsSSHExecutor(nil) }
	fx.runner.executors = winExec
	fx.retry.executors = winExec

	records := fx.runner.RunPlan(fx.planForAssets(t, []uint{id}, nil))
	require.Len(t, records, 1)
	require.Equal(t, model.ChangeSecretUnverified, records[0].Status)
	require.EqualValues(t, 4, seen.Load(), "一次改密加三次驗證指令")

	var cand model.ChangeSecretCandidate
	require.NoError(t, fx.db.Where("asset_id = ?", id).First(&cand).Error)
	require.Equal(t, model.HostKeyBindingBound, cand.HostKeyBinding)
	adoptRemoteKey(t, srv, fx.db, id, true)

	svc := NewHostIdentityTakeoverService(fx.db, authz).WithCandidateRunner(fx.retry)
	svc.SetAuditTxSink(audit.NewTxSink())
	require.NoError(t, fx.db.AutoMigrate(&model.CredentialHostIdentityConfirmation{}))
	tg := takeoverTarget{kind: takeoverKindCandidate, jobID: cand.ID, svc: svc, db: fx.db, authz: authz,
		capKey: CredCapAccountRotate, assetID: id,
		req: validConfirmRequest(t, fx.db, id), attempts: srv.authAttempts.Load}
	return windowsVerifyTarget{verifyTarget: verifyTarget{takeoverTarget: tg, f: fx}, srv: srv, execSeen: seen, acctID: cand.AccountID}
}

// failFirstVerifyThen 讓確認期間第一次驗證指令失敗（逼出第二次撥號），並在該指令到達時執行 onFirst。
func (w windowsVerifyTarget) failFirstVerifyThen(onFirst func()) {
	first := w.execSeen.Load() + 1
	w.srv.mu.Lock()
	defer w.srv.mu.Unlock()
	w.srv.execExitByCall = map[int32]int{first: 1}
	w.srv.onExec = func(n int32) {
		w.execSeen.Store(n)
		if n == first && onFirst != nil {
			onFirst()
		}
	}
}

func (w windowsVerifyTarget) localPassword(t *testing.T) string {
	t.Helper()
	creds, err := w.f.assets.GetWithCredentialsForAccount(w.assetID, w.acctID)
	require.NoError(t, err)
	return secretText(t, creds.Password)
}

func (w windowsVerifyTarget) candidateGone(t *testing.T) bool {
	t.Helper()
	var n int64
	require.NoError(t, w.db.Model(&model.ChangeSecretCandidate{}).Where("id = ?", w.jobID).Count(&n).Error)
	return n == 0
}

func runTakeoverVariants(t *testing.T) {
	const p = "4.1/驗證/候選/"
	delays := len(windowsVerifyDelays())

	t.Run(p+"WindowsSSH通道/第一次驗證失敗第二次撥號仍核身分_提交", func(t *testing.T) {
		w := newWindowsVerifyTarget(t)
		before := w.localPassword(t)
		w.failFirstVerifyThen(nil)
		att := w.attempts()
		audits := confirmAuditCount(t, w.db)

		require.NoError(t, w.svc.ConfirmHostIdentityAndVerify(adminCtx(), w.kind, w.jobID, w.request()))

		used := w.attempts() - att
		assert.GreaterOrEqual(t, int(used), 1)
		assert.LessOrEqual(t, int(used), delays, "authAttempts 介於 1 與 verifyDelays 長度之間")
		assert.EqualValues(t, 2, used, "第一次指令失敗、第二次撥號成功")
		assert.True(t, w.candidateGone(t), "提交：候選轉正")
		assert.NotEqual(t, before, w.localPassword(t))
		rec := onlyRecord(t, w.takeoverTarget)
		assert.Equal(t, takeoverOutcomeVerified, rec.Outcome)
		assert.Equal(t, audits+1, confirmAuditCount(t, w.db))
		a := lastConfirmAudit(t, w.db)
		assert.Equal(t, true, a["verify_only"])
		assert.Equal(t, false, a["deadline_reset"])
		assert.Equal(t, "ssh", a["transport"])
	})

	t.Run(p+"WindowsSSH通道/第二次撥號前換成B_拒絕不提交", func(t *testing.T) {
		w := newWindowsVerifyTarget(t)
		before := w.localPassword(t)
		orig := candRowOf(t, w.f, w.jobID)
		var fired atomic.Int32
		w.failFirstVerifyThen(func() {
			fired.Add(1)
			adoptRemoteKey(t, w.srv, w.db, w.assetID, true)
		})
		att := w.attempts()
		audits := confirmAuditCount(t, w.db)

		err := w.svc.ConfirmHostIdentityAndVerify(adminCtx(), w.kind, w.jobID, w.request())
		require.EqualValues(t, 1, fired.Load(), "注入器必須真的觸發")
		requireConflict(t, err, "")

		used := int(w.attempts() - att)
		assert.GreaterOrEqual(t, used, 1)
		assert.LessOrEqual(t, used, delays)
		assert.Equal(t, 1, used, "第二次撥號握手即被拒，沒有第二次認證")
		assert.False(t, w.candidateGone(t), "不提交")
		assert.Equal(t, before, w.localPassword(t))
		assert.Equal(t, orig, candRowOf(t, w.f, w.jobID))
		rec := onlyRecord(t, w.takeoverTarget)
		assert.Equal(t, takeoverOutcomeMoved, rec.Outcome)
		assert.NotNil(t, rec.ConsumedAt)
		assert.Equal(t, audits+1, confirmAuditCount(t, w.db), "只有建立時的一筆承接審計")
	})

	for _, isKey := range []bool{false, true} {
		kind := "密碼"
		if isKey {
			kind = "SSH金鑰"
		}
		q := p + kind + "/"

		t.Run(q+"派送標記曾失敗_applied為false仍可確認並驗證", func(t *testing.T) {
			v := newVerifyTarget(t, isKey)
			require.NoError(t, v.db.Model(&model.ChangeSecretCandidate{}).Where("id = ?", v.jobID).
				Update("applied", false).Error)
			cand := candidateOfAccount(t, v.f)
			require.False(t, cand.Applied, "前置：派送標記未寫成")
			require.Equal(t, model.HostKeyBindingBound, cand.HostKeyBinding)
			before := v.localSecret(t)
			chBase, att := v.f.server.chpasswdCalls.Load(), v.attempts()
			audits := confirmAuditCount(t, v.db)

			require.NoError(t, v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, v.request()))

			assert.EqualValues(t, att+1, v.attempts(), "恰一次邏輯驗證")
			assert.Equal(t, chBase, v.f.server.chpasswdCalls.Load(), "只 Verify 不 Rotate")
			assert.EqualValues(t, 0, v.f.candidateCount(t), "提交：候選轉正")
			assert.NotEqual(t, before, v.localSecret(t))
			rec := onlyRecord(t, v.takeoverTarget)
			assert.Equal(t, takeoverOutcomeVerified, rec.Outcome)
			assert.Equal(t, audits+1, confirmAuditCount(t, v.db))
			assert.Equal(t, true, lastConfirmAudit(t, v.db)["verify_only"])
		})

		t.Run(q+"公鑰不同且帶accept_different_key_審計different_key為true_驗證一次", func(t *testing.T) {
			v := newVerifyTarget(t, isKey) // 夾具已由正式觀察加 Adopt 採用 B
			var own model.AssetHostKey
			require.NoError(t, v.db.Where("asset_id = ?", v.assetID).First(&own).Error)
			orig := candRowOf(t, v.f, v.jobID)
			require.NotEqual(t, orig.Fingerprint, own.Fingerprint, "前置：當下記錄的公鑰與原快照不同")
			var adopted int64
			require.NoError(t, v.db.Model(&model.AuditLog{}).Where("details LIKE ?", "%"+own.Fingerprint+"%").Count(&adopted).Error)
			require.Positive(t, adopted, "前置：B 經正式採用路徑留有採用審計")

			att := v.attempts()
			require.NoError(t, v.svc.ConfirmHostIdentityAndVerify(adminCtx(), v.kind, v.jobID, v.request()))

			assert.EqualValues(t, att+1, v.attempts(), "驗證恰一次")
			assert.EqualValues(t, 0, v.f.candidateCount(t))
			a := lastConfirmAudit(t, v.db)
			assert.Equal(t, true, a["different_key"])
			assert.Equal(t, true, a["verify_only"])
			rec := onlyRecord(t, v.takeoverTarget)
			assert.True(t, rec.AcceptDifferentKey)
			assert.Equal(t, takeoverOutcomeVerified, rec.Outcome)
		})
	}
}
