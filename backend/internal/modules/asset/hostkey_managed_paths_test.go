package asset

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// managedPathsFixture 以行程內 SSH 靶機跑真撥號：連線測試（互動）與改密、重試、輪替（背景）
// 四條受管路徑的主機金鑰不符處置。靶機的主機金鑰固定；要造「不符」就把資產記錄改成另一把金鑰。
type managedPathsFixture struct {
	*csFixture
	alerts *recordingAlertSink
}

func setupManagedPathsFixture(t *testing.T) *managedPathsFixture {
	t.Helper()
	f := setupChangeSecretFixture(t, "root", "oldpass123")
	require.NoError(t, f.db.AutoMigrate(&model.AssetHostKeyMismatch{}, &model.User{},
		&model.CredentialRotation{}, &model.CredentialRotationMember{}))
	alerts := &recordingAlertSink{}
	f.hostKeys.SetAuditTxSink(audit.NewTxSink())
	f.hostKeys.SetSystemAlertSink(alerts)
	f.assets.SetHostKeyService(f.hostKeys)
	return &managedPathsFixture{csFixture: f, alerts: alerts}
}

// seedForeignRecord 為資產寫入一筆與靶機不同的主機金鑰記錄（撥號位址同靶機），讓下一次撥號判為不符。
func (f *managedPathsFixture) seedForeignRecord(t *testing.T) ssh.PublicKey {
	t.Helper()
	foreign := genHostKey(t)
	var a model.Asset
	require.NoError(t, f.db.First(&a, f.assetID).Error)
	host, port, ok := a.HostKeyAddress()
	require.True(t, ok)
	require.NoError(t, f.db.Where("asset_id = ?", f.assetID).Delete(&model.AssetHostKey{}).Error)
	require.NoError(t, f.db.Create(&model.AssetHostKey{
		AssetID: f.assetID, Algorithm: foreign.Type(), Fingerprint: ssh.FingerprintSHA256(foreign),
		PublicKey: base64.StdEncoding.EncodeToString(foreign.Marshal()), Host: host, Port: port,
	}).Error)
	return foreign
}

func (f *managedPathsFixture) mismatchAudits(t *testing.T) []map[string]any {
	t.Helper()
	var rows []model.AuditLog
	require.NoError(t, f.db.Where("action = ?", string(model.ActionHostKeyMismatch)).Order("id ASC").Find(&rows).Error)
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		var d map[string]any
		require.NoError(t, json.Unmarshal([]byte(r.Details), &d), r.Details)
		d["_user_id"] = r.UserID
		d["_username"] = r.Username
		out = append(out, d)
	}
	return out
}

func (f *managedPathsFixture) recordFingerprint(t *testing.T) string {
	t.Helper()
	var rec model.AssetHostKey
	require.NoError(t, f.db.Where("asset_id = ?", f.assetID).First(&rec).Error)
	return rec.Fingerprint
}

// TestHostKeyMismatchManagedPaths 連線測試放行並附警示碼；改密、重試與輪替拒絕撥號、靶機零認證嘗試、
// 原因碼為主機金鑰不符；查核失敗時原因碼不是主機金鑰不符。
func TestHostKeyMismatchManagedPaths(t *testing.T) {
	t.Run("connection_test", func(t *testing.T) {
		f := setupManagedPathsFixture(t)
		foreign := f.seedForeignRecord(t)
		before := f.server.passwordAuthCalls.Load()
		ctx := ContextWithClientIP(contextWithInitiator(context.Background(), 9, "probe-user"), "198.51.100.7")
		res, err := f.assets.TestConnection(ctx, f.assetID, 5)
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.True(t, res.Success, "不符時連線測試仍成功: code=%s msg=%s", res.Code, res.Message)
		assert.Equal(t, apierror.CodeSSHHostKeyChanged, res.WarningCode)
		assert.Equal(t, before+1, f.server.passwordAuthCalls.Load(), "互動路徑放行後憑證已送出（靶機收到認證）")
		audits := f.mismatchAudits(t)
		require.Len(t, audits, 1)
		assert.Equal(t, "connection_test", audits[0]["path"])
		assert.Equal(t, "allowed", audits[0]["outcome"])
		assert.EqualValues(t, 9, audits[0]["_user_id"])
		assert.Equal(t, "probe-user", audits[0]["_username"])
		_, hasRef := audits[0]["connection_ref"]
		assert.False(t, hasRef, "連線測試的連線識別留空")
		assert.Equal(t, ssh.FingerprintSHA256(foreign), audits[0]["recorded_fingerprint"])
		require.Len(t, f.alerts.events, 1)
		assert.Equal(t, port.SystemAlertHostKeyMismatch, f.alerts.events[0].Type)
		assert.Equal(t, "198.51.100.7", f.alerts.events[0].ClientIP)
		assert.Equal(t, ssh.FingerprintSHA256(foreign), f.recordFingerprint(t), "記錄不改寫")
		var sent []model.AuditLog
		require.NoError(t, f.db.Where("action = ?", string(model.ActionHostKeyCredSent)).Find(&sent).Error)
		require.Len(t, sent, 1)
		var d map[string]any
		require.NoError(t, json.Unmarshal([]byte(sent[0].Details), &d))
		assert.Equal(t, "succeeded", d["auth_result"])
	})

	t.Run("connection_test 放行後認證失敗：仍帶不符警示碼並補記憑證已送出（失敗）", func(t *testing.T) {
		f := setupManagedPathsFixture(t)
		f.seedForeignRecord(t)
		f.server.setPassword("rotated-elsewhere") // 託管密碼已不是靶機密碼：不符放行後認證被拒
		before := f.server.passwordAuthCalls.Load()
		res, err := f.assets.TestConnection(contextWithInitiator(context.Background(), 9, "probe-user"), f.assetID, 5)
		require.NoError(t, err)
		assert.False(t, res.Success)
		assert.Equal(t, apierror.CodeSSHAuthFailed, res.Code)
		assert.Equal(t, apierror.CodeSSHHostKeyChanged, res.WarningCode, "認證失敗也要保留不符警示：憑證可能已送出")
		assert.Equal(t, before+1, f.server.passwordAuthCalls.Load())
		var sent []model.AuditLog
		require.NoError(t, f.db.Where("action = ?", string(model.ActionHostKeyCredSent)).Find(&sent).Error)
		require.Len(t, sent, 1, "放行後應補記憑證已送出")
		var d map[string]any
		require.NoError(t, json.Unmarshal([]byte(sent[0].Details), &d))
		assert.Equal(t, "failed", d["auth_result"])
		assert.Equal(t, "connection_test", d["path"])
		audits := f.mismatchAudits(t)
		require.Len(t, audits, 1)
		assert.Equal(t, audits[0]["correlation_id"], d["correlation_id"])
		assert.Equal(t, "about_to_be_sent", audits[0]["credentials"])
	})

	t.Run("connection_test 查核失敗", func(t *testing.T) {
		f := setupManagedPathsFixture(t)
		f.seedForeignRecord(t)
		// 不符留痕寫不進去：觀察紀錄表不存在 → 留痕交易失敗 → 中止於送出憑證之前
		require.NoError(t, f.db.Migrator().DropTable(&model.AssetHostKeyMismatch{}))
		before := f.server.passwordAuthCalls.Load()
		res, err := f.assets.TestConnection(contextWithInitiator(context.Background(), 9, "probe-user"), f.assetID, 5)
		require.NoError(t, err)
		assert.False(t, res.Success)
		assert.Equal(t, apierror.CodeSSHHostKeyCheckFailed, res.Code)
		assert.Equal(t, "host_key_check_failed", res.ErrorCode)
		assert.Empty(t, res.WarningCode)
		assert.Equal(t, before, f.server.passwordAuthCalls.Load(), "查核失敗時憑證不得送出")
	})

	t.Run("credential_change", func(t *testing.T) {
		f := setupManagedPathsFixture(t)
		foreign := f.seedForeignRecord(t)
		plan := f.plan(t, nil)
		before := f.server.passwordAuthCalls.Load()
		records := f.runner.RunPlan(plan)
		require.Len(t, records, 1)
		assert.Equal(t, model.ChangeSecretFailed, records[0].Status)
		assert.Equal(t, model.ChangeSecretReasonHostKeyMismatch, records[0].Error)
		assert.Equal(t, before, f.server.passwordAuthCalls.Load(), "背景路徑拒絕撥號：靶機零認證嘗試")
		assert.EqualValues(t, 0, f.candidateCount(t), "舊憑證撥號遇不符＝遠端確定未變更、乾淨失敗，不留候選")
		assert.Equal(t, "oldpass123", f.storedPassword(t), "本地憑證不變")
		audits := f.mismatchAudits(t)
		require.Len(t, audits, 1)
		assert.Equal(t, "credential_change", audits[0]["path"])
		assert.Equal(t, "refused", audits[0]["outcome"])
		assert.EqualValues(t, 1, audits[0]["_user_id"], "連線使用者＝計畫授權脈絡的發起者")
		assert.Equal(t, "tester", audits[0]["_username"])
		assert.Equal(t, fmt.Sprintf("change_secret_plan:%d", plan.ID), audits[0]["connection_ref"])
		require.Len(t, f.alerts.events, 1)
		assert.Equal(t, "refused", f.alerts.events[0].Params["outcome"])
		assert.Equal(t, "not_sent", audits[0]["credentials"])
		assert.Equal(t, ssh.FingerprintSHA256(foreign), f.recordFingerprint(t))
		var n int64
		f.db.Model(&model.AuditLog{}).Where("action = ?", string(model.ActionHostKeyCredSent)).Count(&n)
		assert.EqualValues(t, 0, n, "拒絕路徑不得補記憑證已送出")
	})

	t.Run("credential_change 重試", func(t *testing.T) {
		f := setupManagedPathsFixture(t)
		// 先讓改密成功但驗證被拒，留下帶授權脈絡的候選（記錄此時已以靶機金鑰首次信任）
		f.server.rejectVerifyLogin = true
		records := f.runner.RunPlan(f.plan(t, nil))
		require.Len(t, records, 1)
		require.Equal(t, model.ChangeSecretUnverified, records[0].Status, records[0].Error)
		var cand model.ChangeSecretCandidate
		require.NoError(t, f.db.First(&cand).Error)
		f.server.mu.Lock()
		f.server.rejectVerifyLogin = false
		f.server.mu.Unlock()
		// 遠端出示與記錄、與綁定快照都不符的另一把金鑰 → 重試撥號不符 → 拒絕、留痕；記錄本身不被改寫。
		// （記錄被換成別把金鑰屬主機身分變更，由撥號前查庫擋下，另見 3.4 的重試子案例）
		recorded := f.recordFingerprint(t)
		foreign := f.server.swapHostKey(t)
		before := f.server.passwordAuthCalls.Load()
		promoted := f.retry.RetryOne(&cand)
		assert.False(t, promoted)
		assert.Equal(t, before, f.server.passwordAuthCalls.Load(), "重試遇不符：靶機零認證嘗試")
		var after model.ChangeSecretCandidate
		require.NoError(t, f.db.First(&after, cand.ID).Error)
		assert.Equal(t, model.ChangeSecretReasonHostKeyMismatch, after.LastError)
		assert.EqualValues(t, 1, f.candidateCount(t), "新秘密驗證撥號遇不符：候選保留")
		audits := f.mismatchAudits(t)
		require.Len(t, audits, 1)
		assert.Equal(t, "credential_change", audits[0]["path"])
		assert.Equal(t, "refused", audits[0]["outcome"])
		assert.Equal(t, fmt.Sprintf("change_secret_candidate:%d", cand.ID), audits[0]["connection_ref"])
		assert.EqualValues(t, 1, audits[0]["_user_id"])
		assert.Equal(t, ssh.FingerprintSHA256(foreign), audits[0]["observed_fingerprint"], "觀察到的是遠端出示的那把")
		assert.Equal(t, recorded, f.recordFingerprint(t), "記錄不被改寫")
	})

	t.Run("credential_rotation", func(t *testing.T) {
		f := setupManagedPathsFixture(t)
		var acct model.AssetAccount
		require.NoError(t, f.db.First(&acct, f.accountID).Error)
		rotations := NewCredentialRotationService(f.db, f.assets, f.candidates, f.hostKeys,
			aesColumnCodec(t, make([]byte, 32)), audit.NewTxSink(), newAllowAllAuthorizer()).WithSystemAlertSink(newFakeAlertSink())
		ctx := contextWithInitiator(context.Background(), 5, "rotator")

		// 舊秘密撥號遇不符：成員乾淨失敗、候選清除、靶機零認證嘗試
		foreign := f.seedForeignRecord(t)
		rot, err := rotations.Start(ctx, acct.CredentialID, StartRotationRequest{})
		require.NoError(t, err)
		before := f.server.passwordAuthCalls.Load()
		require.NoError(t, rotations.Run(ctx, rot.ID))
		var member model.CredentialRotationMember
		require.NoError(t, f.db.Where("rotation_id = ? AND account_id = ?", rot.ID, f.accountID).First(&member).Error)
		assert.Contains(t, []string{model.CredentialMemberRetryWait, model.CredentialMemberTerminalFailed}, member.State,
			"舊秘密撥號不符＝遠端確定未變更、乾淨失敗（退避等待或終局失敗）")
		assert.Equal(t, model.ChangeSecretReasonHostKeyMismatch, member.LastError)
		assert.Equal(t, before, f.server.passwordAuthCalls.Load())
		assert.EqualValues(t, 0, f.candidateCount(t))
		audits := f.mismatchAudits(t)
		require.Len(t, audits, 1)
		assert.Equal(t, "credential_rotation", audits[0]["path"])
		assert.Equal(t, "refused", audits[0]["outcome"])
		assert.EqualValues(t, 5, audits[0]["_user_id"])
		assert.Equal(t, "rotator", audits[0]["_username"])
		assert.Equal(t, fmt.Sprintf("credential_rotation_member:%d", member.ID), audits[0]["connection_ref"])
		require.Len(t, f.alerts.events, 1)
		assert.Equal(t, ssh.FingerprintSHA256(foreign), f.recordFingerprint(t))

		// 同一指紋再拒絕：審計累計、告警不增
		require.NoError(t, rotations.RunMember(ctx, rot.ID, member.ID))
		assert.Len(t, f.mismatchAudits(t), 2)
		assert.Len(t, f.alerts.events, 1)
	})

	t.Run("credential_rotation 新秘密驗證撥號不符", func(t *testing.T) {
		f := setupManagedPathsFixture(t)
		var acct model.AssetAccount
		require.NoError(t, f.db.First(&acct, f.accountID).Error)
		rotations := NewCredentialRotationService(f.db, f.assets, f.candidates, f.hostKeys,
			aesColumnCodec(t, make([]byte, 32)), audit.NewTxSink(), newAllowAllAuthorizer()).WithSystemAlertSink(newFakeAlertSink())
		ctx := contextWithInitiator(context.Background(), 5, "rotator")
		// 第一輪：改密下達成功、驗證登入被拒 → 已下達未驗證、候選保留（記錄已以靶機金鑰首次信任）
		f.server.rejectVerifyLogin = true
		rot, err := rotations.Start(ctx, acct.CredentialID, StartRotationRequest{})
		require.NoError(t, err)
		require.NoError(t, rotations.Run(ctx, rot.ID))
		var member model.CredentialRotationMember
		require.NoError(t, f.db.Where("rotation_id = ? AND account_id = ?", rot.ID, f.accountID).First(&member).Error)
		require.Equal(t, model.CredentialMemberChangedUnverified, member.State, member.LastError)
		require.EqualValues(t, 1, f.candidateCount(t))
		f.server.mu.Lock()
		f.server.rejectVerifyLogin = false
		f.server.mu.Unlock()
		// 補跑驗證撥號遇不符：仍為已下達未驗證、候選保留、原因碼主機金鑰不符
		// 遠端出示與記錄、與綁定快照都不符的另一把金鑰；記錄本身不動（記錄被換屬主機身分變更，另見 3.4 成員子案例）
		recorded := f.recordFingerprint(t)
		f.server.swapHostKey(t)
		before := f.server.passwordAuthCalls.Load()
		require.NoError(t, rotations.RunMember(ctx, rot.ID, member.ID))
		require.NoError(t, f.db.First(&member, member.ID).Error)
		assert.Equal(t, model.CredentialMemberChangedUnverified, member.State)
		assert.Equal(t, model.ChangeSecretReasonHostKeyMismatch, member.LastError)
		assert.EqualValues(t, 1, f.candidateCount(t), "候選保留待收斂")
		assert.Equal(t, before, f.server.passwordAuthCalls.Load())
		audits := f.mismatchAudits(t)
		require.Len(t, audits, 1)
		assert.Equal(t, "credential_rotation", audits[0]["path"])
		assert.Equal(t, recorded, f.recordFingerprint(t), "記錄不被改寫")
	})

	t.Run("查核失敗不歸主機金鑰不符", func(t *testing.T) {
		f := setupManagedPathsFixture(t)
		plan := f.plan(t, nil)
		require.NoError(t, f.db.Migrator().DropTable(&model.AssetHostKey{}))
		before := f.server.passwordAuthCalls.Load()
		records := f.runner.RunPlan(plan)
		require.Len(t, records, 1)
		assert.NotEqual(t, model.ChangeSecretReasonHostKeyMismatch, records[0].Error)
		assert.Equal(t, model.ChangeSecretReasonHostKeyCheckFailed, records[0].Error)
		assert.Equal(t, before, f.server.passwordAuthCalls.Load(), "查核失敗同樣在送出憑證前中止")
	})
}
