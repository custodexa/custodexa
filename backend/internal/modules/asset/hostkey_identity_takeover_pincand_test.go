package asset

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 升級前候選的實際操作順序（前端「立即重試」→ 開確認框 → 確認）：
// 升級形狀＝目標指紋為空、主機身分綁定為 legacy、授權引用為空、已送出。

// upgradeShapeCandidate 把候選改成升級後的形狀。
func upgradeShapeCandidate(t *testing.T, f *csFixture, id uint) {
	t.Helper()
	require.NoError(t, f.db.Model(&model.ChangeSecretCandidate{}).Where("id = ?", id).Updates(map[string]any{
		"target_fingerprint": "", "authorization_id": nil,
		"host_key_binding": model.HostKeyBindingLegacy, "host_key_transport": "", "host_key_record_id": 0,
		"host_key_algorithm": "", "host_key_fingerprint": "", "host_key_generation": 0}).Error)
	c := candRowOf(t, f, id)
	require.Equal(t, model.HostKeyBindingLegacy, c.Binding)
	var row model.ChangeSecretCandidate
	require.NoError(t, f.db.First(&row, id).Error)
	require.Empty(t, row.TargetFingerprint)
	require.Nil(t, row.AuthorizationID)
	require.True(t, row.Applied, "前置：已送出")
}

func runTakeoverCandidateUpgradeFlow(t *testing.T) {
	const p = "4.4/升級前候選/"

	t.Run(p+"一般重試開框後帶確認重試_補記後成功轉正", func(t *testing.T) {
		s := newRetryScenario(t)
		cand := candidateOfAccount(t, s.f)
		upgradeShapeCandidate(t, s.f, cand.ID)
		svc := NewHostIdentityTakeoverService(s.f.db, s.authz).WithCandidateRunner(s.f.retry)
		svc.SetAuditTxSink(audit.NewTxSink())
		require.NoError(t, s.f.db.AutoMigrate(&model.CredentialHostIdentityConfirmation{}))
		want, err := loadTargetFingerprint(s.f.db, s.f.accountID)
		require.NoError(t, err)
		chBase := s.f.server.chpasswdCalls.Load()

		// 第一步：不帶 body 的一般重試（前端「立即重試」）
		cand = candidateOfAccount(t, s.f)
		res := s.f.retry.RetryOneAsResult(adminCtx(), &cand)
		assert.False(t, res.Promoted)
		require.NotNil(t, res.HostIdentity, "回應帶 host_identity：前端開確認框")
		assert.Equal(t, hostIdentityUnboundLegacy, res.HostIdentity.Status)
		assert.True(t, res.HostIdentity.Confirmable)
		assert.Equal(t, want, candidateOfAccount(t, s.f).TargetFingerprint, "一般重試的重驗階段已補記指紋")

		// 第二步：帶確認 body 的重試
		req := validConfirmRequest(t, s.f.db, s.f.assetID)
		err = svc.ConfirmHostIdentityAndVerify(adminCtx(), takeoverKindCandidate, cand.ID, req)
		require.NoError(t, err, "確認應成功承接")
		assert.EqualValues(t, 0, s.f.candidateCount(t), "候選轉正後刪除")
		assert.Equal(t, chBase, s.f.server.chpasswdCalls.Load(), "改密指令 0：只 Verify 不 Rotate")
	})

	t.Run(p+"無來源/一般重試補記_再確認成功_Verify1次_轉正", func(t *testing.T) {
		s := newRetryScenario(t)
		cand := candidateOfAccount(t, s.f)
		upgradeShapeCandidate(t, s.f, cand.ID)
		require.NoError(t, s.f.db.Model(&model.ChangeSecretCandidate{}).Where("id = ?", cand.ID).
			Updates(map[string]any{"plan_id": 0, "batch_id": 0}).Error)
		cand = candidateOfAccount(t, s.f)
		require.Zero(t, cand.PlanID)
		require.Zero(t, cand.BatchID)
		svc := NewHostIdentityTakeoverService(s.f.db, s.authz).WithCandidateRunner(s.f.retry)
		svc.SetAuditTxSink(audit.NewTxSink())
		require.NoError(t, s.f.db.AutoMigrate(&model.CredentialHostIdentityConfirmation{}))
		want, err := loadTargetFingerprint(s.f.db, s.f.accountID)
		require.NoError(t, err)
		var authBase int64
		require.NoError(t, s.f.db.Model(&model.CredentialJobAuthorization{}).Count(&authBase).Error)
		chBase := s.f.server.chpasswdCalls.Load()

		res := s.f.retry.RetryOneAsResult(adminCtx(), &cand)
		assert.False(t, res.Promoted)
		require.NotNil(t, res.HostIdentity, "回應帶 host_identity：前端開確認框")
		assert.Equal(t, want, candidateOfAccount(t, s.f).TargetFingerprint, "無來源的一般重試也補記指紋")
		var authNow int64
		require.NoError(t, s.f.db.Model(&model.CredentialJobAuthorization{}).Count(&authNow).Error)
		assert.Equal(t, authBase, authNow, "無來源不留持久授權列")

		req := validConfirmRequest(t, s.f.db, s.f.assetID)
		require.NoError(t, svc.ConfirmHostIdentityAndVerify(adminCtx(), takeoverKindCandidate, cand.ID, req))
		assert.EqualValues(t, 0, s.f.candidateCount(t), "候選轉正後刪除")
		assert.Equal(t, chBase, s.f.server.chpasswdCalls.Load(), "改密指令 0：只 Verify 不 Rotate")
	})

	t.Run(p+"跳過一般重試直接帶確認_回目標變更_指紋仍空", func(t *testing.T) {
		s := newRetryScenario(t)
		cand := candidateOfAccount(t, s.f)
		upgradeShapeCandidate(t, s.f, cand.ID)
		svc := NewHostIdentityTakeoverService(s.f.db, s.authz).WithCandidateRunner(s.f.retry)
		svc.SetAuditTxSink(audit.NewTxSink())
		require.NoError(t, s.f.db.AutoMigrate(&model.CredentialHostIdentityConfirmation{}))

		err := svc.ConfirmHostIdentityAndVerify(adminCtx(), takeoverKindCandidate, cand.ID,
			validConfirmRequest(t, s.f.db, s.f.assetID))
		require.ErrorIs(t, err, ErrHostIdentityConfirmTargetChanged, "確認框只會在一般重試的回應之後出現")
		assert.Empty(t, candidateOfAccount(t, s.f).TargetFingerprint)
		assert.EqualValues(t, 1, s.f.candidateCount(t), "候選保留")
	})
}
