package asset

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// 人工承接的子案例（root：TestCredentialRecoveryHostIdentityTakeover，前綴 4.1/）。
// 夾具的綁定與主機金鑰記錄一律經正式回呼建立（RunPlan／輪替下達的首次派送）；
// 身分異動走採用、重置與刪列的正式資料面結果，沒有直接寫 bound。

// 對外唯讀檢視的欄位白名單：多一個、少一個都算違反（秘密、公鑰本體與來源資產不得夾帶）。
var (
	hostIdentityViewKeys     = []string{"candidate_applied", "confirmable", "current", "deadline", "detail", "expired", "original", "phase", "status", "verification_sent"}
	hostIdentityOriginalKeys = []string{"algorithm", "binding", "bound_at", "fingerprint", "generation", "record_id", "transport"}
	hostIdentityCurrentKeys  = []string{"algorithm", "fingerprint", "generation", "record_id", "recorded_at", "reset_pending", "transport"}
)

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// requireViewWhitelist 以欄位白名單比對序列化後的檢視，並確認字串中不含任何禁出內容。
func requireViewWhitelist(t *testing.T, v *HostIdentityView, forbidden ...string) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	var top map[string]any
	require.NoError(t, json.Unmarshal(raw, &top))
	assert.Equal(t, hostIdentityViewKeys, sortedKeys(top), "頂層欄位白名單")
	if o, ok := top["original"].(map[string]any); ok {
		assert.Equal(t, hostIdentityOriginalKeys, sortedKeys(o), "original 欄位白名單")
	}
	if c, ok := top["current"].(map[string]any); ok {
		assert.Equal(t, hostIdentityCurrentKeys, sortedKeys(c), "current 欄位白名單")
	}
	for _, f := range forbidden {
		require.NotEmpty(t, f, "禁出內容不得為空字串（否則斷言恆真）")
		assert.NotContains(t, string(raw), f)
	}
	return top
}

// ownKeyRow 資產當下的自身金鑰記錄。
func ownKeyRow(t *testing.T, f *csFixture) model.AssetHostKey {
	t.Helper()
	var own model.AssetHostKey
	require.NoError(t, f.db.Where("asset_id = ?", f.assetID).First(&own).Error)
	return own
}

// requireChangedView 候選或成員被擋下時的檢視：原快照、當下記錄、階段與送出狀態。
func requireChangedView(t *testing.T, v *HostIdentityView, orig model.AssetHostKey, now model.AssetHostKey,
	applied bool, deadline time.Time) {
	t.Helper()
	require.NotNil(t, v, "被擋下必須帶 host_identity")
	assert.Equal(t, "changed", v.Status)
	assert.Equal(t, hostIdentityGenerationChanged, v.Detail)
	assert.Equal(t, hostIdentityPhasePrecheck, v.Phase)
	assert.Equal(t, verificationSentFalse, v.VerificationSent, "撥號前停止：新秘密沒有送出過認證")
	require.NotNil(t, v.Original)
	assert.Equal(t, model.HostKeyTransportSSH, v.Original.Transport)
	assert.Equal(t, orig.ID, v.Original.RecordID)
	assert.Equal(t, orig.Algorithm, v.Original.Algorithm)
	assert.Equal(t, orig.Fingerprint, v.Original.Fingerprint)
	assert.Equal(t, orig.TrustGeneration, v.Original.Generation)
	assert.Equal(t, model.HostKeyBindingBound, v.Original.Binding)
	assert.NotNil(t, v.Original.BoundAt, "綁定時刻來自首次派送的正式綁定")
	require.NotNil(t, v.Current)
	assert.Equal(t, model.HostKeyTransportSSH, v.Current.Transport)
	assert.Equal(t, now.ID, v.Current.RecordID)
	assert.Equal(t, now.Algorithm, v.Current.Algorithm)
	assert.Equal(t, now.Fingerprint, v.Current.Fingerprint)
	assert.Equal(t, now.TrustGeneration, v.Current.Generation)
	assert.NotEqual(t, orig.Fingerprint, v.Current.Fingerprint, "當下出示的是另一把")
	assert.False(t, v.Current.ResetPending)
	assert.False(t, v.Current.RecordedAt.IsZero(), "recorded_at 取自身列更新時刻")
	assert.Equal(t, applied, v.CandidateApplied)
	require.NotNil(t, v.Deadline)
	assert.WithinDuration(t, deadline, *v.Deadline, time.Second)
	assert.False(t, v.Expired)
	assert.True(t, v.Confirmable)
}

func TestCredentialRecoveryHostIdentityTakeover(t *testing.T) {
	t.Run("4.1/不帶確認/候選重試帶出host_identity", func(t *testing.T) {
		s := newRetryScenario(t)
		orig := ownKeyRow(t, s.f)
		cand := candidateOfAccount(t, s.f)
		secret, err := s.f.candidates.Secret(context.Background(), &cand)
		require.NoError(t, err)
		var candSecret string
		require.NoError(t, withProtocolSecret(secret.Password, func(b []byte) error { candSecret = string(b); return nil }))
		secret.Destroy()
		require.NotEmpty(t, candSecret)

		adoptRemoteKey(t, s.f.server, s.f.db, s.f.assetID, true)
		now := ownKeyRow(t, s.f)
		require.NotEqual(t, orig.Fingerprint, now.Fingerprint)
		var asset model.Asset
		require.NoError(t, s.f.db.First(&asset, s.f.assetID).Error)

		res := s.f.retry.RetryOneAsResult(adminCtx(), &cand)
		assert.False(t, res.Promoted)
		assert.EqualValues(t, s.baseAuth, s.f.server.authAttempts.Load(), "不帶確認：authAttempts 0（候選密碼不得送出）")
		requireChangedView(t, res.HostIdentity, orig, now, true, cand.CreatedAt.Add(candidateRetryDeadline))
		requireViewWhitelist(t, res.HostIdentity, candSecret, orig.PublicKey, now.PublicKey, asset.Host, asset.Name)
		assert.EqualValues(t, 1, s.f.candidateCount(t), "候選保留")

		// 同一身分狀態再重試一次：審計已去重，檢視仍要帶出
		cand = candidateOfAccount(t, s.f)
		again := s.f.retry.RetryOneAsResult(adminCtx(), &cand)
		require.NotNil(t, again.HostIdentity, "去重後不再寫審計，但檢視仍要帶出")
		assert.Equal(t, res.HostIdentity.Current.Fingerprint, again.HostIdentity.Current.Fingerprint)
		assert.EqualValues(t, s.baseAuth, s.f.server.authAttempts.Load())
	})

	t.Run("4.1/不帶確認/候選不可確認的兩種狀態", func(t *testing.T) {
		cases := []struct {
			name        string
			apply       func(t *testing.T, s *retryScenario)
			status      string
			detail      string
			wantCurrent bool
			resetFlag   bool
		}{
			{"記錄被刪", func(t *testing.T, s *retryScenario) {
				require.NoError(t, s.f.db.Where("asset_id = ?", s.f.assetID).Delete(&model.AssetHostKey{}).Error)
			}, hostIdentityRecordMissing, hostIdentityRecordMissing, false, false},
			{"記錄待重置", func(t *testing.T, s *retryScenario) {
				existed, err := s.f.hostKeys.Reset(s.f.assetID, HostKeyActor{UserID: 1, Username: "super"})
				require.NoError(t, err)
				require.True(t, existed)
			}, hostIdentityResetPending, hostIdentityResetPending, true, true},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				s := newRetryScenario(t)
				cand := candidateOfAccount(t, s.f)
				tc.apply(t, s)
				res := s.f.retry.RetryOneAsResult(adminCtx(), &cand)
				assert.False(t, res.Promoted)
				assert.EqualValues(t, s.baseAuth, s.f.server.authAttempts.Load())
				v := res.HostIdentity
				require.NotNil(t, v)
				assert.Equal(t, tc.status, v.Status)
				assert.Equal(t, tc.detail, v.Detail)
				assert.False(t, v.Confirmable, "沒有可核對的記錄：不可在此確認")
				require.NotNil(t, v.Original)
				assert.Equal(t, tc.wantCurrent, v.Current != nil)
				if v.Current != nil {
					assert.Equal(t, tc.resetFlag, v.Current.ResetPending)
				}
				requireViewWhitelist(t, v)
			})
		}
	})

	t.Run("4.1/不帶確認/成員補跑帶出host_identity", func(t *testing.T) {
		f, rot, m := sentUnverified(t, false)
		orig := ownKeyRow(t, &csFixture{db: f.db, assetID: f.assetID})
		var asset model.Asset
		require.NoError(t, f.db.First(&asset, f.assetID).Error)
		base := f.server.authAttempts.Load()

		// 對照：身分未變、可驗證的成員不帶檢視
		okF, okRot, okM := sentUnverified(t, false)
		okRes, err := okF.rotations.RunMemberResult(adminCtx(), okRot.ID, okM.ID, RotationRecordOrigin{})
		require.NoError(t, err)
		assert.Nil(t, okRes.HostIdentity, "沒有被擋下就不帶 host_identity")
		assert.Equal(t, model.CredentialMemberApplied, okF.member(t, okRot.ID).State)

		adoptRemoteKey(t, f.server, f.db, f.assetID, true)
		now := ownKeyRow(t, &csFixture{db: f.db, assetID: f.assetID})
		res, err := f.rotations.RunMemberResult(adminCtx(), rot.ID, m.ID, RotationRecordOrigin{})
		require.NoError(t, err)
		assert.EqualValues(t, base, f.server.authAttempts.Load(), "不帶確認：authAttempts 0")
		held := f.member(t, rot.ID)
		assert.Equal(t, model.CredentialMemberChangedUnverified, held.State, "成員保留在已下達未驗證")
		requireChangedView(t, res.HostIdentity, orig, now, true, rot.StartedAt.Add(candidateRetryDeadline))
		requireViewWhitelist(t, res.HostIdentity, asset.Host, asset.Name, orig.PublicKey, now.PublicKey)
		_, stillCollecting := f.rotations.stopCollectors.Load(m.ID)
		assert.False(t, stillCollecting, "補跑結束後收集器必須移除")
	})

	t.Run("4.1/pending照常重試", func(t *testing.T) {
		f := newPendingRetryScenario(t)
		cand := candidateOfAccount(t, f)
		// 第一次：靶機密碼未變，驗證失敗，但這是首次派送：照常撥號、不給 host_identity
		res := f.retry.RetryOneAsResult(adminCtx(), &cand)
		assert.False(t, res.Promoted)
		assert.Nil(t, res.HostIdentity, "pending 從未送出過秘密：沒有可承接的身分")
		assert.EqualValues(t, 1, f.server.authAttempts.Load(), "照常重試：確實撥號驗證一次")
		assert.Equal(t, model.HostKeyBindingBound, candidateOfAccount(t, f).HostKeyBinding, "首次派送經正式回呼綁定")

		// 規則本體：pending 的停止事實不產生檢視（以純函式輸入驗證，不構造產品不可達的資料列）
		in := hostIdentityStopInput{
			Job:    hostIdentityJob{Binding: model.HostKeyBindingPending},
			Detail: hostIdentityGenerationChanged, Phase: hostIdentityPhasePrecheck, VerificationSent: verificationSentFalse,
		}
		assert.Nil(t, newHostIdentityView(in, time.Now()))
		in.Job.Binding = model.HostKeyBindingBound
		assert.NotNil(t, newHostIdentityView(in, time.Now()), "對照：同樣輸入改為 bound 就有檢視")
	})

	t.Run("4.1/pending候選密碼可登入則照常轉正", func(t *testing.T) {
		f := newPendingRetryScenario(t)
		cand := candidateOfAccount(t, f)
		secret, err := f.candidates.Secret(context.Background(), &cand)
		require.NoError(t, err)
		require.NoError(t, withProtocolSecret(secret.Password, func(b []byte) error {
			f.server.setPassword(string(b))
			return nil
		}))
		secret.Destroy()
		res := f.retry.RetryOneAsResult(adminCtx(), &cand)
		assert.True(t, res.Promoted)
		assert.Nil(t, res.HostIdentity)
		assert.EqualValues(t, 0, f.candidateCount(t))
		assert.False(t, strings.Contains(f.storedPassword(t), "oldpass123"), "轉正後本地憑證換成候選")
	})

	runTakeoverGate(t)
	runTakeoverCreate(t)
	runTakeoverVerify(t)
	runTakeoverVariants(t)
	runTakeoverMember(t)
	runTakeoverMemberPin(t)
	runTakeoverCandidateUpgradeFlow(t)
	runTakeoverExpired(t)
	runTakeoverSites(t)
	runTakeoverGaps(t)
	runTakeoverAuthz(t)
	runTakeoverTransport(t)
	runTakeoverCrash(t)
	runTakeoverExternalReview(t)
	runTakeoverTargetReview(t)
	runTakeoverRecheck(t)
}
