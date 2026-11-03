package asset

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 共用憑證作為多台執行身分時，整組輪替沿用既有引擎：成員＝當下全部掛載、範圍化主體遇範圍外掛載須影響確認、
// 以憑證為目標的計劃經同一起始路徑、脫離後新專用憑證的掛載仍是執行身分。

// outOfScopeImpactSource 範圍化主體的替身：out 內的資產不在操作能力範圍內，其餘在範圍內且可檢視。
type outOfScopeImpactSource struct{ out map[uint]bool }

func (s outOfScopeImpactSource) CredentialScopeView(context.Context) (CredentialScopeView, error) {
	return nil, nil
}

func (s outOfScopeImpactSource) CredentialImpactScopeIn(_ context.Context, _ *gorm.DB, _ string,
	ids []uint) (map[uint]bool, map[uint]bool, bool, error) {
	inCap, inView := map[uint]bool{}, map[uint]bool{}
	for _, id := range ids {
		if !s.out[id] {
			inCap[id], inView[id] = true, true
		}
	}
	return inCap, inView, true, nil
}

func TestSharedExecutorGroupRotation(t *testing.T) {
	f := setupBatchFixture(t)
	hosts := []string{"10.9.7.1", "10.9.7.2", "10.9.7.3"}
	credID, mounts := f.sharedOn(t, "共用執行身分輪替", "cx-exec", "exec-old", hosts...)
	require.Len(t, mounts, 3)
	markExecutor(t, mounts...)
	rec := newSecretRecorder()
	f.useExecutor(rec)
	f.rotations.executors = func(string) rotationExecutor { return rec }
	outAsset := f.bindingOf(t, mounts[2]).AssetID

	t.Run("scoped principal without confirmation is rejected before any remote call", func(t *testing.T) {
		f.rotations.WithScopeSource(outOfScopeImpactSource{out: map[uint]bool{outAsset: true}})
		defer f.rotations.WithScopeSource(nil)
		_, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
		var required *CredentialImpactConfirmationRequiredError
		require.True(t, errors.As(err, &required), "err=%v", err)
		assert.Equal(t, 1, required.Count)
		var rotations int64
		require.NoError(t, f.db.Model(&model.CredentialRotation{}).Where("credential_id = ?", credID).
			Count(&rotations).Error)
		assert.Zero(t, rotations, "被拒時不建立輪替")
		_, rotateCalls, verifyCalls := rec.snapshotCalls()
		assert.Empty(t, rotateCalls, "遠端零操作")
		assert.Empty(t, verifyCalls, "遠端零操作")
	})

	t.Run("global principal rotates all three executor mounts", func(t *testing.T) {
		rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
		require.NoError(t, err)
		members, err := rotationMembers(f.db, rot.ID)
		require.NoError(t, err)
		require.Len(t, members, 3, "成員恰為三台執行身分掛載")
		require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
		cred := f.credentialOf(t, credID)
		require.NotNil(t, cred.CurrentVersionID)
		assert.Equal(t, *rot.TargetVersionID, *cred.CurrentVersionID, "全部就位後提升新版")
		for _, id := range mounts {
			b := f.bindingOf(t, id)
			require.NotNil(t, b.EffectiveVersionID)
			assert.Equal(t, *rot.TargetVersionID, *b.EffectiveVersionID, "三台就位新版")
			assert.Equal(t, model.AccountPurposeExecutor, b.Purpose)
		}
	})

	t.Run("credential target plan rotates the same three mounts", func(t *testing.T) {
		req := planRequest("共用執行身分定期輪替", []uint{f.bindingOf(t, mounts[0]).AssetID})
		req.TargetKind = model.PlanTargetCredential
		req.TargetCredentialID = credID
		plan, err := f.plans.Create(adminCtx(), req)
		require.NoError(t, err, "以執行身分憑證為目標的計劃可存檔")
		records := f.runner.RunPlan(plan)
		require.Len(t, records, 3, "計劃產生的輪替成員恰為三台")
		seen := map[uint]bool{}
		for _, r := range records {
			assert.Equal(t, model.ChangeSecretSuccess, r.Status, "錯誤: %s", r.Error)
			assert.Equal(t, credID, r.CredentialID)
			seen[r.AccountID] = true
		}
		for _, id := range mounts {
			assert.True(t, seen[id], "掛載 %d 應在成員中", id)
		}
		var planRotations int64
		require.NoError(t, f.db.Model(&model.CredentialRotation{}).Where("credential_id = ?", credID).
			Count(&planRotations).Error)
		assert.EqualValues(t, 2, planRotations, "計劃觸發一次整組輪替")
	})

	t.Run("detach keeps the new dedicated mount as executor", func(t *testing.T) {
		_, err := f.rotations.Detach(adminCtx(), credID, mounts[0], DetachCredentialRequest{Source: DetachSourceRandom})
		require.NoError(t, err)
		detached := f.bindingOf(t, mounts[0])
		assert.NotEqual(t, credID, detached.CredentialID, "脫離後改引用新專用憑證")
		assert.Equal(t, model.AccountPurposeExecutor, detached.Purpose)
		assert.False(t, detached.IsDefault)
		for _, id := range mounts[1:] {
			b := f.bindingOf(t, id)
			assert.Equal(t, credID, b.CredentialID, "其餘兩台仍引用原憑證")
			assert.Equal(t, model.AccountPurposeExecutor, b.Purpose)
		}
	})
}
