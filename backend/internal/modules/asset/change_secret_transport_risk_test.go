package asset

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// 改密紀錄的傳輸風險欄：以秘密連過目標的處理才依資產快照填值；
// 跳過與本地前置失敗沒有連過目標，一律為空。

// addDBNativeAsset 在 fixture 內另建一台設為 db_native 的 mysql 資產。
func addDBNativeAsset(t *testing.T, f *csFixture, host, tlsMode string) uint {
	t.Helper()
	id := f.addRotationAsset(t, &CreateAssetRequest{
		Name: host, Protocol: model.ProtocolMySQL, Host: host, Port: 3306,
		Username: "dbuser", Password: "oldpass123",
		RotationChannel: model.RotationChannelDBNative,
	})
	// TLS 檔位直接寫列：驗的是紀錄寫入端，不是資產表單對 TLS 檔位的驗證
	require.NoError(t, f.db.Model(&model.Asset{}).Where("id = ?", id).Update("db_tls_mode", tlsMode).Error)
	return id
}

func runDBNativePlan(t *testing.T, f *csFixture, rec *rotationRecorder, assetID uint) model.ChangeSecretRecord {
	t.Helper()
	f.runner.executors = func(string) rotationExecutor { return rec }
	f.retry.executors = func(string) rotationExecutor { return rec }
	records := f.runner.RunPlan(f.planForAssets(t, []uint{assetID}, nil))
	got := recordByAsset(records, assetID)
	require.NotNil(t, got)
	return *got
}

func TestChangeSecretRecordTransportRisk(t *testing.T) {
	const risk = model.RiskDBRotationUnencrypted

	t.Run("成功", func(t *testing.T) {
		f := setupChangeSecretFixture(t, "root", "oldpass123")
		id := addDBNativeAsset(t, f, "10.31.0.1", "")
		got := runDBNativePlan(t, f, newRotationRecorder(), id)
		assert.Equal(t, model.ChangeSecretSuccess, got.Status)
		assert.Equal(t, risk, got.TransportRisk)
	})

	t.Run("舊密碼登入失敗", func(t *testing.T) {
		f := setupChangeSecretFixture(t, "root", "oldpass123")
		id := addDBNativeAsset(t, f, "10.31.0.2", "disable")
		rec := newRotationRecorder()
		rec.setRotateErr("10.31.0.2", &remoteRejectedError{reason: model.ChangeSecretReasonOldCredentialLoginFailed})
		got := runDBNativePlan(t, f, rec, id)
		assert.Equal(t, model.ChangeSecretFailed, got.Status)
		assert.Equal(t, model.ChangeSecretReasonOldCredentialLoginFailed, got.Error)
		assert.Equal(t, risk, got.TransportRisk)
	})

	t.Run("遠端拒絕", func(t *testing.T) {
		f := setupChangeSecretFixture(t, "root", "oldpass123")
		id := addDBNativeAsset(t, f, "10.31.0.3", "")
		rec := newRotationRecorder()
		rec.setRotateErr("10.31.0.3", &remoteRejectedError{reason: model.ChangeSecretReasonRemoteRejected})
		got := runDBNativePlan(t, f, rec, id)
		assert.Equal(t, model.ChangeSecretFailed, got.Status)
		assert.Equal(t, model.ChangeSecretReasonRemoteRejected, got.Error)
		assert.Equal(t, risk, got.TransportRisk)
	})

	t.Run("只做驗證的重試成功", func(t *testing.T) {
		f := setupChangeSecretFixture(t, "root", "oldpass123")
		id := addDBNativeAsset(t, f, "10.31.0.4", "")
		rec := newRotationRecorder()
		rec.setVerifyErr("10.31.0.4", errors.New("verify timeout"))
		first := runDBNativePlan(t, f, rec, id)
		require.Equal(t, model.ChangeSecretUnverified, first.Status)
		var cand model.ChangeSecretCandidate
		require.NoError(t, f.db.Where("asset_id = ?", id).First(&cand).Error)
		rec.setVerifyErr("10.31.0.4", nil)
		_, rotateBefore, _ := rec.snapshot()
		require.True(t, f.retry.RetryOne(&cand))
		_, rotateAfter, _ := rec.snapshot()
		assert.Equal(t, rotateBefore["10.31.0.4"], rotateAfter["10.31.0.4"], "重試只驗證、不再改密")
		var promoted model.ChangeSecretRecord
		require.NoError(t, f.db.Where("asset_id = ? AND error = ?", id, model.ChangeSecretReasonRetryPromoted).
			First(&promoted).Error)
		assert.Equal(t, model.ChangeSecretSuccess, promoted.Status)
		assert.Equal(t, risk, promoted.TransportRisk)
	})

	t.Run("共用憑證成員成功", func(t *testing.T) {
		f := setupBatchFixture(t)
		cred, err := f.creds.Create(adminCtx(), &CreateCredentialRequest{
			Name: "db-shared", Username: "dbuser", ProtocolFamily: model.ProtocolFamilyDatabase, Password: "old-shared",
		})
		require.NoError(t, err)
		accountIDs := make([]uint, 0, 2)
		for _, host := range []string{"10.31.1.1", "10.31.1.2"} {
			a, aerr := f.assets.Create(WithSystemCaller(adminCtx()), &CreateAssetRequest{
				Name: host, Protocol: model.ProtocolMySQL, Host: host, Port: 3306, CreatedBy: 1,
				RotationChannel: model.RotationChannelDBNative,
			})
			require.NoError(t, aerr)
			binding, berr := f.creds.Bind(adminCtx(), cred.ID, &BindCredentialRequest{AssetID: a.ID})
			require.NoError(t, berr)
			accountIDs = append(accountIDs, binding.ID)
		}
		rec := newSecretRecorder()
		f.useRotationExecutor(rec)
		rot, err := f.rotations.Start(adminCtx(), cred.ID, StartRotationRequest{})
		require.NoError(t, err)
		require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
		var rows []model.ChangeSecretRecord
		require.NoError(t, f.db.Where("account_id IN ?", accountIDs).Find(&rows).Error)
		require.Len(t, rows, 2)
		for _, r := range rows {
			assert.Equal(t, model.ChangeSecretSuccess, r.Status)
			assert.Equal(t, risk, r.TransportRisk)
		}
	})

	t.Run("本地前置失敗為空", func(t *testing.T) {
		f := setupChangeSecretFixture(t, "root", "oldpass123")
		id := addDBNativeAsset(t, f, "10.31.0.6", "")
		rec := newRotationRecorder()
		rec.setRotateErr("10.31.0.6", &localPreconditionError{reason: model.ChangeSecretReasonInvalidNewSecret})
		got := runDBNativePlan(t, f, rec, id)
		assert.Equal(t, model.ChangeSecretFailed, got.Status)
		assert.Equal(t, model.ChangeSecretReasonInvalidNewSecret, got.Error)
		assert.Empty(t, got.TransportRisk)
	})

	t.Run("跳過為空", func(t *testing.T) {
		f := setupChangeSecretFixture(t, "root", "oldpass123")
		id := addDBNativeAsset(t, f, "10.31.0.7", "")
		rec := newRotationRecorder()
		// 先留下一筆未驗證候選，第二次執行即因候選待處理而跳過
		rec.setVerifyErr("10.31.0.7", errors.New("verify timeout"))
		require.Equal(t, model.ChangeSecretUnverified, runDBNativePlan(t, f, rec, id).Status)
		got := runDBNativePlan(t, f, rec, id)
		assert.Equal(t, model.ChangeSecretSkipped, got.Status)
		assert.Equal(t, model.ChangeSecretReasonCandidatePending, got.Error)
		assert.Empty(t, got.TransportRisk)
	})

	t.Run("TLS為verify-full的成功為空", func(t *testing.T) {
		f := setupChangeSecretFixture(t, "root", "oldpass123")
		id := addDBNativeAsset(t, f, "10.31.0.8", "verify-full")
		got := runDBNativePlan(t, f, newRotationRecorder(), id)
		assert.Equal(t, model.ChangeSecretSuccess, got.Status)
		assert.Empty(t, got.TransportRisk)
	})
}
