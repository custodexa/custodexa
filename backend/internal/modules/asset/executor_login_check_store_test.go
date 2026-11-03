package asset

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// TestExecutorLoginCheckStore 結果表的讀寫語義：過期判定、覆蓋、值域檢查。
func TestExecutorLoginCheckStore(t *testing.T) {
	db := openInventoryPG(t)
	require.NoError(t, db.AutoMigrate(&model.ExecutorLoginCheck{}))
	version := uint(11)
	mount := model.AssetAccount{AssetID: 5, Username: "cx-exec", CredentialID: 3, Purpose: model.AccountPurposeExecutor, EffectiveVersionID: &version}
	require.NoError(t, db.Create(&mount).Error)
	save := func(result, method, inv string) {
		t.Helper()
		require.NoError(t, upsertExecutorLoginCheck(db, &model.ExecutorLoginCheck{
			AssetAccountID: mount.ID, AssetID: 5, CredentialID: 3, CredentialVersionID: 11,
			Result: result, Method: method, InventoryRead: inv, CheckedBy: 1, CheckedByName: "alice", CheckedAt: time.Now(),
		}))
	}
	count := func() int64 {
		var n int64
		require.NoError(t, db.Model(&model.ExecutorLoginCheck{}).Count(&n).Error)
		return n
	}

	t.Run("沒有專用帳號回 nil 釘住值", func(t *testing.T) {
		st, pin, err := loadExecutorLoginCheck(db, 999)
		require.NoError(t, err)
		assert.Nil(t, st)
		assert.Nil(t, pin)
	})
	t.Run("無列 tested=false stale=false", func(t *testing.T) {
		st, _, err := loadExecutorLoginCheck(db, 5)
		require.NoError(t, err)
		assert.False(t, st.Tested)
		assert.False(t, st.Stale)
	})
	t.Run("成功後讀 tested=true", func(t *testing.T) {
		save("", model.ExecutorCheckMethodSudoNopasswd, model.ExecutorCheckInventoryOK)
		st, _, err := loadExecutorLoginCheck(db, 5)
		require.NoError(t, err)
		assert.True(t, st.Tested)
		assert.True(t, st.Success)
		assert.False(t, st.Stale)
		assert.Equal(t, model.ExecutorCheckMethodSudoNopasswd, st.Method)
		assert.Equal(t, "cx-exec", st.AccountUsername)
		require.NotNil(t, st.CheckedAt)
	})
	t.Run("同掛載第二次測試覆蓋第一次", func(t *testing.T) {
		save(model.ExecCheckLoginFailed, "", "")
		assert.EqualValues(t, 1, count())
		st, _, err := loadExecutorLoginCheck(db, 5)
		require.NoError(t, err)
		assert.True(t, st.Tested)
		assert.False(t, st.Success)
		assert.Equal(t, model.ExecCheckLoginFailed, st.Code)
	})
	t.Run("輪替推進就位版本 stale=true", func(t *testing.T) {
		next := uint(12)
		require.NoError(t, db.Model(&model.AssetAccount{}).Where("id = ?", mount.ID).Update("effective_version_id", next).Error)
		st, _, err := loadExecutorLoginCheck(db, 5)
		require.NoError(t, err)
		assert.False(t, st.Tested)
		assert.True(t, st.Stale)
		assert.Empty(t, st.Code)
		require.NoError(t, db.Model(&model.AssetAccount{}).Where("id = ?", mount.ID).Update("effective_version_id", version).Error)
		st, _, err = loadExecutorLoginCheck(db, 5)
		require.NoError(t, err)
		assert.True(t, st.Tested, "版本回到測試當時的值就不再過期")
	})
	t.Run("更換專用帳號 stale=true", func(t *testing.T) {
		require.NoError(t, db.Delete(&model.AssetAccount{}, mount.ID).Error)
		other := model.AssetAccount{AssetID: 5, Username: "cx-exec2", CredentialID: 4, Purpose: model.AccountPurposeExecutor, EffectiveVersionID: &version}
		require.NoError(t, db.Create(&other).Error)
		st, _, err := loadExecutorLoginCheck(db, 5)
		require.NoError(t, err)
		assert.False(t, st.Tested)
		assert.True(t, st.Stale, "掛載被更換：舊列識別與當下不同")
		// 新掛載測過一次後不再過期
		require.NoError(t, upsertExecutorLoginCheck(db, &model.ExecutorLoginCheck{
			AssetAccountID: other.ID, AssetID: 5, CredentialID: 4, CredentialVersionID: 11, CheckedAt: time.Now().Add(time.Second)}))
		st, _, err = loadExecutorLoginCheck(db, 5)
		require.NoError(t, err)
		assert.True(t, st.Tested)
		// 同掛載識別但憑證被改綁
		require.NoError(t, upsertExecutorLoginCheck(db, &model.ExecutorLoginCheck{
			AssetAccountID: other.ID, AssetID: 5, CredentialID: 99, CredentialVersionID: 11, CheckedAt: time.Now().Add(2 * time.Second)}))
		st, _, err = loadExecutorLoginCheck(db, 5)
		require.NoError(t, err)
		assert.True(t, st.Stale)
		assert.False(t, st.Tested)
	})
	t.Run("值域外的結果被拒絕", func(t *testing.T) {
		before := count()
		for _, bad := range []model.ExecutorLoginCheck{
			{AssetAccountID: 77, Result: "SOMETHING_ELSE", CheckedAt: time.Now()},
			{AssetAccountID: 77, Method: "bogus", CheckedAt: time.Now()},
			{AssetAccountID: 77, InventoryRead: "bogus", CheckedAt: time.Now()},
		} {
			assert.ErrorIs(t, upsertExecutorLoginCheck(db, &bad), ErrExecutorCheckResultInvalid)
		}
		assert.Equal(t, before, count())
	})
}
