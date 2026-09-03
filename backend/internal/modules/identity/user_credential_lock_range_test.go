package identity

import (
	"math"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 使用者級鎖以 int32 當 advisory lock 鍵：超出 32 位元值域的 userID 必須在入口被拒，
// 不得折疊後撞到別人的鍵（兩種 dialect 一致，這裡以 sqlite 打入口檢查）。
func TestUserCredentialLockRejectsUserIDBeyondUint32(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)

	called := false
	err = WithUserCredentialLock(db, uint(math.MaxUint32)+1, func(*gorm.DB) error {
		called = true
		return nil
	})
	require.Error(t, err, "超出值域的 userID 應在入口被拒")
	require.False(t, called, "被拒時不得執行受保護區段")

	err = WithUserCredentialLock(db, uint(math.MaxUint32), func(*gorm.DB) error {
		called = true
		return nil
	})
	require.NoError(t, err, "值域上限本身仍可取鎖")
	require.True(t, called)
}
