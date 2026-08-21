package session

import (
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
)

// IsTerminated 是兌換點啟動 proxy 前的最後複查（design 行 268），fail-close 語義
// 使它的「誤報 true」不會被任何單測的錯誤路徑抓到——歷史缺陷：Pluck 用純量 dest
// 必然報 Scan 錯誤，令所有協議連線建立即被砍，單測全綠、e2e 場景 12 才抓到。
// 本測試走真 GORM 路徑鎖定三種判定，杜絕同型回歸。

func setupTerminationDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	// sqlite :memory: 連線池陷阱（ff51836）：單連線
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&model.Session{}))
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })
	return db
}

func TestIsTerminated(t *testing.T) {
	db := setupTerminationDB(t)
	svc := &SessionService{}

	active := model.Session{SessionID: "sess-active", UserID: 1,
		Status: model.SessionStatusActive}
	require.NoError(t, db.Create(&active).Error)
	closed := model.Session{SessionID: "sess-closed", UserID: 1,
		Status: model.SessionStatusDisconnected}
	require.NoError(t, db.Create(&closed).Error)

	// active 會話必須放行——恆 true 的回歸（如 Pluck 純量 dest）在此變紅
	assert.False(t, svc.IsTerminated(active.ID), "active 會話不得被判為已終止")
	// 已標記終止的會話必須擋下
	assert.True(t, svc.IsTerminated(closed.ID), "disconnected 會話必須判為已終止")
	// 查無此列 fail-close
	assert.True(t, svc.IsTerminated(999999), "不存在的會話必須 fail-close")
}
