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
	"github.com/custodexa/backend/pkg/crypto"
)

// 訂閱建立的升級前預檢與鎖內重驗是兩道閘。處理端的整合測試只看得到
// 「連線沒有升級」，預檢單獨就能讓它們全綠，鎖內閘拿掉也不會有人發現。
// 本檔直接打 JoinWithGenerationGuard：預檢通過之後才發生撤權，鎖內閘必須
// 拒絕，且 join 回呼不得被呼叫。
//
// 突變自檢：把 JoinWithGenerationGuard 鎖內的 checkObserverState 呼叫拿掉，
// 三個撤權格皆應轉紅（對照格仍綠）。

func setupJoinGuardDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	// :memory: 每條連線各自獨立空庫，單連線
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.OIDCProvider{}))
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })
	return db
}

func TestJoinWithGenerationGuardRejectsRevocationAfterPrecheck(t *testing.T) {
	const providerID = uint(1)
	oidcCtx := func(provider uint) crypto.AuthContext {
		return crypto.AuthContext{
			AuthMethod: crypto.AuthMethodOIDC, ProviderID: provider,
		}
	}
	cases := []struct {
		name    string
		authCtx crypto.AuthContext
		revoke  func(t *testing.T, db *gorm.DB)
	}{
		{
			name: "provider 停用", authCtx: oidcCtx(providerID),
			revoke: func(t *testing.T, db *gorm.DB) {
				require.NoError(t, db.Model(&model.OIDCProvider{}).Where("id = ?", providerID).
					Updates(map[string]any{"enabled": false, "auth_epoch": gorm.Expr("auth_epoch + 1")}).Error)
			},
		},
		{
			name: "使用者停用", authCtx: crypto.AuthContext{},
			revoke: func(t *testing.T, db *gorm.DB) {
				require.NoError(t, db.Model(&model.User{}).Where("id = ?", 1).
					Update("active", false).Error)
			},
		},
		{
			name: "憑證世代推進", authCtx: crypto.AuthContext{},
			revoke: func(t *testing.T, db *gorm.DB) {
				require.NoError(t, db.Model(&model.User{}).Where("id = ?", 1).
					Update("credential_epoch", gorm.Expr("credential_epoch + 1")).Error)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := setupJoinGuardDB(t)
			require.NoError(t, db.Create(&model.OIDCProvider{Name: "p1", Enabled: true}).Error)
			require.NoError(t, db.Create(&model.User{Username: "obs", Password: "x", Active: true}).Error)

			// 預檢通過：此刻撤權尚未發生
			require.NoError(t, PrecheckObserverBeforeUpgrade(tc.authCtx, 1),
				"撤權前預檢必須通過，否則本格沒有走到鎖內閘")

			tc.revoke(t, db)

			called := false
			joined, err := JoinWithGenerationGuard(tc.authCtx, 1, func() bool {
				called = true
				return true
			})
			require.Error(t, err, "預檢後才撤權：鎖內閘必須拒絕")
			assert.False(t, called, "被拒時 join 回呼不得執行")
			assert.False(t, joined)
			// 預檢此刻同樣會拒，確認撤權確實生效（排除「閘拒絕」來自別的原因）
			assert.Error(t, PrecheckObserverBeforeUpgrade(tc.authCtx, 1))
		})
	}

	t.Run("對照：未撤權則放行並執行 join", func(t *testing.T) {
		db := setupJoinGuardDB(t)
		require.NoError(t, db.Create(&model.OIDCProvider{Name: "p1", Enabled: true}).Error)
		require.NoError(t, db.Create(&model.User{Username: "obs", Password: "x", Active: true}).Error)
		called := false
		joined, err := JoinWithGenerationGuard(oidcCtx(providerID), 1, func() bool {
			called = true
			return true
		})
		require.NoError(t, err)
		assert.True(t, called)
		assert.True(t, joined)
	})
}
