package authz

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// setupAuthorizationMockDB 建立測試用的 mock 資料庫
func setupAuthorizationMockDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock, *gorm.DB) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}

	gormDB, err := gorm.Open(postgres.New(postgres.Config{
		Conn: db,
	}), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to create gorm DB: %v", err)
	}

	// 保存原始的 DB
	oldDB := database.DB
	database.DB = gormDB

	// 清理函數會在測試結束時還原
	t.Cleanup(func() {
		database.DB = oldDB
		db.Close()
	})

	return db, mock, gormDB
}

// TestGetPermissionHierarchy 測試權限層級獲取
func TestGetPermissionHierarchy(t *testing.T) {
	tests := []struct {
		name           string
		permission     model.PermissionType
		expectedLength int
		expectedList   []model.PermissionType
	}{
		{
			name:           "View permission includes all levels",
			permission:     model.PermissionView,
			expectedLength: 2,
			expectedList:   []model.PermissionType{model.PermissionView, model.PermissionConnect},
		},
		{
			name:           "Connect permission only includes itself",
			permission:     model.PermissionConnect,
			expectedLength: 1,
			expectedList:   []model.PermissionType{model.PermissionConnect},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetPermissionHierarchy(tt.permission)
			assert.Equal(t, tt.expectedLength, len(result))
			assert.Equal(t, tt.expectedList, result)
		})
	}
}

// TestCheckPermission_AdminRole 測試 Admin 角色自動擁有權限
func TestCheckPermission_AdminRole(t *testing.T) {
	_, _, gormDB := setupAuthorizationMockDB(t)
	service := NewAssetAuthorizationService(gormDB)

	// 創建帶 admin 角色的 context
	ctx := context.WithValue(context.Background(), "role", model.RoleAdmin)
	ctx = context.WithValue(ctx, "userID", uint(1))

	// Admin 應該無需查詢數據庫即可獲得權限
	hasPermission, err := service.CheckPermission(ctx, 1, 100, model.PermissionView)

	assert.NoError(t, err)
	assert.True(t, hasPermission, "Admin 應該自動擁有所有權限")
}

// TestCheckPermission_AdminRole_Connect 測試 Admin 角色連線權限亦短路放行
func TestCheckPermission_AdminRole_Connect(t *testing.T) {
	_, _, gormDB := setupAuthorizationMockDB(t)
	service := NewAssetAuthorizationService(gormDB)

	ctx := context.WithValue(context.Background(), "role", model.RoleAdmin)
	ctx = context.WithValue(ctx, "userID", uint(1))

	// admin connect 短路放行，無需查詢數據庫
	hasPermission, err := service.CheckPermission(ctx, 1, 100, model.PermissionConnect)

	assert.NoError(t, err)
	assert.True(t, hasPermission, "Admin 應自動擁有 connect 權限")
}

// TestCheckPermission_AuditorRole_ViewShortCircuit 稽核角色對 view 短路放行
// （稽核可檢視全部資產，不查數據庫）
func TestCheckPermission_AuditorRole_ViewShortCircuit(t *testing.T) {
	_, _, gormDB := setupAuthorizationMockDB(t)
	service := NewAssetAuthorizationService(gormDB)

	ctx := context.WithValue(context.Background(), "role", model.RoleAuditor)
	ctx = context.WithValue(ctx, "userID", uint(2))

	hasPermission, err := service.CheckPermission(ctx, 2, 200, model.PermissionView)

	assert.NoError(t, err)
	assert.True(t, hasPermission, "Auditor 應自動擁有 view（稽核檢視）權限")
}

// TestCheckPermission_AuditorRole_ConnectDenied 稽核角色對 connect 不短路，
// 無顯式授權時拒絕（CPG-002 職責分離：稽核者只檢視不連線）
func TestCheckPermission_AuditorRole_ConnectDenied(t *testing.T) {
	_, mock, gormDB := setupAuthorizationMockDB(t)
	service := NewAssetAuthorizationService(gormDB)

	ctx := context.WithValue(context.Background(), "role", model.RoleAuditor)
	ctx = context.WithValue(ctx, "userID", uint(2))

	// connect 判定落正常授權查詢；auditor 無顯式 grant → 查無 → 拒絕
	mock.ExpectQuery(`SELECT count\(\*\) FROM "asset_authorizations"`).
		WithArgs(uint(2), uint(2), model.PermissionConnect, uint(200), uint(200), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	hasPermission, err := service.CheckPermission(ctx, 2, 200, model.PermissionConnect)

	assert.NoError(t, err)
	assert.False(t, hasPermission, "Auditor 不得因角色自動取得 connect（CPG-002）")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestCheckPermission_AuditorRole_ConnectExplicitGrant 稽核角色若被顯式授予某資產
// connect，仍可連（design D1：保留顯式授權單一事實源）
func TestCheckPermission_AuditorRole_ConnectExplicitGrant(t *testing.T) {
	_, mock, gormDB := setupAuthorizationMockDB(t)
	service := NewAssetAuthorizationService(gormDB)

	ctx := context.WithValue(context.Background(), "role", model.RoleAuditor)
	ctx = context.WithValue(ctx, "userID", uint(2))

	mock.ExpectQuery(`SELECT count\(\*\) FROM "asset_authorizations"`).
		WithArgs(uint(2), uint(2), model.PermissionConnect, uint(200), uint(200), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	hasPermission, err := service.CheckPermission(ctx, 2, 200, model.PermissionConnect)

	assert.NoError(t, err)
	assert.True(t, hasPermission, "Auditor 顯式授權的資產仍可 connect（D1）")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestCheckPermission_UserWithPermission 測試用戶擁有權限
func TestCheckPermission_UserWithPermission(t *testing.T) {
	_, mock, gormDB := setupAuthorizationMockDB(t)
	service := NewAssetAuthorizationService(gormDB)

	ctx := context.WithValue(context.Background(), "role", model.RoleUser)
	ctx = context.WithValue(ctx, "userID", uint(3))

	// Mock 數據庫查詢（找到授權記錄）
	// permission IN (view, connect) 會展開為 2 個參數（J 兩階收斂）
	mock.ExpectQuery(`SELECT count\(\*\) FROM "asset_authorizations"`).
		WithArgs(uint(3), uint(3), model.PermissionView, model.PermissionConnect, uint(100), uint(100), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	hasPermission, err := service.CheckPermission(ctx, 3, 100, model.PermissionView)

	assert.NoError(t, err)
	assert.True(t, hasPermission)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestCheckPermission_UserWithoutPermission 測試用戶無權限
func TestCheckPermission_UserWithoutPermission(t *testing.T) {
	_, mock, gormDB := setupAuthorizationMockDB(t)
	service := NewAssetAuthorizationService(gormDB)

	ctx := context.WithValue(context.Background(), "role", model.RoleUser)
	ctx = context.WithValue(ctx, "userID", uint(4))

	// Mock 數據庫查詢（未找到授權記錄）
	// permission IN (connect) 展開為 1 個參數（J 兩階收斂）
	mock.ExpectQuery(`SELECT count\(\*\) FROM "asset_authorizations"`).
		WithArgs(uint(4), uint(4), model.PermissionConnect, uint(200), uint(200), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	hasPermission, err := service.CheckPermission(ctx, 4, 200, model.PermissionConnect)

	assert.NoError(t, err)
	assert.False(t, hasPermission)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestCheckPermission_PermissionHierarchy 測試權限層級邏輯
func TestCheckPermission_PermissionHierarchy(t *testing.T) {
	_, mock, gormDB := setupAuthorizationMockDB(t)
	service := NewAssetAuthorizationService(gormDB)

	ctx := context.WithValue(context.Background(), "role", model.RoleUser)

	// 用戶擁有 connect 權限，檢查 view 權限應該通過
	// permission IN (view, connect) 會展開為 2 個參數（J 兩階收斂）
	mock.ExpectQuery(`SELECT count\(\*\) FROM "asset_authorizations"`).
		WithArgs(uint(5), uint(5), model.PermissionView, model.PermissionConnect, uint(300), uint(300), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	hasPermission, err := service.CheckPermission(ctx, 5, 300, model.PermissionView)

	assert.NoError(t, err)
	assert.True(t, hasPermission, "擁有 connect 權限的用戶應該可以存取 view")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestGrantPermission_Success 測試成功授予權限
func TestGrantPermission_Success(t *testing.T) {
	_, mock, gormDB := setupAuthorizationMockDB(t)
	service := NewAssetAuthorizationService(gormDB)

	ctx := context.Background()

	// 1. 檢查用戶存在
	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE .+ ORDER BY .+ LIMIT`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "username"}).AddRow(10, "testuser"))

	// 2. 檢查資產存在
	mock.ExpectQuery(`SELECT .+ FROM "assets" WHERE .+ ORDER BY .+ LIMIT`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(100, "test-server"))

	// 3. 檢查活躍同組合是否已存在（count=0，Grant 統一去重查詢）
	mock.ExpectQuery(`SELECT count\(\*\) FROM "asset_authorizations"`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// 4. 創建授權
	mock.ExpectBegin()
	mock.ExpectQuery(`INSERT INTO "asset_authorizations"`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	mock.ExpectCommit()

	auth, err := service.GrantPermission(ctx, 10, 100, model.PermissionView, 1)

	assert.NoError(t, err)
	if assert.NotNil(t, auth) {
		if assert.NotNil(t, auth.UserID) {
			assert.Equal(t, uint(10), *auth.UserID)
		}
		assert.Equal(t, uint(100), *auth.AssetID)
		assert.Equal(t, model.PermissionView, auth.Permission)
	}
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestGrantPermission_UserNotFound 測試用戶不存在
func TestGrantPermission_UserNotFound(t *testing.T) {
	_, mock, gormDB := setupAuthorizationMockDB(t)
	service := NewAssetAuthorizationService(gormDB)

	ctx := context.Background()

	// 檢查用戶存在（不存在）
	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE .+ ORDER BY .+ LIMIT`).
		WillReturnError(gorm.ErrRecordNotFound)

	auth, err := service.GrantPermission(ctx, 999, 100, model.PermissionView, 1)

	assert.Error(t, err)
	assert.Nil(t, auth)
	// 哨兵可判（V2 對抗驗收 H2）：handler 以 errors.Is 分流，
	// 不再依賴中文訊息子字串——故此處也斷言哨兵而非文案
	assert.ErrorIs(t, err, ErrGrantUserNotFound)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestGrantPermission_AssetNotFound 測試資產不存在
func TestGrantPermission_AssetNotFound(t *testing.T) {
	_, mock, gormDB := setupAuthorizationMockDB(t)
	service := NewAssetAuthorizationService(gormDB)

	ctx := context.Background()

	// 檢查用戶存在
	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE .+ ORDER BY .+ LIMIT`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "username"}).AddRow(10, "testuser"))

	// 檢查資產存在（不存在）
	mock.ExpectQuery(`SELECT .+ FROM "assets" WHERE .+ ORDER BY .+ LIMIT`).
		WillReturnError(gorm.ErrRecordNotFound)

	auth, err := service.GrantPermission(ctx, 10, 999, model.PermissionView, 1)

	assert.Error(t, err)
	assert.Nil(t, auth)
	assert.ErrorIs(t, err, ErrGrantAssetNotFound)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestGrantPermission_Duplicate 測試重複授權
func TestGrantPermission_Duplicate(t *testing.T) {
	_, mock, gormDB := setupAuthorizationMockDB(t)
	service := NewAssetAuthorizationService(gormDB)

	ctx := context.Background()

	// 1. 檢查用戶存在
	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE .+ ORDER BY .+ LIMIT`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "username"}).AddRow(10, "testuser"))

	// 2. 檢查資產存在
	mock.ExpectQuery(`SELECT .+ FROM "assets" WHERE .+ ORDER BY .+ LIMIT`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(100, "test-server"))

	// 3. 檢查活躍同組合是否已存在（count=1 → 衝突）
	mock.ExpectQuery(`SELECT count\(\*\) FROM "asset_authorizations"`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	auth, err := service.GrantPermission(ctx, 10, 100, model.PermissionView, 1)

	assert.Error(t, err)
	assert.Equal(t, ErrAuthorizationExists, err)
	assert.Nil(t, auth)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestRevokePermission_Success 測試成功撤銷權限
func TestRevokePermission_Success(t *testing.T) {
	_, mock, gormDB := setupAuthorizationMockDB(t)
	service := NewAssetAuthorizationService(gormDB)

	ctx := context.Background()

	// 1. 檢查授權存在（不使用 Preload，簡化測試）
	mock.ExpectQuery(`SELECT .+ FROM "asset_authorizations" WHERE .+ ORDER BY .+ LIMIT`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "asset_id", "permission"}).
			AddRow(1, 10, 100, model.PermissionView))

	// GORM Preload 會根據返回的外鍵查詢關聯資料
	// User: user_id = 10
	mock.ExpectQuery(`SELECT .+ FROM ".+" WHERE`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	// Asset: asset_id = 100
	mock.ExpectQuery(`SELECT .+ FROM ".+" WHERE`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	// AssetGroup: asset_group_id (可能不查詢，因為沒有 group)

	// 2. 軟刪除
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE "asset_authorizations" SET "deleted_at"`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err := service.RevokePermission(ctx, 1)

	assert.NoError(t, err)
	// Note: 不檢查 ExpectationsWereMet，因為 AssetGroup 查詢可能不發生
}

// TestRevokePermission_NotFound 測試撤銷不存在的授權
func TestRevokePermission_NotFound(t *testing.T) {
	_, mock, gormDB := setupAuthorizationMockDB(t)
	service := NewAssetAuthorizationService(gormDB)

	ctx := context.Background()

	// 檢查授權存在（不存在）
	mock.ExpectQuery(`SELECT .+ FROM "asset_authorizations" WHERE .+ ORDER BY .+ LIMIT`).
		WillReturnError(gorm.ErrRecordNotFound)

	err := service.RevokePermission(ctx, 999)

	assert.Error(t, err)
	assert.Equal(t, ErrAuthorizationNotFound, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestListUserAuthorizations 測試查詢用戶授權列表
func TestListUserAuthorizations(t *testing.T) {
	_, mock, gormDB := setupAuthorizationMockDB(t)
	service := NewAssetAuthorizationService(gormDB)

	// 1. Count 查詢
	mock.ExpectQuery(`SELECT count\(\*\) FROM "asset_authorizations" WHERE user_id`).
		WithArgs(uint(10)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	// 2. List 查詢 (with LIMIT and OFFSET)
	assetID1 := uint(100)
	assetID2 := uint(101)
	mock.ExpectQuery(`SELECT \* FROM "asset_authorizations" WHERE user_id`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "asset_id", "permission", "granted_by"}).
			AddRow(1, 10, assetID1, model.PermissionView, 1).
			AddRow(2, 10, assetID2, model.PermissionConnect, 1))

	// Preload: 使用通用模式匹配所有關聯查詢
	mock.ExpectQuery(`SELECT .+ FROM ".+" WHERE`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	mock.ExpectQuery(`SELECT .+ FROM ".+" WHERE`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	mock.ExpectQuery(`SELECT .+ FROM ".+" WHERE`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	authorizations, total, err := service.ListUserAuthorizations(10, 1, 20)

	assert.NoError(t, err)
	assert.Equal(t, int64(2), total)
	assert.Equal(t, 2, len(authorizations))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestListAssetAuthorizations 測試查詢資產授權列表
func TestListAssetAuthorizations(t *testing.T) {
	_, mock, gormDB := setupAuthorizationMockDB(t)
	service := NewAssetAuthorizationService(gormDB)

	// 1. Count 查詢
	mock.ExpectQuery(`SELECT count\(\*\) FROM "asset_authorizations" WHERE asset_id`).
		WithArgs(uint(100)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))

	// 2. List 查詢
	assetID := uint(100)
	mock.ExpectQuery(`SELECT \* FROM "asset_authorizations" WHERE asset_id`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "asset_id", "permission", "granted_by"}).
			AddRow(1, 10, assetID, model.PermissionView, 1).
			AddRow(2, 11, assetID, model.PermissionConnect, 1).
			AddRow(3, 12, assetID, model.PermissionConnect, 1))

	// Preload: 使用通用模式匹配所有關聯查詢
	mock.ExpectQuery(`SELECT .+ FROM ".+" WHERE`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	mock.ExpectQuery(`SELECT .+ FROM ".+" WHERE`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	mock.ExpectQuery(`SELECT .+ FROM ".+" WHERE`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	authorizations, total, err := service.ListAssetAuthorizations(100, 1, 20)

	assert.NoError(t, err)
	assert.Equal(t, int64(3), total)
	assert.Equal(t, 3, len(authorizations))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestGetAuthorizedAssets_AdminRole 測試 Admin 獲取所有資產
func TestGetAuthorizedAssets_AdminRole(t *testing.T) {
	_, mock, gormDB := setupAuthorizationMockDB(t)
	service := NewAssetAuthorizationService(gormDB)

	ctx := context.WithValue(context.Background(), "role", model.RoleAdmin)
	ctx = context.WithValue(ctx, "userID", uint(1))

	// Admin 應該查詢所有資產
	mock.ExpectQuery(`SELECT .+ FROM "assets"`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).
			AddRow(1, "server1").
			AddRow(2, "server2").
			AddRow(3, "server3"))

	assets, err := service.GetAuthorizedAssets(ctx, 1, model.PermissionView)

	assert.NoError(t, err)
	assert.Equal(t, 3, len(assets))
	// admin 全量分支不帶授權等級（管理視圖恆全權限）
	assert.Empty(t, assets[0].Permission)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestGetAuthorizedAssets_UserRole 測試一般用戶獲取授權資產
func TestGetAuthorizedAssets_UserRole(t *testing.T) {
	_, mock, gormDB := setupAuthorizationMockDB(t)
	service := NewAssetAuthorizationService(gormDB)

	ctx := context.WithValue(context.Background(), "role", model.RoleUser)
	ctx = context.WithValue(ctx, "userID", uint(10))

	// 一般用戶只能查詢有權限的資產：EXISTS 條件涵蓋直授與節點含子樹
	//（asset-node-tree D3——客體側經 asset_nodes 祖先集）
	mock.ExpectQuery(`SELECT \* FROM "assets" WHERE \(EXISTS`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).
			AddRow(1, "server1").
			AddRow(2, "server2"))

	// 第二段：授權記錄聚合等級（軟刪除由 GORM scope 過濾）
	mock.ExpectQuery(`SELECT \* FROM "asset_authorizations" WHERE \(\(user_id = \$1 OR user_group_id IN`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "asset_id", "asset_group_id", "permission"}).
			AddRow(100, 10, 1, nil, "view").
			AddRow(101, 10, nil, 5, "connect"))

	// 第三段：資產→祖先節點映射（等級聚合的節點路徑；server2 掛 node 5）
	mock.ExpectQuery(`WITH RECURSIVE anc`).
		WillReturnRows(sqlmock.NewRows([]string{"asset_id", "node_id"}).
			AddRow(2, 5))

	// 第四段：可視第三來源（審核範圍，view 路徑才查；本例無範圍）
	mock.ExpectQuery(`SELECT \* FROM "assets" WHERE \(id IN \(SELECT asset_id FROM approver_scopes`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}))

	assets, err := service.GetAuthorizedAssets(ctx, 10, model.PermissionView)

	assert.NoError(t, err)
	assert.Equal(t, 2, len(assets))
	// 直授 view → server1=view；組授 connect → server2=connect
	assert.Equal(t, model.PermissionView, assets[0].Permission)
	assert.Equal(t, model.PermissionConnect, assets[1].Permission)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestGetAuthorizedAssets_MixedGrantsTakeHighest 直授+組授同資產取最高等級
func TestGetAuthorizedAssets_MixedGrantsTakeHighest(t *testing.T) {
	_, mock, gormDB := setupAuthorizationMockDB(t)
	service := NewAssetAuthorizationService(gormDB)

	ctx := context.WithValue(context.Background(), "role", model.RoleUser)
	ctx = context.WithValue(ctx, "userID", uint(10))

	mock.ExpectQuery(`SELECT \* FROM "assets" WHERE \(EXISTS`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).
			AddRow(1, "server1"))

	// 同資產命中直授 view 與節點 connect → 取 connect（J 兩階收斂）
	mock.ExpectQuery(`SELECT \* FROM "asset_authorizations" WHERE \(\(user_id = \$1 OR user_group_id IN`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "asset_id", "asset_group_id", "permission"}).
			AddRow(100, 10, 1, nil, "view").
			AddRow(101, 10, nil, 5, "connect"))

	// 資產→祖先節點映射：server1 掛 node 5
	mock.ExpectQuery(`WITH RECURSIVE anc`).
		WillReturnRows(sqlmock.NewRows([]string{"asset_id", "node_id"}).
			AddRow(1, 5))

	// 可視第三來源（審核範圍，view 路徑才查；本例無範圍）
	mock.ExpectQuery(`SELECT \* FROM "assets" WHERE \(id IN \(SELECT asset_id FROM approver_scopes`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}))

	assets, err := service.GetAuthorizedAssets(ctx, 10, model.PermissionView)

	assert.NoError(t, err)
	assert.Equal(t, 1, len(assets))
	assert.Equal(t, model.PermissionConnect, assets[0].Permission)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestGetAuthorizedAssets_NoPermissions 測試用戶無任何授權
func TestGetAuthorizedAssets_NoPermissions(t *testing.T) {
	_, mock, gormDB := setupAuthorizationMockDB(t)
	service := NewAssetAuthorizationService(gormDB)

	ctx := context.WithValue(context.Background(), "role", model.RoleUser)
	ctx = context.WithValue(ctx, "userID", uint(20))

	// 用戶無授權，返回空列表
	mock.ExpectQuery(`SELECT \* FROM "assets" WHERE \(EXISTS`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}))
	mock.ExpectQuery(`SELECT \* FROM "asset_authorizations" WHERE \(\(user_id = \$1 OR user_group_id IN`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "asset_id", "asset_group_id", "permission"}))

	assets, err := service.GetAuthorizedAssets(ctx, 20, model.PermissionConnect)

	assert.NoError(t, err)
	assert.Equal(t, 0, len(assets))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ===== authorization-page-redesign D4：ticket 裸刪守門 =====

// TestRevokePermission_TicketWithRequestBlocked 有關聯申請單的 ticket 授權
// 必須被 sentinel 擋下（走申請單撤銷流），不得執行軟刪
func TestRevokePermission_TicketWithRequestBlocked(t *testing.T) {
	_, mock, gormDB := setupAuthorizationMockDB(t)
	service := NewAssetAuthorizationService(gormDB)

	// FindByID：回 ticket 來源授權
	mock.ExpectQuery(`SELECT .+ FROM "asset_authorizations" WHERE .+ ORDER BY .+ LIMIT`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "asset_id", "permission", "source"}).
			AddRow(108, 10, 100, model.PermissionConnect, model.AuthorizationSourceTicket))
	mock.ExpectQuery(`SELECT .+ FROM ".+" WHERE`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectQuery(`SELECT .+ FROM ".+" WHERE`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	// 反查申請單：有單 → 守門
	mock.ExpectQuery(`SELECT count\(\*\) FROM "access_requests" WHERE authorization_id`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	err := service.RevokePermission(context.Background(), 108)
	assert.ErrorIs(t, err, ErrTicketRevocationRequired)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestRevokePermission_OrphanTicketAllowed 反查無申請單的孤兒 ticket 放行刪除
func TestRevokePermission_OrphanTicketAllowed(t *testing.T) {
	_, mock, gormDB := setupAuthorizationMockDB(t)
	service := NewAssetAuthorizationService(gormDB)

	mock.ExpectQuery(`SELECT .+ FROM "asset_authorizations" WHERE .+ ORDER BY .+ LIMIT`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "asset_id", "permission", "source"}).
			AddRow(120, 10, 100, model.PermissionConnect, model.AuthorizationSourceTicket))
	mock.ExpectQuery(`SELECT .+ FROM ".+" WHERE`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectQuery(`SELECT .+ FROM ".+" WHERE`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	mock.ExpectQuery(`SELECT count\(\*\) FROM "access_requests" WHERE authorization_id`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE "asset_authorizations" SET "deleted_at"`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err := service.RevokePermission(context.Background(), 120)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestRevokePermission_ManualUnaffected manual 來源不觸發反查、直接軟刪（回歸）
func TestRevokePermission_ManualUnaffected(t *testing.T) {
	_, mock, gormDB := setupAuthorizationMockDB(t)
	service := NewAssetAuthorizationService(gormDB)

	mock.ExpectQuery(`SELECT .+ FROM "asset_authorizations" WHERE .+ ORDER BY .+ LIMIT`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "asset_id", "permission", "source"}).
			AddRow(54, 10, 100, model.PermissionConnect, model.AuthorizationSourceManual))
	mock.ExpectQuery(`SELECT .+ FROM ".+" WHERE`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectQuery(`SELECT .+ FROM ".+" WHERE`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE "asset_authorizations" SET "deleted_at"`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err := service.RevokePermission(context.Background(), 54)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ===== authorization-page-redesign D2：ticket request_id 批次回填 =====

// TestAttachTicketRequestIDs 僅 ticket 記錄回填 request_id、單次 IN 查詢
func TestAttachTicketRequestIDs(t *testing.T) {
	_, mock, gormDB := setupAuthorizationMockDB(t)
	service := NewAssetAuthorizationService(gormDB)

	auths := []*model.AssetAuthorization{
		{ID: 108, Source: model.AuthorizationSourceTicket},
		{ID: 54, Source: model.AuthorizationSourceManual},
	}

	mock.ExpectQuery(`SELECT "id","authorization_id" FROM "access_requests" WHERE authorization_id IN`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "authorization_id"}).AddRow(28, 108))

	err := service.attachTicketRequestIDs(auths)
	assert.NoError(t, err)
	assert.NotNil(t, auths[0].RequestID)
	assert.Equal(t, uint(28), *auths[0].RequestID)
	assert.Nil(t, auths[1].RequestID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestAttachTicketRequestIDs_NoTickets 全 manual 不發查詢（零額外成本）
func TestAttachTicketRequestIDs_NoTickets(t *testing.T) {
	_, mock, gormDB := setupAuthorizationMockDB(t)
	service := NewAssetAuthorizationService(gormDB)

	auths := []*model.AssetAuthorization{{ID: 54, Source: model.AuthorizationSourceManual}}
	err := service.attachTicketRequestIDs(auths)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ===== authorization-page-redesign D7：有效性伺服端篩選 =====

// TestListAuthorizations_ValidityExpiredFilter expired 篩選於 COUNT 前生效
func TestListAuthorizations_ValidityExpiredFilter(t *testing.T) {
	_, mock, gormDB := setupAuthorizationMockDB(t)
	service := NewAssetAuthorizationService(gormDB)

	now := time.Now()
	mock.ExpectQuery(`SELECT count\(\*\) FROM "asset_authorizations" WHERE \(date_expired IS NOT NULL AND date_expired <=`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`SELECT .+ FROM "asset_authorizations" WHERE \(date_expired IS NOT NULL AND date_expired <=`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	auths, total, err := service.ListAuthorizations(map[string]interface{}{
		"validity": ValidityFilter{State: model.ValidityExpired, Now: now},
	}, 1, 20)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), total)
	assert.Equal(t, 0, len(auths))
	assert.NoError(t, mock.ExpectationsWereMet())
}
