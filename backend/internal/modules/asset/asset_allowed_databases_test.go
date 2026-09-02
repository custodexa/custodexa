package asset

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 允許資料庫清單（查詢主控台的執行目標限制）的驗證、協議切換清空與留痕。

func setupAllowedDBTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&model.Asset{}, &model.AuditLog{}, &model.AssetGroup{}, &model.AssetNode{},
		&model.AssetAccount{},
	))
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })
	return db
}

func newAllowedDBService(t *testing.T) *AssetService {
	t.Helper()
	svc, err := NewAssetService(aesColumnCodec(t, make([]byte, 32)), "localhost", 4822, audit.NewTxSink())
	require.NoError(t, err)
	return svc
}

// updateCtx 帶操作者身分：資產變更審計只在 userID 非零時落地
func updateCtx() context.Context {
	ctx := context.WithValue(context.Background(), "userID", uint(1))
	return context.WithValue(ctx, "username", "admin")
}

func TestValidateAllowedDatabases(t *testing.T) {
	long := strings.Repeat("d", 129)
	exactly128 := strings.Repeat("d", 128)
	sixtyFour := make(model.StringList, 64)
	for i := range sixtyFour {
		sixtyFour[i] = string(rune('a'+i%26)) + strings.Repeat("x", i)
	}
	sixtyFive := append(append(model.StringList{}, sixtyFour...), "one-too-many")

	cases := []struct {
		name     string
		protocol model.ProtocolType
		list     model.StringList
		wantErr  bool
	}{
		{"空清單於任何協議皆合法", model.ProtocolSSH, nil, false},
		{"空陣列於任何協議皆合法", model.ProtocolRedis, model.StringList{}, false},
		{"mysql 合法清單", model.ProtocolMySQL, model.StringList{"app", "report"}, false},
		{"postgres 合法清單", model.ProtocolPostgres, model.StringList{"app"}, false},
		{"mssql 合法清單", model.ProtocolMSSQL, model.StringList{"App", "app"}, false},
		{"名稱含空白與逗號合法", model.ProtocolMySQL, model.StringList{"my db, prod"}, false},
		{"恰好 128 字元合法", model.ProtocolMySQL, model.StringList{exactly128}, false},
		{"恰好 64 項合法", model.ProtocolMySQL, sixtyFour, false},

		{"ssh 非空被拒", model.ProtocolSSH, model.StringList{"app"}, true},
		{"redis 非空被拒", model.ProtocolRedis, model.StringList{"0"}, true},
		{"k8s 非空被拒", model.ProtocolK8s, model.StringList{"app"}, true},
		{"逾 128 字元被拒", model.ProtocolMySQL, model.StringList{long}, true},
		{"空字串項被拒", model.ProtocolMySQL, model.StringList{"app", ""}, true},
		{"重複項被拒", model.ProtocolMySQL, model.StringList{"app", "app"}, true},
		{"逾 64 項被拒", model.ProtocolMySQL, sixtyFive, true},
		{"含 NUL 被拒", model.ProtocolMySQL, model.StringList{"a\x00b"}, true},
		{"含換行被拒", model.ProtocolMySQL, model.StringList{"a\nb"}, true},
		{"含定位字元被拒", model.ProtocolMySQL, model.StringList{"a\tb"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAllowedDatabases(tc.protocol, tc.list)
			if tc.wantErr {
				require.ErrorIs(t, err, ErrInvalidAllowedDatabases)
				return
			}
			require.NoError(t, err)
		})
	}

	// 大小寫不做正規化：`App` 與 `app` 是兩個名稱，不算重複。
	// 折大小寫會在 MSSQL（目錄保留建立時的大小寫）上把兩個合法的不同庫判成重複
	require.NoError(t, validateAllowedDatabases(model.ProtocolMSSQL, model.StringList{"App", "app", "APP"}))
}

// TestCreateAssetRejectsAllowedDatabasesOnNonConsoleProtocol 建立端點的協議閘。
func TestCreateAssetRejectsAllowedDatabasesOnNonConsoleProtocol(t *testing.T) {
	db := setupAllowedDBTestDB(t)
	svc := newAllowedDBService(t)

	_, err := svc.Create(&CreateAssetRequest{
		Name: "ssh-with-list", Protocol: model.ProtocolSSH, Host: "10.0.0.1", Port: 22,
		Username: "root", AllowedDatabases: model.StringList{"app"},
	})
	require.ErrorIs(t, err, ErrInvalidAllowedDatabases)

	var n int64
	require.NoError(t, db.Model(&model.Asset{}).Where("name = ?", "ssh-with-list").Count(&n).Error)
	require.Zero(t, n, "驗證失敗時資產不得被建立")
}

// TestUpdateAssetRejectsAllowedDatabasesOnNonConsoleProtocol 更新端點的協議閘，
// 且以**套用後的最終協議**判定——協議與清單在同一次請求中一起改也擋得住。
func TestUpdateAssetRejectsAllowedDatabasesOnNonConsoleProtocol(t *testing.T) {
	db := setupAllowedDBTestDB(t)
	svc := newAllowedDBService(t)

	created, err := svc.Create(&CreateAssetRequest{
		Name: "mysql-a", Protocol: model.ProtocolMySQL, Host: "10.0.0.2", Port: 3306,
		Username: "app", AllowedDatabases: model.StringList{"app"},
	})
	require.NoError(t, err)

	ssh := model.ProtocolSSH
	list := model.StringList{"app"}
	_, err = svc.Update(updateCtx(), created.ID, &UpdateAssetRequest{
		Protocol: &ssh, AllowedDatabases: &list,
	})
	require.ErrorIs(t, err, ErrInvalidAllowedDatabases)

	var after model.Asset
	require.NoError(t, db.First(&after, created.ID).Error)
	require.Equal(t, model.ProtocolMySQL, after.Protocol, "驗證失敗時整筆更新不得生效")
	require.Equal(t, model.StringList{"app"}, after.AllowedDatabases)
}

// TestAllowedDatabasesStoredWithoutDialing 儲存時不連線驗證名稱是否存在。
//
// 兩件事一起斷言：目標端不存在的名稱照樣存得進去（Non-goal 明載不做存在性驗證），
// 以及過程中沒有對目標端撥號。**撥號的判準取牆鐘時間**：host 取 TEST-NET-1
// （RFC 5737 保留給文件用途，路由上是黑洞），真的撥下去會停在撥測逾時
// （下限 1 秒、預設 10 秒）而不是 2 秒內回來；旁證是撥測結果三欄維持未測狀態。
func TestAllowedDatabasesStoredWithoutDialing(t *testing.T) {
	db := setupAllowedDBTestDB(t)
	svc := newAllowedDBService(t)

	start := time.Now()
	created, err := svc.Create(&CreateAssetRequest{
		Name: "mysql-blackhole", Protocol: model.ProtocolMySQL, Host: "192.0.2.1", Port: 3306,
		Username: "app", AllowedDatabases: model.StringList{"does-not-exist-on-target"},
	})
	require.NoError(t, err)
	elapsed := time.Since(start)
	require.Less(t, elapsed, 2*time.Second,
		"建立資產耗時 %s：對黑洞位址的撥號至少會停在撥測逾時下限（1 秒），此耗時顯示發生了連線嘗試", elapsed)

	var stored model.Asset
	require.NoError(t, db.First(&stored, created.ID).Error)
	require.Equal(t, model.StringList{"does-not-exist-on-target"}, stored.AllowedDatabases)
	require.Empty(t, stored.LastTestStatus, "儲存路徑不得產生撥測結果")
	require.Nil(t, stored.LastTestAt)
}

// TestAllowedDatabasesClearedOnProtocolSwitch 協議切換清空＋留痕＋改回仍空。
func TestAllowedDatabasesClearedOnProtocolSwitch(t *testing.T) {
	db := setupAllowedDBTestDB(t)
	svc := newAllowedDBService(t)

	created, err := svc.Create(&CreateAssetRequest{
		Name: "mysql-b", Protocol: model.ProtocolMySQL, Host: "10.0.0.3", Port: 3306,
		Username: "app", AllowedDatabases: model.StringList{"app", "report", "staging"},
	})
	require.NoError(t, err)

	// ── 改協議為 ssh：請求**不帶** allowed_databases，伺服端仍須清空 ──
	ssh := model.ProtocolSSH
	updated, err := svc.Update(updateCtx(), created.ID, &UpdateAssetRequest{Protocol: &ssh})
	require.NoError(t, err)
	require.Empty(t, updated.AllowedDatabases)

	var afterSwitch model.Asset
	require.NoError(t, db.First(&afterSwitch, created.ID).Error)
	require.Empty(t, afterSwitch.AllowedDatabases, "協議改離主控台協議後庫內不得留殘值")

	// ── 審計列須記載清空事實與清空前項數 ──
	var logs []model.AuditLog
	require.NoError(t, db.Where("resource = ? AND action = ?",
		model.ResourceAsset, model.ActionUpdate).Find(&logs).Error)

	var cleared *model.AssetChangeDetails
	for i := range logs {
		if logs[i].Details == "" {
			continue
		}
		var d model.AssetChangeDetails
		if err := json.Unmarshal([]byte(logs[i].Details), &d); err != nil {
			continue
		}
		if d.AllowedDatabasesCleared {
			cleared = &d
			break
		}
	}
	require.NotNil(t, cleared, "協議切換的更新審計未記載自動清空事實")
	require.Equal(t, 3, cleared.PreviousAllowedDatabaseCount)

	var sawDiff bool
	for _, ch := range cleared.Changes {
		if ch.Field == "allowed_databases" {
			sawDiff = true
		}
	}
	require.True(t, sawDiff, "審計的欄位 diff 未含 allowed_databases")

	// ── 改回 mysql：清單仍空，不得靜默恢復 ──
	mysql := model.ProtocolMySQL
	back, err := svc.Update(updateCtx(), created.ID, &UpdateAssetRequest{Protocol: &mysql})
	require.NoError(t, err)
	require.Empty(t, back.AllowedDatabases)

	var afterRestore model.Asset
	require.NoError(t, db.First(&afterRestore, created.ID).Error)
	require.Empty(t, afterRestore.AllowedDatabases, "協議改回後清單不得靜默恢復")
}

// TestAllowedDatabasesExplicitClearIsNotReportedAsServerCleared 反向對照：
// 在主控台協議上顯式清空是管理者的動作，不得被記成伺服端自動清空——
// 兩者在稽核上要能分辨「誰做的」。
func TestAllowedDatabasesExplicitClearIsNotReportedAsServerCleared(t *testing.T) {
	db := setupAllowedDBTestDB(t)
	svc := newAllowedDBService(t)

	created, err := svc.Create(&CreateAssetRequest{
		Name: "mysql-c", Protocol: model.ProtocolMySQL, Host: "10.0.0.4", Port: 3306,
		Username: "app", AllowedDatabases: model.StringList{"app"},
	})
	require.NoError(t, err)

	empty := model.StringList{}
	_, err = svc.Update(updateCtx(), created.ID, &UpdateAssetRequest{AllowedDatabases: &empty})
	require.NoError(t, err)

	var logs []model.AuditLog
	require.NoError(t, db.Where("resource = ? AND action = ?",
		model.ResourceAsset, model.ActionUpdate).Find(&logs).Error)
	for _, l := range logs {
		if l.Details == "" {
			continue
		}
		var d model.AssetChangeDetails
		if err := json.Unmarshal([]byte(l.Details), &d); err != nil {
			continue
		}
		require.False(t, d.AllowedDatabasesCleared,
			"協議未變動時的顯式清空不得記成伺服端自動清空")
	}

	var after model.Asset
	require.NoError(t, db.First(&after, created.ID).Error)
	require.Empty(t, after.AllowedDatabases)
}
