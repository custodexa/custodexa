package asset

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/testgate"
)

// 建立停用的資產：資料列一寫入就是停用（同一交易內沒有啟用的中間值），建立事件的 hook 看到的也是停用；
// 建立稽核記下建立時即為停用，與一般建立（不帶明細）分得開。

func TestCreateInactiveAssetIsInactiveFromInsert(t *testing.T) {
	testCreateInactiveAsset(t, func(t *testing.T) *gorm.DB {
		db := setupAccountDB(t)
		require.NoError(t, db.AutoMigrate(&model.AssetAuthorization{}))
		return db
	})
}

// TestCreateInactiveAssetIsInactiveFromInsertPG 同上，在 PostgreSQL 上（資產表的啟用欄帶資料庫預設值、
// 寫入走 RETURNING）。未設 TEST_PG_DSN 即略過，REQUIRE_INTEGRATION=1 時略過轉失敗。
func TestCreateInactiveAssetIsInactiveFromInsertPG(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	testCreateInactiveAsset(t, func(t *testing.T) *gorm.DB {
		admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		schema := fmt.Sprintf("create_inactive_%d", time.Now().UnixNano())
		require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
		t.Cleanup(func() {
			_ = admin.Exec("DROP SCHEMA " + schema + " CASCADE").Error
			if s, err := admin.DB(); err == nil {
				_ = s.Close()
			}
		})
		db, err := gorm.Open(postgres.Open(dsn+" search_path="+schema), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		t.Cleanup(func() {
			if s, err := db.DB(); err == nil {
				_ = s.Close()
			}
		})
		require.Equal(t, "postgres", db.Dialector.Name())
		require.NoError(t, db.AutoMigrate(&model.Asset{}, &model.AssetAccount{}, &model.Credential{},
			&model.CredentialSecretVersion{}, &model.AuditLog{}, &model.AssetGroup{}, &model.AssetNode{},
			&model.CredentialJobAuthorization{}, &model.AssetAuthorization{}))
		old := database.DB
		database.DB = db
		t.Cleanup(func() { database.DB = old })
		return db
	})
}

func testCreateInactiveAsset(t *testing.T, open func(t *testing.T) *gorm.DB) {
	type seen struct {
		atInsert   bool
		statements int
	}
	// observe 記錄資產列寫入當下（同一交易、hook 之前）資料庫裡的啟用值，以及交易內對資產列的更新次數
	observe := func(t *testing.T, db *gorm.DB) *seen {
		s := &seen{}
		require.NoError(t, db.Callback().Create().After("gorm:create").Register("test:active_at_insert", func(d *gorm.DB) {
			if d.Statement.Table != "assets" || d.Error != nil {
				return
			}
			id, _ := d.Statement.Schema.PrioritizedPrimaryField.ValueOf(d.Statement.Context, d.Statement.ReflectValue)
			var active bool
			require.NoError(t, d.Session(&gorm.Session{NewDB: true}).Raw("SELECT active FROM assets WHERE id = ?", id).Scan(&active).Error)
			s.atInsert = active
		}))
		require.NoError(t, db.Callback().Update().Before("gorm:update").Register("test:asset_updates", func(d *gorm.DB) {
			if d.Statement.Table == "assets" {
				s.statements++
			}
		}))
		t.Cleanup(func() {
			_ = db.Callback().Create().Remove("test:active_at_insert")
			_ = db.Callback().Update().Remove("test:asset_updates")
		})
		return s
	}
	createAudits := func(t *testing.T, db *gorm.DB, assetID uint) []model.AuditLog {
		var rows []model.AuditLog
		require.NoError(t, db.Where("resource = ? AND resource_id = ?", model.ResourceAsset, assetID).Order("id").Find(&rows).Error)
		return rows
	}
	boolp := func(b bool) *bool { return &b }

	for _, tc := range []struct {
		name        string
		active      *bool
		wantActive  bool
		wantDetails string
	}{
		{"inactive", boolp(false), false, `{"active":false}`},
		{"explicit_active", boolp(true), true, ""},
		{"omitted_defaults_to_active", nil, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := open(t)
			assets, _ := newAccountServices(t)
			s := observe(t, db)

			resp, err := assets.Create(WithSystemCaller(context.Background()), &CreateAssetRequest{Name: "ci-" + tc.name,
				Protocol: model.ProtocolVNC, Host: "198.51.100.44", Port: 5900, Active: tc.active, CreatedBy: 1})
			require.NoError(t, err)
			assert.Equal(t, tc.wantActive, resp.Active, "回應")
			assert.Equal(t, tc.wantActive, s.atInsert, "資料列寫入當下的啟用值")
			assert.Zero(t, s.statements, "建立交易內不得再更新資產列")

			var row model.Asset
			require.NoError(t, db.First(&row, resp.ID).Error)
			assert.Equal(t, tc.wantActive, row.Active, "提交後的資料列")

			// 不帶帳號欄位：不建預設帳號，資產名下的稽核只有建立事件本身
			audits := createAudits(t, db, resp.ID)
			require.Len(t, audits, 1, "只有一筆建立稽核，沒有另一筆變更稽核")
			assert.Equal(t, model.ActionCreate, audits[0].Action)
			assert.Equal(t, tc.wantDetails, audits[0].Details, "建立稽核的明細（由建立 hook 依其所見寫入）")
		})
	}
}
