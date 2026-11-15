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

// 寫入回應所需的讀取與寫入同成敗：回應的節點歸屬與待配憑證讀不到時，整筆寫入不發生，
// 不以更新前的舊值或未填的預設值回成功，也不在寫入已提交後才回失敗。

var errInjectedRead = errors.New("injected read failure")

// failReadAfterWrite 對 writeTable 的寫入（建立或更新）完成之後，第一次查詢 readTable 時回錯。
// 回傳讀取失敗是否確實注入過。
func failReadAfterWrite(t *testing.T, db *gorm.DB, writeTable, readTable string) *bool {
	t.Helper()
	armed, fired := false, false
	arm := func(d *gorm.DB) {
		if d.Statement.Table == writeTable && d.Error == nil {
			armed = true
		}
	}
	require.NoError(t, db.Callback().Create().After("gorm:create").Register("test:arm_read_failure_c", arm))
	require.NoError(t, db.Callback().Update().After("gorm:update").Register("test:arm_read_failure_u", arm))
	require.NoError(t, db.Callback().Query().Before("gorm:query").Register("test:inject_read_failure", func(d *gorm.DB) {
		if armed && !fired && d.Statement.Table == readTable {
			fired = true
			_ = d.AddError(errInjectedRead)
		}
	}))
	t.Cleanup(func() {
		_ = db.Callback().Create().Remove("test:arm_read_failure_c")
		_ = db.Callback().Update().Remove("test:arm_read_failure_u")
		_ = db.Callback().Query().Remove("test:inject_read_failure")
	})
	return &fired
}

func TestAssetWriteResponseReadFailureRollsBack(t *testing.T) {
	setup := func(t *testing.T) (*gorm.DB, *AssetService) {
		db := setupAccountDB(t)
		require.NoError(t, db.AutoMigrate(&model.AssetAuthorization{}))
		assets, _ := newAccountServices(t)
		return db, assets
	}
	mounted := func(t *testing.T, db *gorm.DB, assets *AssetService) *model.Asset {
		node := model.AssetGroup{Name: "rf-node"}
		require.NoError(t, db.Create(&node).Error)
		a, err := assets.Create(WithSystemCaller(context.Background()), &CreateAssetRequest{Name: "rf-asset",
			Protocol: model.ProtocolSSH, Host: "198.51.100.42", Port: 22, Username: "root", NodeIDs: []uint{node.ID}, CreatedBy: 1})
		require.NoError(t, err)
		require.Equal(t, []uint{node.ID}, a.NodeIDs, "前提：資產掛在節點上")
		return a
	}
	count := func(t *testing.T, db *gorm.DB, table string) int64 {
		var n int64
		require.NoError(t, db.Table(table).Count(&n).Error)
		return n
	}

	for _, tc := range []struct{ name, readTable string }{
		{"update_node_membership_read_fails", "asset_nodes"},
		{"update_credential_pending_read_fails", "asset_accounts"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, assets := setup(t)
			a := mounted(t, db, assets)
			audits := count(t, db, "audit_logs")
			fired := failReadAfterWrite(t, db, "assets", tc.readTable)

			resp, err := assets.Update(uvCtx(), a.ID, &UpdateAssetRequest{Description: strp("after read failure")})
			require.True(t, *fired, "前提：資產列寫入之後確實注入了讀取失敗")
			require.ErrorIs(t, err, errInjectedRead, "回應讀不到時不得回成功（回應：%+v）", resp)
			assert.Nil(t, resp)

			var got model.Asset
			require.NoError(t, db.First(&got, a.ID).Error)
			assert.Equal(t, "", got.Description, "讀取失敗時整筆不寫")
			assert.Equal(t, audits, count(t, db, "audit_logs"), "讀取失敗時不留變更稽核")
		})
	}

	t.Run("create_node_membership_read_fails", func(t *testing.T) {
		db, assets := setup(t)
		before := map[string]int64{}
		for _, tbl := range []string{"assets", "asset_accounts", "credentials", "audit_logs"} {
			before[tbl] = count(t, db, tbl)
		}
		fired := failReadAfterWrite(t, db, "assets", "asset_nodes")

		resp, err := assets.Create(WithSystemCaller(context.Background()), &CreateAssetRequest{Name: "rf-create",
			Protocol: model.ProtocolSSH, Host: "198.51.100.43", Port: 22, Username: "root", CreatedBy: 1})
		require.True(t, *fired, "前提：資產列寫入之後確實注入了讀取失敗")
		require.ErrorIs(t, err, errInjectedRead, "回應讀不到時不得回成功（回應：%+v）", resp)
		assert.Nil(t, resp)
		for tbl, n := range before {
			assert.Equal(t, n, count(t, db, tbl), "讀取失敗時整筆不寫：%s", tbl)
		}
	})
}
