package api

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
)

// 節點與使用者群組的寫入回應所需的讀取與寫入同成敗：回應要帶的路徑或成員欄位讀不到時整筆不寫，
// 不會出現「寫入已提交、回應卻是失敗」（呼叫端以為沒寫入而重送）。

var errInjectedResponseRead = errors.New("injected response read failure")

// failQueryAfterWrite 對 writeTable 的寫入（建立或更新）完成之後，第一次符合 match 的查詢回錯。
// 回傳讀取失敗是否確實注入過。
func failQueryAfterWrite(t *testing.T, db *gorm.DB, writeTable string, match func(*gorm.DB) bool) *bool {
	t.Helper()
	armed, fired := false, false
	arm := func(d *gorm.DB) {
		if d.Statement.Table == writeTable && d.Error == nil {
			armed = true
		}
	}
	require.NoError(t, db.Callback().Create().After("gorm:create").Register("test:arm_response_read_c", arm))
	require.NoError(t, db.Callback().Update().After("gorm:update").Register("test:arm_response_read_u", arm))
	require.NoError(t, db.Callback().Query().Before("gorm:query").Register("test:inject_response_read", func(d *gorm.DB) {
		if armed && !fired && match(d) {
			fired = true
			_ = d.AddError(errInjectedResponseRead)
		}
	}))
	t.Cleanup(func() {
		_ = db.Callback().Create().Remove("test:arm_response_read_c")
		_ = db.Callback().Update().Remove("test:arm_response_read_u")
		_ = db.Callback().Query().Remove("test:inject_response_read")
	})
	return &fired
}

// isFullNodeScan 節點路徑的計算：無條件讀出全部節點列。
func isFullNodeScan(d *gorm.DB) bool {
	if d.Statement.Table != "asset_groups" {
		return false
	}
	if _, where := d.Statement.Clauses["WHERE"]; where {
		return false
	}
	_, ok := d.Statement.Dest.(*[]model.AssetGroup)
	return ok
}

func TestNodeWriteResponsePathReadFailureWritesNothing(t *testing.T) {
	type nodeRow struct {
		Name     string
		ParentID *uint
	}
	snapshot := func(t *testing.T, db *gorm.DB) map[uint]nodeRow {
		var rows []model.AssetGroup
		require.NoError(t, db.Unscoped().Order("id").Find(&rows).Error)
		out := map[uint]nodeRow{}
		for _, r := range rows {
			out[r.ID] = nodeRow{r.Name, r.ParentID}
		}
		return out
	}
	auditCount := func(t *testing.T, db *gorm.DB) int64 {
		var n int64
		require.NoError(t, db.Model(&model.AuditLog{}).Count(&n).Error)
		return n
	}
	cases := []struct {
		name   string
		method string
		path   func(e *nodeScopeEnv) string
		body   func(e *nodeScopeEnv) any
	}{
		{"create", http.MethodPost, func(*nodeScopeEnv) string { return "/asset-groups" },
			func(e *nodeScopeEnv) any { return map[string]any{"name": "cache", "parent_id": e.id("prod/db")} }},
		{"rename", http.MethodPut, func(e *nodeScopeEnv) string { return "/asset-groups/" + e.idStr("prod/web") },
			func(*nodeScopeEnv) any { return map[string]any{"name": "frontend", "description": "renamed"} }},
		{"move", http.MethodPut, func(e *nodeScopeEnv) string { return "/asset-groups/" + e.idStr("prod/db/a") + "/move" },
			func(e *nodeScopeEnv) any { return map[string]any{"parent_id": e.id("sit")} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newNodeScopeEnv(t)
			admin := e.superAdmin()
			before, audits := snapshot(t, e.db), auditCount(t, e.db)
			fired := failQueryAfterWrite(t, e.db, "asset_groups", isFullNodeScan)

			code, body := e.do(admin, tc.method, tc.path(e), tc.body(e))
			require.True(t, *fired, "前提：節點列寫入之後確實注入了路徑讀取失敗")
			assert.GreaterOrEqual(t, code, 500, "回應讀不到時不得回成功：%d %s", code, body)
			if !reflect.DeepEqual(before, snapshot(t, e.db)) {
				t.Errorf("路徑讀取失敗時整筆不寫，節點列卻已改變（%d %s）", code, body)
			}
			assert.Equal(t, audits, auditCount(t, e.db), "路徑讀取失敗時不留節點稽核")
		})
	}
}

func TestUserGroupUpdateResponseReadFailureWritesNothing(t *testing.T) {
	e := newUserGroupGetOneEnv(t)
	h := NewUserGroupHandler(identity.NewUserGroupService(e.db, audit.NewTxSink(), nil))
	g := e.r.Group("/api/v1/user-groups-rf")
	g.PUT("/:id", h.Update)
	grp := model.UserGroup{Name: "rf-ops", Description: "before"}
	require.NoError(t, e.db.Create(&grp).Error)

	fired := failQueryAfterWrite(t, e.db, "user_groups", func(d *gorm.DB) bool { return d.Statement.Table == "user_groups" })
	code, body := e.send(http.MethodPut, fmt.Sprintf("/api/v1/user-groups-rf/%d", grp.ID),
		map[string]any{"name": "rf-renamed", "description": "after"})
	require.True(t, *fired, "前提：群組列寫入之後確實注入了回應讀取失敗")
	assert.GreaterOrEqual(t, code, 500, "回應讀不到時不得回成功：%d %s", code, body)

	var got model.UserGroup
	require.NoError(t, e.db.First(&got, grp.ID).Error)
	assert.Equal(t, "rf-ops", got.Name, "回應讀取失敗時整筆不寫")
	assert.Equal(t, "before", got.Description)
}
