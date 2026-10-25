package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// roleAuditView 操作日誌 API 回傳的一列（只取本測試要斷言的欄位）
type roleAuditView struct {
	ID           uint
	UserID       uint
	Username     string
	Action       string
	Resource     string
	Method       string
	Path         string
	ClientIP     string
	RequestID    string
	Details      string
	ReasonCode   string
	ReasonParams map[string]string
}

// requestMiddlewareRequestID 等稽核中介層列落地（它在處理器之後非同步寫入），回傳該請求的 request_id
func requestMiddlewareRequestID(t *testing.T, env *baselineEnv, method, path string, actor uint, since time.Time) string {
	t.Helper()
	var requestID string
	require.Eventually(t, func() bool {
		var row model.AuditLog
		err := env.db.Where("method = ? AND path = ? AND user_id = ? AND request_id <> '' AND created_at >= ?",
			method, path, actor, since).Order("id DESC").First(&row).Error
		if err != nil {
			return false
		}
		requestID = row.RequestID
		return true
	}, 10*time.Second, 50*time.Millisecond, "稽核中介層列未落地: %s %s", method, path)
	return requestID
}

func strOf(v any) string { s, _ := v.(string); return s }

func listAuditRows(t *testing.T, env *baselineEnv, query string) []roleAuditView {
	t.Helper()
	c, out := env.api("AUD", http.MethodGet, "/api/v1/audit-logs?"+query, nil)
	require.Equal(t, http.StatusOK, c, "%v", out)
	raw, ok := out["data"].([]any)
	require.True(t, ok, "%v", out)
	var rows []roleAuditView
	for _, r := range raw {
		m := r.(map[string]any)
		v := roleAuditView{
			ID: uint(m["id"].(float64)), Username: strOf(m["username"]), Action: strOf(m["action"]), Resource: strOf(m["resource"]),
			Method: strOf(m["method"]), Path: strOf(m["path"]), ClientIP: strOf(m["client_ip"]), RequestID: strOf(m["request_id"]),
			Details: strOf(m["details"]), ReasonCode: strOf(m["reason_code"]),
		}
		if f, ok := m["user_id"].(float64); ok {
			v.UserID = uint(f)
		}
		if p, ok := m["reason_params"].(map[string]any); ok {
			v.ReasonParams = map[string]string{}
			for k, val := range p {
				v.ReasonParams[k] = strOf(val)
			}
		}
		rows = append(rows, v)
	}
	return rows
}

func shapeSet(rows []roleAuditView) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Action+"/"+r.Resource+"/"+r.ReasonCode)
	}
	sort.Strings(out)
	return out
}

// serviceRowOf 取同請求中指定資源的服務列（有原因碼、且不是分級列）
func serviceRowOf(t *testing.T, rows []roleAuditView, resource string) roleAuditView {
	t.Helper()
	for _, r := range rows {
		if r.Resource == resource && r.ReasonCode != "" && r.ReasonCode != "event.grant_change_graded" {
			return r
		}
	}
	t.Fatalf("找不到 %s 服務列: %v", resource, shapeSet(rows))
	return roleAuditView{}
}

func permissionStrings(ps []authz.Permission) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, string(p))
	}
	return out
}

// TestRoleWriteAuditRowsShareRequest 經正式路由與稽核中介層擋：一次角色寫入請求落下的各列
// 共用同一個 request_id、操作者與來源 IP；每列的原因碼依列型別如設計；參數經讀取期換名成名稱；
// details 原文只有識別碼；換名的查詢次數不隨列數成長。
func TestRoleWriteAuditRowsShareRequest(t *testing.T) {
	env := newBaselineEnv(t)
	k := model.BuiltinIdentityAdmin
	var idRole model.Role
	if err := env.db.Where("name = ?", "identity_admin").First(&idRole).Error; err != nil {
		idRole = model.Role{Name: "identity_admin", BuiltinKey: &k, DefinitionVersion: 1}
		require.NoError(t, env.db.Create(&idRole).Error)
	}
	ida := env.createUser("rw-ida", nil)
	require.NoError(t, model.AssignUserRoleWithSource(env.db, ida, idRole.ID, model.RoleSourceManual, model.RoleOriginSystem))
	env.subjects["IDA"] = &baselineSubject{ID: "IDA", Username: "rw-ida", UserID: ida, Kind: "session", Token: env.issueSessionToken(ida)}
	aud := env.createUser("rw-auditor", []string{model.RoleAuditor})
	env.subjects["AUD"] = &baselineSubject{ID: "AUD", Username: "rw-auditor", UserID: aud, Kind: "session", Token: env.issueSessionToken(aud)}
	target := env.createUser("rw-target", []string{model.RoleUser})
	n1 := env.apiID("S01", http.MethodPost, "/api/v1/asset-groups", map[string]any{"name": "rw-node-1"}, "node 1")
	n2 := env.apiID("S01", http.MethodPost, "/api/v1/asset-groups", map[string]any{"name": "rw-node-2"}, "node 2")
	group := model.UserGroup{Name: "rw-group"}
	require.NoError(t, env.db.Create(&group).Error)

	userPath := fmt.Sprintf("/api/v1/users/%d/roles", target)
	selfPath := fmt.Sprintf("/api/v1/users/%d/roles", ida)
	groupPath := fmt.Sprintf("/api/v1/user-groups/%d/role-bindings", group.ID)

	// do 以身分管理員送出一次寫入，回傳同一請求的全部審計列（經操作日誌 API 取回）
	do := func(path string, body any) (string, []roleAuditView) {
		since := time.Now().Add(-time.Second)
		c, out := env.api("IDA", http.MethodPut, path, body)
		require.Equal(t, http.StatusOK, c, "%v", out)
		rid := requestMiddlewareRequestID(t, env, http.MethodPut, path, ida, since)
		return rid, listAuditRows(t, env, "page_size=100&request_id="+rid)
	}
	const graded = "update/user/event.grant_change_graded"
	const mw = "update/user/"

	cases := []struct {
		key, name string
		path      string
		body      any
		shapes    []string
	}{
		{"R1", "加資產管理員限一個節點", userPath,
			map[string]any{"manual_roles": []string{"user", "asset_admin"}, "role_nodes": map[string][]uint{"asset_admin": {n1}}},
			[]string{mw, "assign/user_role/user_role_assign_nodes", graded}},
		{"R2", "只把範圍改到另一節點", userPath,
			map[string]any{"manual_roles": []string{"user", "asset_admin"}, "role_nodes": map[string][]uint{"asset_admin": {n2}}},
			[]string{mw, "update/user_role/event.role_binding_range_changed", graded}},
		{"R3", "移除該角色", userPath,
			map[string]any{"manual_roles": []string{"user"}},
			[]string{mw, "revoke/user_role/user_role_revoke"}},
		{"R4", "對自己追加稽核人員", selfPath,
			map[string]any{"manual_roles": []string{"identity_admin", "auditor"}},
			[]string{mw, "assign/user_role/user_role_assign", graded}},
		{"R5", "群組角色", groupPath,
			map[string]any{"role_ids": []uint{env.roleID(model.RoleAuditor)}},
			[]string{"update/user_group/", "assign/user_group_role/user_group_role_assign"}},
	}
	got := map[string][]roleAuditView{}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.key+" "+tc.name, func(t *testing.T) {
			rid, rows := do(tc.path, tc.body)
			got[tc.key] = rows
			want := append([]string(nil), tc.shapes...)
			sort.Strings(want)
			// (a) 同請求的 (action, resource, reason_code) 多重集合完全相等，多一列少一列都紅
			assert.Equal(t, want, shapeSet(rows))
			require.NotEmpty(t, rows)
			ip := rows[0].ClientIP
			for _, r := range rows {
				// (b) 操作者、來源 IP、方法與路徑都是該次請求，沒有 system 列
				assert.Equal(t, rid, r.RequestID)
				assert.Equal(t, ida, r.UserID, "%s/%s", r.Action, r.Resource)
				assert.Equal(t, "rw-ida", r.Username)
				assert.Equal(t, ip, r.ClientIP)
				assert.NotEmpty(t, r.ClientIP)
				assert.Equal(t, http.MethodPut, r.Method)
				assert.Equal(t, tc.path, r.Path)
				// (e) details 原文只有識別碼，不含任何名稱
				for _, name := range []string{"rw-ida", "rw-target", "rw-group", "rw-node", "asset_admin", "identity_admin", "auditor"} {
					assert.NotContains(t, r.Details, name, "%s/%s", r.Action, r.Resource)
				}
				// (c) 中介層列沿用既有呈現：沒有原因碼，畫面顯示請求路徑
				if r.ReasonCode == "" {
					assert.Equal(t, tc.path, r.Path)
				}
			}
			// (d) 以 request_id 篩選取回的列恰是資料庫中同一請求的那一組
			var ids []uint
			require.NoError(t, env.db.Model(&model.AuditLog{}).Where("request_id = ?", rid).Order("id").Pluck("id", &ids).Error)
			var viaAPI []uint
			for _, r := range rows {
				viaAPI = append(viaAPI, r.ID)
			}
			sort.Slice(viaAPI, func(i, j int) bool { return viaAPI[i] < viaAPI[j] })
			assert.Equal(t, ids, viaAPI)
		})
	}

	t.Run("details 的鍵集合與修改前相同", func(t *testing.T) {
		keysOf := func(r roleAuditView) []string {
			var m map[string]any
			require.NoError(t, json.Unmarshal([]byte(r.Details), &m))
			var ks []string
			for k := range m {
				ks = append(ks, k)
			}
			sort.Strings(ks)
			return ks
		}
		assert.Equal(t, []string{"origin", "range_after", "range_after_count", "resource", "role_id", "user_id"},
			keysOf(serviceRowOf(t, got["R1"], "user_role")))
		assert.Equal(t, []string{"event", "origin", "range_after", "range_after_count", "range_before", "range_before_count", "resource", "role_id", "user_id"},
			keysOf(serviceRowOf(t, got["R2"], "user_role")))
		assert.Equal(t, []string{"origin", "resource", "role_id", "user_id"}, keysOf(serviceRowOf(t, got["R3"], "user_role")))
	})

	t.Run("讀取期換名：角色、對象、節點", func(t *testing.T) {
		r1 := serviceRowOf(t, got["R1"], "user_role")
		assert.Equal(t, "asset_admin", r1.ReasonParams["role"])
		assert.Equal(t, "rw-target", r1.ReasonParams["target"])
		assert.Equal(t, "rw-node-1", r1.ReasonParams["nodes"])
		assert.Equal(t, "1", r1.ReasonParams["nodes_count"])
		assert.Equal(t, "api", r1.ReasonParams["origin"])

		r2 := serviceRowOf(t, got["R2"], "user_role")
		assert.Equal(t, "rw-node-1", r2.ReasonParams["before"])
		assert.Equal(t, "rw-node-2", r2.ReasonParams["after"])
		assert.Equal(t, "user", r2.ReasonParams["target_kind"])

		g := serviceRowOf(t, got["R5"], "user_group_role")
		assert.Equal(t, "rw-group", g.ReasonParams["target"])
		assert.NotContains(t, g.ReasonParams, "target_kind", "群組指派句已寫明使用者群組")
		assert.Equal(t, "auditor", g.ReasonParams["role"])

		// 分級列只陳述已建立告警的標記
		for key, mark := range map[string]string{"R1": "management_grant", "R4": "self_authorization"} {
			found := false
			for _, r := range got[key] {
				if r.ReasonCode == "event.grant_change_graded" {
					found = true
					assert.Equal(t, mark, r.ReasonParams["marks"], key)
				}
			}
			assert.True(t, found, key)
		}

		// 先限節點、再改為全系統：after 為 global，不換名
		do(userPath, map[string]any{"manual_roles": []string{"user", "asset_admin"}, "role_nodes": map[string][]uint{"asset_admin": {n1}}})
		_, rows := do(userPath, map[string]any{"manual_roles": []string{"user", "asset_admin"}, "role_nodes": map[string]any{"asset_admin": nil}})
		r := serviceRowOf(t, rows, "user_role")
		assert.Equal(t, "event.role_binding_range_changed", r.ReasonCode)
		assert.Equal(t, "rw-node-1", r.ReasonParams["before"])
		assert.Equal(t, "global", r.ReasonParams["after"])
	})

	t.Run("刪除後回退：節點回識別碼、角色回原名", func(t *testing.T) {
		// 節點刪除後，R2 的 after 回 #<id>
		require.NoError(t, env.db.Delete(&model.AssetGroup{}, n2).Error)
		rows := listAuditRows(t, env, "page_size=100&request_id="+got["R2"][0].RequestID)
		r2 := serviceRowOf(t, rows, "user_role")
		assert.Equal(t, "rw-node-1", r2.ReasonParams["before"])
		assert.Equal(t, fmt.Sprintf("#%d", n2), r2.ReasonParams["after"])

		// 自訂角色指派後移除、再刪除：指派列仍回原名
		c, out := env.api("S01", http.MethodPost, "/api/v1/role-definitions", map[string]any{
			"name": "rw-custom-role", "permissions": permissionStrings(authz.ScopedTemplateAssetAdminPermissions())})
		require.Equal(t, http.StatusCreated, c, "%v", out)
		roleID := uint(out["id"].(float64))
		var created model.Role
		require.NoError(t, env.db.First(&created, roleID).Error)
		version := created.DefinitionVersion
		since := time.Now().Add(-time.Second)
		c, out = env.api("S01", http.MethodPut, userPath, map[string]any{"manual_roles": []string{"user", "rw-custom-role"}})
		require.Equal(t, http.StatusOK, c, "%v", out)
		rid := requestMiddlewareRequestID(t, env, http.MethodPut, userPath, env.subjects["S01"].UserID, since)
		c, out = env.api("S01", http.MethodPut, userPath, map[string]any{"manual_roles": []string{"user"}})
		require.Equal(t, http.StatusOK, c, "%v", out)
		c, out = env.api("S01", http.MethodDelete, fmt.Sprintf("/api/v1/role-definitions/%d?expected_version=%d", roleID, version), nil)
		require.Less(t, c, 300, "%v", out)
		var stored model.Role
		require.NoError(t, env.db.Unscoped().First(&stored, roleID).Error)
		require.Contains(t, stored.Name, "~del", "刪除後的角色名帶改名字尾")

		rows = listAuditRows(t, env, "page_size=100&request_id="+rid)
		r := serviceRowOf(t, rows, "user_role")
		assert.Equal(t, "rw-custom-role", r.ReasonParams["role"])
	})

	t.Run("換名的查詢次數不隨列數成長", func(t *testing.T) {
		var n atomic.Int64
		watched := map[string]bool{"roles": true, "user_groups": true, "asset_groups": true}
		name := "rw-count-queries"
		require.NoError(t, database.DB.Callback().Query().Before("gorm:query").Register(name, func(tx *gorm.DB) {
			if watched[tx.Statement.Table] {
				n.Add(1)
			}
		}))
		defer func() { _ = database.DB.Callback().Query().Remove(name) }()
		count := func(size int) int64 {
			n.Store(0)
			rows := listAuditRows(t, env, fmt.Sprintf("page_size=%d&resource=user_role&sort_order=asc", size))
			require.Len(t, rows, size)
			return n.Load()
		}
		one, many := count(1), count(20)
		assert.Equal(t, one, many, "1 列與 20 列的查詢次數應相同")
		assert.Greater(t, one, int64(0), "換名確實查了名稱表")
	})

	t.Run("只持稽核以外角色者讀操作日誌仍被拒", func(t *testing.T) {
		env.subjects["PLAIN"] = &baselineSubject{ID: "PLAIN", Username: "rw-target", UserID: target, Kind: "session", Token: env.issueSessionToken(target)}
		c, _ := env.api("PLAIN", http.MethodGet, "/api/v1/audit-logs?request_id=x", nil)
		assert.Equal(t, http.StatusForbidden, c)
	})
}
