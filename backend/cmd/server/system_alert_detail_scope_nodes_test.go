package main

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// TestSystemAlertDetailScopeNodes 經正式路由擋：管理類發放的告警詳情帶出節點範圍（編號與路徑），
// 已刪除的節點只剩編號；全域發放的詳情不出現 scope_nodes。
func TestSystemAlertDetailScopeNodes(t *testing.T) {
	env := newBaselineEnv(t)
	k := model.BuiltinIdentityAdmin
	var idRole model.Role
	if err := env.db.Where("name = ?", "identity_admin").First(&idRole).Error; err != nil {
		idRole = model.Role{Name: "identity_admin", BuiltinKey: &k, DefinitionVersion: 1}
		require.NoError(t, env.db.Create(&idRole).Error)
	}
	ida := env.createUser("sa-ida", nil)
	require.NoError(t, model.AssignUserRoleWithSource(env.db, ida, idRole.ID, model.RoleSourceManual, model.RoleOriginSystem))
	env.subjects["IDA"] = &baselineSubject{ID: "IDA", Username: "sa-ida", UserID: ida, Kind: "session", Token: env.issueSessionToken(ida)}
	aud := env.createUser("sa-auditor", []string{model.RoleAuditor})
	env.subjects["AUD"] = &baselineSubject{ID: "AUD", Username: "sa-auditor", UserID: aud, Kind: "session", Token: env.issueSessionToken(aud)}
	scopedTarget := env.createUser("sa-scoped", []string{model.RoleUser})
	globalTarget := env.createUser("sa-global", []string{model.RoleUser})
	n1 := env.apiID("S01", http.MethodPost, "/api/v1/asset-groups", map[string]any{"name": "sa-node-1"}, "node 1")
	n2 := env.apiID("S01", http.MethodPost, "/api/v1/asset-groups", map[string]any{"name": "sa-node-2"}, "node 2")

	// 共用整合環境以模型建的 command_alerts 在 sqlite 讀回時間欄會是字串；
	// 換成與正式欄位語義相同的 DATETIME 表，詳情端點才讀得回
	// 明細與投遞佇列以告警編號關聯，跟著清空，新表的編號才不會撞上舊列
	for _, tbl := range []string{"system_alert_details", "system_alert_outbox", "command_alerts"} {
		require.NoError(t, env.db.Exec("DELETE FROM "+tbl).Error)
	}
	require.NoError(t, env.db.Exec(`DROP TABLE command_alerts`).Error)
	require.NoError(t, env.db.Exec(`CREATE TABLE command_alerts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id INTEGER, rule_name TEXT NOT NULL,
		session_id INTEGER, user_id INTEGER NOT NULL, asset_id INTEGER,
		command TEXT NOT NULL, severity TEXT NOT NULL, triggered_at DATETIME NOT NULL,
		reviewed_by INTEGER, reviewed_at DATETIME,
		disposition TEXT NOT NULL DEFAULT 'pending', note TEXT NOT NULL DEFAULT '',
		blocked BOOLEAN NOT NULL DEFAULT 0,
		kind TEXT NOT NULL DEFAULT 'rule', reason_code TEXT NOT NULL DEFAULT ''
	)`).Error)

	latestAlert := func() uint {
		var id uint
		require.NoError(t, env.db.Model(&model.CommandAlert{}).Where("kind = ?", model.AlertKindSystemSecurity).
			Order("id DESC").Limit(1).Pluck("id", &id).Error)
		require.NotZero(t, id)
		return id
	}
	detail := func(id uint) map[string]any {
		c, out := env.api("AUD", http.MethodGet, fmt.Sprintf("/api/v1/command-alerts/%d/system-detail", id), nil)
		require.Equal(t, http.StatusOK, c, "%v", out)
		return out
	}

	c, out := env.api("IDA", http.MethodPut, fmt.Sprintf("/api/v1/users/%d/roles", scopedTarget), map[string]any{
		"manual_roles": []string{"user", "asset_admin"},
		"role_nodes":   map[string][]uint{"asset_admin": {n1, n2}},
	})
	require.Equal(t, http.StatusOK, c, "%v", out)
	scopedAlert := latestAlert()

	t.Run("兩個節點各帶編號與路徑", func(t *testing.T) {
		d := detail(scopedAlert)
		assert.Equal(t, "management_role_granted", d["alert_type"])
		nodes, ok := d["scope_nodes"].([]any)
		require.True(t, ok, "%v", d)
		require.Len(t, nodes, 2)
		got := map[uint]string{}
		for _, n := range nodes {
			m := n.(map[string]any)
			got[uint(m["id"].(float64))] = m["path"].(string)
		}
		assert.Equal(t, map[uint]string{n1: "sa-node-1", n2: "sa-node-2"}, got)
		params := d["params"].(map[string]any)
		assert.Equal(t, "2", params["scope_node_count"])
	})

	t.Run("刪除其中一個節點後該筆路徑為空", func(t *testing.T) {
		require.NoError(t, env.db.Delete(&model.AssetGroup{}, n2).Error)
		d := detail(scopedAlert)
		nodes := d["scope_nodes"].([]any)
		require.Len(t, nodes, 2)
		got := map[uint]string{}
		for _, n := range nodes {
			m := n.(map[string]any)
			got[uint(m["id"].(float64))] = m["path"].(string)
		}
		assert.Equal(t, map[uint]string{n1: "sa-node-1", n2: ""}, got)
	})

	t.Run("全域發放的詳情不含 scope_nodes 鍵", func(t *testing.T) {
		c, out := env.api("IDA", http.MethodPut, fmt.Sprintf("/api/v1/users/%d/roles", globalTarget), map[string]any{
			"manual_roles": []string{"user", "asset_admin"},
		})
		require.Equal(t, http.StatusOK, c, "%v", out)
		d := detail(latestAlert())
		assert.Equal(t, "management_role_granted", d["alert_type"])
		assert.NotContains(t, d, "scope_nodes")
		assert.NotContains(t, d["params"], "scope_node_ids")
	})
}
