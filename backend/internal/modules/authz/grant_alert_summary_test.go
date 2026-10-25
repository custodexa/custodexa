package authz

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
)

// TestManagementGrantParamsNodeScope 擋：管理類發放事件把節點範圍壓成 "nodes" 字樣、丟掉節點編號。
func TestManagementGrantParamsNodeScope(t *testing.T) {
	nodes := func(role uint, ids ...uint) GrantEntry {
		return GrantEntry{Via: ViaDirect, RoleID: role, RoleName: "asset-mgr", Scope: model.ScopeKindNodes, Nodes: ids}
	}

	t.Run("兩個節點範圍項得到節點聯集與總數", func(t *testing.T) {
		p := ManagementGrantParams("replace", "ops-lee", []GrantEntry{nodes(4, 167), nodes(5, 158, 167)})
		assert.Equal(t, "158,167", p["scope_node_ids"])
		assert.Equal(t, "2", p["scope_node_count"])
		assert.Equal(t, "nodes", p["scope_summary"])
	})

	t.Run("純全域發放不帶節點鍵", func(t *testing.T) {
		g := GrantEntry{Via: ViaDirect, RoleID: 4, RoleName: "asset-mgr", Scope: model.ScopeKindGlobal}
		p := ManagementGrantParams("replace", "ops-lee", []GrantEntry{g})
		assert.NotContains(t, p, "scope_node_ids")
		assert.NotContains(t, p, "scope_node_count")
	})

	t.Run("全域與節點並存時只列節點項的節點", func(t *testing.T) {
		g := GrantEntry{Via: ViaDirect, RoleID: 9, RoleName: "other", Scope: model.ScopeKindGlobal}
		p := ManagementGrantParams("replace", "ops-lee", []GrantEntry{g, nodes(4, 7)})
		assert.Equal(t, "7", p["scope_node_ids"])
		assert.Equal(t, "1", p["scope_node_count"])
	})

	t.Run("節點很多時清單短於淨化上限、總數仍是實際數量", func(t *testing.T) {
		var ids []uint
		for i := uint(1000); i < 1150; i++ {
			ids = append(ids, i)
		}
		p := ManagementGrantParams("replace", "ops-lee", []GrantEntry{nodes(4, ids...)})
		assert.Equal(t, "150", p["scope_node_count"])
		list := p["scope_node_ids"]
		assert.Less(t, len([]rune(list)), notifycat.MaxOpaqueRunes)
		assert.Equal(t, list, notifycat.SanitizeOpaque(list), "清單不得被淨化截成殘缺編號")
		for _, part := range strings.Split(list, ",") {
			_, err := strconv.Atoi(part)
			assert.NoError(t, err, part)
		}
		assert.LessOrEqual(t, len(strings.Split(list, ",")), model.RangeAuditMaxNodes)
	})

	t.Run("外送模板：節點範圍帶編號與數量，全域不出現節點字樣", func(t *testing.T) {
		base := func(extra map[string]string) map[string]string {
			p := map[string]string{"actor": "ops-ida", "severity": "medium"}
			for k, v := range extra {
				p[k] = v
			}
			return p
		}
		scoped := base(ManagementGrantParams("replace", "ops-lee", []GrantEntry{nodes(4, 167), nodes(5, 158, 167)}))
		global := base(ManagementGrantParams("replace", "ops-lee",
			[]GrantEntry{{Via: ViaDirect, RoleID: 4, RoleName: "asset-mgr", Scope: model.ScopeKindGlobal}}))
		nodeWord := map[string]string{"zh-TW": "節點", "en-US": "nodes", "ja-JP": "ノード"}
		for _, lang := range []string{"zh-TW", "en-US", "ja-JP"} {
			_, withNodes := notifycat.Render(lang, notifycat.EventSystemAlertManagementRoleGranted, scoped)
			assert.Contains(t, withNodes, "158,167", lang)
			assert.Contains(t, withNodes, "2", lang)
			assert.Contains(t, withNodes, nodeWord[lang], lang)
			_, noNodes := notifycat.Render(lang, notifycat.EventSystemAlertManagementRoleGranted, global)
			assert.NotContains(t, noNodes, nodeWord[lang], lang)
			assert.NotContains(t, noNodes, "[", lang)
		}
	})
}
