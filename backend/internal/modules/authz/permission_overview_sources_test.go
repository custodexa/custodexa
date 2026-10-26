package authz

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

var overviewSourceKinds = []string{OverviewSourceDirect, OverviewSourceMapped, OverviewSourceGroup, OverviewSourceCompatDefault, OverviewSourceAgentFixed}

func sourceKeys(t *testing.T, s OverviewSource) []string {
	t.Helper()
	keys := []string{}
	for k := range jsonMap(t, s) {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sourcesOfKind(m OverviewManagement, kind string) []OverviewSource {
	var out []OverviewSource
	for _, s := range m.Sources {
		if s.Kind == kind {
			out = append(out, s)
		}
	}
	return out
}

// 管理者來源只有「管理者指派」：JSON 以 source_ref 以外的內容比較時，三種形成 both 的途徑逐欄相同。
func directWithoutRef(t *testing.T, s OverviewSource) string {
	t.Helper()
	m := jsonMap(t, s)
	delete(m, "source_ref")
	b, err := json.Marshal(m)
	require.NoError(t, err)
	return string(b)
}

// TestPermissionOverviewSources 五種來源、both 拆兩個來源、管理者指派不帶指派者、日期與固定標示。
func TestPermissionOverviewSources(t *testing.T) {
	t.Run("manual 只產生 direct，mapped 只產生 mapped，both 各一個", func(t *testing.T) {
		e := newOvEnv(t)
		viewer := e.globalViewer()
		manual, mapped, both := e.user("ov-m"), e.user("ov-p"), e.user("ov-b")
		e.assign(manual.ID, model.BuiltinAuditor, model.RoleSourceManual)
		e.assign(mapped.ID, model.BuiltinAuditor, model.RoleSourceMapped)
		e.assign(both.ID, model.BuiltinAuditor, model.RoleSourceBoth)
		count := func(u *model.User) (d, m int) {
			ms := e.overview(viewer, u).Management
			for _, s := range ms.Sources {
				assert.Contains(t, overviewSourceKinds, s.Kind, "kind 值域只有五種")
			}
			return len(sourcesOfKind(ms, OverviewSourceDirect)), len(sourcesOfKind(ms, OverviewSourceMapped))
		}
		d, m := count(manual)
		assert.Equal(t, [2]int{1, 0}, [2]int{d, m})
		d, m = count(mapped)
		assert.Equal(t, [2]int{0, 1}, [2]int{d, m})
		d, m = count(both)
		assert.Equal(t, [2]int{1, 1}, [2]int{d, m})
	})

	t.Run("三種形成 both 的途徑產生相同的 direct 與 mapped 來源且不含指派者日期固定標示", func(t *testing.T) {
		e := newOvEnv(t)
		viewer := e.globalViewer()
		// 三種形成途徑的終態都是同一列 source=both：手動列之後被映射命中、映射賦予後經固定端點、映射賦予後經追加角色端點。
		// 概覽只讀這一列，故以模型層寫入各自的起點與終態；身分模組的端點行為由其自身測試覆蓋。
		byAssign, byPin, byAdd := e.user("ov-assign"), e.user("ov-pin"), e.user("ov-add")
		e.assign(byAssign.ID, model.BuiltinAuditor, model.RoleSourceManual)
		require.NoError(t, model.SetUserRoleSource(e.db, byAssign.ID, e.roles[model.BuiltinAuditor], model.RoleSourceBoth))
		require.NoError(t, model.AssignUserRoleWithSource(e.db, byPin.ID, e.roles[model.BuiltinAuditor], model.RoleSourceMapped, model.RoleOriginSystem))
		require.NoError(t, model.SetUserRoleSource(e.db, byPin.ID, e.roles[model.BuiltinAuditor], model.RoleSourceBoth))
		require.NoError(t, model.AssignUserRoleWithSource(e.db, byAdd.ID, e.roles[model.BuiltinAuditor], model.RoleSourceMapped, model.RoleOriginSystem))
		require.NoError(t, model.SetUserRoleSource(e.db, byAdd.ID, e.roles[model.BuiltinAuditor], model.RoleSourceBoth))
		e.mappings.roles[e.roles[model.BuiltinAuditor]] = []OverviewRuleRef{{RuleID: 7, SourceName: "corp-oidc", ExternalGroup: "g-audit"}}

		var directs, mappeds []string
		for _, u := range []*model.User{byAssign, byPin, byAdd} {
			got := e.overview(viewer, u)
			ms := got.Management
			d, m := sourcesOfKind(ms, OverviewSourceDirect), sourcesOfKind(ms, OverviewSourceMapped)
			require.Len(t, d, 1)
			require.Len(t, m, 1)
			directs = append(directs, directWithoutRef(t, d[0]))
			mappeds = append(mappeds, directWithoutRef(t, m[0]))
			assert.ElementsMatch(t, []string{"effective_permissions", "ineffective", "kind", "role", "scope", "source_ref"}, sourceKeys(t, d[0]),
				"direct 來源的鍵集合恰為六個共同欄位")
			full := strings.ToLower(jsonOf(t, got))
			for _, banned := range []string{"granted_by", "granted_at", "established_by", "pinned", "assigner", "assigned_by", "assigned_at"} {
				assert.NotContains(t, full, banned)
			}
		}
		assert.Equal(t, directs[0], directs[1])
		assert.Equal(t, directs[0], directs[2])
		assert.Equal(t, mappeds[0], mappeds[1])
		assert.Equal(t, mappeds[0], mappeds[2])
	})

	t.Run("映射賦予帶規則編號、來源名與外部群組標籤", func(t *testing.T) {
		e := newOvEnv(t)
		viewer := e.globalViewer()
		u := e.user("ov-mapped")
		e.assign(u.ID, model.BuiltinAuditor, model.RoleSourceMapped)
		e.mappings.roles[e.roles[model.BuiltinAuditor]] = []OverviewRuleRef{{RuleID: 11, SourceName: "corp-ldap", ExternalGroup: "cn=auditors"}}
		ms := e.overview(viewer, u).Management
		m := sourcesOfKind(ms, OverviewSourceMapped)
		require.Len(t, m, 1)
		require.NotNil(t, m[0].MappingRules)
		assert.Equal(t, []OverviewRuleRef{{RuleID: 11, SourceName: "corp-ldap", ExternalGroup: "cn=auditors"}}, *m[0].MappingRules)
		assert.Nil(t, m[0].Group)
	})

	t.Run("經群組帶群組名與成員來源，成員經映射加入時附規則標籤", func(t *testing.T) {
		e := newOvEnv(t)
		fx := newOvFixture(e)
		viewer := e.globalViewer()
		manual, viaRule, both := e.user("ov-gm"), e.user("ov-gr"), e.user("ov-gb")
		g := e.group("ov-prod-group")
		e.groupRole(g.ID, model.BuiltinAssetAdmin, fx.nA)
		e.join(g.ID, manual.ID, true)
		e.join(g.ID, viaRule.ID, false)
		e.join(g.ID, both.ID, true)
		e.mappings.groups[g.ID] = []OverviewRuleRef{{RuleID: 3, SourceName: "corp-oidc", ExternalGroup: "ops"}}
		for _, c := range []struct {
			u      *model.User
			member string
			rules  int
		}{{manual, "both", 1}, {viaRule, "mapped", 1}, {both, "both", 1}} {
			// stub 對所有使用者回同一張表；成員旗標取自 user_group_members
			ms := e.overview(viewer, c.u).Management
			gs := sourcesOfKind(ms, OverviewSourceGroup)
			require.Len(t, gs, 1)
			require.NotNil(t, gs[0].Group)
			assert.Equal(t, "ov-prod-group", gs[0].Group.Name)
			assert.Equal(t, g.ID, gs[0].Group.ID)
			assert.Equal(t, c.member, gs[0].Group.MemberSource)
			assert.Len(t, gs[0].Group.MappingRules, c.rules)
		}
		// 沒有映射支持的手動成員
		e.mappings.groups[g.ID] = nil
		ms := e.overview(viewer, manual).Management
		gs := sourcesOfKind(ms, OverviewSourceGroup)
		require.Len(t, gs, 1)
		assert.Equal(t, "manual", gs[0].Group.MemberSource)
		assert.Empty(t, gs[0].Group.MappingRules)
	})

	t.Run("零角色為 compat_default，agent 為 agent_fixed", func(t *testing.T) {
		e := newOvEnv(t)
		viewer := e.globalViewer()
		zero, agent := e.user("ov-zero"), e.agent("ov-agent")
		ms := e.overview(viewer, zero).Management
		require.Len(t, ms.Sources, 1)
		assert.Equal(t, OverviewSourceCompatDefault, ms.Sources[0].Kind)
		assert.Nil(t, ms.Sources[0].Role)
		ms = e.overview(viewer, agent).Management
		require.Len(t, ms.Sources, 1)
		assert.Equal(t, OverviewSourceAgentFixed, ms.Sources[0].Kind)
	})

	t.Run("同一角色兼有直接與群組兩來源時合為一張卡、sources 兩筆", func(t *testing.T) {
		e := newOvEnv(t)
		fx := newOvFixture(e)
		viewer := e.globalViewer()
		u := e.user("ov-both-paths")
		e.assign(u.ID, model.BuiltinAssetAdmin, "", fx.nA)
		g := e.group("ov-both-paths-group")
		e.groupRole(g.ID, model.BuiltinAssetAdmin, fx.nB)
		e.join(g.ID, u.ID, true)
		ms := e.overview(viewer, u).Management
		require.Len(t, ms.Bindings, 1)
		assert.Len(t, ms.Sources, 2)
		assert.Equal(t, []string{ms.Sources[0].SourceRef, ms.Sources[1].SourceRef}, ms.Bindings[0].SourceRefs)
		require.NotNil(t, ms.Bindings[0].ManageableAssetCount)
		assert.Equal(t, int64(3), *ms.Bindings[0].ManageableAssetCount, "兩個來源範圍內的管理可視資產去重後共三台")
	})
}
