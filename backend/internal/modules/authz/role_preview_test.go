package authz

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEntryPagePathsCoverRouteEntryRules 擋：入口鏡像的路徑沒有歸屬、同一路徑被兩類同時認領、
// 跟隨或固定頁指向不存在的入口、警示頁少了入口 ID。
func TestEntryPagePathsCoverRouteEntryRules(t *testing.T) {
	direct := map[string][]string{}
	for id, path := range EntryPagePaths() {
		direct[path] = append(direct[path], id)
	}
	followed, fixed := FollowedPagePaths(), FixedPagePaths()
	personal := map[string]bool{}
	for _, p := range PersonalQualificationPaths() {
		personal[p] = true
	}
	descriptor := map[string]EntryDescriptor{}
	for _, e := range EntryDescriptors() {
		descriptor[e.ID] = e
	}

	t.Run("入口鏡像每條路徑恰好歸一類", func(t *testing.T) {
		rules := RouteEntryRules()
		require.Len(t, rules, 36)
		unowned := 0
		for _, r := range rules {
			n := 0
			if len(direct[r.Path]) > 0 {
				n++
			}
			if followed[r.Path] != "" {
				n++
			}
			if fixed[r.Path] != "" {
				n++
			}
			if personal[r.Path] {
				n++
			}
			if n == 0 {
				unowned++
				t.Errorf("路徑 %s 沒有歸屬", r.Path)
			} else if n > 1 {
				t.Errorf("路徑 %s 同時被 %d 類認領", r.Path, n)
			}
		}
		assert.Equal(t, 0, unowned)
	})

	t.Run("對照表裡的路徑都在入口鏡像內", func(t *testing.T) {
		inMirror := map[string]bool{}
		for _, r := range RouteEntryRules() {
			inMirror[r.Path] = true
		}
		all := []string{}
		for p := range direct {
			all = append(all, p)
		}
		for p := range followed {
			all = append(all, p)
		}
		for p := range fixed {
			all = append(all, p)
		}
		for p := range personal {
			all = append(all, p)
		}
		for _, p := range all {
			assert.True(t, inMirror[p], "%s 不在入口鏡像", p)
		}
	})

	t.Run("警示頁對三個入口", func(t *testing.T) {
		ids := direct["/alerts"]
		sort.Strings(ids)
		assert.Equal(t, []string{"alert_rules", "alerts", "system_alerts"}, ids)
	})

	t.Run("跟隨規則", func(t *testing.T) {
		for _, p := range []string{"/audit/workbench", "/audit/agent-tasks", "/audit/exports", "/commands"} {
			assert.Equal(t, "audit_logs", followed[p], p)
		}
		assert.Equal(t, "change_secret", followed["/change-secret-batches"])
		assert.Equal(t, "security_policies", followed["/access-control"])
		assert.Len(t, followed, 6)
		for p, id := range followed {
			d, ok := descriptor[id]
			require.True(t, ok, "%s 跟隨不存在的入口 %s", p, id)
			assert.Equal(t, PlacementPage, d.PlacementKind(), "%s 跟隨的 %s 不是頁面入口", p, id)
		}
	})

	t.Run("固定頁與個人資格頁", func(t *testing.T) {
		fixedEntries := map[string]bool{}
		for _, id := range FixedEntries() {
			fixedEntries[id] = true
		}
		for p, id := range fixed {
			assert.True(t, fixedEntries[id], "%s 的固定入口 %s 不在 FixedEntries", p, id)
		}
		assert.Len(t, fixed, 5)
		assert.Equal(t, []string{"/approvals", "/my-agents"}, PersonalQualificationPaths())
	})
}

func previewPerms(ks ...string) []string { return ks }

// TestRolePreviewCapabilities 擋：預覽集合與真正只持此角色者的目前使用者投影分岔、個人資格被帶入、
// 頁面狀態與摘要判定分家、超管可預覽、回應夾帶範圍或資料、預覽依角色名稱判定。
func TestRolePreviewCapabilities(t *testing.T) {
	t.Run("與只持該角色一筆全域指派者的目前使用者投影逐鍵相同", func(t *testing.T) {
		db := newRoleDefDB(t)
		type roleCase struct {
			name       string
			builtinKey string
			version    int64
			perms      []string
		}
		cases := []roleCase{}
		for _, key := range []string{model.BuiltinAuditor, model.BuiltinUser, model.BuiltinApprover,
			model.BuiltinIdentityAdmin, model.BuiltinSecurityAdmin, model.BuiltinAssetAdmin, model.BuiltinAuthzAdmin} {
			cases = append(cases, roleCase{name: "builtin-" + key, builtinKey: key, version: 1})
		}
		cases = append(cases,
			roleCase{name: "R1", version: 1, perms: previewPerms("asset:view", "asset:create", "asset:update", "asset:delete", "asset:test", "assetgroup:manage", "session:view")},
			roleCase{name: "empty", version: 1},
			roleCase{name: "with-global-only", version: 1, perms: previewPerms("asset:view", "securitypolicy:manage", "role:view")},
		)
		for _, c := range cases {
			var role *model.Role
			if c.builtinKey != "" {
				role = mkRole(t, db, c.name, c.builtinKey)
			} else {
				ps := make([]Permission, len(c.perms))
				for i, k := range c.perms {
					ps[i] = Permission(k)
				}
				role = mkCustomRole(t, db, c.name, ps...)
			}
			u := model.User{Username: "u-" + c.name, Active: true}
			require.NoError(t, db.Create(&u).Error)
			assignDirect(t, db, u.ID, role.ID, model.ScopeKindGlobal)
			p, err := NewResolver(db).ResolveUser(u.ID, TokenFacts{SubjectKind: model.KindHuman})
			require.NoError(t, err)
			real := ProjectCapabilitiesWithNodePaths(p, ProjectionInputs{}, nil).Permissions

			got := PreviewRole(c.builtinKey, c.version, c.perms)
			require.True(t, got.Previewable, c.name)
			assert.Equal(t, real, got.Permissions, "%s 的預覽集合與實際使用者投影不同", c.name)
			assert.NotContains(t, got.Permissions, UIMyAgents, c.name)
			assert.NotContains(t, got.Permissions, UIConnectBypass, c.name)
			assert.NotContains(t, got.Permissions, UISuperAdmin, c.name)
			if c.builtinKey == model.BuiltinApprover {
				assert.NotContains(t, got.Permissions, UIApprovals, "審核資格是個人資格，不來自角色")
			}
		}
	})

	t.Run("頁面狀態與摘要判定同源", func(t *testing.T) {
		pages := EntryPagePaths()
		followed, fixed := FollowedPagePaths(), FixedPagePaths()
		rank := map[string]int{PreviewStateManage: 3, PreviewStateRead: 2, PreviewStateAvailable: 1}
		toState := func(level string) string {
			switch level {
			case StateManage, statePartial:
				return PreviewStateManage
			case StateRead:
				return PreviewStateRead
			}
			return PreviewStateAvailable
		}
		check := func(name string, builtinKey string, perms []string) {
			got := PreviewRole(builtinKey, 1, perms)
			require.True(t, got.Previewable, name)
			held := map[string]bool{}
			for _, k := range got.Permissions {
				held[k] = true
			}
			caps := []Permission{}
			for _, k := range got.Permissions {
				if !strings.HasPrefix(k, UIPrefix) {
					caps = append(caps, Permission(k))
				}
			}
			sum := SummarizeRole(caps)
			want := map[string]string{} // 路徑 → 狀態
			for _, r := range RouteEntryRules() {
				if !r.satisfiedBy(func(k string) bool { return held[k] }) {
					continue
				}
				best := ""
				for id, path := range pages {
					if path != r.Path {
						continue
					}
					s := toState(summaryLevelOf(sum, id))
					if best == "" || rank[s] > rank[best] {
						best = s
					}
				}
				switch {
				case best != "":
					want[r.Path] = best
				case followed[r.Path] != "":
					want[r.Path] = toState(summaryLevelOf(sum, followed[r.Path]))
				case fixed[r.Path] != "":
					want[r.Path] = PreviewStateAvailable
				}
			}
			gotMap := map[string]string{}
			seen := map[string]bool{}
			for _, e := range got.EntryStates {
				assert.False(t, seen[e.Path], "%s 路徑重複 %s", name, e.Path)
				seen[e.Path] = true
				gotMap[e.Path] = e.State
			}
			assert.Equal(t, want, gotMap, name)
			assert.NotContains(t, gotMap, "/approvals", name)
			assert.NotContains(t, gotMap, "/my-agents", name)
			assert.True(t, sort.SliceIsSorted(got.EntryStates, func(i, j int) bool { return got.EntryStates[i].Path < got.EntryStates[j].Path }), name)
		}
		for _, key := range []string{model.BuiltinAuditor, model.BuiltinUser, model.BuiltinApprover,
			model.BuiltinIdentityAdmin, model.BuiltinSecurityAdmin, model.BuiltinAssetAdmin, model.BuiltinAuthzAdmin} {
			check("builtin-"+key, key, nil)
		}
		check("empty", "", nil)
		check("R1", "", previewPerms("asset:view", "asset:create", "asset:update", "asset:delete", "asset:test", "assetgroup:manage", "session:view"))
	})

	t.Run("判定案例表逐列", func(t *testing.T) {
		stateOf := func(perms []string, path string) (PreviewEntryState, bool) {
			for _, e := range PreviewRole("", 1, perms).EntryStates {
				if e.Path == path {
					return e, true
				}
			}
			return PreviewEntryState{}, false
		}
		cases := []struct {
			name  string
			perms []string
			path  string
			want  string
		}{
			{"完整管理", previewPerms("asset:view", "asset:create", "asset:update", "asset:delete", "asset:test", "assetgroup:manage", "session:view"), "/assets", PreviewStateManage},
			{"部分管理", previewPerms("asset:view", "asset:update"), "/assets", PreviewStateManage},
			{"完整讀取憑證庫", previewPerms("asset:view", "credential:view"), "/credentials", PreviewStateRead},
			{"完整讀取資產", previewPerms("asset:view", "credential:view"), "/assets", PreviewStateRead},
			{"Hidden 回退入口鏡像放行", previewPerms("credential:view"), "/credentials", PreviewStateAvailable},
			{"Hidden 回退登入即可見", previewPerms("session:view"), "/assets", PreviewStateAvailable},
			{"自有唯讀說明", previewPerms("policygroup:view"), "/policy-groups", PreviewStateRead},
		}
		for _, c := range cases {
			e, ok := stateOf(c.perms, c.path)
			require.True(t, ok, "%s: %s 未列出", c.name, c.path)
			assert.Equal(t, c.want, e.State, c.name)
		}
		// 只持 audit:view：/alerts 單筆，四個稽核頁跟隨 audit_logs
		prev := PreviewRole("", 1, previewPerms("audit:view"))
		count := 0
		for _, e := range prev.EntryStates {
			if e.Path == "/alerts" {
				count++
			}
		}
		assert.Equal(t, 1, count)
		owner, ok := stateOf(previewPerms("audit:view"), "/audit-logs")
		require.True(t, ok)
		for _, path := range []string{"/audit/workbench", "/audit/agent-tasks", "/audit/exports", "/commands"} {
			e, ok := stateOf(previewPerms("audit:view"), path)
			require.True(t, ok, path)
			assert.Equal(t, "audit_logs", e.Entry, path)
			assert.Equal(t, owner.State, e.State, "%s 的狀態跟隨 audit_logs", path)
		}
		// 不持 session:view 之外的集合進不了不相關的頁
		_, ok = stateOf(previewPerms("session:view"), "/users")
		assert.False(t, ok, "入口鏡像不放行的頁不列")
	})

	t.Run("超管角色不可預覽且兩陣列為空", func(t *testing.T) {
		got := PreviewRole(model.BuiltinSuperAdmin, 1, nil)
		assert.False(t, got.Previewable)
		assert.Equal(t, PreviewReasonReservedSuperAdmin, got.Reason)
		require.NotNil(t, got.Permissions)
		require.NotNil(t, got.EntryStates)
		assert.Empty(t, got.Permissions)
		assert.Empty(t, got.EntryStates)
		// 持有目錄全部權限點的自訂角色不是超管，照常預覽
		all := []string{}
		for _, k := range CatalogKeys() {
			all = append(all, string(k))
		}
		custom := PreviewRole("", 1, all)
		assert.True(t, custom.Previewable)
		assert.NotContains(t, custom.Permissions, UISuperAdmin)
		// 其他內建角色可預覽
		assert.True(t, PreviewRole(model.BuiltinAuditor, 1, nil).Previewable)
	})

	t.Run("回應不含範圍或資料", func(t *testing.T) {
		got := PreviewRole("", 1, previewPerms("asset:view", "session:view", "audit:view"))
		b, err := json.Marshal(map[string]any{"permissions": got.Permissions, "entry_states": got.EntryStates})
		require.NoError(t, err)
		for _, banned := range []string{"scope_summary", "nodes", "binding_scope"} {
			assert.NotContains(t, string(b), banned)
		}
	})

	t.Run("目錄外的鍵不授權", func(t *testing.T) {
		got := PreviewRole("", 1, previewPerms("asset:view", "no:such-key"))
		assert.NotContains(t, got.Permissions, "no:such-key")
		assert.Contains(t, got.Permissions, "asset:view")
	})

	t.Run("無內建識別且版本為零的列不取得能力", func(t *testing.T) {
		got := PreviewRole("", 0, previewPerms("asset:view"))
		assert.NotContains(t, got.Permissions, "asset:view", "與正式解析相同：未納管的舊列不憑儲存的鍵授權")
	})
}
