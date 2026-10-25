package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"context"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
)

// roleDefinitionReadRoutes 本階段宣告的四條角色定義讀取路由（逐條列名）。
var roleDefinitionReadRoutes = [][2]string{
	{"GET", "/api/v1/role-definitions"},
	{"GET", "/api/v1/role-definitions/descriptors"},
	{"GET", "/api/v1/role-definitions/:id"},
	{"POST", "/api/v1/role-definitions/summary"},
}

// TestRoleDefinitionRoutes 擋：讀取路由缺登錄或登錄錯能力、無檢視能力者讀到內容、列表與投影分岔、
// 描述與 authz 描述表分岔、草稿摘要寫了資料、舊 GET /roles 形狀被新增的角色改變。
func TestRoleDefinitionRoutes(t *testing.T) {
	t.Run("四條讀取路由在登錄表、agent 登錄（預設拒絕）與路由清冊都有", func(t *testing.T) {
		routes, _ := buildRouter(t, "release", true)
		for _, r := range roleDefinitionReadRoutes {
			e, ok := authz.LookupRoute(r[0], r[1])
			require.True(t, ok, "%s %s 未登錄", r[0], r[1])
			assert.Equal(t, authz.BasePerm, e.Base)
			assert.Equal(t, authz.PermRoleView, e.Perm)
			allowed, registered := middleware.AgentRouteDecision(r[0], r[1])
			assert.True(t, registered, "%s %s 未在 agent 路由登錄", r[0], r[1])
			assert.False(t, allowed, "%s %s 不得開放給 agent", r[0], r[1])
			_, inInventory := routes[[2]string{r[0], r[1]}]
			assert.True(t, inInventory, "%s %s 不在路由清冊", r[0], r[1])
		}
	})

	env := newBaselineEnv(t)
	k := model.BuiltinIdentityAdmin
	var idRole model.Role
	if err := env.db.Where("name = ?", "identity_admin").First(&idRole).Error; err != nil {
		idRole = model.Role{Name: "identity_admin", BuiltinKey: &k, DefinitionVersion: 1}
		require.NoError(t, env.db.Create(&idRole).Error)
	}
	ida := env.createUser("defs-ida", nil)
	require.NoError(t, model.AssignUserRoleWithSource(env.db, ida, idRole.ID, model.RoleSourceManual, model.RoleOriginSystem))
	env.subjects["IDA"] = &baselineSubject{ID: "IDA", Username: "defs-ida", UserID: ida, Kind: "session", Token: env.issueSessionToken(ida)}

	raw := func(subject, method, path string, body any) (int, []byte) {
		var rd *strings.Reader
		if body != nil {
			b, err := json.Marshal(body)
			require.NoError(t, err)
			rd = strings.NewReader(string(b))
		} else {
			rd = strings.NewReader("")
		}
		req := httptest.NewRequest(method, path, rd)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if tok := env.subjects[subject].Token; tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		w := env.serve(req)
		return w.Code, w.Body.Bytes()
	}
	get := func(subject, path string) (int, map[string]any) {
		c, b := raw(subject, "GET", path, nil)
		out := map[string]any{}
		_ = json.Unmarshal(b, &out)
		return c, out
	}
	rows := func(out map[string]any) map[uint]map[string]any {
		m := map[uint]map[string]any{}
		list, _ := out["data"].([]any)
		for _, r := range list {
			row := r.(map[string]any)
			m[uint(row["id"].(float64))] = row
		}
		return m
	}

	defs := identity.NewRoleDefinitionService(env.db, audit.NewTxSink(), identity.NewPermissionChainEventWriter(),
		identity.NewGrantGrader(audit.NewTxSink(), audit.NewSystemAlertSink(nil)))
	super := env.subjects["S01"].UserID
	ctx := context.Background()
	custom, err := defs.Create(ctx, super, identity.RoleInput{Name: "route-custom", Permissions: []string{"asset:view", "asset:update"}})
	require.NoError(t, err)

	t.Run("無角色檢視能力者四條都被拒，未登入為 401", func(t *testing.T) {
		for _, sub := range []string{"S02", "S03"} {
			for _, r := range roleDefinitionReadRoutes {
				path := strings.Replace(r[1], ":id", fmt.Sprint(custom.ID), 1)
				var body any
				if r[0] == "POST" {
					body = map[string]any{"permissions": []string{}}
				}
				c, b := raw(sub, r[0], path, body)
				assert.Equal(t, http.StatusForbidden, c, "%s %s %s", sub, r[0], r[1])
				assert.NotContains(t, string(b), "route-custom", "拒絕回應不含角色內容")
			}
		}
		c, _ := raw("S00", "GET", "/api/v1/role-definitions", nil)
		assert.Equal(t, http.StatusUnauthorized, c)
	})

	t.Run("列表每列欄位與投影逐列相同，每列 summary 與單筆讀取相同", func(t *testing.T) {
		c, out := get("S01", "/api/v1/role-definitions")
		require.Equal(t, http.StatusOK, c, "%v", out)
		got := rows(out)
		assert.EqualValues(t, len(got), out["total"])
		assert.Equal(t, true, out["can_define"])

		// 對照的投影器與路由同用正式組裝的關卡（目標集合以實際注入為準）
		proj := identity.NewRoleProjector(env.db, newMappingAssignmentGuard())
		set, err := proj.ProjectRoles(super)
		require.NoError(t, err)
		require.Equal(t, len(set.ByRole), len(got))
		for id, want := range set.ByRole {
			row, ok := got[id]
			require.True(t, ok, "角色 %d 不在列表", id)
			wb, err := json.Marshal(want)
			require.NoError(t, err)
			var wm map[string]any
			require.NoError(t, json.Unmarshal(wb, &wm))
			for key, v := range wm {
				assert.Equal(t, v, row[key], "角色 %d 欄位 %s", id, key)
			}
			for _, key := range []string{"id", "name", "description", "builtin_key", "locked", "definition_version", "template_role_id", "summary"} {
				assert.Contains(t, row, key, "角色 %d 缺 %s", id, key)
			}
			cs, one := get("S01", fmt.Sprintf("/api/v1/role-definitions/%d", id))
			require.Equal(t, http.StatusOK, cs)
			assert.Equal(t, one["summary"], row["summary"], "角色 %d 的 summary 與單筆相同", id)
		}
		assert.Contains(t, got, custom.ID)
	})

	t.Run("狀態：超管在相容目錄下系統安全管理員、新範本與自訂角色未開放；非超管看到超管與安全管理員受保護", func(t *testing.T) {
		_, out := get("S01", "/api/v1/role-definitions")
		got := rows(out)
		state := func(name string) string {
			for _, r := range got {
				if r["name"] == name {
					return r["assignment_state"].(string)
				}
			}
			t.Fatalf("列表缺 %s", name)
			return ""
		}
		// 投影器直接取狀態（明示注入的那一種目錄用）
		projected := func(t *testing.T, g *identity.AssignmentGuard, id uint) string {
			set, err := identity.NewRoleProjector(env.db, g).ProjectRoles(super)
			require.NoError(t, err)
			p, ok := set.ByRole[id]
			require.True(t, ok, "投影缺角色 %d", id)
			return p.AssignmentState
		}
		assembledFull := assembledCatalogIsFull()

		t.Run("相容目錄（"+catalogVia(false)+"）", func(t *testing.T) {
			if !assembledFull {
				assert.Equal(t, identity.AssignmentStateNotOpen, state("identity_admin"))
				assert.Equal(t, identity.AssignmentStateNotOpen, state("route-custom"))
				assert.Equal(t, identity.AssignmentStateOpen, state(model.RoleAuditor))
				assert.Equal(t, identity.AssignmentStateOpen, state(model.RoleAdmin))
				return
			}
			compat := identity.NewAssignmentGuard(identity.CompatCatalog())
			assert.Equal(t, identity.AssignmentStateNotOpen, projected(t, compat, idRole.ID))
			assert.Equal(t, identity.AssignmentStateNotOpen, projected(t, compat, custom.ID))
			assert.Equal(t, identity.AssignmentStateOpen, projected(t, compat, env.roleID(model.RoleAuditor)))
			assert.Equal(t, identity.AssignmentStateOpen, projected(t, compat, env.roleID(model.RoleAdmin)))
		})

		t.Run("完整目錄（"+catalogVia(true)+"）", func(t *testing.T) {
			if assembledFull {
				assert.Equal(t, true, out["can_define"])
				for _, name := range []string{"identity_admin", "route-custom", model.RoleAuditor, model.RoleAdmin} {
					assert.Equal(t, identity.AssignmentStateOpen, state(name), name)
				}
				return
			}
			fullGuard := identity.NewAssignmentGuard(identity.FullCatalog())
			for _, id := range []uint{idRole.ID, custom.ID, env.roleID(model.RoleAuditor), env.roleID(model.RoleAdmin)} {
				assert.Equal(t, identity.AssignmentStateOpen, projected(t, fullGuard, id), "角色 %d", id)
			}
		})

		c, out := get("IDA", "/api/v1/role-definitions")
		require.Equal(t, http.StatusOK, c, "%v", out)
		assert.Equal(t, false, out["can_define"])
		for _, r := range rows(out) {
			if r["builtin_key"] == model.BuiltinSuperAdmin || r["builtin_key"] == model.BuiltinSecurityAdmin {
				assert.Equal(t, identity.AssignmentStateProtected, r["assignment_state"], "%v", r["name"])
			}
		}

		// 完整目錄：同一個投影器換注入的目標集合，全部開放且超管可定義
		full := identity.NewRoleProjector(env.db, identity.NewAssignmentGuard(identity.FullCatalog()))
		set, err := full.ProjectRoles(super)
		require.NoError(t, err)
		assert.True(t, set.CanDefine)
		for id, p := range set.ByRole {
			assert.Equal(t, identity.AssignmentStateOpen, p.AssignmentState, "角色 %d", id)
		}
	})

	t.Run("編輯描述的三組與描述表逐項相同，獨立能力的 ID 集合等於凍結清單", func(t *testing.T) {
		c, out := get("IDA", "/api/v1/role-definitions/descriptors")
		require.Equal(t, http.StatusOK, c, "%v", out)
		entries, _ := out["entries"].([]any)
		want := authz.EntryDescriptors()
		require.Len(t, entries, len(want))
		for i, w := range want {
			e := entries[i].(map[string]any)
			assert.Equal(t, w.ID, e["id"])
			assert.Equal(t, authz.EntryNodeScopable(w), e["scopable"], w.ID)
			assert.Equal(t, string(w.Group), e["group"])
			states := e["states"].([]any)
			require.Len(t, states, len(w.States), w.ID)
			for j, s := range w.States {
				sv := states[j].(map[string]any)
				assert.Equal(t, s.Name, sv["name"], w.ID)
				var keys []string
				for _, kk := range sv["keys"].([]any) {
					keys = append(keys, kk.(string))
				}
				var wantKeys []string
				for _, kk := range s.Keys {
					wantKeys = append(wantKeys, string(kk))
				}
				assert.Equal(t, wantKeys, keys, "%s/%s", w.ID, s.Name)
			}
			details := e["details"].([]any)
			require.Len(t, details, len(w.Details), w.ID)
			for j, d := range w.Details {
				assert.Equal(t, map[string]any{"id": d.ID, "key": string(d.Key), "scopable": authz.PermissionScopeEnforced(d.Key)}, details[j])
			}
		}
		caps, _ := out["capabilities"].([]any)
		wantCaps := authz.CapabilityDescriptors()
		require.Len(t, caps, len(wantCaps))
		ids := map[string]bool{}
		for i, w := range wantCaps {
			cv := caps[i].(map[string]any)
			assert.Equal(t, map[string]any{"id": w.ID, "key": string(w.Key), "trust_hint": w.TrustHint, "requires_entry": w.RequiresEntry,
				"scopable": authz.PermissionScopeEnforced(w.Key)}, cv)
			ids[w.ID] = true
		}
		assert.Equal(t, map[string]bool{"role_assign": true, "access_policy_override": true, "recording_delete": true}, ids)
		var fixed []string
		for _, f := range out["fixed_entries"].([]any) {
			fixed = append(fixed, f.(string))
		}
		assert.Equal(t, authz.FixedEntries(), fixed)
	})
	t.Run("編輯描述每個入口帶 write_keys，列表與單筆的 summary 帶 partial", func(t *testing.T) {
		c, out := get("IDA", "/api/v1/role-definitions/descriptors")
		require.Equal(t, http.StatusOK, c, "%v", out)
		entries, _ := out["entries"].([]any)
		for i, w := range authz.EntryDescriptors() {
			e := entries[i].(map[string]any)
			raw, ok := e["write_keys"].([]any)
			require.True(t, ok, "%s 缺 write_keys", w.ID)
			var got []string
			for _, k := range raw {
				got = append(got, k.(string))
			}
			want := []string{}
			for _, k := range authz.EntryWriteKeys(w) {
				want = append(want, string(k))
			}
			assert.Equal(t, want, append([]string{}, got...), w.ID)
		}
		cl, list := get("S01", "/api/v1/role-definitions")
		require.Equal(t, http.StatusOK, cl)
		for id, row := range rows(list) {
			sum, _ := row["summary"].(map[string]any)
			_, has := sum["partial"].([]any)
			assert.True(t, has, "角色 %d 的 summary 缺 partial 陣列", id)
		}
	})

	t.Run("單筆：權限鍵、版本、摘要與缺依賴；查無回 404、非數字 ID 回 400", func(t *testing.T) {
		c, one := get("IDA", fmt.Sprintf("/api/v1/role-definitions/%d", custom.ID))
		require.Equal(t, http.StatusOK, c, "%v", one)
		assert.Equal(t, []any{"asset:update", "asset:view"}, one["permissions"])
		assert.EqualValues(t, 1, one["definition_version"])
		for _, key := range []string{"summary", "missing_dependencies", "blocked_screens", "template_role_id", "builtin_key"} {
			assert.Contains(t, one, key)
		}
		c, _ = get("IDA", "/api/v1/role-definitions/999999")
		assert.Equal(t, http.StatusNotFound, c)
		c, _ = get("IDA", "/api/v1/role-definitions/abc")
		assert.Equal(t, http.StatusBadRequest, c)
	})

	t.Run("草稿摘要回傳缺少依賴，呼叫前後角色、版本與審計列數不變", func(t *testing.T) {
		snap := func() (roles int64, perms int64, ver int64, audits int64, rv int64) {
			require.NoError(t, env.db.Unscoped().Model(&model.Role{}).Count(&roles).Error)
			require.NoError(t, env.db.Model(&model.RolePermission{}).Count(&perms).Error)
			v, err := authz.CurrentVersion(env.db)
			require.NoError(t, err)
			require.NoError(t, env.db.Model(&model.AuditLog{}).Where("action IN ?", []model.AuditAction{
				model.ActionRoleDefinitionCreate, model.ActionRoleDefinitionCopy, model.ActionRoleDefinitionUpdate, model.ActionRoleDefinitionDelete,
			}).Count(&audits).Error)
			var d model.Role
			require.NoError(t, env.db.First(&d, custom.ID).Error)
			return roles, perms, v, audits, d.DefinitionVersion
		}
		r0, p0, v0, a0, rv0 := snap()
		const summaryPath = "/api/v1/role-definitions/summary"
		summaryRows := func(action model.AuditAction) int64 {
			var n int64
			require.NoError(t, env.db.Model(&model.AuditLog{}).
				Where("method = ? AND path = ? AND action = ? AND resource = ?", "POST", summaryPath, action, model.ResourceRole).
				Count(&n).Error)
			return n
		}
		readBefore, createBefore := summaryRows(model.ActionRead), summaryRows(model.ActionCreate)
		draft := []string{"asset:update"}
		c, b := raw("IDA", "POST", "/api/v1/role-definitions/summary", map[string]any{"permissions": draft})
		require.Equal(t, http.StatusOK, c, string(b))
		var out struct {
			Summary             map[string]any            `json:"summary"`
			MissingDependencies []authz.MissingDependency `json:"missing_dependencies"`
			BlockedScreens      []authz.BlockedScreen     `json:"blocked_screens"`
		}
		require.NoError(t, json.Unmarshal(b, &out))
		perms, err := authz.NormalizeRolePermissions(draft)
		require.NoError(t, err)
		wantMissing := authz.MissingDependencies(perms)
		require.NotEmpty(t, wantMissing, "夾具應有缺依賴")
		assert.Equal(t, wantMissing, out.MissingDependencies)
		assert.Equal(t, authz.BlockedScreens(perms), out.BlockedScreens)
		assert.Contains(t, out.Summary, "manage")
		r1, p1, v1, a1, rv1 := snap()
		assert.Equal(t, []int64{r0, p0, v0, a0, rv0}, []int64{r1, p1, v1, a1, rv1})

		// 請求本身仍留痕，但動作是讀取，不得出現同一請求的建立角色列（審計為非同步，輪詢等待）
		require.Eventually(t, func() bool { return summaryRows(model.ActionRead) == readBefore+1 },
			5*time.Second, 50*time.Millisecond, "草稿摘要請求應留下一列 read/role")
		time.Sleep(200 * time.Millisecond)
		assert.Equal(t, createBefore, summaryRows(model.ActionCreate), "草稿摘要不得被記成 create/role")
		assert.Equal(t, readBefore+1, summaryRows(model.ActionRead))

		// 未列的頂層鍵與不合法的權限鍵：400，且不寫入
		c, _ = raw("IDA", "POST", "/api/v1/role-definitions/summary", map[string]any{"permissions": draft, "scope": "global"})
		assert.Equal(t, http.StatusBadRequest, c)
		c, b = raw("IDA", "POST", "/api/v1/role-definitions/summary", map[string]any{"permissions": []string{"no:such"}})
		assert.Equal(t, http.StatusBadRequest, c)
		assert.Contains(t, string(b), string(apierror.CodeRolePermissionInvalid))
		assert.NotContains(t, string(b), "no:such")

		// 本文必須恰為一份 JSON 物件：多餘的右括號、串接第二份 JSON 都拒絕；合法本文仍通過
		for name, body := range map[string]string{
			"多一個右大括號": `{"permissions":[]}}`,
			"多一個右中括號": `{"permissions":[]}]`,
			"串接第二份":   `{"permissions":[]}{"permissions":[]}`,
			"尾端垃圾":    `{"permissions":[]} x`,
		} {
			req := httptest.NewRequest("POST", summaryPath, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+env.subjects["IDA"].Token)
			w := env.serve(req)
			assert.Equal(t, http.StatusBadRequest, w.Code, name)
		}
		req := httptest.NewRequest("POST", summaryPath, strings.NewReader("{\"permissions\":[]}\n"))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+env.subjects["IDA"].Token)
		assert.Equal(t, http.StatusOK, env.serve(req).Code, "尾端空白換行仍視為合法")
	})

	t.Run("新增自訂角色前後，舊 GET /roles 回應逐位元組相同", func(t *testing.T) {
		c0, before := raw("S01", "GET", "/api/v1/roles", nil)
		require.Equal(t, http.StatusOK, c0)
		_, err := defs.Create(ctx, super, identity.RoleInput{Name: "route-custom-2", Permissions: []string{"asset:view"}})
		require.NoError(t, err)
		c1, after := raw("S01", "GET", "/api/v1/roles", nil)
		require.Equal(t, http.StatusOK, c1)
		assert.Equal(t, string(before), string(after))
		assert.NotContains(t, string(after), "route-custom")
	})

	t.Run("GET /users/:id 頂層帶 account_ops，data 與 role_sets 仍在", func(t *testing.T) {
		target := env.subjects["S06"].UserID // 超管（直接）
		c, out := get("IDA", fmt.Sprintf("/api/v1/users/%d", target))
		require.Equal(t, http.StatusOK, c, "%v", out)
		assert.Contains(t, out, "data")
		assert.Contains(t, out, "role_sets")
		ops, ok := out["account_ops"].(map[string]any)
		require.True(t, ok, "%v", out)
		assert.Len(t, ops, len(identity.AccountOpKeys))
		assert.Equal(t, identity.AccountOpClassSuperOnly, ops["set_password"])
		c, out = get("S01", fmt.Sprintf("/api/v1/users/%d", target))
		require.Equal(t, http.StatusOK, c)
		assert.Equal(t, identity.AccountOpClassAllowed, out["account_ops"].(map[string]any)["set_password"])
		// 列表不加
		c, out = get("S01", "/api/v1/users")
		require.Equal(t, http.StatusOK, c)
		assert.NotContains(t, out, "account_ops")
	})

	runRoleDefinitionWriteRouteCases(t, env)
}
