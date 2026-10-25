package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
)

// roleDefinitionWriteRoutes 四條寫入路由（逐條列名）。
var roleDefinitionWriteRoutes = [][2]string{
	{"POST", "/api/v1/role-definitions"},
	{"POST", "/api/v1/role-definitions/:id/copy"},
	{"PUT", "/api/v1/role-definitions/:id"},
	{"DELETE", "/api/v1/role-definitions/:id"},
}

// runRoleDefinitionWriteRouteCases 經正式組裝的路由驗證四條寫入：登錄、超管成功、非超管拒絕、
// 缺依賴集合、禁止範本、嚴格本文、版本衝突、引用拒絕，以及預覽與實際修改的對照。
// 由 TestRoleDefinitionRoutes 呼叫，與讀取案例共用同一個環境。
func runRoleDefinitionWriteRouteCases(t *testing.T, env *baselineEnv) {
	f := newPreviewFixture(t, env)
	auditorID := env.roleID(model.RoleAuditor)
	adminID := env.roleID(model.RoleAdmin)

	// 持有全部可指派權限、但不是超級管理者的操作者
	var all []string
	for _, k := range authz.AssignableKeys() {
		all = append(all, string(k))
	}
	allRole := f.role("rw-all-assignable", all...)
	allUser := f.user("rw-all-user")
	f.hold(allUser, allRole)
	env.subjects["RWALL"] = &baselineSubject{ID: "RWALL", Username: "rw-all-user", UserID: allUser, Kind: "session", Token: env.issueSessionToken(allUser)}

	type snapshot struct {
		roles, perms, version, alerts, defVersion int64
	}
	snap := func(roleID uint) snapshot {
		var s snapshot
		require.NoError(t, env.db.Unscoped().Model(&model.Role{}).Count(&s.roles).Error)
		require.NoError(t, env.db.Model(&model.RolePermission{}).Count(&s.perms).Error)
		v, err := authz.CurrentVersion(env.db)
		require.NoError(t, err)
		s.version = v
		require.NoError(t, env.db.Table("system_alert_details").Count(&s.alerts).Error)
		if roleID != 0 {
			var r model.Role
			require.NoError(t, env.db.Unscoped().First(&r, roleID).Error)
			s.defVersion = r.DefinitionVersion
		}
		return s
	}
	idOf := func(out map[string]any) uint { return uint(out["id"].(float64)) }
	codeOf := func(out map[string]any) string { s, _ := out["code"].(string); return s }
	path := func(id uint) string { return fmt.Sprintf("/api/v1/role-definitions/%d", id) }

	t.Run("四條寫入路由在登錄表（登入即可）、agent 登錄（預設拒絕）與路由清冊都有", func(t *testing.T) {
		routes, _ := buildRouter(t, "release", true)
		for _, r := range roleDefinitionWriteRoutes {
			e, ok := authz.LookupRoute(r[0], r[1])
			require.True(t, ok, "%s %s 未登錄", r[0], r[1])
			assert.Equal(t, authz.BaseAuthenticated, e.Base)
			allowed, registered := middleware.AgentRouteDecision(r[0], r[1])
			assert.True(t, registered, "%s %s 未在 agent 路由登錄", r[0], r[1])
			assert.False(t, allowed, "%s %s 不得開放給 agent", r[0], r[1])
			_, inInventory := routes[[2]string{r[0], r[1]}]
			assert.True(t, inInventory, "%s %s 不在路由清冊", r[0], r[1])
		}
	})

	t.Run("超管：新增、以非超管內建範本起手新增、複製、修改、刪除未被引用的自訂角色皆成功", func(t *testing.T) {
		c, out := env.api("S01", "POST", "/api/v1/role-definitions", map[string]any{"name": "rw-new", "description": "d", "permissions": []string{"asset:view"}})
		require.Equal(t, http.StatusCreated, c, "%v", out)
		id := idOf(out)
		c, out = env.api("S01", "POST", "/api/v1/role-definitions", map[string]any{"name": "rw-from-tpl", "permissions": []string{"asset:view"}, "template_role_id": auditorID})
		require.Equal(t, http.StatusCreated, c, "%v", out)
		assert.EqualValues(t, auditorID, out["template_role_id"])
		c, out = env.api("S01", "POST", path(id)+"/copy", map[string]any{"name": "rw-copy", "description": "c"})
		require.Equal(t, http.StatusCreated, c, "%v", out)
		copyID := idOf(out)
		c, out = env.api("S01", "PUT", path(id), map[string]any{"name": "rw-new", "description": "d2", "permissions": []string{"asset:view", "asset:update"}, "expected_version": 1})
		require.Equal(t, http.StatusOK, c, "%v", out)
		assert.EqualValues(t, 2, out["definition_version"])
		c, _ = env.api("S01", "DELETE", path(copyID)+"?expected_version=1", nil)
		assert.Equal(t, http.StatusNoContent, c)
		c, _ = env.api("S01", "GET", path(copyID), nil)
		assert.Equal(t, http.StatusNotFound, c, "刪除後讀不到")
	})

	t.Run("持全部可指派權限的非超管：四種寫入皆拒且角色不變，拒絕回應不含角色名或權限名", func(t *testing.T) {
		target := f.role("rw-target", "asset:view")
		cases := []struct {
			name, method, path string
			body               any
		}{
			{"新增", "POST", "/api/v1/role-definitions", map[string]any{"name": "rw-nonsuper", "permissions": []string{"asset:view"}}},
			{"複製", "POST", path(target) + "/copy", map[string]any{"name": "rw-nonsuper-copy"}},
			{"修改", "PUT", path(target), map[string]any{"name": "rw-target", "permissions": []string{"asset:view", "asset:update"}, "expected_version": 1}},
			{"刪除", "DELETE", path(target) + "?expected_version=1", nil},
		}
		for _, tc := range cases {
			for _, sub := range []string{"RWALL", "IDA"} {
				before := snap(target)
				c, out := env.api(sub, tc.method, tc.path, tc.body)
				b, _ := json.Marshal(out)
				assert.Equal(t, http.StatusForbidden, c, "%s %s: %s", sub, tc.name, b)
				assert.Equal(t, string(apierror.CodePermissionDenied), codeOf(out), "%s %s", sub, tc.name)
				for _, leak := range []string{"rw-target", "rw-nonsuper", "asset:view", "asset:update"} {
					assert.NotContains(t, string(b), leak, "%s %s：拒絕回應不得含角色名或權限名", sub, tc.name)
				}
				assert.Equal(t, before, snap(target), "%s %s：被拒的寫入不改任何資料", sub, tc.name)
			}
		}
	})

	t.Run("缺依賴的集合新增與修改都成功並回 missing_dependencies", func(t *testing.T) {
		c, out := env.api("S01", "POST", "/api/v1/role-definitions", map[string]any{"name": "rw-missing", "permissions": []string{"asset:update"}})
		require.Equal(t, http.StatusCreated, c, "%v", out)
		assert.NotEmpty(t, out["missing_dependencies"])
		id := idOf(out)
		ok := f.role("rw-missing-ok", "asset:view")
		c, out = env.api("S01", "PUT", path(ok), map[string]any{"name": "rw-missing-ok", "permissions": []string{"asset:update"}, "expected_version": 1})
		require.Equal(t, http.StatusOK, c, "%v", out)
		assert.NotEmpty(t, out["missing_dependencies"])
		_ = id
	})

	t.Run("以超管為起手範本或複製超管被拒，不新增角色", func(t *testing.T) {
		before := snap(0)
		c, out := env.api("S01", "POST", "/api/v1/role-definitions", map[string]any{"name": "rw-from-admin", "permissions": []string{}, "template_role_id": adminID})
		assert.GreaterOrEqual(t, c, 400, "%v", out)
		assert.Less(t, c, 500, "%v", out)
		c, out = env.api("S01", "POST", path(adminID)+"/copy", map[string]any{"name": "rw-copy-admin"})
		assert.Equal(t, http.StatusConflict, c, "%v", out)
		assert.Equal(t, string(apierror.CodeRoleDefinitionLocked), codeOf(out))
		assert.Equal(t, before, snap(0))
	})

	t.Run("本文多帶 scope 或其他未列鍵回 400，角色不變", func(t *testing.T) {
		target := f.role("rw-strict", "asset:view")
		before := snap(target)
		for name, tc := range map[string]struct {
			method, path string
			body         map[string]any
		}{
			"新增": {"POST", "/api/v1/role-definitions", map[string]any{"name": "rw-s", "permissions": []string{}, "scope": "global"}},
			"複製": {"POST", path(target) + "/copy", map[string]any{"name": "rw-s", "scope": "global"}},
			"修改": {"PUT", path(target), map[string]any{"name": "rw-strict", "permissions": []string{"asset:view"}, "expected_version": 1, "builtin_key": "x"}},
		} {
			c, out := env.api("S01", tc.method, tc.path, tc.body)
			assert.Equal(t, http.StatusBadRequest, c, "%s: %v", name, out)
		}
		assert.Equal(t, before, snap(target))
	})

	t.Run("舊版本修改回 ROLE_DEFINITION_CONFLICT", func(t *testing.T) {
		target := f.role("rw-stale", "asset:view")
		c, out := env.api("S01", "PUT", path(target), map[string]any{"name": "rw-stale", "permissions": []string{"asset:view"}, "expected_version": 7})
		assert.Equal(t, http.StatusConflict, c, "%v", out)
		assert.Equal(t, string(apierror.CodeRoleDefinitionConflict), codeOf(out))
	})

	t.Run("有直接指派、只有無成員群組指派、只有停用映射規則引用的三個角色刪除各回 ROLE_DEFINITION_IN_USE", func(t *testing.T) {
		direct := f.role("rw-in-use-direct", "asset:view")
		f.hold(f.user("rw-in-use-holder"), direct)
		grouped := f.role("rw-in-use-group", "asset:view")
		f.group("rw-in-use-g", nil, nil, []uint{grouped})
		mapped := f.role("rw-in-use-map", "asset:view")
		m := model.GroupRoleMapping{MatchValue: "cn=rw", ExternalGroupID: 1, RoleID: mapped, CreatedBy: f.sup}
		require.NoError(t, env.db.Create(&m).Error)
		require.NoError(t, env.db.Model(&m).Update("enabled", false).Error)
		for name, id := range map[string]uint{"直接指派": direct, "無成員群組": grouped, "停用映射規則": mapped} {
			before := snap(id)
			c, out := env.api("S01", "DELETE", path(id)+"?expected_version=1", nil)
			assert.Equal(t, http.StatusConflict, c, "%s: %v", name, out)
			assert.Equal(t, string(apierror.CodeRoleDefinitionInUse), codeOf(out), name)
			assert.Equal(t, before, snap(id), name)
		}
	})

	t.Run("經 stage2 組裝的路由修改他人持有的角色並加入管理權限，同交易恰一筆管理類發放事件", func(t *testing.T) {
		held := f.role("rw-held", "asset:view")
		f.hold(f.user("rw-held-holder"), held)
		before := snap(held)
		c, out := env.api("S01", "PUT", path(held), map[string]any{"name": "rw-held", "permissions": []string{"asset:view", "authorization:manage"}, "expected_version": 1})
		require.Equal(t, http.StatusOK, c, "%v", out)
		after := snap(held)
		assert.Equal(t, before.alerts+1, after.alerts)
		var ev model.SystemAlertDetail
		require.NoError(t, env.db.Order("alert_id DESC").First(&ev).Error)
		assert.Equal(t, authz.AlertKeyManagementGranted, ev.AlertType)
		assert.Equal(t, "role", ev.TargetKind)
		assert.Equal(t, fmt.Sprint(held), ev.TargetID)
	})

	t.Run("agent 直接或只經群組持有的角色經路由加入受限權限點：403 同指派 agent 的拒絕碼、角色不變、審計表恰多一列且帶拒絕明細", func(t *testing.T) {
		restricted := string(authz.PermAlertRuleManage)
		owner := f.sup
		for _, src := range []string{"direct", "group"} {
			name := "rw-agent-held-" + src
			held := f.role(name, "asset:view")
			ag := model.User{Username: "rw-agent-holder-" + src, Kind: model.KindAgent, OwnerUserID: &owner, Active: true}
			require.NoError(t, env.db.Create(&ag).Error, src)
			if src == "direct" {
				f.hold(ag.ID, held)
			} else {
				f.group("rw-agent-g-"+src, []uint{ag.ID}, nil, []uint{held})
			}
			before := snap(held)
			var audits0, lastID int64
			require.NoError(t, env.db.Model(&model.AuditLog{}).Count(&audits0).Error)
			require.NoError(t, env.db.Model(&model.AuditLog{}).Select("COALESCE(MAX(id), 0)").Scan(&lastID).Error)
			c, out := env.api("S01", "PUT", path(held), map[string]any{"name": name, "permissions": []string{"asset:view", restricted}, "expected_version": 1})
			assert.Equal(t, http.StatusForbidden, c, "%s: %v", src, out)
			assert.Equal(t, string(apierror.CodePermissionDenied), codeOf(out), src)
			assert.Equal(t, before, snap(held), "%s: 修改交易回滾：集合、版本、持有與告警不變", src)
			raw, _ := json.Marshal(out)
			assert.NotContains(t, string(raw), "agent_count", "%s: 拒絕明細只進審計，不進回應", src)

			// 恰多一列（請求的審計列帶拒絕明細，服務層不另寫），且該列在修改交易回滾後仍存在
			var audits1 int64
			require.NoError(t, env.db.Model(&model.AuditLog{}).Count(&audits1).Error)
			assert.Equal(t, audits0+1, audits1, "%s: 拒絕只留一列", src)
			var rows []model.AuditLog
			require.NoError(t, env.db.Where("id > ?", lastID).Order("id").Find(&rows).Error)
			require.Len(t, rows, 1, src)
			row := rows[0]
			assert.Equal(t, model.ActionUpdate, row.Action, src)
			assert.Equal(t, model.ResourceRole, row.Resource, src)
			require.NotNil(t, row.ResourceID, src)
			assert.Equal(t, held, *row.ResourceID, src)
			assert.Equal(t, model.StatusDenied, row.Status, src)
			assert.Equal(t, f.sup, row.UserID, src)
			assert.Equal(t, http.MethodPut, row.Method, src)
			var det map[string]any
			require.NoError(t, json.Unmarshal([]byte(row.Details), &det), row.Details)
			assert.Equal(t, identity.DenyReasonAgentRole, det["deny_reason"], src)
			assert.Equal(t, "1", det["agent_count"], src)
			assert.Equal(t, restricted, det["restricted_permissions"], src)
		}
	})

	t.Run("預覽沒有持有者、只被一條停用映射規則指向的自訂角色加入管理權限，再 PUT 恰一筆以該角色為目標的管理類發放", func(t *testing.T) {
		role := f.role("rw-preview", "asset:view")
		m := model.GroupRoleMapping{MatchValue: "cn=rwp", ExternalGroupID: 1, RoleID: role, CreatedBy: f.sup}
		require.NoError(t, env.db.Create(&m).Error)
		require.NoError(t, env.db.Model(&m).Update("enabled", false).Error)
		perms := []string{"asset:view", "asset:update"}
		c, pre := env.api("S01", "POST", "/api/v1/role-assignment-previews", map[string]any{"kind": "role_definition", "role_id": role, "permissions": perms})
		require.Equal(t, http.StatusOK, c, "%v", pre)
		assert.EqualValues(t, 0, pre["total"])
		assert.Equal(t, []string{authz.GrantMarkManagementGrant}, strs(opOf(pre)["marks"]))
		if b, err := json.Marshal(pre); err == nil {
			t.Logf("FIXTURE role_definition_preview %s", b)
		}

		var maxAlert int64
		require.NoError(t, env.db.Table("system_alert_details").Select("COALESCE(MAX(alert_id),0)").Scan(&maxAlert).Error)
		c, out := env.api("S01", "PUT", path(role), map[string]any{"name": "rw-preview", "permissions": perms, "expected_version": 1})
		require.Equal(t, http.StatusOK, c, "%v", out)
		var evs []model.SystemAlertDetail
		require.NoError(t, env.db.Where("alert_id > ?", maxAlert).Find(&evs).Error)
		require.Len(t, evs, 1)
		assert.Equal(t, authz.AlertKeyManagementGranted, evs[0].AlertType)
		assert.Equal(t, "role", evs[0].TargetKind)
		assert.Equal(t, fmt.Sprint(role), evs[0].TargetID)
	})

	t.Run("經定義端點建立的自訂角色，在開放目標集合未含它時送到 PUT /users/:id/roles 仍被拒", func(t *testing.T) {
		c, out := env.api("S01", "POST", "/api/v1/role-definitions", map[string]any{"name": "rw-unassignable", "permissions": []string{"asset:view"}})
		require.Equal(t, http.StatusCreated, c, "%v", out)
		full := assembledCatalogIsFull()
		op := identity.Operator{UserID: f.sup, Username: env.subjects["S01"].Username}

		// 正式組裝的路由只代表它實際注入的那一種目錄；另一種以明示注入的服務驗同一個指派
		t.Run("相容目錄（"+catalogVia(false)+"）", func(t *testing.T) {
			target := f.user("rw-assign-target")
			if !full {
				c, out := env.api("S01", "PUT", fmt.Sprintf("/api/v1/users/%d/roles", target), map[string]any{"manual_roles": []string{"rw-unassignable"}})
				assert.Equal(t, http.StatusBadRequest, c, "%v", out)
				assert.Equal(t, "VALIDATION_ROLE_NOT_FOUND", codeOf(out))
				return
			}
			svc := identity.NewUserService(env.db, nil)
			svc.SetAssignmentGuard(identity.NewAssignmentGuard(identity.CompatCatalog()))
			_, err := svc.AssignRolesBy(op, target, []string{"rw-unassignable"})
			assert.ErrorIs(t, err, identity.ErrRoleNotFound)
		})

		t.Run("完整目錄（"+catalogVia(true)+"）", func(t *testing.T) {
			target := f.user("rw-assign-target-full")
			if full {
				c, out := env.api("S01", "PUT", fmt.Sprintf("/api/v1/users/%d/roles", target), map[string]any{"manual_roles": []string{"rw-unassignable"}})
				assert.Equal(t, http.StatusOK, c, "%v", out)
			} else {
				svc := identity.NewUserService(env.db, nil)
				svc.SetAssignmentGuard(identity.NewAssignmentGuard(identity.FullCatalog()))
				_, err := svc.AssignRolesBy(op, target, []string{"rw-unassignable"})
				require.NoError(t, err)
			}
			var r model.Role
			require.NoError(t, env.db.Where("name = ?", "rw-unassignable").First(&r).Error)
			assert.Equal(t, model.RoleSourceManual, f.roleSource(target, r.ID))
		})
	})
}
