package main

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestRoleDefinitionExposureBoundary 擋：新範本或自訂角色從舊入口提前取得、既有 GET /roles 形狀被新種子改變、
// 路由集合出現角色定義寫入口。依據是路由集合與服務行為，不是前端隱藏。
func TestRoleDefinitionExposureBoundary(t *testing.T) {
	newDB := func(t *testing.T) (*gorm.DB, map[string]uint) {
		db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		sqlDB, _ := db.DB()
		sqlDB.SetMaxOpenConns(1)
		t.Cleanup(func() { _ = sqlDB.Close() })
		require.NoError(t, db.AutoMigrate(&model.User{}, &model.Role{}, &model.RolePermission{}, &model.AuthzState{}, &model.AuditLog{}, &model.RefreshToken{}, &model.UserRoleMappingRuleSupport{}, &model.UserGroupMappingRuleSupport{}, &model.UserChannelObservation{}, &model.PasswordHistory{}))
		require.NoError(t, db.AutoMigrate(&model.UserRole{}))
		require.NoError(t, db.Exec("INSERT INTO authz_state (id, version) VALUES (1, 0)").Error)
		ids := map[string]uint{}
		mk := func(name string, version int64, key string) {
			r := model.Role{Name: name, DefinitionVersion: version}
			if key != "" {
				k := key
				r.BuiltinKey = &k
			}
			require.NoError(t, db.Create(&r).Error)
			ids[name] = r.ID
		}
		for _, n := range []string{"admin", "auditor", "user", "approver"} {
			mk(n, 0, "")
		}
		mk("legacy-extra", 0, "") // 升級前已存在的其他角色
		mk("identity_admin", 1, model.BuiltinIdentityAdmin)
		mk("security_admin", 1, model.BuiltinSecurityAdmin)
		mk(model.BuiltinAssetAdmin, 1, model.BuiltinAssetAdmin)
		mk(model.BuiltinAuthzAdmin, 1, model.BuiltinAuthzAdmin)
		mk("custom-new", 1, "")
		return db, ids
	}

	t.Run("GET /roles 的集合只含升級前存量，欄位不因新欄位改變", func(t *testing.T) {
		db, _ := newDB(t)
		roles, total, err := identity.NewUserService(db, nil).ListRoles()
		require.NoError(t, err)
		var names []string
		for _, r := range roles {
			names = append(names, r.Name)
		}
		assert.ElementsMatch(t, []string{"admin", "auditor", "user", "approver", "legacy-extra"}, names, "含升級前未知角色，不含新範本與新自訂角色")
		assert.EqualValues(t, 5, total)
		b, err := jsonMarshalKeys(roles[0])
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"id", "created_at", "updated_at", "name", "description"}, b)
	})

	t.Run("替換、追加、建帳號帶角色、釘住逐入口拒絕新角色，舊目標行為不變", func(t *testing.T) {
		db, ids := newDB(t)
		svc := identity.NewUserService(db, nil)
		u := model.User{Username: "target", Active: true}
		require.NoError(t, db.Create(&u).Error)
		require.NoError(t, db.Create(&model.UserRole{UserID: u.ID, RoleID: ids["user"], Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
		// 釘住的拒絕要落在「目錄找不到角色」而不是「角色不是映射來的」：先讓新角色都帶映射成分
		for _, name := range []string{"identity_admin", "security_admin", model.BuiltinAssetAdmin, model.BuiltinAuthzAdmin, "custom-new"} {
			require.NoError(t, db.Create(&model.UserRole{UserID: u.ID, RoleID: ids[name], Source: model.RoleSourceMapped, ScopeKind: model.ScopeKindGlobal}).Error)
		}
		for _, name := range []string{"identity_admin", "security_admin", model.BuiltinAssetAdmin, model.BuiltinAuthzAdmin, "custom-new"} {
			_, err := svc.AssignRoles(u.ID, []string{name})
			assert.ErrorIs(t, err, identity.ErrRoleNotFound, "AssignRoles %s", name)
			assert.ErrorIs(t, svc.AddRole(u.ID, name), identity.ErrRoleNotFound, "AddRole %s", name)
			_, err = svc.PinMappedRole(u.ID, name)
			assert.ErrorIs(t, err, identity.ErrRoleNotFound, "PinMappedRole %s", name)
			_, err = svc.Create(&identity.CreateUserRequest{Username: "new-" + name, Password: "pw123456", Email: name + "@example.com", Roles: []string{name}})
			assert.ErrorIs(t, err, identity.ErrRoleNotFound, "Create %s", name)
		}
		var rows []model.UserRole
		require.NoError(t, db.Where("user_id = ?", u.ID).Order("role_id").Find(&rows).Error)
		got := map[uint]string{}
		for _, r := range rows {
			got[r.RoleID] = r.Source
		}
		assert.Equal(t, map[uint]string{ids["user"]: model.RoleSourceManual, ids["identity_admin"]: model.RoleSourceMapped,
			ids["security_admin"]: model.RoleSourceMapped, ids[model.BuiltinAssetAdmin]: model.RoleSourceMapped,
			ids[model.BuiltinAuthzAdmin]: model.RoleSourceMapped, ids["custom-new"]: model.RoleSourceMapped}, got, "被拒絕後原指派與來源不變")
		var n int64
		require.NoError(t, db.Model(&model.User{}).Where("username LIKE ?", "new-%").Count(&n).Error)
		assert.Zero(t, n, "建帳號被拒時不留下帳號")

		// 舊目標行為不變：四個入口對存量角色（含升級前未知角色）都成功
		require.NoError(t, svc.AddRole(u.ID, "legacy-extra"))
		_, err := svc.AssignRoles(u.ID, []string{"auditor", "legacy-extra"})
		require.NoError(t, err)
		created, err := svc.Create(&identity.CreateUserRequest{Username: "legacy-create", Password: "pw123456", Email: "legacy@example.com", Roles: []string{"legacy-extra"}})
		require.NoError(t, err, "存量角色建帳號必須成功（夾具若缺表，這裡會先紅）")
		var createdRoles []model.UserRole
		require.NoError(t, db.Where("user_id = ?", created.ID).Find(&createdRoles).Error)
		require.Len(t, createdRoles, 1)
		assert.Equal(t, ids["legacy-extra"], createdRoles[0].RoleID)
		pinUser := model.User{Username: "pin-target", Active: true}
		require.NoError(t, db.Create(&pinUser).Error)
		require.NoError(t, db.Create(&model.UserRole{UserID: pinUser.ID, RoleID: ids["legacy-extra"], Source: model.RoleSourceMapped, ScopeKind: model.ScopeKindGlobal}).Error)
		_, err = svc.PinMappedRole(pinUser.ID, "legacy-extra")
		require.NoError(t, err, "存量角色釘住必須成功")
		source, exists, err := model.UserRoleSourceOf(db, pinUser.ID, ids["legacy-extra"])
		require.NoError(t, err)
		require.True(t, exists)
		assert.Equal(t, model.RoleSourceBoth, source)
	})

	// 上一案用服務預設（相容目錄）；本案注入完整目錄，依正式組裝實際注入的目錄決定來源
	fullGuard, fullVia := catalogGuard(true)
	t.Run("完整目錄（"+fullVia+"）：替換、追加、建帳號帶角色、釘住對新角色放行，GET /roles 集合不變", func(t *testing.T) {
		db, ids := newDB(t)
		svc := identity.NewUserService(db, nil)
		svc.SetAssignmentGuard(fullGuard)
		for _, name := range []string{"identity_admin", "security_admin", "custom-new"} {
			u := model.User{Username: "t-" + name, Active: true}
			require.NoError(t, db.Create(&u).Error)
			_, err := svc.AssignRoles(u.ID, []string{name})
			assert.NoError(t, err, "AssignRoles %s", name)
			p := model.User{Username: "p-" + name, Active: true}
			require.NoError(t, db.Create(&p).Error)
			assert.NoError(t, svc.AddRole(p.ID, name), "AddRole %s", name)
			m := model.User{Username: "m-" + name, Active: true}
			require.NoError(t, db.Create(&m).Error)
			require.NoError(t, db.Create(&model.UserRole{UserID: m.ID, RoleID: ids[name], Source: model.RoleSourceMapped, ScopeKind: model.ScopeKindGlobal}).Error)
			_, err = svc.PinMappedRole(m.ID, name)
			assert.NoError(t, err, "PinMappedRole %s", name)
			source, _, err := model.UserRoleSourceOf(db, m.ID, ids[name])
			require.NoError(t, err)
			assert.Equal(t, model.RoleSourceBoth, source, name)
			created, err := svc.Create(&identity.CreateUserRequest{Username: "new-" + name, Password: "pw123456", Email: name + "@example.com", Roles: []string{name}})
			require.NoError(t, err, "Create %s", name)
			var rows []model.UserRole
			require.NoError(t, db.Where("user_id = ?", created.ID).Find(&rows).Error)
			require.Len(t, rows, 1)
			assert.Equal(t, ids[name], rows[0].RoleID)
		}
		roles, total, err := svc.ListRoles()
		require.NoError(t, err)
		var names []string
		for _, r := range roles {
			names = append(names, r.Name)
		}
		assert.ElementsMatch(t, []string{"admin", "auditor", "user", "approver", "legacy-extra"}, names, "完整目錄下 GET /roles 集合仍只含升級前存量")
		assert.EqualValues(t, 5, total)
	})

	t.Run("角色定義路由恰為宣告的四讀四寫八條，/roles 仍只有 GET", func(t *testing.T) {
		// 逐條列名的固定期望集合，不依實際註冊數推得。
		// 每個可達組態（模式與審計開關的四格）都套同一組期望
		configs := []struct {
			name  string
			mode  string
			audit bool
		}{
			{"dev-auditon", "debug", true},
			{"dev-auditoff", "debug", false},
			{"release-auditon", "release", true},
			{"release-auditoff", "release", false},
		}
		for _, cfg := range configs {
			routes, _ := buildRouter(t, cfg.mode, cfg.audit)
			definitionRoutes, roleRoutes := roleDefinitionSurface(routes)
			assert.ElementsMatch(t, expectedRoleDefinitionRoutes, definitionRoutes, cfg.name)
			assert.Equal(t, []string{"GET /api/v1/roles"}, roleRoutes, cfg.name)
		}
	})

	t.Run("注入多餘的角色定義寫入口必被判為不符", func(t *testing.T) {
		routes, _ := buildRouter(t, "release", true)
		d, r := roleDefinitionSurface(routes)
		require.True(t, roleSurfaceMatches(d, r), "未注入時必須相符，否則反例沒有對照意義")

		inject := func(method, path, handler string) map[[2]string]string {
			out := map[[2]string]string{}
			for k, v := range routes {
				out[k] = v
			}
			out[[2]string{method, path}] = handler
			return out
		}
		const defHandler = "github.com/custodexa/backend/internal/api.(*RoleDefinitionHandler)."
		cases := map[string]map[[2]string]string{
			"同命名空間的多餘方法":        inject("PATCH", "/api/v1/role-definitions/:id", defHandler+"Update-fm"),
			"同命名空間的多餘路徑":        inject("POST", "/api/v1/role-definitions/:id/publish", defHandler+"Create-fm"),
			"別名路徑掛角色定義 handler": inject("PUT", "/api/v1/users/:id/roles/:roleID/definition", defHandler+"Update-fm"),
			"路徑不含關鍵字也不含 users":  inject("POST", "/api/v1/permission-sets", defHandler+"Create-fm"),
			"多一條 /roles 寫入":     inject("POST", "/api/v1/roles", "github.com/custodexa/backend/internal/api.(*RoleHandler).Create-fm"),
		}
		for name, mutated := range cases {
			d, r := roleDefinitionSurface(mutated)
			assert.False(t, roleSurfaceMatches(d, r), name)
		}
	})
}

// expectedRoleDefinitionRoutes 角色定義路由的固定期望集合（四讀四寫）。
var expectedRoleDefinitionRoutes = []string{
	"GET /api/v1/role-definitions",
	"GET /api/v1/role-definitions/descriptors",
	"GET /api/v1/role-definitions/:id",
	"POST /api/v1/role-definitions/summary",
	"POST /api/v1/role-definitions",
	"POST /api/v1/role-definitions/:id/copy",
	"PUT /api/v1/role-definitions/:id",
	"DELETE /api/v1/role-definitions/:id",
}

// roleDefinitionSurface 從路由清冊挑出角色定義面：路徑含 role-definition 的，加上不論路徑為何、
// 由角色定義 handler 處理的（防別名），以及 /roles 命名空間（不含 /users/ 下的子路徑）。
func roleDefinitionSurface(routes map[[2]string]string) (definitionRoutes, roleRoutes []string) {
	for k, handler := range routes {
		p := strings.ToLower(k[1])
		switch {
		case strings.Contains(p, "role-definition"), strings.Contains(p, "role_definition"),
			strings.Contains(handler, "RoleDefinitionHandler"):
			definitionRoutes = append(definitionRoutes, k[0]+" "+k[1])
		case strings.Contains(p, "/roles") && !strings.Contains(p, "/users/"):
			roleRoutes = append(roleRoutes, k[0]+" "+k[1])
		}
	}
	return definitionRoutes, roleRoutes
}

func roleSurfaceMatches(definitionRoutes, roleRoutes []string) bool {
	a := append([]string(nil), definitionRoutes...)
	b := append([]string(nil), expectedRoleDefinitionRoutes...)
	sort.Strings(a)
	sort.Strings(b)
	return strings.Join(a, "\n") == strings.Join(b, "\n") && len(roleRoutes) == 1 && roleRoutes[0] == "GET /api/v1/roles"
}

func jsonMarshalKeys(v any) ([]string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys, nil
}
