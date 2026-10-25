package identity

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// TestLocalAdminScopeUsesBuiltinIdentity 擋：群組或節點範圍取得的超管墊高計數，使最後一位
// 本地超管可被移除；以及超管身分被角色名稱而非內建識別決定。
func TestLocalAdminScopeUsesBuiltinIdentity(t *testing.T) {
	t.Run("經群組取得的超管不計", func(t *testing.T) {
		db := localAdminDB(t)
		if err := db.AutoMigrate(&model.UserRole{}, &model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{}); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		direct := seedAccount(t, db, adminSpec{username: "direct-admin", admin: true, active: true})
		// 外部託管的超管只讓「一般的最後管理員檢查」放行，使本測試打到本地超管不變式
		seedAccount(t, db, adminSpec{username: "sso-admin", admin: true, active: true, origin: model.AuthSourceOIDC})
		viaGroup := seedAccount(t, db, adminSpec{username: "group-admin", active: true})
		var adminRole model.Role
		if err := db.Where("name = ?", model.RoleAdmin).First(&adminRole).Error; err != nil {
			t.Fatalf("load role: %v", err)
		}
		group := model.UserGroup{Name: "ops"}
		if err := db.Create(&group).Error; err != nil {
			t.Fatalf("group: %v", err)
		}
		if err := db.Create(&model.UserGroupMember{UserGroupID: group.ID, UserID: viaGroup.ID}).Error; err != nil {
			t.Fatalf("member: %v", err)
		}
		if err := db.Create(&model.UserGroupRole{UserGroupID: group.ID, RoleID: adminRole.ID, ScopeKind: model.ScopeKindGlobal}).Error; err != nil {
			t.Fatalf("group role: %v", err)
		}
		if n := mustCountLocalAdmins(t, db); n != 1 {
			t.Fatalf("經群組取得的超管不得計入：本地超管應為 1（僅直接指派者），got %d", n)
		}
		// 解析器確實把群組帶來的超管視為該主體的超管身分——證明被排除的是計數口徑，不是資料沒建好
		p, err := authz.NewResolver(db).ResolveUser(viaGroup.ID, authz.TokenFacts{})
		if err != nil || !p.IsSuperAdmin() {
			t.Fatalf("群組帶來的超管應被解析為超管身分: %v %v", p, err)
		}
		svc := NewUserService(db, authz.NewAssetAuthorizationService(db))
		assertLastLocalAdminRejection(t, svc.UpdateStatus(direct.ID, false))
	})

	t.Run("節點範圍的超管列不計", func(t *testing.T) {
		db := localAdminDB(t)
		direct := seedAccount(t, db, adminSpec{username: "direct-admin", admin: true, active: true})
		scoped := seedAccount(t, db, adminSpec{username: "scoped-admin", admin: true, active: true})
		if err := db.Exec("UPDATE user_roles SET scope_kind = ? WHERE user_id = ?", model.ScopeKindNodes, scoped.ID).Error; err != nil {
			t.Fatalf("set scope: %v", err)
		}
		if n := mustCountLocalAdmins(t, db); n != 1 {
			t.Fatalf("節點範圍的超管列不得計入：應為 1，got %d", n)
		}
		svc := NewUserService(db, authz.NewAssetAuthorizationService(db))
		assertLastLocalAdminRejection(t, svc.UpdateStatus(direct.ID, false))
	})

	t.Run("內建身分不依角色名稱", func(t *testing.T) {
		db := localAdminDB(t)
		root := seedAccount(t, db, adminSpec{username: "root-by-key", admin: true, active: true})
		seedAccount(t, db, adminSpec{username: "sso-admin", admin: true, active: true, origin: model.AuthSourceOIDC})
		// 把內建超管範本改名：計數仍認 builtin_key，不認名稱
		if err := db.Model(&model.Role{}).Where("name = ?", model.RoleAdmin).Update("name", "ops-root").Error; err != nil {
			t.Fatalf("rename: %v", err)
		}
		if n := mustCountLocalAdmins(t, db); n != 1 {
			t.Fatalf("內建超管改名後仍應計入：應為 1，got %d", n)
		}
		// 反向：名稱叫 admin 但不是內建範本（以原始 SQL 寫入，繞過保留名稱的寫入規則）→ 不計
		if err := db.Exec("INSERT INTO roles (name, description, created_at, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)", model.RoleAdmin, "name only").Error; err != nil {
			t.Fatalf("insert lookalike: %v", err)
		}
		var lookalike model.Role
		if err := db.Where("name = ?", model.RoleAdmin).First(&lookalike).Error; err != nil {
			t.Fatalf("load lookalike: %v", err)
		}
		if lookalike.BuiltinKey != nil {
			t.Fatalf("以原始 SQL 寫入的同名角色不應帶內建識別: %v", *lookalike.BuiltinKey)
		}
		other := seedAccount(t, db, adminSpec{username: "name-only-admin", active: true})
		if err := db.Exec("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", other.ID, lookalike.ID).Error; err != nil {
			t.Fatalf("attach: %v", err)
		}
		if n := mustCountLocalAdmins(t, db); n != 1 {
			t.Fatalf("只有名稱叫 admin 的非內建角色不得計入：應為 1，got %d", n)
		}
		svc := NewUserService(db, authz.NewAssetAuthorizationService(db))
		assertLastLocalAdminRejection(t, svc.UpdateStatus(root.ID, false))
	})
}
