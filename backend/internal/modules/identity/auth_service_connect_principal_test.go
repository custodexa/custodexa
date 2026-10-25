package identity

import (
	"errors"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// TestCurrentConnectPrincipal 一次查詢完成可連線
// 複查與 DB 現查主體。有效角色以舊相容設定檔折疊（超管>稽核員>一般使用者）、不受
// 綁定順序影響；不可連線回既有 sentinel（與 CheckUserConnectable 對齊）。
func TestCurrentConnectPrincipal(t *testing.T) {
	auth, _, db := setupLockoutEnv(t)
	user := seedLockoutUser(t, db, "right-pass-1")

	// 無角色 active user：primaryRoleOf fallback 為 user
	p, err := auth.CurrentConnectPrincipal(user.ID)
	if err != nil || p.LegacyRole() != model.RoleUser {
		t.Fatalf("無角色 active user = (%v, %v), want (user, nil)", p.LegacyRole(), err)
	}

	// 多角色 admin+user：折疊為 admin（不受綁定順序影響）
	adminKey, userKey := model.BuiltinSuperAdmin, model.BuiltinUser
	adminRole := model.Role{Name: model.RoleAdmin, BuiltinKey: &adminKey}
	userRole := model.Role{Name: model.RoleUser, BuiltinKey: &userKey}
	if err := db.Create(&adminRole).Error; err != nil {
		t.Fatalf("seed admin role: %v", err)
	}
	if err := db.Create(&userRole).Error; err != nil {
		t.Fatalf("seed user role: %v", err)
	}
	if err := db.Model(user).Association("Roles").Append(&userRole, &adminRole); err != nil {
		t.Fatalf("append roles: %v", err)
	}
	p, err = auth.CurrentConnectPrincipal(user.ID)
	if err != nil || p.LegacyRole() != model.RoleAdmin || !p.IsSuperAdmin() {
		t.Fatalf("admin+user 折疊 = (%v, %v), want (admin, nil)", p.LegacyRole(), err)
	}

	// 停用：ErrUserInactive
	db.Model(user).Update("active", false)
	if _, err := auth.CurrentConnectPrincipal(user.ID); !errors.Is(err, ErrUserInactive) {
		t.Errorf("停用 = %v, want ErrUserInactive", err)
	}

	// 鎖定中：ErrAccountLocked
	future := time.Now().Add(30 * time.Minute)
	db.Model(user).Updates(map[string]interface{}{"active": true, "locked_until": future})
	if _, err := auth.CurrentConnectPrincipal(user.ID); !errors.Is(err, ErrAccountLocked) {
		t.Errorf("鎖定中 = %v, want ErrAccountLocked", err)
	}

	// 不存在：ErrUserNotFound
	if _, err := auth.CurrentConnectPrincipal(99999); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("不存在用戶 = %v, want ErrUserNotFound", err)
	}
}
