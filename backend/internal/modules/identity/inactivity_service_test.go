package identity

import (
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/policy"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupInactivityEnv sqlite + 政策 + UserService + InactivityService（真 DB 確定性測試）
func setupInactivityEnv(t *testing.T) (*InactivityService, *policy.SecurityPolicyService, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.SecurityPolicy{},
		&model.PasswordHistory{}, &model.RefreshToken{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	policies := policy.NewSecurityPolicyService(db)
	users := NewUserService(db, authz.NewAssetAuthorizationService(db))
	users.SetSecurityPolicies(policies)
	svc := NewInactivityService(db, policies, users, nil)
	return svc, policies, db
}

// mkUserWithLogin 建立指定最後登入時間、豁免旗標、角色的用戶
func mkUserWithLogin(t *testing.T, db *gorm.DB, name string, lastLogin time.Time, exempt bool, role string) *model.User {
	t.Helper()
	u := &model.User{
		Username: name, Email: strPtr(name + "@x"), Password: "x", Active: true,
		LastLoginAt: &lastLogin, InactivityExempt: exempt,
	}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	if role != "" {
		r := &model.Role{}
		db.Where("name = ?", role).FirstOrCreate(r, model.Role{Name: role})
		db.Exec("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", u.ID, r.ID)
	}
	return u
}

// TestInactivityDisablesStaleAccounts 逾期未登入的 active 非豁免帳號被停用
func TestInactivityDisablesStaleAccounts(t *testing.T) {
	svc, policies, db := setupInactivityEnv(t)
	policies.Update(policy.PolicyInactiveDisableDays, "90", "admin")

	stale := mkUserWithLogin(t, db, "stale", time.Now().AddDate(0, 0, -100), false, "user")
	fresh := mkUserWithLogin(t, db, "fresh", time.Now().AddDate(0, 0, -10), false, "user")

	n, err := svc.DisableInactive()
	if err != nil {
		t.Fatalf("DisableInactive: %v", err)
	}
	if n != 1 {
		t.Errorf("停用數 = %d, want 1", n)
	}

	var reloadStale, reloadFresh model.User
	db.First(&reloadStale, stale.ID)
	db.First(&reloadFresh, fresh.ID)
	if reloadStale.Active {
		t.Error("逾期帳號應被停用")
	}
	if !reloadFresh.Active {
		t.Error("近期登入帳號不應被停用")
	}
}

// TestInactivityExemptSkipped 豁免帳號即使逾期也不停用
func TestInactivityExemptSkipped(t *testing.T) {
	svc, policies, db := setupInactivityEnv(t)
	policies.Update(policy.PolicyInactiveDisableDays, "90", "admin")

	exempt := mkUserWithLogin(t, db, "exempt", time.Now().AddDate(0, 0, -200), true, "user")

	n, _ := svc.DisableInactive()
	if n != 0 {
		t.Errorf("停用數 = %d, want 0（豁免）", n)
	}
	var reloaded model.User
	db.First(&reloaded, exempt.ID)
	if !reloaded.Active {
		t.Error("豁免帳號不應被停用")
	}
}

// TestInactivityDisabledWhenPolicyZero 政策 0=關閉，直接返回不掃描
func TestInactivityDisabledWhenPolicyZero(t *testing.T) {
	svc, _, db := setupInactivityEnv(t)
	// 政策維持出廠 0
	mkUserWithLogin(t, db, "veryold", time.Now().AddDate(-2, 0, 0), false, "user")

	n, err := svc.DisableInactive()
	if err != nil || n != 0 {
		t.Errorf("政策 0 應不停用任何帳號，got n=%d err=%v", n, err)
	}
}

// TestInactivityNullLastLoginUsesCreatedAt last_login_at 為 NULL 時以 created_at 起算
func TestInactivityNullLastLoginUsesCreatedAt(t *testing.T) {
	svc, policies, db := setupInactivityEnv(t)
	policies.Update(policy.PolicyInactiveDisableDays, "90", "admin")

	// 直接建立 last_login_at=NULL、created_at 久遠的用戶
	u := &model.User{Username: "nologin", Email: strPtr("n@x"), Password: "x", Active: true}
	db.Create(u)
	db.Model(&model.User{}).Where("id = ?", u.ID).
		Update("created_at", time.Now().AddDate(0, 0, -120))
	r := &model.Role{}
	db.Where("name = ?", "user").FirstOrCreate(r, model.Role{Name: "user"})
	db.Exec("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", u.ID, r.ID)

	n, _ := svc.DisableInactive()
	if n != 1 {
		t.Errorf("停用數 = %d, want 1（NULL last_login 以 created_at 起算）", n)
	}
}

// TestInactivitySkipsLastAdmin 唯一 active admin 逾期不被停用（避免鎖死系統）
func TestInactivitySkipsLastAdmin(t *testing.T) {
	svc, policies, db := setupInactivityEnv(t)
	policies.Update(policy.PolicyInactiveDisableDays, "90", "admin")

	// 唯一 admin，非豁免、久未登入
	admin := mkUserWithLogin(t, db, "soleadmin", time.Now().AddDate(0, 0, -300), false, "admin")

	n, _ := svc.DisableInactive()
	if n != 0 {
		t.Errorf("停用數 = %d, want 0（唯一 admin 應被 last-admin 守衛跳過）", n)
	}
	var reloaded model.User
	db.First(&reloaded, admin.ID)
	if !reloaded.Active {
		t.Error("唯一管理員不應被自動停用鎖死系統")
	}
}
