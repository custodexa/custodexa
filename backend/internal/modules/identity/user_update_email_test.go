package identity

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupUserSvc(t *testing.T) (*UserService, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewUserService(db, authz.NewAssetAuthorizationService(db)), db
}

// TestUpdateEmailConflict admin 改 email 撞其他 live 帳號回 typed ErrEmailConflict（R1，非通用 500）
func TestUpdateEmailConflict(t *testing.T) {
	svc, db := setupUserSvc(t)
	db.Create(&model.User{Username: "a", Email: strPtr("a@x.com"), Active: true})
	b := &model.User{Username: "b", Email: strPtr("b@x.com"), Active: true}
	db.Create(b)

	if _, _, err := svc.Update(b.ID, &UpdateUserRequest{Email: "a@x.com"}); !errors.Is(err, ErrEmailConflict) {
		t.Fatalf("want ErrEmailConflict, got %v", err)
	}
}

// TestUpdateEmailConflictCaseInsensitive 大小寫/前後空白差異也視為衝突（trim/小寫正規化後，
// binding 已放寬讓 whitespace 變體能抵達 service 偵測——spec surrounding whitespace → conflict）
func TestUpdateEmailConflictCaseInsensitive(t *testing.T) {
	svc, db := setupUserSvc(t)
	db.Create(&model.User{Username: "a", Email: strPtr("a@x.com"), Active: true})
	b := &model.User{Username: "b", Email: strPtr("b@x.com"), Active: true}
	db.Create(b)

	if _, _, err := svc.Update(b.ID, &UpdateUserRequest{Email: "  A@X.com  "}); !errors.Is(err, ErrEmailConflict) {
		t.Fatalf("want ErrEmailConflict for case/space variant, got %v", err)
	}
}

// TestUpdateInvalidEmail 正規化後仍非合法格式 → ErrInvalidEmail（binding 放寬後由 service 把關）
func TestUpdateInvalidEmail(t *testing.T) {
	svc, db := setupUserSvc(t)
	u := &model.User{Username: "u", Email: strPtr("u@x.com"), Active: true}
	db.Create(u)

	for _, bad := range []string{"notanemail", "no@dot", "  spaced garbage  "} {
		if _, _, err := svc.Update(u.ID, &UpdateUserRequest{Email: bad}); !errors.Is(err, ErrInvalidEmail) {
			t.Fatalf("email=%q want ErrInvalidEmail, got %v", bad, err)
		}
	}
}

// TestUpdateAuditDiff 更新回傳欄位級 before/after diff（R2）；同值不記變更
func TestUpdateAuditDiff(t *testing.T) {
	svc, db := setupUserSvc(t)
	u := &model.User{Username: "u", Email: strPtr("old@x.com"), FullName: "Old Name", Active: true}
	db.Create(u)

	_, diff, err := svc.Update(u.ID, &UpdateUserRequest{Email: "new@x.com", FullName: "New Name"})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	want := map[string]string{
		"email.before":     "old@x.com",
		"email.after":      "new@x.com",
		"full_name.before": "Old Name",
		"full_name.after":  "New Name",
	}
	for k, v := range want {
		if diff[k] != v {
			t.Fatalf("diff[%q] = %q, want %q (full diff %v)", k, diff[k], v, diff)
		}
	}

	// 再次以相同值更新 → 無變更，diff 為空
	_, diff2, err := svc.Update(u.ID, &UpdateUserRequest{Email: "new@x.com", FullName: "New Name"})
	if err != nil {
		t.Fatalf("noop update: %v", err)
	}
	if len(diff2) != 0 {
		t.Fatalf("no-op update should yield empty diff, got %v", diff2)
	}
}

// TestFullNameNotMasked full_name/local_display_name 不再被脫敏（R2/4.3，非機密）
func TestFullNameNotMasked(t *testing.T) {
	masked := audit.MaskSensitiveFields(map[string]interface{}{
		"full_name":          "Alice Wang",
		"local_display_name": "小王",
		"password":           "secret",
	})
	if masked["full_name"] != "Alice Wang" {
		t.Fatalf("full_name masked: %v", masked["full_name"])
	}
	if masked["local_display_name"] != "小王" {
		t.Fatalf("local_display_name masked: %v", masked["local_display_name"])
	}
	if masked["password"] != "***MASKED***" {
		t.Fatalf("password should be masked, got %v", masked["password"])
	}
}

// TestLDAPProvisionEmailNull LDAP 供應遇 email 衝突存 NULL（非 ”），多個無 email 影子帳號並存（R3/4.4）
func TestLDAPProvisionEmailNull(t *testing.T) {
	auth, db := setupProfileEnv(t)
	// provisionShadowUser 綁 "user" 角色，需先建
	if err := db.Create(&model.Role{Name: model.RoleUser}).Error; err != nil {
		t.Fatalf("seed role: %v", err)
	}
	// 既有帳號佔用 dup@x
	db.Create(&model.User{Username: "existing", Email: strPtr("dup@x"), Active: true})

	s1, err := auth.provisionShadowUser(&LDAPUserInfo{Username: "ldap1", Email: "dup@x", FullName: "L1"})
	if err != nil {
		t.Fatalf("provision 1: %v", err)
	}
	if s1.Email != nil {
		t.Fatalf("shadow1 email should be NULL on conflict, got %q", *s1.Email)
	}
	// 第二個同樣 email 衝突的影子帳號 → 也存 NULL，且不撞唯一索引
	s2, err := auth.provisionShadowUser(&LDAPUserInfo{Username: "ldap2", Email: "dup@x", FullName: "L2"})
	if err != nil {
		t.Fatalf("provision 2 (multiple email-less must coexist): %v", err)
	}
	if s2.Email != nil {
		t.Fatalf("shadow2 email should be NULL, got %q", *s2.Email)
	}

	// DB 中兩個 NULL email 帳號並存
	var nullCount int64
	db.Model(&model.User{}).Where("email IS NULL").Count(&nullCount)
	if nullCount != 2 {
		t.Fatalf("expected 2 NULL-email accounts, got %d", nullCount)
	}
}
