package database

import (
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupBootstrapDB 以 in-memory SQLite 覆蓋 package-level DB，回傳還原函式。
// deployment-hardening：CountUsers / seedAdmin / ScanLegacyDefaultAdmins 皆用 package DB。
func setupBootstrapDB(t *testing.T) func() {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.PasswordHistory{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	prev := DB
	DB = db
	return func() { DB = prev }
}

func bcryptHash(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	return string(h)
}

// createAdminUser 建立掛 admin 角色的使用者（legacy 掃描夾具；須先 seedRoles）
func createAdminUser(t *testing.T, username, passwordHash string, isLDAP bool) *model.User {
	t.Helper()
	u := model.User{Username: username, Password: passwordHash, Active: true, IsLDAP: isLDAP}
	if err := DB.Create(&u).Error; err != nil {
		t.Fatalf("create user %s: %v", username, err)
	}
	var adminRole model.Role
	if err := DB.Where("name = ?", model.RoleAdmin).First(&adminRole).Error; err != nil {
		t.Fatalf("找不到 admin 角色（應先 seedRoles）: %v", err)
	}
	if err := DB.Model(&u).Association("Roles").Append(&adminRole); err != nil {
		t.Fatalf("append role: %v", err)
	}
	return &u
}

func TestCountUsers(t *testing.T) {
	defer setupBootstrapDB(t)()
	n, err := CountUsers()
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("空 DB CountUsers=%d, want 0", n)
	}
	if err := DB.Create(&model.User{Username: "x", Password: "h"}).Error; err != nil {
		t.Fatal(err)
	}
	if n, _ = CountUsers(); n != 1 {
		t.Fatalf("CountUsers=%d, want 1", n)
	}
}

// TestSeedAdmin_FreshInstallUsesInitialPassword：空 DB seed 以 ADMIN_INITIAL_PASSWORD 建 admin，
// 使用與驗證相同 bytes（admin123 不可登入），MustChangePassword=true，PasswordHistory 同筆。
func TestSeedAdmin_FreshInstallUsesInitialPassword(t *testing.T) {
	defer setupBootstrapDB(t)()
	const pw = "Str0ngInitialPw2026"
	if err := SeedDatabase(pw); err != nil {
		t.Fatalf("SeedDatabase: %v", err)
	}
	var admin model.User
	if err := DB.Where("username = ?", "admin").First(&admin).Error; err != nil {
		t.Fatalf("admin 未建立: %v", err)
	}
	if bcrypt.CompareHashAndPassword([]byte(admin.Password), []byte(pw)) != nil {
		t.Error("admin 密碼非 ADMIN_INITIAL_PASSWORD")
	}
	if bcrypt.CompareHashAndPassword([]byte(admin.Password), []byte("admin123")) == nil {
		t.Error("admin 竟可用公開預設 admin123 登入")
	}
	if !admin.MustChangePassword {
		t.Error("admin MustChangePassword 應為 true")
	}
	var histCount int64
	DB.Model(&model.PasswordHistory{}).Where("user_id = ?", admin.ID).Count(&histCount)
	if histCount != 1 {
		t.Errorf("PasswordHistory=%d, want 1（與 admin 同原子交易）", histCount)
	}
	// admin 角色須於同一原子交易掛上（deployment-hardening：role 指派在 tx 內，
	// 避免半初始化「已建 admin 但未掛 admin 角色」）
	var adminWithRoles model.User
	if err := DB.Preload("Roles").First(&adminWithRoles, admin.ID).Error; err != nil {
		t.Fatalf("reload admin roles: %v", err)
	}
	if !userHasAdminRole(&adminWithRoles) {
		t.Error("初始 admin 未掛 admin 角色（角色指派應在 seed 原子交易內）")
	}
}

// TestSeedAdmin_EmptyPasswordRejected：防禦層——空初始密碼不得建立管理員。
func TestSeedAdmin_EmptyPasswordRejected(t *testing.T) {
	defer setupBootstrapDB(t)()
	if err := seedRoles(); err != nil {
		t.Fatal(err)
	}
	if err := seedAdmin(""); err == nil {
		t.Error("seedAdmin(\"\") 應回錯誤（拒以空密碼建 admin）")
	}
	if n, _ := CountUsers(); n != 0 {
		t.Errorf("空密碼不應建立任何使用者，count=%d", n)
	}
}

// TestScanLegacyDefaultAdmins：改名 admin、多 admin 任一用 admin123 皆須命中；
// 良好密碼/LDAP/非 admin 皆不命中（deployment-hardening D6）。
func TestScanLegacyDefaultAdmins(t *testing.T) {
	defer setupBootstrapDB(t)()
	if err := seedRoles(); err != nil {
		t.Fatal(err)
	}
	renamed := createAdminUser(t, "root2", bcryptHash(t, "admin123"), false)     // 改名仍用 admin123 → 命中
	createAdminUser(t, "admin_ok", bcryptHash(t, "Str0ngInitialPw2026"), false)  // 良好密碼 → 不命中
	second := createAdminUser(t, "root3", bcryptHash(t, "admin123"), false)      // 多 admin 任一 → 命中
	inactive := createAdminUser(t, "root_off", bcryptHash(t, "admin123"), false) // inactive 亦不豁免 → 命中
	if err := DB.Model(inactive).Update("active", false).Error; err != nil {
		t.Fatal(err)
	}
	createAdminUser(t, "ldap_admin", bcryptHash(t, "admin123"), true) // LDAP → 跳過
	emptyPw := createAdminUser(t, "empty_pw", "", false)              // 空密碼 admin → 跳過（不 crash、不命中）
	_ = emptyPw
	nonAdmin := model.User{Username: "bob", Password: bcryptHash(t, "admin123"), Active: true}
	if err := DB.Create(&nonAdmin).Error; err != nil { // 非 admin → 不命中
		t.Fatal(err)
	}

	hits, err := ScanLegacyDefaultAdmins()
	if err != nil {
		t.Fatal(err)
	}
	hitSet := map[uint]bool{}
	for _, id := range hits {
		hitSet[id] = true
	}
	if !hitSet[renamed.ID] {
		t.Error("改名 admin(root2) 用 admin123 應命中")
	}
	if !hitSet[second.ID] {
		t.Error("第二 admin(root3) 用 admin123 應命中")
	}
	if !hitSet[inactive.ID] {
		t.Error("停用 admin(root_off) 用 admin123 應命中（inactive 不豁免）")
	}
	if len(hits) != 3 {
		t.Errorf("命中數=%d, want 3（良好密碼/LDAP/空密碼/非 admin 皆不該命中）", len(hits))
	}
}

// TestScanLegacyDefaultAdmins_NoHits：全為良好密碼時零命中。
func TestScanLegacyDefaultAdmins_NoHits(t *testing.T) {
	defer setupBootstrapDB(t)()
	if err := seedRoles(); err != nil {
		t.Fatal(err)
	}
	createAdminUser(t, "admin_ok", bcryptHash(t, "Str0ngInitialPw2026"), false)
	hits, err := ScanLegacyDefaultAdmins()
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Errorf("無 admin123 應零命中，got %d", len(hits))
	}
}
