package identity

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupProfileEnv sqlite in-memory + 全域 database.DB 置換（AuthService 走全域 DB）
func setupProfileEnv(t *testing.T) (*AuthService, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserGroup{},
		&model.Asset{}, &model.AssetAuthorization{}, &model.ApproverScope{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })
	return NewAuthService("test-secret", 15*time.Minute), db
}

// TestValidateDisplayName 輸入驗證與正規化：
// nil/全空白 → nil（清除）；超長或控制字元 → ErrInvalidDisplayName
func TestValidateDisplayName(t *testing.T) {
	sp := func(s string) *string { return &s }
	ok := func(raw *string, want *string) {
		got, err := validateDisplayName(raw)
		if err != nil {
			t.Fatalf("validateDisplayName(%v) unexpected err: %v", raw, err)
		}
		switch {
		case want == nil && got != nil:
			t.Fatalf("want nil, got %q", *got)
		case want != nil && (got == nil || *got != *want):
			t.Fatalf("want %q, got %v", *want, got)
		}
	}
	bad := func(raw *string) {
		if _, err := validateDisplayName(raw); !errors.Is(err, ErrInvalidDisplayName) {
			t.Fatalf("validateDisplayName(%v) want ErrInvalidDisplayName, got %v", raw, err)
		}
	}

	ok(nil, nil)                                                   // 缺欄 → 清除
	ok(sp("   "), nil)                                             // 全空白 → 清除
	ok(sp("  小王  "), sp("小王"))                                     // trim 保留
	ok(sp(strings.Repeat("あ", 100)), sp(strings.Repeat("あ", 100))) // 剛好上限（rune 計）
	bad(sp(strings.Repeat("a", 101)))                              // 超長
	bad(sp("a\nb"))                                                // 換行
	bad(sp("a\tb"))                                                // 控制字元
	bad(sp("a\x00b"))                                              // NUL
}

// TestUpdateOwnDisplayName_Success 成功更新並回傳 canonical UserInfo（含 resolve 後 display_name）
func TestUpdateOwnDisplayName_Success(t *testing.T) {
	auth, db := setupProfileEnv(t)
	full := "Alice Wang"
	u := &model.User{Username: "alice", FullName: full, Email: strPtr("a@x"), Active: true}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	raw := "小王"
	info, err := auth.UpdateOwnDisplayName(u.ID, &raw)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if info.DisplayName != "小王" {
		t.Fatalf("display_name = %q, want 小王", info.DisplayName)
	}
	if info.LocalDisplayName == nil || *info.LocalDisplayName != "小王" {
		t.Fatalf("local_display_name = %v, want 小王", info.LocalDisplayName)
	}
	// 正式身分未被更動（只寫 local_display_name）
	if info.FullName != full || info.Email != "a@x" || info.Username != "alice" {
		t.Fatalf("identity fields mutated: %+v", info)
	}
	// DB 落地確認
	var reloaded model.User
	db.First(&reloaded, u.ID)
	if reloaded.LocalDisplayName == nil || *reloaded.LocalDisplayName != "小王" {
		t.Fatalf("db local_display_name = %v", reloaded.LocalDisplayName)
	}
}

// TestUpdateOwnDisplayName_Clear 空白提交清除為 NULL，顯示名回退 full_name
func TestUpdateOwnDisplayName_Clear(t *testing.T) {
	auth, db := setupProfileEnv(t)
	pre := "舊名"
	u := &model.User{Username: "bob", FullName: "Bob Lee", Email: strPtr("b@x"), Active: true, LocalDisplayName: &pre}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	blank := "   "
	info, err := auth.UpdateOwnDisplayName(u.ID, &blank)
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	if info.LocalDisplayName != nil {
		t.Fatalf("local_display_name should be nil after clear, got %q", *info.LocalDisplayName)
	}
	if info.DisplayName != "Bob Lee" {
		t.Fatalf("display_name = %q, want Bob Lee (fallback)", info.DisplayName)
	}
	var reloaded model.User
	db.First(&reloaded, u.ID)
	if reloaded.LocalDisplayName != nil {
		t.Fatalf("db should store NULL after clear")
	}
}

// TestUpdateOwnDisplayName_DisabledRejected 已停用帳號拒絕（AuthMiddleware 不重查 active 的補正）
func TestUpdateOwnDisplayName_DisabledRejected(t *testing.T) {
	auth, db := setupProfileEnv(t)
	u := &model.User{Username: "carol", Email: strPtr("c@x"), Active: true}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	// GORM default:true 會忽略建立時的零值 false，須顯式改為停用
	if err := db.Model(u).Update("active", false).Error; err != nil {
		t.Fatalf("disable: %v", err)
	}
	raw := "任意"
	if _, err := auth.UpdateOwnDisplayName(u.ID, &raw); !errors.Is(err, ErrUserInactive) {
		t.Fatalf("want ErrUserInactive, got %v", err)
	}
}

// TestUpdateOwnDisplayName_Validation 超長/控制字元被端點層拒絕
func TestUpdateOwnDisplayName_Validation(t *testing.T) {
	auth, db := setupProfileEnv(t)
	u := &model.User{Username: "dave", Email: strPtr("d@x"), Active: true}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	long := strings.Repeat("a", 101)
	if _, err := auth.UpdateOwnDisplayName(u.ID, &long); !errors.Is(err, ErrInvalidDisplayName) {
		t.Fatalf("want ErrInvalidDisplayName for long, got %v", err)
	}
	ctrl := "bad\nname"
	if _, err := auth.UpdateOwnDisplayName(u.ID, &ctrl); !errors.Is(err, ErrInvalidDisplayName) {
		t.Fatalf("want ErrInvalidDisplayName for control char, got %v", err)
	}
}
