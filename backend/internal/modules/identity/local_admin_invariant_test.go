package identity

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/authz"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// --- fixture ---

func localAdminMigrate(t *testing.T, db *gorm.DB) {
	t.Helper()
	// ApproverScope／UserGroup／RefreshToken 為 Delete／UpdateStatus 的連動清理與
	// 撤銷路徑所需——缺表會讓「應允許」的情境敗在無關的 SQL 錯誤上
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserGroup{},
		&model.ApproverScope{}, &model.RefreshToken{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for _, name := range []string{model.RoleAdmin, "user"} {
		if err := db.Create(&model.Role{Name: name}).Error; err != nil {
			t.Fatalf("seed role %s: %v", name, err)
		}
	}
}

// localAdminDB 單連線 :memory: fixture。
// SetMaxOpenConns(1) 為必要：sqlite `:memory:` 每條連線各自是一個獨立的空資料庫，
// 連線池放行第二條即出現「建了資料卻查不到」的假紅（見 ff51836）。
func localAdminDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql db: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	localAdminMigrate(t, db)
	return db
}

type adminSpec struct {
	username string
	admin    bool
	active   bool
	// external 三訊號擇一模擬（空＝本地帳號）
	ldapUser bool
	extCred  bool
	origin   string
}

func seedAccount(t *testing.T, db *gorm.DB, spec adminSpec) *model.User {
	t.Helper()
	origin := spec.origin
	if origin == "" {
		origin = model.AuthSourceLocal
	}
	u := &model.User{
		Username:           spec.username,
		Password:           "$2a$10$fakehashfakehashfakehashfakehashfakehashfakehashfakeha",
		ProvisioningOrigin: origin,
		IsLDAP:             spec.ldapUser,
		ExternalCredential: spec.extCred,
	}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("seed user %s: %v", spec.username, err)
	}
	// active 帶 gorm default:true，Create 時的零值 false 會被 DB default 覆寫，
	// 故停用狀態一律以顯式 UPDATE 落地（同 model.User 註解所述的 GORM 陷阱）
	if !spec.active {
		if err := db.Model(&model.User{}).Where("id = ?", u.ID).
			Update("active", false).Error; err != nil {
			t.Fatalf("deactivate %s: %v", spec.username, err)
		}
	}
	if spec.admin {
		var role model.Role
		if err := db.Where("name = ?", model.RoleAdmin).First(&role).Error; err != nil {
			t.Fatalf("load admin role: %v", err)
		}
		if err := db.Exec("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)",
			u.ID, role.ID).Error; err != nil {
			t.Fatalf("attach admin role to %s: %v", spec.username, err)
		}
	}
	return u
}

func mustCountLocalAdmins(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	n, err := CountLocalAdmins(db)
	if err != nil {
		t.Fatalf("CountLocalAdmins: %v", err)
	}
	return n
}

// --- 情境 4：計數定義 ---

// TestCountLocalAdminsExcludesNonLocal 只有「啟用中＋admin 角色＋未外部化」計入。
// 三個外部訊號（is_ldap／external_credential／provisioning_origin）各自足以排除，
// 與 model.User.IsExternal() 的 fail-secure 聯集語義一致
func TestCountLocalAdminsExcludesNonLocal(t *testing.T) {
	db := localAdminDB(t)
	seedAccount(t, db, adminSpec{username: "local-admin", admin: true, active: true})
	seedAccount(t, db, adminSpec{username: "ldap-admin", admin: true, active: true, ldapUser: true})
	seedAccount(t, db, adminSpec{username: "extcred-admin", admin: true, active: true, extCred: true})
	seedAccount(t, db, adminSpec{username: "oidc-admin", admin: true, active: true, origin: model.AuthSourceOIDC})
	seedAccount(t, db, adminSpec{username: "inactive-admin", admin: true, active: false})
	seedAccount(t, db, adminSpec{username: "plain-user", admin: false, active: true})

	if n := mustCountLocalAdmins(t, db); n != 1 {
		t.Fatalf("本地 admin 數應為 1（僅 local-admin），got %d", n)
	}
}

// --- 情境 1：2 → 1 允許 ---

func TestLocalAdminInvariantAllowsTwoToOne(t *testing.T) {
	db := localAdminDB(t)
	a := seedAccount(t, db, adminSpec{username: "admin-a", admin: true, active: true})
	seedAccount(t, db, adminSpec{username: "admin-b", admin: true, active: true})
	svc := NewUserService(db, authz.NewAssetAuthorizationService(db))

	if err := svc.UpdateStatus(a.ID, false); err != nil {
		t.Fatalf("2→1 應允許停用，got %v", err)
	}
	if n := mustCountLocalAdmins(t, db); n != 1 {
		t.Fatalf("停用後本地 admin 應剩 1，got %d", n)
	}
}

// --- 情境 2：1 → 0 拒絕（三條已接路徑各測）---
//
// 每個子情境都額外種一個**外部** admin：既有的 ErrLastAdmin 檢查只問「還有沒有
// active admin」，若不種它，Delete／UpdateStatus 會先被舊檢查擋下，驗不到新不變式。

func TestLocalAdminInvariantRejectsDisableLastLocalAdmin(t *testing.T) {
	db := localAdminDB(t)
	local := seedAccount(t, db, adminSpec{username: "last-local", admin: true, active: true})
	seedAccount(t, db, adminSpec{username: "sso-admin", admin: true, active: true, origin: model.AuthSourceOIDC})
	svc := NewUserService(db, authz.NewAssetAuthorizationService(db))

	err := svc.UpdateStatus(local.ID, false)
	assertLastLocalAdminRejection(t, err)
	if n := mustCountLocalAdmins(t, db); n != 1 {
		t.Fatalf("被拒後本地 admin 應仍為 1，got %d", n)
	}
}

func TestLocalAdminInvariantRejectsDeleteLastLocalAdmin(t *testing.T) {
	db := localAdminDB(t)
	local := seedAccount(t, db, adminSpec{username: "last-local", admin: true, active: true})
	seedAccount(t, db, adminSpec{username: "sso-admin", admin: true, active: true, extCred: true})
	svc := NewUserService(db, authz.NewAssetAuthorizationService(db))

	err := svc.Delete(local.ID)
	assertLastLocalAdminRejection(t, err)
	if n := mustCountLocalAdmins(t, db); n != 1 {
		t.Fatalf("被拒後本地 admin 應仍為 1，got %d", n)
	}
	var alive int64
	db.Model(&model.User{}).Where("id = ?", local.ID).Count(&alive)
	if alive != 1 {
		t.Fatalf("被拒的刪除不得留下副作用（帳號應仍存在），got count=%d", alive)
	}
}

func TestLocalAdminInvariantRejectsRoleRemovalOfLastLocalAdmin(t *testing.T) {
	db := localAdminDB(t)
	local := seedAccount(t, db, adminSpec{username: "last-local", admin: true, active: true})
	seedAccount(t, db, adminSpec{username: "sso-admin", admin: true, active: true, ldapUser: true})
	svc := NewUserService(db, authz.NewAssetAuthorizationService(db))

	err := svc.AssignRoles(local.ID, []string{"user"})
	assertLastLocalAdminRejection(t, err)
	if n := mustCountLocalAdmins(t, db); n != 1 {
		t.Fatalf("被拒後本地 admin 應仍為 1，got %d", n)
	}
}

// 仍保留 admin 的角色重設不受不變式約束（不減少計數者不得被誤擋）
func TestLocalAdminInvariantAllowsRoleResetKeepingAdmin(t *testing.T) {
	db := localAdminDB(t)
	local := seedAccount(t, db, adminSpec{username: "only-local", admin: true, active: true})
	svc := NewUserService(db, authz.NewAssetAuthorizationService(db))

	if err := svc.AssignRoles(local.ID, []string{model.RoleAdmin, "user"}); err != nil {
		t.Fatalf("保留 admin 的角色重設應允許，got %v", err)
	}
	if n := mustCountLocalAdmins(t, db); n != 1 {
		t.Fatalf("角色重設後本地 admin 應仍為 1，got %d", n)
	}
}

func assertLastLocalAdminRejection(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("應被最後本地 admin 不變式拒絕，got nil")
	}
	if !errors.Is(err, ErrLastLocalAdmin) {
		t.Fatalf("錯誤應為 ErrLastLocalAdmin，got %v", err)
	}
	// 相容性：既有 handler 只認 ErrLastAdmin 並回 400，斷了就變 500
	if !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("錯誤應同時滿足 errors.Is(err, ErrLastAdmin)（handler 相容），got %v", err)
	}
	var typed *LastLocalAdminError
	if !errors.As(err, &typed) {
		t.Fatalf("錯誤應可經 errors.As 取得 LastLocalAdminError，got %v", err)
	}
	if typed.Code != apierror.CodeLastLocalAdmin {
		t.Fatalf("出口碼應為 %s，got %s", apierror.CodeLastLocalAdmin, typed.Code)
	}
}

// --- 情境 3：已為 0 時不阻擋 ---

// TestLocalAdminInvariantDoesNotBlockWhenAlreadyZero 已無本地 admin 的既有部署
// （例如全員已切 SSO）SHALL NOT 因本不變式被鎖死一切管理操作
func TestLocalAdminInvariantDoesNotBlockWhenAlreadyZero(t *testing.T) {
	db := localAdminDB(t)
	extA := seedAccount(t, db, adminSpec{username: "sso-admin-a", admin: true, active: true, origin: model.AuthSourceOIDC})
	extB := seedAccount(t, db, adminSpec{username: "sso-admin-b", admin: true, active: true, origin: model.AuthSourceOIDC})
	plain := seedAccount(t, db, adminSpec{username: "plain", admin: false, active: true})
	svc := NewUserService(db, authz.NewAssetAuthorizationService(db))

	if n := mustCountLocalAdmins(t, db); n != 0 {
		t.Fatalf("前提：本地 admin 應為 0，got %d", n)
	}
	if err := svc.UpdateStatus(extA.ID, false); err != nil {
		t.Fatalf("本地 admin 已為 0 時停用外部 admin 不應被擋，got %v", err)
	}
	if err := svc.AssignRoles(extB.ID, []string{"user"}); err != nil {
		t.Fatalf("本地 admin 已為 0 時移除外部 admin 角色不應被擋，got %v", err)
	}
	if err := svc.Delete(plain.ID); err != nil {
		t.Fatalf("本地 admin 已為 0 時刪除一般帳號不應被擋，got %v", err)
	}
}

// --- 鎖鍵不撞號（key_manager_lock.go 的 advisory keyspace 登記要求）---

func TestLocalAdminLockKeyDistinct(t *testing.T) {
	if LocalAdminLockKey == keyvault.KEKDataKeysLockKey {
		t.Fatalf("advisory lock key 撞號：LocalAdminLockKey 與 keyvault.KEKDataKeysLockKey 同為 %#x", LocalAdminLockKey)
	}
}

// --- 並發：write-skew ---

// localAdminConcurrentDB 檔案型 sqlite（非 :memory:）＋兩條連線。
//
// **刻意不同於其他測試的 :memory:＋MaxOpenConns(1)**：單連線會把兩個 goroutine 的
// 一切 DB 存取序列化，使「兩者各自讀到對方仍在」的 write-skew 交錯無法穩定重現——
// 突變測試（把鎖內重讀改成鎖外預讀）會因為第二個 goroutine 的預讀被迫等到第一個
// 交易提交後才發生而**看似仍然安全**，測試就失去辨識力。檔案型 DB 的兩條真連線
// 可讓預讀真正並行，突變因此被確定性地抓到。
func localAdminConcurrentDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "localadmin.db") + "?_pragma=busy_timeout(5000)"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql db: %v", err)
	}
	sqlDB.SetMaxOpenConns(2)
	localAdminMigrate(t, db)
	return db
}

// TestLocalAdminInvariantConcurrentRemovalKeepsOne 兩個並發的移除類操作
// （停用 A、刪除 B）作用於僅剩的兩名本地 admin：至多一個成功，事後本地 admin ≥ 1。
//
// 單次操作內的檢查對此完全無感——兩個請求各自看見「對方還在」即可同時提交。
// 交錯由 localAdminPreWriteHook 在「判定通過、寫入之前」
// 製造：正確實作下第二個操作被系統級鎖擋在門外，等第一個提交後才重讀而被拒絕。
func TestLocalAdminInvariantConcurrentRemovalKeepsOne(t *testing.T) {
	db := localAdminConcurrentDB(t)
	a := seedAccount(t, db, adminSpec{username: "admin-a", admin: true, active: true})
	b := seedAccount(t, db, adminSpec{username: "admin-b", admin: true, active: true})
	svc := NewUserService(db, authz.NewAssetAuthorizationService(db))

	var mu sync.Mutex
	arrived := 0
	gate := make(chan struct{})
	localAdminPreWriteHook = func() {
		mu.Lock()
		arrived++
		n := arrived
		mu.Unlock()
		if n >= 2 {
			// 兩方都走到「判定已通過、尚未寫入」——不變式已被突破，立刻放行讓
			// 兩筆寫入都落地，使測試看到歸零的結果（而非被計時掩蓋）
			close(gate)
			return
		}
		select {
		case <-gate:
		case <-time.After(300 * time.Millisecond):
		}
	}
	defer func() { localAdminPreWriteHook = nil }()

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		errs[0] = svc.UpdateStatus(a.ID, false)
	}()
	go func() {
		defer wg.Done()
		errs[1] = svc.Delete(b.ID)
	}()
	wg.Wait()

	failures := 0
	for _, err := range errs {
		if err != nil {
			failures++
			if !errors.Is(err, ErrLastLocalAdmin) {
				t.Fatalf("失敗方應為最後本地 admin 不變式拒絕，got %v", err)
			}
		}
	}
	if failures < 1 {
		t.Errorf("兩個並發移除操作至少一個應失敗，got 全部成功（errs=%v）", errs)
	}
	if n := mustCountLocalAdmins(t, db); n < 1 {
		t.Errorf("事後本地 admin 應 ≥ 1，got %d", n)
	}
}
