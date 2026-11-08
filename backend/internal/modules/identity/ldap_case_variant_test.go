package identity

import (
	"errors"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 目錄登入以不分大小寫的名稱對應既有帳號：
// 帳號的停用、鎖定狀態套用到整個大小寫變體組，且不另建影子帳號。
// 全部走真 sqlite 與真登入流程，斷言落在回傳錯誤、帳號數與目錄呼叫次數上。

// caseVariantUser 建一個目錄供應帳號；active／locked 以建立後更新寫入
// （Active 欄位有資料庫預設值 true，建立時給 false 會被預設值蓋掉）。
func caseVariantUser(t *testing.T, db *gorm.DB, username string, active, locked bool) *model.User {
	t.Helper()
	u := roleMappingUser(t, db, username)
	if !active {
		if err := db.Model(&model.User{}).Where("id = ?", u.ID).Update("active", false).Error; err != nil {
			t.Fatalf("停用 %s: %v", username, err)
		}
	}
	if locked {
		until := time.Now().Add(time.Hour)
		if err := db.Model(&model.User{}).Where("id = ?", u.ID).Update("locked_until", until).Error; err != nil {
			t.Fatalf("鎖定 %s: %v", username, err)
		}
	}
	return u
}

func caseVariantUserCount(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	if err := db.Unscoped().Model(&model.User{}).Count(&n).Error; err != nil {
		t.Fatalf("計數: %v", err)
	}
	return n
}

// caseVariantLogin 以指定名稱走一次目錄登入，回傳錯誤、目錄呼叫次數與登入後的帳號數。
func caseVariantLogin(t *testing.T, auth *AuthService, db *gorm.DB, name string) (*LoginResponse, error, int, int64) {
	t.Helper()
	fake := &fakeLDAPAuthenticator{info: &LDAPUserInfo{Username: name}}
	auth.SetLDAPResolver(staticLDAPResolver(fake))
	resp, err := auth.Login(&LoginRequest{Username: name, Password: "directory-password"})
	return resp, err, fake.calls, caseVariantUserCount(t, db)
}

func TestLDAPCaseVariant_InactiveAccountExactNameMissing(t *testing.T) {
	auth, _, db := setupRoleMappingEnv(t)
	caseVariantUser(t, db, "alice", false, false)
	before := caseVariantUserCount(t, db)

	resp, err, _, after := caseVariantLogin(t, auth, db, "Alice")
	if !errors.Is(err, ErrUserInactive) {
		t.Fatalf("err = %v, want ErrUserInactive（resp=%v）", err, resp != nil)
	}
	if after != before {
		t.Fatalf("帳號數 %d -> %d，不應新增帳號", before, after)
	}
}

func TestLDAPCaseVariant_LockedAccountExactNameMissing(t *testing.T) {
	auth, _, db := setupRoleMappingEnv(t)
	caseVariantUser(t, db, "alice", true, true)
	before := caseVariantUserCount(t, db)

	resp, err, calls, after := caseVariantLogin(t, auth, db, "ALICE")
	if !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("err = %v, want ErrAccountLocked（resp=%v）", err, resp != nil)
	}
	if calls != 0 {
		t.Fatalf("目錄被呼叫 %d 次，鎖定須在目錄認證前拒絕", calls)
	}
	if after != before {
		t.Fatalf("帳號數 %d -> %d，不應新增帳號", before, after)
	}
}

func TestLDAPCaseVariant_ExactActiveCopyWithInactiveVariant(t *testing.T) {
	auth, _, db := setupRoleMappingEnv(t)
	caseVariantUser(t, db, "alice", false, false)
	caseVariantUser(t, db, "Alice", true, false)
	before := caseVariantUserCount(t, db)

	resp, err, _, after := caseVariantLogin(t, auth, db, "Alice")
	if !errors.Is(err, ErrUserInactive) {
		t.Fatalf("err = %v, want ErrUserInactive（resp=%v）", err, resp != nil)
	}
	if after != before {
		t.Fatalf("帳號數 %d -> %d", before, after)
	}
}

func TestLDAPCaseVariant_ExactActiveCopyWithLockedVariant(t *testing.T) {
	auth, _, db := setupRoleMappingEnv(t)
	caseVariantUser(t, db, "alice", true, true)
	caseVariantUser(t, db, "Alice", true, false)

	resp, err, calls, _ := caseVariantLogin(t, auth, db, "Alice")
	if !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("err = %v, want ErrAccountLocked（resp=%v）", err, resp != nil)
	}
	if calls != 0 {
		t.Fatalf("目錄被呼叫 %d 次，鎖定須在目錄認證前拒絕", calls)
	}
}

func TestLDAPCaseVariant_LocalAccountDifferingOnlyInCase(t *testing.T) {
	auth, _, db := setupRoleMappingEnv(t)
	local := &model.User{Username: "Bob", Password: "irrelevant", Active: true}
	if err := db.Create(local).Error; err != nil {
		t.Fatal(err)
	}
	before := caseVariantUserCount(t, db)

	resp, err, calls, after := caseVariantLogin(t, auth, db, "bob")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials（resp=%v）", err, resp != nil)
	}
	if calls != 0 {
		t.Fatalf("目錄被呼叫 %d 次，不應打目錄", calls)
	}
	if after != before {
		t.Fatalf("帳號數 %d -> %d，不應新增帳號", before, after)
	}
}

func TestLDAPCaseVariant_SeveralActiveVariantsNoExactMatch(t *testing.T) {
	auth, _, db := setupRoleMappingEnv(t)
	caseVariantUser(t, db, "carol", true, false)
	caseVariantUser(t, db, "Carol", true, false)
	before := caseVariantUserCount(t, db)

	resp, err, _, after := caseVariantLogin(t, auth, db, "CAROL")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials（resp=%v）", err, resp != nil)
	}
	if after != before {
		t.Fatalf("帳號數 %d -> %d，不應新增帳號", before, after)
	}
}

// 大小寫變體對應到既有帳號：登入屬於既有帳號、帳號數不變。
func TestLDAPCaseVariant_ResolvesToExistingAccount(t *testing.T) {
	auth, _, db := setupRoleMappingEnv(t)
	existing := caseVariantUser(t, db, "alice", true, false)
	before := caseVariantUserCount(t, db)

	resp, err, calls, after := caseVariantLogin(t, auth, db, "Alice")
	if err != nil {
		t.Fatalf("登入失敗: %v", err)
	}
	if resp == nil || resp.User == nil || resp.User.ID != existing.ID || resp.User.Username != "alice" {
		t.Fatalf("登入的帳號不是既有 alice: %+v", resp)
	}
	if calls != 1 {
		t.Fatalf("目錄呼叫 %d 次，want 1", calls)
	}
	if after != before {
		t.Fatalf("帳號數 %d -> %d", before, after)
	}
}

// 回歸：同大小寫、單一目錄帳號登入不受影響。
func TestLDAPCaseVariant_SameCaseSingleAccountUnchanged(t *testing.T) {
	auth, _, db := setupRoleMappingEnv(t)
	existing := caseVariantUser(t, db, "alice", true, false)

	resp, err, calls, _ := caseVariantLogin(t, auth, db, "alice")
	if err != nil || resp == nil || resp.User.ID != existing.ID || calls != 1 {
		t.Fatalf("resp=%+v err=%v calls=%d", resp, err, calls)
	}
}

// 回歸：組為空時沿用首次登入供應。
func TestLDAPCaseVariant_EmptySetStillProvisions(t *testing.T) {
	auth, _, db := setupRoleMappingEnv(t)

	resp, err, calls, after := caseVariantLogin(t, auth, db, "dave")
	if err != nil || resp == nil || resp.User.Username != "dave" || calls != 1 {
		t.Fatalf("resp=%+v err=%v calls=%d", resp, err, calls)
	}
	if after != 1 {
		t.Fatalf("帳號數 = %d, want 1", after)
	}
}

// 回歸：精確命中本地帳號，走本地密碼路徑、不打目錄。
func TestLDAPCaseVariant_ExactLocalAccountKeepsLocalPath(t *testing.T) {
	auth, _, db := setupRoleMappingEnv(t)
	local := &model.User{Username: "Bob", Password: "not-a-hash", Active: true}
	if err := db.Create(local).Error; err != nil {
		t.Fatal(err)
	}
	// 另有一個目錄帳號只差大小寫：不影響精確命中的本地帳號
	caseVariantUser(t, db, "bob", true, false)

	_, err, calls, _ := caseVariantLogin(t, auth, db, "Bob")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials（本地密碼比對失敗）", err)
	}
	if calls != 0 {
		t.Fatalf("目錄被呼叫 %d 次，本地帳號不得走目錄", calls)
	}
}

// 升級整併程序可行：只停用多餘帳號仍被拒；刪除後兩種大小寫都登入到保留帳號。
func TestLDAPCaseVariant_ConsolidationByDeletion(t *testing.T) {
	auth, _, db := setupRoleMappingEnv(t)
	keep := caseVariantUser(t, db, "gina", true, false)
	extra := caseVariantUser(t, db, "Gina", false, false)
	before := caseVariantUserCount(t, db)

	_, err, _, _ := caseVariantLogin(t, auth, db, "gina")
	if !errors.Is(err, ErrUserInactive) {
		t.Fatalf("只停用不刪除：err = %v, want ErrUserInactive", err)
	}

	if err := db.Delete(&model.User{}, extra.ID).Error; err != nil {
		t.Fatalf("軟刪除: %v", err)
	}
	for _, name := range []string{"gina", "Gina"} {
		resp, err, _, after := caseVariantLogin(t, auth, db, name)
		if err != nil || resp == nil || resp.User.ID != keep.ID {
			t.Fatalf("刪除後以 %s 登入: resp=%+v err=%v", name, resp, err)
		}
		if after != before {
			t.Fatalf("帳號數 %d -> %d", before, after)
		}
	}
}
