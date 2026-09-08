package identity

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 本地管理員計數的來源條件（雙向）。
//
// # 為什麼要雙向
//
// 只驗「映射來的不算」時，把整個計數改成恆零一樣會綠——而恆零的後果不是
// 保守而是門戶洞開：`assertLocalAdminInvariant` 的第一步是「目標當下不是本地
// 管理員就放行」，恆零之下每一次移除都放行，最後一個管理員可以被刪掉。
// 故另一個方向必須同時釘住：管理者指派的列一定要使計數增加。
//
// 兩支測試共用同一個 fixture，差別只在關聯列的來源值。

// seedAdminRoleWithSource 給指定帳號掛一列管理員角色，並落指定的來源值。
func seedAdminRoleWithSource(t *testing.T, db *gorm.DB, userID uint, source string) {
	t.Helper()
	var role model.Role
	if err := db.Where("name = ?", model.RoleAdmin).First(&role).Error; err != nil {
		t.Fatalf("load admin role: %v", err)
	}
	if err := db.Create(&model.UserRole{
		UserID: userID, RoleID: role.ID, Source: source,
	}).Error; err != nil {
		t.Fatalf("attach admin role (source=%s): %v", source, err)
	}
}

// TestLocalAdminScopeExcludesMappedOnly 僅由外部群組映射取得管理員角色者不計入。
//
// 計入的後果：計數被墊高，移除真正的本地管理員時不變式放行；
// 群組管理員把人移出群組之後那一列在下次登入消失，總數歸零，無人能解封。
func TestLocalAdminScopeExcludesMappedOnly(t *testing.T) {
	db := localAdminDB(t)
	// 一個貨真價實的本地管理員當基準，讓斷言比對的是「有沒有多算一個」
	seedAccount(t, db, adminSpec{username: "manual-admin", admin: true, active: true})
	if n := mustCountLocalAdmins(t, db); n != 1 {
		t.Fatalf("基準計數 = %d, want 1：fixture 本身就不成立", n)
	}

	// 另一個帳號，除了「管理員角色只由映射賦予」之外每一個條件都滿足
	// ——啟用中、本地憑證、密碼非空
	mapped := seedAccount(t, db, adminSpec{username: "mapped-admin", admin: false, active: true})
	seedAdminRoleWithSource(t, db, mapped.ID, model.RoleSourceMapped)

	if n := mustCountLocalAdmins(t, db); n != 1 {
		t.Fatalf("本地管理員數 = %d, want 1：僅由映射取得管理員角色者被計入了。"+
			"該列的壽命只到下一次登入重算，計入它會讓移除最後一個真正的本地管理員被放行", n)
	}
	// 個別資格也要一致：計數與「你是不是」必須同一定義，
	// 否則會出現「總數說有兩個、但兩個都被判為不是」這種自相矛盾的狀態
	isAdmin, err := isLocalAdmin(db, mapped.ID)
	if err != nil {
		t.Fatalf("isLocalAdmin: %v", err)
	}
	if isAdmin {
		t.Fatalf("僅由映射取得管理員角色者被判為本地管理員")
	}
}

// TestLocalAdminScopeCountsManual 管理者指派的管理員角色必須使計數增加。
//
// 這是上一支的反面。少了它，「把計數改成恆零」與「正確排除映射列」不可區分，
// 而恆零之下每一次移除都會被放行。並存態（管理者指派與映射同時存在）同樣要算
// ——管理者的那一半不因為映射也給了同一個角色而消失。
func TestLocalAdminScopeCountsManual(t *testing.T) {
	db := localAdminDB(t)
	seedAccount(t, db, adminSpec{username: "manual-admin", admin: true, active: true})
	if n := mustCountLocalAdmins(t, db); n != 1 {
		t.Fatalf("基準計數 = %d, want 1", n)
	}

	// 第二位：以管理者指派的來源值直接落列，計數必須變成 2
	second := seedAccount(t, db, adminSpec{username: "manual-admin-2", admin: false, active: true})
	seedAdminRoleWithSource(t, db, second.ID, model.RoleSourceManual)
	if n := mustCountLocalAdmins(t, db); n != 2 {
		t.Fatalf("本地管理員數 = %d, want 2：管理者指派的列沒有使計數增加，"+
			"計數可能已退化為恆零——那會讓每一次移除都被放行", n)
	}
	isAdmin, err := isLocalAdmin(db, second.ID)
	if err != nil {
		t.Fatalf("isLocalAdmin: %v", err)
	}
	if !isAdmin {
		t.Fatalf("管理者指派的管理員未被判為本地管理員")
	}

	// 第三位：並存態。管理者指派的那一半不因為映射也命中同一個角色而消失
	third := seedAccount(t, db, adminSpec{username: "both-admin", admin: false, active: true})
	seedAdminRoleWithSource(t, db, third.ID, model.RoleSourceBoth)
	if n := mustCountLocalAdmins(t, db); n != 3 {
		t.Fatalf("本地管理員數 = %d, want 3：並存態未計入，"+
			"管理者指派的成分被映射的存在抵消了", n)
	}
}
