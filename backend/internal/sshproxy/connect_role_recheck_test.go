package sshproxy

import (
	"net/http"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// clearUserRoles 清空指定 user 的 DB 角色關聯（模擬降權：primaryRoleOf 退回 user）
func clearUserRoles(t *testing.T, db *gorm.DB, userID uint) {
	t.Helper()
	var u model.User
	if err := db.First(&u, userID).Error; err != nil {
		t.Fatalf("load user %d: %v", userID, err)
	}
	if err := db.Model(&u).Association("Roles").Clear(); err != nil {
		t.Fatalf("clear roles: %v", err)
	}
}

// appendUserRole 追加一個既有角色關聯（模擬多角色帳號）
func appendUserRole(t *testing.T, db *gorm.DB, userID uint, roleName string) {
	t.Helper()
	var u model.User
	if err := db.First(&u, userID).Error; err != nil {
		t.Fatalf("load user %d: %v", userID, err)
	}
	var role model.Role
	if err := db.Where("name = ?", roleName).First(&role).Error; err != nil {
		t.Fatalf("load role %s: %v", roleName, err)
	}
	if err := db.Model(&u).Association("Roles").Append(&role); err != nil {
		t.Fatalf("append role: %v", err)
	}
}

// TestConnectRoleUsesLiveDBRole：connect 簽發與兌換的 admin 特權判定
// SHALL 以 DB 現查有效角色為準，不憑 JWT／token 攜帶的角色快照——降權即時生效、
// 撤權殘窗歸零。fixture 中 user2 具 admin 角色但對 asset1 無顯式 grant（僅 user1 有），
// 其連線能力純來自 admin 角色短路，故降權後即失去連線資格，是最乾淨的觀測點。
func TestConnectRoleUsesLiveDBRole(t *testing.T) {
	t.Run("簽發點：JWT admin 但 DB 已降為 user、無授權→簽發 403、不產 token", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		clearUserRoles(t, db, 2) // user2 admin→無角色（primaryRoleOf 退回 user）

		// issueToken 仍以 admin mock role 呼叫，模擬「JWT 攜帶 admin 快照」——
		// 簽發點 SHALL 以 DB 現況（user）判定，不套用 admin 短路
		code, resp, _ := issueToken(h, 2, model.RoleAdmin, 1)
		if code != http.StatusForbidden || resp["connect_token"] != nil {
			t.Fatalf("DB 降權後簽發應 403、不產 token（不信 JWT 角色快照）: code=%d resp=%v", code, resp)
		}
	})

	t.Run("文字終端兌換點：簽發後 DB 降權→兌換 403", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)

		// user2=admin 先正常簽出 token（admin 短路，對 asset1 無 grant 仍放行）
		code, resp, _ := issueToken(h, 2, model.RoleAdmin, 1)
		if code != http.StatusOK || resp["connect_token"] == nil {
			t.Fatalf("admin 簽發前置應成功: code=%d resp=%v", code, resp)
		}
		token, _ := resp["connect_token"].(string)

		// 簽發後、兌換前降權 user2（admin→user，對 asset1 無 grant）
		clearUserRoles(t, db, 2)

		rcode, rresp := redeemSSH(h, token)
		if rcode != http.StatusForbidden {
			t.Fatalf("兌換點 DB 降權應即時生效 403（不憑簽發時 admin 快照）: code=%d resp=%v", rcode, rresp)
		}
	})

	t.Run("多角色 admin+user 未降權→簽發正常放行（折疊為 admin）", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		appendUserRole(t, db, 2, model.RoleUser) // user2 現為 admin+user

		code, resp, _ := issueToken(h, 2, model.RoleAdmin, 1)
		if code != http.StatusOK || resp["connect_token"] == nil {
			t.Fatalf("admin+user 多角色未降權應以 admin 放行（折疊不受綁定順序影響）: code=%d resp=%v", code, resp)
		}
	})
}
