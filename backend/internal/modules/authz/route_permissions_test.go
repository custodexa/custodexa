package authz

import "testing"

// TestHasPermission_LeastPrivilege 鎖定最小權限矩陣（7.2.x +）：
// user 不得看審計/告警/session；auditor 顯式保留（不因從 user 移除而被架空）；admin 全權
func TestHasPermission_LeastPrivilege(t *testing.T) {
	cases := []struct {
		role string
		perm Permission
		want bool
	}{
		// admin 全權
		{"admin", PermAuditView, true},
		{"admin", PermAlertView, true},
		{"admin", PermAssetDelete, true},
		{"admin", PermSessionView, true},

		// user 最小權限：僅資產 view，不得看審計、告警與 session 管理視圖
		//（session:view 收斂為稽核職能）
		{"user", PermAssetView, true},
		{"user", PermSessionView, false},
		{"user", PermAuditView, false},
		{"user", PermAlertView, false},
		{"user", PermAlertManage, false},

		// auditor 顯式保留審計/告警 view + 告警管理（不可被 user 移除連帶架空）
		{"auditor", PermAssetView, true},
		{"auditor", PermSessionView, true},
		{"auditor", PermAuditView, true},
		{"auditor", PermAlertView, true},
		{"auditor", PermAlertManage, true},
		// auditor 無資產寫入權
		{"auditor", PermAssetDelete, false},

		// 未知角色一律拒
		{"guest", PermAssetView, false},
		{"", PermAuditView, false},
	}

	for _, c := range cases {
		if got := RoutePermissions(c.role, c.perm); got != c.want {
			t.Errorf("RoutePermissions(%q, %q) = %v, want %v", c.role, c.perm, got, c.want)
		}
	}
}

// TestUserPermissionsSliceNotAliased 防禦：auditor 權限不得與 user 共用底層陣列
// （原 bug：append(userPermissions, ...) 會讓兩者耦合）——確認獨立定義
func TestUserPermissionsSliceNotAliased(t *testing.T) {
	// user 有 AlertManage 應為 false、auditor 應為 true——若共用陣列會互相污染
	if RoutePermissions("user", PermAlertManage) {
		t.Error("user 不應有 PermAlertManage")
	}
	if !RoutePermissions("auditor", PermAlertManage) {
		t.Error("auditor 應有 PermAlertManage")
	}
}

// TestCredentialManagePermissionNotGrantedToUserOrAuditor 憑證庫授權點的角色邊界。
//
// 憑證識別、名稱與掛載拓撲合起來就是一張「哪些主機共用同一組秘密」的地圖，
// 對非管理者而言那是免費的橫向移動路線。稽核角色要核對共用關係走輪替證據報告
// （只投影名稱與共用標記），那是刻意的顯式例外，不以本授權點承載。
//
// **雙向**：既釘住 credential:manage 不得落到非管理角色，也釘住既有角色的權限集合
// 不因新增授權點而變動（該清的歸零、該留的維持）。判定一律經 RoutePermissions
// 的回傳——userPermissions 與 auditorPermissions 是函式內的區域變數，測試取不到；
// 把 credential:manage 加進其中任一個只要一行，而那一行會立即反應在回傳值上。
func TestCredentialManagePermissionNotGrantedToUserOrAuditor(t *testing.T) {
	if got := RoutePermissions("admin", PermCredentialManage); !got {
		t.Error("admin 應具 credential:manage（admin 短路）")
	}
	for _, role := range []string{"user", "auditor", "guest", ""} {
		if RoutePermissions(role, PermCredentialManage) {
			t.Errorf("角色 %q 不得具 credential:manage", role)
		}
	}
	// 既有角色的權限集合不得因新增授權點而變動
	for _, c := range []struct {
		role string
		perm Permission
		want bool
	}{
		{"user", PermAssetView, true},
		{"auditor", PermAuditView, true},
		{"auditor", PermAssetView, true},
	} {
		if got := RoutePermissions(c.role, c.perm); got != c.want {
			t.Errorf("RoutePermissions(%q, %q) = %v, want %v", c.role, c.perm, got, c.want)
		}
	}
}
