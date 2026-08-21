package authz

import "testing"

// TestHasPermission_LeastPrivilege 鎖定 D9 最小權限矩陣（7.2.x + session-access-scoping）：
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
		//（session:view 收斂為稽核職能，session-access-scoping）
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
// （D9 原 bug：append(userPermissions, ...) 會讓兩者耦合）——確認獨立定義
func TestUserPermissionsSliceNotAliased(t *testing.T) {
	// user 有 AlertManage 應為 false、auditor 應為 true——若共用陣列會互相污染
	if RoutePermissions("user", PermAlertManage) {
		t.Error("user 不應有 PermAlertManage")
	}
	if !RoutePermissions("auditor", PermAlertManage) {
		t.Error("auditor 應有 PermAlertManage")
	}
}
