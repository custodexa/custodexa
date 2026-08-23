package authz

// 路由級 RBAC 表。
//
// 本檔自 `internal/middleware/permission.go` **原樣搬入**：權限常數值、
// 角色→權限對照、判定順序逐字未改，行為位元相同。搬入是為了收掉
// 「權限判定第三份真相散落在 middleware」——表與判定函式屬授權語義，
// 應與資產級 ACL 同住 authz，middleware 只保留「取角色 → 問 authz → 回 403」
// 這段 HTTP 關注點。
//
// **刻意不做的事**：與 `AssetAuthorizationService` 的權限階層合流，
// 屬路由級 RBAC 與資產級 ACL 的語義合流，是設計變更不是重構，故延後
// （已列入待辦）。本檔不得引入任何 DB 存取或模組相依——它是純表＋純函式。

// Permission 權限常數
type Permission string

const (
	// Asset 權限
	PermAssetView   Permission = "asset:view"
	PermAssetCreate Permission = "asset:create"
	PermAssetUpdate Permission = "asset:update"
	PermAssetDelete Permission = "asset:delete"
	PermAssetTest   Permission = "asset:test"

	// Session 權限
	PermSessionView      Permission = "session:view"
	PermSessionTerminate Permission = "session:terminate"

	// Audit 權限
	PermAuditView Permission = "audit:view"

	// Alert 權限
	PermAlertView   Permission = "alert:view"
	PermAlertManage Permission = "alert:manage"
)

// RoutePermissions 檢查角色是否有指定權限（原 `middleware.hasPermission`）。
//
// 簡化實現：基於角色的權限控制（RBAC）
//   - admin: 擁有所有權限
//   - user: 僅有 asset view 權限（session 檢視收斂為稽核職能，不授予）
//   - auditor: 擁有 view、session 和 audit 相關權限
func RoutePermissions(role string, perm Permission) bool {
	// Admin 擁有所有權限
	if role == "admin" {
		return true
	}

	// 定義 user 角色權限（最小權限，7.2.x +）：
	// 一般使用者不得看審計、告警與 session 管理視圖——session 檢視（列表/詳情/統計/指令）
	// 屬稽核職能，收斂為 admin/auditor；user 看自己的連線走 /my/connections 自助端點
	userPermissions := []Permission{
		PermAssetView,
	}

	// 定義 auditor 角色權限：顯式保留 audit/alert view（不可用 append(userPermissions)
	// 繼承——否則從 user 移除這兩項會連帶架空 auditor）。auditor = 稽核唯讀 + 告警管理
	auditorPermissions := []Permission{
		PermAssetView,
		PermSessionView,
		PermAuditView,
		PermAlertView,
		PermAlertManage,
	}

	// 根據角色檢查權限
	var allowedPermissions []Permission
	switch role {
	case "user":
		allowedPermissions = userPermissions
	case "auditor":
		allowedPermissions = auditorPermissions
	default:
		return false
	}

	// 檢查權限是否在允許列表中
	for _, p := range allowedPermissions {
		if p == perm {
			return true
		}
	}

	return false
}
