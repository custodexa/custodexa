package api

import "strings"

// frontendRouteSegments 前端路由的第一段集合。
//
// 登入後重導向目標除了「同源相對路徑」之外，還須匹配前端既有路由枚舉。
// 只比對**第一段**而非完整路徑：`/sessions/:id`、`/terminal/:assetId` 等帶動態
// 參數的路由無法逐一列舉，而第一段已足以把目標限制在應用自有的頁面空間內
// （尤其擋掉 `/api/...`——後端表面不該成為登入後的落點）。
//
// **此集合由 `TestFrontendRouteSegmentsNoDrift` 與 `frontend/src/router/index.js`
// 雙向比對**。新增前端路由時該測試會紅，這是刻意的：靜默漂移的表現是
// 「使用者 SSO 登入後被莫名丟回首頁」，比一個明確變紅的測試難查得多。
var frontendRouteSegments = map[string]bool{
	"":                        true, // 根路徑（預設落點）
	"login":                   true,
	"unseal":                  true,
	"workspace":               true,
	"terminal":                true,
	"share":                   true,
	"dashboard":               true,
	"assets":                  true,
	"sessions":                true,
	"my-connections":          true,
	"profile":                 true,
	"my-requests":             true,
	"approvals":               true,
	"audit-logs":              true,
	"access-reviews":          true,
	"checkpoint-verification": true,
	"commands":                true,
	"alerts":                  true,
	"authorizations":          true,
	"users":                   true,
	"roles":                   true,
	"user-groups":             true,
	"oidc-providers":          true,
	"ldap-directory":          true,
	"approver-scopes":         true,
	"security-policies":       true,
	"access-control":          true,
	"key-management":          true,
	"transmission-inventory":  true,
	"offsite-storage":         true,
	"change-secret-plans":     true,
	// audit：稽核調查工作台 `/audit/workbench`（auditor-workbench）。
	// 這是全站第一個帶第二段的稽核路由；既有稽核頁一律是平坦第一段
	// （audit-logs／alerts／commands），故此段是新開的命名空間而非改名
	"audit": true,
}

// firstPathSegment 取出路徑的第一段（不含前導斜線與查詢字串）
func firstPathSegment(path string) string {
	s := strings.TrimPrefix(path, "/")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
}

// isAllowedRedirectRoute 路徑是否落在前端路由枚舉內
func isAllowedRedirectRoute(path string) bool {
	return frontendRouteSegments[firstPathSegment(path)]
}

// isSHA256Hex 是否為 64 字元的十六進位（SHA256 的字面形狀）。
//
// 用於瀏覽器綁定值的形狀驗證：只驗非空會讓任意字串成為合法綁定
func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}
