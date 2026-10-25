package authz

import (
	"sort"
	"strings"
)

// 授權變更告警的摘要內容與分級鍵。
//
// 分級鍵是系統告警目錄登錄的類型鍵（目錄是唯一來源，由 identity 的呼叫端以同名常數對照並由測試比對）；
// 摘要只列角色名稱、範圍與路徑代碼，不含密碼、token、外部身分的 subject。

const (
	AlertKeySelfIncreased     = "self_privilege_increased"
	AlertKeySelfDecreased     = "self_privilege_decreased"
	AlertKeyManagementGranted = "management_role_granted"
)

// SelfPrivilegeAlertKey 自我授權方向對應的分級鍵；無方向回空字串。
func SelfPrivilegeAlertKey(dir GrantDirection) string {
	switch dir {
	case GrantIncrease:
		return AlertKeySelfIncreased
	case GrantDecrease:
		return AlertKeySelfDecreased
	}
	return ""
}

// SelfPrivilegeParams 自我授權事件的參數：寫入路徑代碼與前後角色名稱。
func SelfPrivilegeParams(path string, before, after []GrantEntry) map[string]string {
	return map[string]string{
		"path":         path,
		"roles_before": RoleNames(before),
		"roles_after":  RoleNames(after),
	}
}

// ManagementGrantParams 管理類發放事件的參數：寫入路徑、受發放主體識別、角色名稱與範圍摘要。
func ManagementGrantParams(path, recipient string, granted []GrantEntry) map[string]string {
	scopes := map[string]bool{}
	for _, e := range granted {
		scopes[e.Scope] = true
	}
	list := make([]string, 0, len(scopes))
	for s := range scopes {
		list = append(list, s)
	}
	sort.Strings(list)
	return map[string]string{
		"path":          path,
		"recipient":     dashIfEmpty(recipient),
		"role_name":     RoleNames(granted),
		"scope_summary": strings.Join(list, ","),
	}
}

// RoleNames 去重排序後以逗號連接的角色名稱；空集合回 "-"（目錄要求必要參數非空）。
func RoleNames(es []GrantEntry) string {
	seen := map[string]bool{}
	var names []string
	for _, e := range es {
		if !seen[e.RoleName] {
			seen[e.RoleName] = true
			names = append(names, e.RoleName)
		}
	}
	sort.Strings(names)
	return dashIfEmpty(strings.Join(names, ","))
}

func dashIfEmpty(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
