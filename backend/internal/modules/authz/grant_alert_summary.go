package authz

import (
	"sort"
	"strconv"
	"strings"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
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
// 發放含節點範圍時另帶 scope_node_ids（節點編號聯集，升冪逗號接）與 scope_node_count（不重複節點數）；
// 全域發放兩者都不帶。
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
	params := map[string]string{
		"path":          path,
		"recipient":     dashIfEmpty(recipient),
		"role_name":     RoleNames(granted),
		"scope_summary": strings.Join(list, ","),
	}
	if ids, count := scopeNodeIDs(granted); count > 0 {
		params["scope_node_ids"] = ids
		params["scope_node_count"] = strconv.Itoa(count)
	}
	return params
}

// scopeNodeIDs 各節點範圍項的節點聯集：升冪、逗號接，回傳列出的清單與不重複的總數。
//
// 清單最多 model.RangeAuditMaxNodes 個，且長度不超過不透明值的淨化上限
// （notifycat.MaxOpaqueRunes，超過會被截成帶省略號的殘缺編號）；總數永遠是實際數量，
// 清單被截短時讀者以總數得知還有多少未列出。
func scopeNodeIDs(granted []GrantEntry) (string, int) {
	set := map[uint]bool{}
	for _, e := range granted {
		if e.Scope != model.ScopeKindNodes {
			continue
		}
		for _, id := range e.Nodes {
			set[id] = true
		}
	}
	if len(set) == 0 {
		return "", 0
	}
	ids := make([]uint, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	var b strings.Builder
	for i, id := range ids {
		if i >= model.RangeAuditMaxNodes {
			break
		}
		part := strconv.FormatUint(uint64(id), 10)
		if i > 0 {
			part = "," + part
		}
		if b.Len()+len(part) >= notifycat.MaxOpaqueRunes {
			break
		}
		b.WriteString(part)
	}
	return b.String(), len(ids)
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
