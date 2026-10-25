package authz

import (
	"sort"
	"strings"
)

// 頁面入口規則的後端鏡像。
//
// 前端導覽與路由守衛的入口規則（router/entryRules.js 的 ENTRY_RULES）是「這個人進不進得去某個頁面」
// 的唯一來源；預覽要回答「儲存後多出或失去哪些頁面」，必須用同一份規則求值。本表逐列鏡像它，
// 並由 internal/api 的 TestRouteEntryRulesMirror 與前端 entry-rules-mirror.spec.js 經同一份
// 共用 golden 雙向比對：任一邊改了規則而另一邊沒改，兩支測試之一必紅。
// 本表只描述規則，不是授權裁決；後端強制點仍是路由登錄表。

// 入口規則種類，值即 golden 的 kind 欄。
const (
	RouteEntrySignedIn = "signed_in" // 登入即可，不看能力
	RouteEntryAll      = "all"       // 清單內每一個權限點都具備
	RouteEntryAny      = "any"       // 清單內任一權限點具備
)

// RouteEntryRule 一個頁面入口的規則。
type RouteEntryRule struct {
	Path        string
	Kind        string
	Permissions []string
}

func entryAll(path string, perms ...string) RouteEntryRule {
	return RouteEntryRule{Path: path, Kind: RouteEntryAll, Permissions: perms}
}

func entryAny(path string, perms ...string) RouteEntryRule {
	return RouteEntryRule{Path: path, Kind: RouteEntryAny, Permissions: perms}
}

func entrySignedIn(path string) RouteEntryRule {
	return RouteEntryRule{Path: path, Kind: RouteEntrySignedIn}
}

// RouteEntryRules 逐列鏡像前端入口規則，依路徑升冪；每次回傳新的副本。
func RouteEntryRules() []RouteEntryRule {
	rules := []RouteEntryRule{
		entrySignedIn("/dashboard"),
		entrySignedIn("/workspace"),
		entrySignedIn("/profile"),
		entrySignedIn("/assets"),
		entrySignedIn("/my-connections"),
		entrySignedIn("/my-requests"),
		entryAll("/my-agents", "ui:my-agents"),
		entryAll("/approvals", "ui:approvals"),
		entryAll("/sessions", "session:view"),
		entryAll("/audit/workbench", "audit:view"),
		entryAll("/audit/agent-tasks", "audit:view"),
		entryAll("/rotation-evidence", "audit:view"),
		entryAll("/audit/exports", "audit:view"),
		entryAll("/audit-logs", "audit:view"),
		entryAll("/commands", "audit:view"),
		entryAny("/alerts", "audit:view", "alertrule:manage", "systemalert:manage"),
		entryAll("/checkpoint-verification", "audit:integrity_view"),
		entryAll("/access-reviews", "audit:view"),
		entryAll("/compliance-map", "compliance:view"),
		entryAny("/credentials",
			"credential:view", "credential:create", "credential:update", "credential:set-secret",
			"credential:rotate", "credential:convert-scope", "credential:detach", "credential:delete",
			"credential:bind", "credential:manage"),
		entryAll("/authorizations", "authorization:manage"),
		entryAll("/change-secret-plans", "changesecret:manage"),
		entryAll("/change-secret-batches", "changesecret:manage"),
		entryAll("/users", "user:manage"),
		entryAll("/roles", "role:view"),
		entryAll("/user-groups", "usergroup:manage"),
		entryAll("/approver-scopes", "approverscope:manage"),
		entryAll("/identity-sources", "identity_source:manage"),
		entryAll("/security-policies", "securitypolicy:manage"),
		entryAll("/policy-groups", "policygroup:manage"),
		entryAll("/access-control", "securitypolicy:manage"),
		entryAll("/key-management", "key:manage"),
		entryAll("/transmission-inventory", "transmission:manage"),
		entryAll("/offsite-storage", "offsite:manage"),
		entryAll("/notification-channels", "notification_channel:manage"),
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Path < rules[j].Path })
	return rules
}

// satisfiedBy 規則在給定能力集合下是否放行；與前端 canEnter 同義（形狀不明一律拒絕）。
func (r RouteEntryRule) satisfiedBy(has func(string) bool) bool {
	switch r.Kind {
	case RouteEntrySignedIn:
		return true
	case RouteEntryAll:
		if len(r.Permissions) == 0 {
			return false
		}
		for _, k := range r.Permissions {
			if !has(k) {
				return false
			}
		}
		return true
	case RouteEntryAny:
		for _, k := range r.Permissions {
			if has(k) {
				return true
			}
		}
	}
	return false
}

// dependsOnUIPoint 規則依賴「呈現點」（審核資格、agent 入口）：那些由本人資格決定，
// 不隨角色內容或指派的假設而變，預覽不把它們列入增減。
func (r RouteEntryRule) dependsOnUIPoint() bool {
	for _, k := range r.Permissions {
		if strings.HasPrefix(k, UIPrefix) {
			return true
		}
	}
	return false
}

// visibleRoutes 主體在某個假設狀態下，受能力規則管轄且放行的入口路徑（升冪）。
// 登入即可的入口恆放行，不列入（不會增減）；依賴呈現點的入口不列入。
func visibleRoutes(p *Principal) []string {
	has := func(k string) bool { return p.Has(Permission(k)) }
	out := []string{}
	for _, r := range RouteEntryRules() {
		if r.Kind == RouteEntrySignedIn || r.dependsOnUIPoint() {
			continue
		}
		if r.satisfiedBy(has) {
			out = append(out, r.Path)
		}
	}
	return out
}
