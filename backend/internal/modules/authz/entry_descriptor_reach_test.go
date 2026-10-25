package authz

import (
	"fmt"
	"sort"
	"testing"
)

// 描述表每個入口的每個非隱藏狀態，所持的鍵集合都必須進得了對應頁面：
// 描述表、依賴表、頁面入口規則三者不一致時，編輯器會讓人選了卻用不了。
func TestEntryDescriptorStatesReachTheirPage(t *testing.T) {
	pages := map[string]string{
		"assets":                  "/assets",
		"credentials":             "/credentials",
		"change_secret":           "/change-secret-plans",
		"authorizations":          "/authorizations",
		"approver_scopes":         "/approver-scopes",
		"users":                   "/users",
		"user_groups":             "/user-groups",
		"roles":                   "/roles",
		"identity_sources":        "/identity-sources",
		"sessions":                "/sessions",
		"audit_logs":              "/audit-logs",
		"checkpoint_verification": "/checkpoint-verification",
		"alerts":                  "/alerts",
		"compliance_map":          "/compliance-map",
		"access_reviews":          "/access-reviews",
		"security_policies":       "/security-policies",
		"policy_groups":           "/policy-groups",
		"key_management":          "/key-management",
		"transmission":            "/transmission-inventory",
		"offsite_storage":         "/offsite-storage",
		"notification_channels":   "/notification-channels",
		"system_alerts":           "/alerts",
		"alert_rules":             "/alerts",
		"rotation_schedules":      "/rotation-evidence",
	}
	exceptions := map[string]string{
		"schedules":      "cron 預覽輔助能力，沒有獨立畫面",
		"instance_guard": "全域橫幅，沒有獨立畫面",
		"syslog":         "設定卡位於傳輸安全頁，入口規則歸該頁",
	}
	rules := map[string]RouteEntryRule{}
	for _, r := range RouteEntryRules() {
		rules[r.Path] = r
	}
	for _, e := range EntryDescriptors() {
		if why, ok := exceptions[e.ID]; ok {
			if why == "" {
				t.Errorf("exception %s needs a reason", e.ID)
			}
			continue
		}
		path, ok := pages[e.ID]
		if !ok {
			t.Errorf("entry %q has no page mapping and is not a listed exception", e.ID)
			continue
		}
		rule, ok := rules[path]
		if !ok {
			t.Errorf("entry %q maps to %s which has no entry rule", e.ID, path)
			continue
		}
		for _, stt := range e.States[1:] {
			have := map[string]bool{}
			keys := []string{}
			for _, k := range stt.Keys {
				have[string(k)] = true
				keys = append(keys, string(k))
			}
			sort.Strings(keys)
			if !rule.satisfiedBy(func(k string) bool { return have[k] }) {
				t.Errorf("entry %s state %s: keys %v cannot enter %s (rule %s %v)",
					e.ID, stt.Name, keys, path, rule.Kind, rule.Permissions)
			}
		}
	}
	descriptorIDs := map[string]bool{}
	for _, e := range EntryDescriptors() {
		descriptorIDs[e.ID] = true
	}
	for id := range pages {
		if !descriptorIDs[id] {
			t.Errorf("%s", fmt.Sprintf("page mapping lists unknown entry %q", id))
		}
	}
}
