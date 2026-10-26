package authz

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// entryPages 有自己頁面的入口對應的頁面路徑（描述表位置為頁面的入口，一個不多、一個不少）。
// 沒有自己頁面的入口（設定卡、輔助能力、橫幅）不得出現在這裡，它們的位置由描述表的位置欄位表達。
func entryPages() map[string]string {
	return map[string]string{
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
}

// 描述表每個入口的每個非隱藏狀態，所持的鍵集合都必須進得了對應頁面：
// 描述表、依賴表、頁面入口規則三者不一致時，編輯器會讓人選了卻用不了。
// 位置不是頁面的入口（設定卡、輔助能力、橫幅）不得被當作有自己的頁面，並須標示所在或使用它的入口。
func TestEntryDescriptorStatesReachTheirPage(t *testing.T) {
	pages := entryPages()
	rules := map[string]RouteEntryRule{}
	for _, r := range RouteEntryRules() {
		rules[r.Path] = r
	}
	descriptorByID := map[string]EntryDescriptor{}
	for _, e := range EntryDescriptors() {
		descriptorByID[e.ID] = e
	}
	isPage := func(id string) bool {
		d, ok := descriptorByID[id]
		return ok && d.PlacementKind() == PlacementPage
	}
	for _, e := range EntryDescriptors() {
		kind := e.PlacementKind()
		switch kind {
		case PlacementPage:
			if len(e.PlacementEntries) != 0 {
				t.Errorf("entry %s is a page but lists placement entries %v", e.ID, e.PlacementEntries)
			}
		case PlacementEmbedded:
			if len(e.PlacementEntries) != 1 || !isPage(firstOf(e.PlacementEntries)) {
				t.Errorf("entry %s is an embedded card and needs exactly one host entry that is a page, got %v", e.ID, e.PlacementEntries)
			}
		case PlacementHelper:
			if len(e.PlacementEntries) == 0 {
				t.Errorf("entry %s is a helper and needs at least one entry that uses it", e.ID)
			}
			for _, u := range e.PlacementEntries {
				if !isPage(u) {
					t.Errorf("entry %s is a helper used by %q, which is not an entry with its own page", e.ID, u)
				}
			}
		case PlacementBanner:
			if len(e.PlacementEntries) != 0 {
				t.Errorf("entry %s is a banner but lists placement entries %v", e.ID, e.PlacementEntries)
			}
		default:
			t.Errorf("entry %s has unknown placement %q", e.ID, kind)
		}
		path, mapped := pages[e.ID]
		if kind != PlacementPage {
			if mapped {
				t.Errorf("entry %s has placement %s but is listed with the page %s", e.ID, kind, path)
			}
			continue
		}
		if !mapped {
			t.Errorf("entry %q is a page but has no page mapping", e.ID)
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
	for id := range pages {
		if _, ok := descriptorByID[id]; !ok {
			t.Errorf("%s", fmt.Sprintf("page mapping lists unknown entry %q", id))
		}
	}
}

func firstOf(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	return ss[0]
}

// summaryLevelOf 入口在摘要中的歸類（hidden／read／available／manage／partial）。
func summaryLevelOf(s RoleSummary, id string) string {
	groups := []struct {
		level string
		ids   []string
	}{
		{StateManage, s.Manage}, {statePartial, s.Partial}, {StateRead, s.Read}, {StateAvailable, s.Available}, {StateHidden, s.Hidden},
	}
	for _, g := range groups {
		for _, x := range g.ids {
			if x == id {
				return g.level
			}
		}
	}
	return ""
}

// minimalEntrySets 一條入口規則的最小可進頁集合：任一鍵放行的規則取各單鍵，全部鍵才放行的規則取全集。
func minimalEntrySets(r RouteEntryRule) [][]Permission {
	toPerms := func(ks []string) []Permission {
		out := make([]Permission, 0, len(ks))
		for _, k := range ks {
			out = append(out, Permission(k))
		}
		return out
	}
	if r.Kind == RouteEntryAny {
		sets := [][]Permission{}
		for _, k := range r.Permissions {
			sets = append(sets, toPerms([]string{k}))
		}
		return sets
	}
	return [][]Permission{toPerms(r.Permissions)}
}

// TestEntrySummaryCoversReachablePages 擋：進得了頁、摘要卻說沒有授予（少報）。
// 正向：每個頁面入口的每個最小可進頁集合，摘要不得把該入口歸為沒有授予。
// 反向：沒有描述入口的受限頁必須登錄由哪個入口涵蓋，且在其最小可進頁集合下該入口不是沒有授予。
func TestEntrySummaryCoversReachablePages(t *testing.T) {
	// 允許表：合理的沒有授予。
	allowed := map[string]string{
		"rotation_schedules|audit:view": "只開報告，排程區另需排程管理",
	}
	// 沒有描述入口的受限頁，由哪個入口涵蓋。清單變動時同步編輯畫面的 roles.editor.entryNote.audit_logs。
	coveredBy := map[string]string{
		"/audit/workbench":       "audit_logs",
		"/audit/agent-tasks":     "audit_logs",
		"/audit/exports":         "audit_logs",
		"/commands":              "audit_logs",
		"/access-control":        "security_policies",
		"/change-secret-batches": "change_secret",
	}
	pages := entryPages()
	rules := map[string]RouteEntryRule{}
	for _, r := range RouteEntryRules() {
		rules[r.Path] = r
	}
	joinKeys := func(ps []Permission) string {
		ss := make([]string, 0, len(ps))
		for _, p := range ps {
			ss = append(ss, string(p))
		}
		return strings.Join(ss, ",")
	}

	ids := make([]string, 0, len(pages))
	for id := range pages {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		path := pages[id]
		rule, ok := rules[path]
		if !ok || rule.Kind == RouteEntrySignedIn {
			continue
		}
		for _, set := range minimalEntrySets(rule) {
			sum := SummarizeRole(set)
			if summaryLevelOf(sum, id) != StateHidden {
				continue
			}
			blocked := false
			for _, b := range BlockedScreens(set) {
				if b.ID == id {
					blocked = true
				}
			}
			if blocked {
				continue
			}
			sibling := false
			for other, p2 := range pages {
				if p2 == path && other != id && summaryLevelOf(sum, other) != StateHidden {
					sibling = true
				}
			}
			if sibling {
				continue
			}
			if _, ok := allowed[id+"|"+joinKeys(set)]; ok {
				continue
			}
			t.Errorf("entry %s: keys [%s] can enter %s but the summary reports it as not granted", id, joinKeys(set), path)
		}
	}

	mapped := map[string]bool{}
	for _, p := range pages {
		mapped[p] = true
	}
	for _, r := range RouteEntryRules() {
		if r.Kind == RouteEntrySignedIn || mapped[r.Path] {
			continue
		}
		onlyUI := len(r.Permissions) > 0
		for _, k := range r.Permissions {
			if !strings.HasPrefix(k, "ui:") {
				onlyUI = false
			}
		}
		if onlyUI {
			continue
		}
		cover, ok := coveredBy[r.Path]
		if !ok {
			t.Errorf("route %s requires %v, has no descriptor entry and is not listed in coveredBy", r.Path, r.Permissions)
			continue
		}
		for _, set := range minimalEntrySets(r) {
			lvl := summaryLevelOf(SummarizeRole(set), cover)
			if lvl == "" {
				t.Errorf("route %s is covered by unknown entry %q", r.Path, cover)
			} else if lvl == StateHidden {
				t.Errorf("route %s: keys [%s] can enter it but covering entry %s is reported as not granted", r.Path, joinKeys(set), cover)
			}
		}
	}
	for path := range coveredBy {
		if _, ok := rules[path]; !ok {
			t.Errorf("coveredBy lists %s which has no entry rule", path)
		}
	}
}
