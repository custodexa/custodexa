package authz

import "sort"

// 入口描述 ID 與頁面路徑的正式對照。
//
// 描述表的入口（有自己頁面者）、入口鏡像（RouteEntryRules）的路徑、固定入口三者的歸屬在此集中定義，
// 供預覽與編輯描述的測試共用，不在測試檔另存第二份。歸屬分四類：
//   - 描述表入口直接對一條路徑（EntryPagePaths；多個入口可對同一路徑，例如警示頁）；
//   - 沒有描述表入口的受限頁，跟隨開啟它的入口（FollowedPagePaths）；
//   - 登入即可見的固定頁（FixedPagePaths）；
//   - 依本人資格呈現的頁（PersonalQualificationPaths），不隨角色內容變化。

// EntryPagePaths 有自己頁面的描述表入口對應的頁面路徑（描述表位置為頁面的入口，一個不多、一個不少）。
// 沒有自己頁面的入口（設定卡、輔助能力、橫幅）不得出現在這裡。每次回傳新的副本。
func EntryPagePaths() map[string]string {
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
		"keystroke_investigation": "/sessions/keystrokes",
		"audit_logs":              "/audit-logs",
		"checkpoint_verification": "/checkpoint-verification",
		"alerts":                  "/alerts",
		"compliance_map":          "/compliance-map",
		"access_reviews":          "/access-reviews",
		"security_policies":       "/security-policies",
		"policy_groups":           "/policy-groups",
		"key_management":          "/key-management",
		"transmission":            "/transmission-inventory",
		"host_account_inventory":  "/account-inventory",
		"offsite_storage":         "/offsite-storage",
		"notification_channels":   "/notification-channels",
		"system_alerts":           "/alerts",
		"alert_rules":             "/alerts",
		"rotation_schedules":      "/rotation-evidence",
	}
}

// FollowedPagePaths 沒有描述表入口的受限頁（路徑 → 開啟它的入口 ID）：頁面狀態跟隨該入口。
func FollowedPagePaths() map[string]string {
	return map[string]string{
		"/audit/workbench":       "audit_logs",
		"/audit/agent-tasks":     "audit_logs",
		"/audit/exports":         "audit_logs",
		"/commands":              "audit_logs",
		"/change-secret-batches": "change_secret",
		"/access-control":        "security_policies",
	}
}

// FixedPagePaths 登入即可見的固定頁（路徑 → 固定入口 ID）。
func FixedPagePaths() map[string]string {
	return map[string]string{
		"/dashboard":      "dashboard",
		"/workspace":      "workspace",
		"/my-connections": "my_connections",
		"/my-requests":    "my_requests",
		"/profile":        "profile",
	}
}

// PersonalQualificationPaths 依本人資格呈現的頁（審核中心、我的 agent），升冪。
func PersonalQualificationPaths() []string {
	out := []string{"/approvals", "/my-agents"}
	sort.Strings(out)
	return out
}
