package audit

import (
	"reflect"
	"strings"
	"testing"
)

// TestClassifyAuditReason 擋：沒有路徑的系統紀錄在畫面上空白或只剩裸機器碼。
//
// 每個樣本的 details 照寫入點的程式碼形狀照抄，註解標出來源；寫入端改了鍵名而
// 這裡沒跟上時，該案會掉到 generic 而紅
func TestClassifyAuditReason(t *testing.T) {
	cases := []struct {
		name       string
		in         AuditReasonInput
		wantCode   string
		wantParams map[string]string
	}{
		{"保留清除成功（retention_service.go:505-526 logPurge）",
			AuditReasonInput{Action: "delete", Resource: "retention", Status: "success",
				Details: `{"target":"audit_logs","days":365,"deleted":1200,"partial":false}`},
			"retention_purge", map[string]string{"target": "audit_logs", "deleted": "1200", "days": "365"}},
		{"保留清除失敗（retention_service.go:510-513）",
			AuditReasonInput{Action: "delete", Resource: "retention", Status: "failure", ErrorMsg: "db locked",
				Details: `{"target":"recordings","days":90,"deleted":0,"partial":true,"error":"db locked"}`},
			"retention_purge_failed", map[string]string{"target": "recordings"}},
		{"資產刪除的資料層列（model/asset_audit.go:220-235 AfterDelete，details 空）",
			AuditReasonInput{Action: "delete", Resource: "asset", Status: "success"},
			"asset_deleted", nil},
		{"帳號狀態投影（identity/principal_state_source.go:45-51）",
			AuditReasonInput{Action: "create", Resource: "user", Status: "success",
				Details: `{"kind":"human","owner_user_id":null,"state_table":"user_principals","user_id":7}`},
			"principal_state_create", nil},
		{"角色映射重算：加減皆有（identity/role_mapping_recompute.go:343-350）",
			AuditReasonInput{Action: "update", Resource: "user", Status: "success", ErrorMsg: "role_mapping_applied",
				Details: `{"channel":"ldap:1","matched_group":["ops"],"roles_added":["admin","審核組"],"roles_removed":["user"],"epoch_bumped":true,"supports_changed":false,"support_changes":[]}`},
			"role_mapping_applied", map[string]string{"added": "admin,審核組", "removed": "user"}},
		{"角色映射重算：只加",
			AuditReasonInput{Action: "update", Resource: "user", Status: "success", ErrorMsg: "role_mapping_applied",
				Details: `{"channel":"oidc:2","roles_added":["auditor"],"roles_removed":null,"supports_changed":false}`},
			"role_mapping_applied_added", map[string]string{"added": "auditor"}},
		{"角色映射重算：只減",
			AuditReasonInput{Action: "update", Resource: "user", Status: "success", ErrorMsg: "role_mapping_applied",
				Details: `{"channel":"oidc:2","roles_added":[],"roles_removed":["auditor"],"supports_changed":false}`},
			"role_mapping_applied_removed", map[string]string{"removed": "auditor"}},
		{"角色映射重算：只有依據變動",
			AuditReasonInput{Action: "update", Resource: "user", Status: "success", ErrorMsg: "role_mapping_applied",
				Details: `{"channel":"oidc:2","roles_added":null,"roles_removed":null,"supports_changed":true}`},
			"role_mapping_applied_basis", nil},
		{"群組映射重算（role_mapping_recompute.go:333）",
			AuditReasonInput{Action: "update", Resource: "user", Status: "success", ErrorMsg: "user_group_mapping_applied",
				Details: `{"channel":"ldap:1","groups_removed":[],"epoch_bumped":false,"support_changes":[]}`},
			"user_group_mapping_applied", nil},
		{"重算跳過：未設群組屬性（role_mapping_recompute.go:158）",
			AuditReasonInput{Action: "update", Resource: "user", Status: "success", ErrorMsg: "role_mapping_source_attr_unset", Details: `{"channel":"ldap:1"}`},
			"role_mapping_source_attr_unset", nil},
		{"重算跳過：讀不到群組（role_mapping_recompute.go:160）",
			AuditReasonInput{Action: "update", Resource: "user", Status: "success", ErrorMsg: "role_mapping_groups_unknown", Details: `{"channel":"ldap:1"}`},
			"role_mapping_groups_unknown", nil},
		{"刪規則撤權（identity/mapping_revocation.go:146-150）",
			AuditReasonInput{Action: "update", Resource: "user", Status: "success", ErrorMsg: "group_mapping_rule_revoked",
				Details: `{"channel":"ldap:1","rule_type":"role","rule_id":3,"roles_removed":["admin"],"groups_removed":[],"epoch_bumped":true}`},
			"group_mapping_rule_revoked", nil},
		{"刪來源撤權（mapping_revocation.go:146-150）",
			AuditReasonInput{Action: "update", Resource: "user", Status: "success", ErrorMsg: "group_mapping_source_revoked",
				Details: `{"channel":"ldap:1","rule_type":"source","rule_id":0}`},
			"group_mapping_source_revoked", nil},
		{"閒置停用新列（identity/inactivity_service.go:79-90）",
			AuditReasonInput{Action: "update", Resource: "user", Status: "success", ErrorMsg: "auto_disabled_inactive_account", Details: `{"inactive_days":90}`},
			"auto_disabled_inactive_account", map[string]string{"days": "90"}},
		{"閒置停用舊列（沒有 details）",
			AuditReasonInput{Action: "update", Resource: "user", Status: "success", ErrorMsg: "auto_disabled_inactive_account"},
			"auto_disabled_inactive_account_nodays", nil},
		{"匯出申請者失權取消（audit_export_job_worker.go:478-503）",
			AuditReasonInput{Action: "update", Resource: "audit_export", Status: "denied",
				Details: `{"job_id":"12","reason":"export_job.requester_revoked","requester":"bob","requester_id":"4"}`},
			"audit_export_requester_revoked", map[string]string{"job_id": "12"}},
		{"外部身分綁定（identity/external_identity_service.go:216-218）",
			AuditReasonInput{Action: "create", Resource: "user", Status: "success",
				Details: `{"event":"external_identity_bound","provider_id":1,"target_user_id":9}`},
			"event.external_identity_bound", nil},
		{"外部身分解綁（external_identity_service.go:247-249）",
			AuditReasonInput{Action: "delete", Resource: "user", Status: "success",
				Details: `{"event":"external_identity_unbound","identity_id":2,"target_user_id":9}`},
			"event.external_identity_unbound", nil},
		{"外部身分解綁被拒（external_identity_service.go:540-547）",
			AuditReasonInput{Action: "update", Resource: "user", Status: "failure",
				Details: `{"event":"external_identity_unbind_rejected","reason":"last_login_path","identity_id":2,"target_user_id":9}`},
			"event.external_identity_unbind_rejected", map[string]string{"reason": "last_login_path"}},
		{"解除代理熔斷（identity/agent_breaker.go:69-73）",
			AuditReasonInput{Action: "update", Resource: "user", Status: "success",
				Details: `{"event":"agent_breaker_released","owner_id":3,"reason":"誤判","user_id":11}`},
			"event.agent_breaker_released", nil},
		{"自助建立代理（identity/agent_self_service.go:85-90）",
			AuditReasonInput{Action: "create", Resource: "user", Status: "success",
				Details: `{"agent_self_create_enabled":true,"agent_self_create_max_per_owner":3,"owner_user_id":3,"purpose":"ci","self_service":true}`},
			"agent_self_created", nil},
		{"使用者群組刪除（identity/user_group_service.go:185-193）",
			AuditReasonInput{Action: "delete", Resource: "user_group", Status: "success",
				Details: `{"group_name":"維運組","revoked_authorizations":4}`},
			"user_group_deleted", map[string]string{"name": "維運組", "revoked": "4"}},
		{"資產分組刪除（asset/asset_group_service.go:555-563）",
			AuditReasonInput{Action: "delete", Resource: "asset", Status: "success",
				Details: `{"asset_node_name":"機房A","revoked_authorizations":2,"revoked_approver_scopes":1}`},
			"asset_group_deleted", map[string]string{"name": "機房A", "revoked": "2"}},
		{"資產帳號刪除（asset/asset_audit_events.go:51-79，details 形狀 model/asset_account_audit.go:52-61）",
			AuditReasonInput{Action: "delete", Resource: "asset", Status: "success",
				Details: `{"resource":"asset_account","account_id":5,"account_username":"oracle","operation":"delete"}`},
			"asset_account_delete", map[string]string{"account": "oracle"}},
		{"憑證刪除（asset/credential_binding.go:668-704）",
			AuditReasonInput{Action: "delete", Resource: "credential", Status: "success",
				Details: `{"resource":"credential","credential_id":8,"operation":"delete","scope":"shared"}`},
			"credential_delete", nil},
		{"群組對角色映射刪除（identity/group_role_mapping_service.go:602-630）",
			AuditReasonInput{Action: "delete", Resource: "auth", Status: "success",
				Details: `{"event":"group_role_mapping_delete","source_kind":"ldap","source_id":1,"rule_id":3,"match_value":"ops","roles":"admin","enabled":true}`},
			"event.group_role_mapping_delete", nil},
		{"群組對群組映射刪除（identity/user_group_mapping_service.go:52-58，error_msg 同事件碼）",
			AuditReasonInput{Action: "delete", Resource: "user_group", Status: "success", ErrorMsg: "group_user_group_mapping_delete",
				Details: `{"event":"group_user_group_mapping_delete","source_kind":"ldap","source_id":1,"rule_id":4}`},
			"event.group_user_group_mapping_delete", nil},
		{"目錄服務設定刪除（identity/ldap_directory_service.go:837-845）",
			AuditReasonInput{Action: "delete", Resource: "auth", Status: "success",
				Details: `{"event":"ldap_directory_delete","directory_id":1,"url":"ldaps://dc:636","enabled":true}`},
			"event.ldap_directory_delete", nil},
		{"登入限流聚合（api/auth_handler.go:186-195）",
			AuditReasonInput{Action: "login", Resource: "auth", Status: "denied",
				Details: `{"event":"login_abuse_aggregate","reason":"rate_limited","client_ip":"10.0.0.1","count":12,"first_at":"2026-10-10T01:00:00Z","last_at":"2026-10-10T01:04:10Z"}`},
			"event.login_abuse_aggregate", map[string]string{"count": "12", "minutes": "5", "reason": "rate_limited"}},
		{"外部登入濫用聚合（identity/oidc_login_service.go:1008-1017）",
			AuditReasonInput{Action: "login", Resource: "auth", Status: "failure",
				Details: `{"event":"oidc_abuse_aggregate","reason":"oidc_state_invalid","client_ip":"10.0.0.2","count":3,"first_at":"2026-10-10T01:00:00Z","last_at":"2026-10-10T01:00:00Z"}`},
			"event.oidc_abuse_aggregate", map[string]string{"count": "3", "minutes": "1", "reason": "oidc_state_invalid"}},
		{"匿名拒絕聚合（middleware/anonymous_rejection_audit.go:390-402）",
			AuditReasonInput{Action: "login", Resource: "auth", Status: "failure",
				Details: `{"event":"auth_rejected_aggregate","reason":"AUTH_TOKEN_INVALID","client_ip":"10.0.0.3","count":40,"first_at":"2026-10-10T01:00:00Z","last_at":"2026-10-10T01:30:00Z"}`},
			"event.auth_rejected_aggregate", map[string]string{"count": "40", "minutes": "30", "reason": "AUTH_TOKEN_INVALID"}},
		{"目錄設定解析失敗（identity/auth_service.go:895-902）",
			AuditReasonInput{Action: "login", Resource: "auth", Status: "failure", Details: `{"event":"ldap_resolve_failed"}`},
			"event.ldap_resolve_failed", nil},
		{"目錄傳輸嚴格拒絕（auth_service.go:784、909-918）",
			AuditReasonInput{Action: "login", Resource: "transmission", Status: "denied",
				Details: `{"event":"ldap_strict_reject","channel":"ldap","risks":[{"code":"plaintext"}]}`},
			"event.ldap_strict_reject", nil},
		{"外部帳號以本機密碼登入（identity/external_login_attempt_audit.go:176-195）",
			AuditReasonInput{Action: "login", Resource: "user", Status: "denied",
				Details: `{"event":"external_user_local_login_attempt","provisioning_origin":"oidc"}`},
			"event.external_user_local_login_attempt", nil},
		{"外部帳號以本機密碼登入（聚合）",
			AuditReasonInput{Action: "login", Resource: "user", Status: "denied",
				Details: `{"event":"external_user_local_login_attempt_aggregated","provisioning_origin":"oidc","suppressed_count":6,"window_start":"2026-10-10T01:00:00Z","window_end":"2026-10-10T01:09:30Z"}`},
			"event.external_user_local_login_attempt_aggregated", map[string]string{"count": "6", "minutes": "10", "reason": ""}},
		{"外部登入首登建帳號（identity/oidc_login_service.go:193-201）",
			AuditReasonInput{Action: "create", Resource: "user", Status: "success", Path: "/api/v1/auth/oidc/callback",
				Details: `{"event":"oidc_user_provisioned","provider_id":1,"provider_name":"Entra","auth_method":"oidc","subject_fingerprint":"abcd"}`},
			"event.oidc_user_provisioned", map[string]string{"provider": "Entra"}},
		{"外部登入准入拒絕（oidc_login_service.go:162-171）",
			AuditReasonInput{Action: "login", Resource: "auth", Status: "denied",
				Details: `{"event":"oidc_admission_denied","provider_id":1,"provider_name":"Entra","failed_rule":"tenant","subject_fingerprint":"abcd"}`},
			"event.oidc_admission_denied", map[string]string{"provider": "Entra", "rule": "tenant"}},
		{"外部登入作廢懸空綁定（identity/oidc_orphan_identity.go:106-120）",
			AuditReasonInput{Action: "delete", Resource: "user", Status: "success",
				Details: `{"event":"oidc_identity_orphan_revoked","provider_id":1,"provider_name":"Entra","issuer":"https://login.example/t","subject":"sub-1","subject_fingerprint":"abcd","previous_user_id":42,"previous_username":"alice\nroot","identity_id":7}`},
			"event.oidc_identity_orphan_revoked", map[string]string{"provider": "Entra", "previous_user_id": "42", "previous_username": "alice root"}},
		{"僅預綁模式下原帳號已刪除（identity/oidc_orphan_identity.go:122-132）",
			AuditReasonInput{Action: "login", Resource: "auth", Status: "denied",
				Details: `{"event":"oidc_account_removed","provider_id":1,"provider_name":"Entra","previous_user_id":42,"subject_fingerprint":"abcd"}`},
			"event.oidc_account_removed", map[string]string{"provider": "Entra"}},
		{"外部登入帳號已停用（identity/oidc_orphan_identity.go:134-143）",
			AuditReasonInput{Action: "login", Resource: "auth", Status: "denied",
				Details: `{"event":"oidc_user_inactive","provider_id":1,"provider_name":"Entra"}`},
			"event.oidc_user_inactive", map[string]string{"provider": "Entra"}},
		{"管理端綁定時作廢懸空綁定（identity/external_identity_service.go:255-259）",
			AuditReasonInput{Action: "delete", Resource: "user", Status: "success",
				Details: `{"event":"external_identity_orphan_revoked","provider_id":1,"issuer":"https://login.example/t","subject":"sub-1","previous_user_id":42,"identity_id":7,"target_user_id":43}`},
			"event.external_identity_orphan_revoked", map[string]string{"previous_user_id": "42"}},
		{"刪除帳號的中介層列（api/user_handler.go:302-306，audit_details 合併）",
			AuditReasonInput{Action: "delete", Resource: "user", Status: "success", Path: "/api/v1/users/42",
				Details: `{"event":"user_deleted","target_username":"alice","external_identities_revoked":"2"}`},
			"event.user_deleted", map[string]string{"username": "alice", "identities": "2"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, params := ClassifyAuditReason(tc.in)
			if code == ReasonGeneric || code == ReasonGenericEvent || code == "" {
				t.Fatalf("得到 %q：寫入點的形狀沒被辨識（want %q）", code, tc.wantCode)
			}
			if code != tc.wantCode {
				t.Fatalf("碼 = %q, want %q", code, tc.wantCode)
			}
			if len(params) == 0 && len(tc.wantParams) == 0 {
				return
			}
			if !reflect.DeepEqual(params, tc.wantParams) {
				t.Fatalf("參數 = %#v, want %#v", params, tc.wantParams)
			}
			if !registered(code) {
				t.Fatalf("碼 %q 不在 AuditReasonCodes：前端完備性守衛看不到它", code)
			}
		})
	}
}

func registered(code string) bool {
	for _, c := range AuditReasonCodes {
		if c == code {
			return true
		}
	}
	return false
}

// TestClassifyAuditReasonFallbacks 擋：鑑識原文被改寫、未登記事件空白、自由字串夾帶控制字元
func TestClassifyAuditReasonFallbacks(t *testing.T) {
	// 自由文字 error_msg：不給碼，畫面照舊顯示原文
	if code, _ := ClassifyAuditReason(AuditReasonInput{Action: "update", Resource: "asset", Status: "failure",
		ErrorMsg: "Error #01: record not found", Path: "/api/v1/assets/3"}); code != "" {
		t.Errorf("自由文字 error_msg 得到碼 %q, want 空", code)
	}
	// 帶路徑的一般請求列：不給碼
	if code, _ := ClassifyAuditReason(AuditReasonInput{Action: "delete", Resource: "asset", Status: "success",
		Path: "/api/v1/assets/3"}); code != "" {
		t.Errorf("帶路徑列得到碼 %q, want 空", code)
	}
	// 未登記事件：generic_event，參數帶原事件名
	code, params := ClassifyAuditReason(AuditReasonInput{Action: "update", Resource: "user", Status: "success",
		Details: `{"event":"some_future_event"}`})
	if code != ReasonGenericEvent || params["event"] != "some_future_event" || params["action"] != "update" || params["resource"] != "user" {
		t.Errorf("未登記事件 = %q %#v", code, params)
	}
	// 什麼都沒有：generic，不得空白
	code, params = ClassifyAuditReason(AuditReasonInput{Action: "update", Resource: "asset", Status: "success"})
	if code != ReasonGeneric || params["action"] != "update" || params["resource"] != "asset" {
		t.Errorf("全空列 = %q %#v", code, params)
	}
	// details 不是 JSON：視為沒有 details
	code, _ = ClassifyAuditReason(AuditReasonInput{Action: "update", Resource: "asset", Status: "success", Details: "not json"})
	if code != ReasonGeneric {
		t.Errorf("非 JSON details = %q, want generic", code)
	}
	// 帳號名夾帶換行與 ANSI：清除後才進參數
	code, params = ClassifyAuditReason(AuditReasonInput{Action: "delete", Resource: "asset", Status: "success",
		Details: `{"resource":"asset_account","account_username":"evil\n\u001b[31mroot\u001b[0m","operation":"delete"}`})
	if code != "asset_account_delete" {
		t.Fatalf("碼 = %q", code)
	}
	if got := params["account"]; strings.ContainsAny(got, "\n\x1b") || got != "evil root" {
		t.Errorf("帳號名未淨化：%q", got)
	}
	// 角色名內含分隔字元：換成空白，前端拆分不會錯位
	_, params = ClassifyAuditReason(AuditReasonInput{Action: "update", Resource: "user", Status: "success",
		ErrorMsg: "role_mapping_applied", Details: `{"roles_added":["a,b","c"],"roles_removed":[]}`})
	if params["added"] != "a b,c" {
		t.Errorf("角色清單 = %q, want %q", params["added"], "a b,c")
	}
}

// TestAuditReasonCodesRegistry 登記表本身：不重複、碼數下限（防空集合假綠）、每個事件可分類
func TestAuditReasonCodesRegistry(t *testing.T) {
	if len(AuditReasonCodes) < minAuditReasonCodes {
		t.Fatalf("AuditReasonCodes 只有 %d 個（至少 %d）", len(AuditReasonCodes), minAuditReasonCodes)
	}
	events := map[string]bool{}
	for _, e := range auditReasonEvents {
		if events[e.Event] {
			t.Errorf("事件 %q 重複登記", e.Event)
		}
		events[e.Event] = true
		code, _ := ClassifyAuditReason(AuditReasonInput{Action: "update", Resource: "user", Details: `{"event":"` + e.Event + `"}`})
		if code != reasonEventPrefix+e.Event {
			t.Errorf("登記的事件 %q 分類成 %q", e.Event, code)
		}
	}
	codes := map[string]bool{}
	for _, m := range auditReasonMachineCodes {
		if codes[m.Code] {
			t.Errorf("機器碼 %q 重複登記", m.Code)
		}
		codes[m.Code] = true
	}
}
