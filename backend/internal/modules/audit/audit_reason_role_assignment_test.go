package audit

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// TestAuditReasonRoleAssignment 擋：指派、移除、只改範圍與授權分級列掉回通用句型或請求路徑，
// 以及範圍參數的形狀（全系統不說成限節點、截斷時總數仍正確）。details 形狀照寫入端抄。
func TestAuditReasonRoleAssignment(t *testing.T) {
	cases := []struct {
		name       string
		in         AuditReasonInput
		wantCode   string
		wantParams map[string]string
	}{
		{"帳號指派限節點（帶請求路徑仍有碼）",
			AuditReasonInput{Action: "assign", Resource: "user_role", Status: "success", Path: "/api/v1/users/9/roles",
				Details: `{"resource":"user_role","user_id":9,"role_id":3,"origin":"api","range_after":[167],"range_after_count":1}`},
			"user_role_assign_nodes", map[string]string{"role": "#3", "target": "#9", "origin": "api", "nodes": "#167", "nodes_count": "1"}},
		{"帳號指派範圍為 global",
			AuditReasonInput{Action: "assign", Resource: "user_role", Status: "success", Path: "/api/v1/users/9/roles",
				Details: `{"resource":"user_role","user_id":9,"role_id":3,"origin":"api","range_after":"global","range_after_count":0}`},
			"user_role_assign", map[string]string{"role": "#3", "target": "#9", "origin": "api"}},
		{"帳號指派沒有範圍欄位",
			AuditReasonInput{Action: "assign", Resource: "user_role", Status: "success",
				Details: `{"resource":"user_role","user_id":9,"role_id":3,"origin":"oidc"}`},
			"user_role_assign", map[string]string{"role": "#3", "target": "#9", "origin": "oidc"}},
		{"帳號移除",
			AuditReasonInput{Action: "revoke", Resource: "user_role", Status: "success", Path: "/api/v1/users/9/roles",
				Details: `{"resource":"user_role","user_id":9,"role_id":3,"origin":"api"}`},
			"user_role_revoke", map[string]string{"role": "#3", "target": "#9", "origin": "api"}},
		{"群組指派",
			AuditReasonInput{Action: "assign", Resource: "user_group_role", Status: "success",
				Details: `{"user_group_id":4,"role_id":3,"origin":"api"}`},
			"user_group_role_assign", map[string]string{"role": "#3", "target": "#4"}},
		{"群組移除",
			AuditReasonInput{Action: "revoke", Resource: "user_group_role", Status: "success",
				Details: `{"user_group_id":4,"role_id":3,"origin":"api"}`},
			"user_group_role_revoke", map[string]string{"role": "#3", "target": "#4"}},
		{"帳號只改範圍：節點改為全系統",
			AuditReasonInput{Action: "update", Resource: "user_role", Status: "success", Path: "/api/v1/users/9/roles",
				Details: `{"resource":"user_role","user_id":9,"role_id":3,"origin":"api","event":"role_binding_range_changed","range_before":[167],"range_after":"global","range_before_count":1,"range_after_count":0}`},
			"event.role_binding_range_changed", map[string]string{"role": "#3", "target": "#9", "target_kind": "user",
				"before": "#167", "before_count": "1", "after": "global", "after_count": "0"}},
		{"群組只改範圍：列出 100 個但總數 150",
			AuditReasonInput{Action: "update", Resource: "user_group_role", Status: "success",
				Details: `{"user_group_id":4,"role_id":3,"origin":"api","event":"role_binding_range_changed","range_before":"global","range_after":` + idList(100) + `,"range_before_count":0,"range_after_count":150}`},
			"event.role_binding_range_changed", nil},
		{"授權分級列帶標記",
			AuditReasonInput{Action: "update", Resource: "user", Status: "success",
				Details: `{"event":"grant_change_graded","path":"replace","grant_marks":["management_grant"],"correlation_id":"c1"}`},
			"event.grant_change_graded", map[string]string{"marks": "management_grant"}},
		{"授權分級列兩個標記",
			AuditReasonInput{Action: "update", Resource: "user_group", Status: "success",
				Details: `{"event":"grant_change_graded","grant_marks":["self_authorization","management_grant"]}`},
			"event.grant_change_graded", map[string]string{"marks": "self_authorization,management_grant"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, params := ClassifyAuditReason(tc.in)
			if code != tc.wantCode {
				t.Fatalf("code = %q, want %q", code, tc.wantCode)
			}
			if tc.wantParams == nil {
				return
			}
			if !reflect.DeepEqual(params, tc.wantParams) {
				t.Errorf("params = %v, want %v", params, tc.wantParams)
			}
		})
	}

	t.Run("截斷時總數仍是實際數量", func(t *testing.T) {
		code, params := ClassifyAuditReason(cases[7].in)
		if code != "event.role_binding_range_changed" {
			t.Fatalf("code = %q", code)
		}
		if params["after_count"] != "150" || params["before"] != "global" || params["target_kind"] != "user_group" {
			t.Errorf("params = %v", params)
		}
		if got := len(strings.Split(params["after"], ",")); got != 100 {
			t.Errorf("列出的節點數 = %d, want 100", got)
		}
		if strings.Contains(params["after"], "…") {
			t.Errorf("節點清單不得被整體截斷: %q", params["after"])
		}
	})

	t.Run("缺識別碼時退成佔位而不是空參數", func(t *testing.T) {
		_, params := ClassifyAuditReason(AuditReasonInput{Action: "revoke", Resource: "user_role", Details: `{"resource":"user_role"}`})
		if params["role"] != "—" || params["target"] != "—" {
			t.Errorf("params = %v", params)
		}
	})
}

// idList 產生 n 個節點編號的 JSON 陣列文字（升冪）
func idList(n int) string {
	var b strings.Builder
	b.WriteByte('[')
	for i := 1; i <= n; i++ {
		if i > 1 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(i))
	}
	b.WriteByte(']')
	return b.String()
}
