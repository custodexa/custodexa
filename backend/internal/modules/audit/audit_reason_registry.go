package audit

import (
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 原因碼登記表。分類邏輯在 audit_reason.go。
//
// 新增事件：在 auditReasonEvents 加一列 {Event: "<details.event 的值>"}（需要參數時再給 Params），
// 並在三語 locale 補 `dailyReview.reason.event.<事件名>`。不需要改分類器或守衛。

var auditReasonMachineCodes = []auditReasonMachineCode{
	{
		Code:     "auto_disabled_inactive_account",
		Variants: []string{"auto_disabled_inactive_account", "auto_disabled_inactive_account_nodays"},
		Build: func(d reasonDetails) (string, reasonParams) {
			if days, ok := d.num(reasonInactiveDaysKey); ok {
				return "auto_disabled_inactive_account", reasonParams{"days": days}
			}
			return "auto_disabled_inactive_account_nodays", nil
		},
	},
	{
		Code: "role_mapping_applied",
		Variants: []string{"role_mapping_applied", "role_mapping_applied_added",
			"role_mapping_applied_removed", "role_mapping_applied_basis"},
		Build: roleMappingAppliedReason,
	},
	{Code: "user_group_mapping_applied"},
	{Code: "role_mapping_source_attr_unset"},
	{Code: "role_mapping_groups_unknown"},
	{Code: "membership_revalidation_expired"},
	{Code: "group_mapping_rule_revoked"},
	{Code: "group_mapping_source_revoked"},
}

// roleMappingAppliedReason 角色增減拆四種句型，避免文案出現空的「加上：」
func roleMappingAppliedReason(d reasonDetails) (string, reasonParams) {
	added := opaqueList(d.strList("roles_added"))
	removed := opaqueList(d.strList("roles_removed"))
	switch {
	case added != "" && removed != "":
		return "role_mapping_applied", reasonParams{"added": added, "removed": removed}
	case added != "":
		return "role_mapping_applied_added", reasonParams{"added": added}
	case removed != "":
		return "role_mapping_applied_removed", reasonParams{"removed": removed}
	default:
		return "role_mapping_applied_basis", nil
	}
}

func reasonOnly(d reasonDetails) reasonParams { return reasonParams{"reason": opaque(d.str("reason"))} }

func providerOnly(d reasonDetails) reasonParams {
	return reasonParams{"provider": opaque(d.str("provider_name"))}
}

// aggregateParams 聚合列：筆數、時間窗分鐘數（不足一分鐘記 1）、原因碼
func aggregateParams(countKey, firstKey, lastKey string) func(d reasonDetails) reasonParams {
	return func(d reasonDetails) reasonParams {
		minutes := "—"
		first, errF := time.Parse(time.RFC3339, d.str(firstKey))
		last, errL := time.Parse(time.RFC3339, d.str(lastKey))
		if errF == nil && errL == nil && !last.Before(first) {
			minutes = strconv.FormatInt(int64(math.Max(1, math.Ceil(last.Sub(first).Minutes()))), 10)
		}
		return reasonParams{"count": d.numOr(countKey, "—"), "minutes": minutes, "reason": opaque(d.str("reason"))}
	}
}

var auditReasonEvents = []auditReasonEvent{
	// 登入失敗與拒絕
	{Event: "login_abuse_aggregate", Params: aggregateParams("count", "first_at", "last_at")},
	{Event: "oidc_abuse_aggregate", Params: aggregateParams("count", "first_at", "last_at")},
	{Event: "auth_rejected_aggregate", Params: aggregateParams("count", "first_at", "last_at")},
	{Event: "auth_rejected", Params: reasonOnly},
	{Event: "ldap_resolve_failed"},
	{Event: "ldap_strict_reject"},
	{Event: "ldap_transport_deviation"},
	{Event: "external_user_local_login_attempt"},
	{Event: "external_user_local_login_attempt_aggregated", Params: aggregateParams("suppressed_count", "window_start", "window_end")},
	{Event: "oidc_flow_error", Params: reasonOnly},
	{Event: "oidc_admission_denied", Params: func(d reasonDetails) reasonParams {
		return reasonParams{"provider": opaque(d.str("provider_name")), "rule": opaque(d.str("failed_rule"))}
	}},
	{Event: "oidc_username_conflict", Params: providerOnly},
	{Event: "oidc_user_provisioned", Params: providerOnly},
	{Event: "oidc_provider_denied", Params: func(d reasonDetails) reasonParams {
		return reasonParams{"error": opaque(d.str("provider_error"))}
	}},
	// 外部身分綁定（管理員操作）
	{Event: "external_identity_bound"},
	{Event: "external_identity_unbound"},
	{Event: "external_identity_unbound_and_account_disabled"},
	{Event: "user_converted_to_external_only"},
	{Event: "external_identity_bind_rejected", Params: reasonOnly},
	{Event: "external_identity_unbind_rejected", Params: reasonOnly},
	{Event: "external_identity_unbind_disable_rejected", Params: reasonOnly},
	{Event: "user_external_only_conversion_rejected", Params: reasonOnly},
	// 代理帳號
	{Event: "agent_breaker_released"},
	// 目錄服務設定
	{Event: "ldap_directory_save"},
	{Event: "ldap_directory_url_changed"},
	{Event: "ldap_directory_delete"},
	{Event: "ldap_directory_save_rejected", Params: reasonOnly},
	// 群組映射規則
	{Event: "group_role_mapping_create"},
	{Event: "group_role_mapping_update"},
	{Event: "group_role_mapping_delete"},
	{Event: "group_user_group_mapping_create"},
	{Event: "group_user_group_mapping_update"},
	{Event: "group_user_group_mapping_delete"},
	{Event: "role_binding_range_changed"},
	{Event: "role_mapping_pin"},
	{Event: "oidc_provider_settings_change"},
	{Event: "user_group_manual_member_added"},
	{Event: "user_group_manual_member_removed"},
	// 授權變更分級與系統安全管理員帳號身分操作（服務審計 details 事件）
	{Event: "grant_change_graded"},
	{Event: "security_admin_account_operated"},
	// 角色修改或 agent 角色寫入提交後，重查發現 agent 持有含受限權限點的角色
	{Event: "role_update_agent_restricted_detected"},
	// 帳號刪除與懸空的外部身分綁定（綁定指向已刪除的帳號）
	{Event: "user_deleted", Params: func(d reasonDetails) reasonParams {
		return reasonParams{"username": opaque(d.str("target_username")),
			"identities": d.numOr("external_identities_revoked", "0")}
	}},
	{Event: "oidc_identity_orphan_revoked", Params: func(d reasonDetails) reasonParams {
		return reasonParams{"provider": opaque(d.str("provider_name")),
			"previous_user_id": d.numOr("previous_user_id", "—"), "previous_username": opaque(d.str("previous_username"))}
	}},
	{Event: "oidc_account_removed", Params: providerOnly},
	{Event: "oidc_user_inactive", Params: providerOnly},
	{Event: "external_identity_orphan_revoked", Params: func(d reasonDetails) reasonParams {
		return reasonParams{"previous_user_id": d.numOr("previous_user_id", "—")}
	}},
}

// 帳號與憑證審計的 operation 值域（帳號側沿用 model.AccountOp*；憑證另有掛載與輪替類）
var (
	reasonAccountOps = []string{model.AccountOpCreate, model.AccountOpUpdate, model.AccountOpDelete,
		model.AccountOpSetDefault, model.AccountOpDiscardCandidate}
	reasonCredentialOps = []string{model.AccountOpCreate, model.AccountOpUpdate, model.AccountOpDelete,
		"bind", "unbind", "scope", "rebind", "rotate", "abandon", "detach", model.AccountOpSetSecret,
		"authorization_stop", "recovery_verify", "rotation_reauthorized", "rotation_interrupted",
		model.AuditOpHostIdentityStop}
)

func reasonPrefixed(prefix string, values []string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = prefix + v
	}
	return out
}

func reasonContains(values []string, v string) bool {
	for _, x := range values {
		if x == v {
			return true
		}
	}
	return false
}

var principalStateActions = []string{string(model.ActionCreate), string(model.ActionUpdate), string(model.ActionDelete)}

var auditReasonShapes = []auditReasonShape{
	{Codes: reasonPrefixed("principal_state_", principalStateActions),
		Match: func(in AuditReasonInput, d reasonDetails) (string, reasonParams, bool) {
			ok := d.str("state_table") == StateTablePrincipals && reasonContains(principalStateActions, in.Action)
			return "principal_state_" + in.Action, nil, ok
		}},
	{Codes: reasonPrefixed("asset_account_", reasonAccountOps),
		Match: func(_ AuditReasonInput, d reasonDetails) (string, reasonParams, bool) {
			op := d.str("operation")
			ok := d.str("resource") == "asset_account" && reasonContains(reasonAccountOps, op)
			return "asset_account_" + op, reasonParams{"account": opaque(d.str("account_username"))}, ok
		}},
	{Codes: reasonPrefixed("credential_", reasonCredentialOps),
		Match: func(in AuditReasonInput, d reasonDetails) (string, reasonParams, bool) {
			op := d.str("operation")
			ok := in.Resource == string(model.ResourceCredential) && d.str("resource") == string(model.ResourceCredential) &&
				reasonContains(reasonCredentialOps, op)
			return "credential_" + op, nil, ok
		}},
	// 改密計畫、批次因發起者當下權限不足而停止（遠端未被觸碰）
	{Codes: []string{"change_secret_authorization_stop"},
		Match: func(in AuditReasonInput, d reasonDetails) (string, reasonParams, bool) {
			ok := in.Resource == string(model.ResourceChangeSecretPlan) &&
				d.str("resource") == string(model.ResourceChangeSecretPlan) && d.str("operation") == "authorization_stop"
			return "change_secret_authorization_stop", nil, ok
		}},
	// 失權後的有限驗證（候選）與一鍵重新授權承接：同屬改密計畫資源，以 operation 區分
	{Codes: []string{"change_secret_recovery_verify"},
		Match: func(in AuditReasonInput, d reasonDetails) (string, reasonParams, bool) {
			ok := in.Resource == string(model.ResourceChangeSecretPlan) &&
				d.str("resource") == string(model.ResourceChangeSecretPlan) && d.str("operation") == "recovery_verify"
			return "change_secret_recovery_verify", nil, ok
		}},
	// 改密候選因目標主機身分異動而停止（輪替成員的同因停止走 credential_ 前綴）
	{Codes: []string{"change_secret_host_identity_stop"},
		Match: func(in AuditReasonInput, d reasonDetails) (string, reasonParams, bool) {
			ok := in.Resource == string(model.ResourceChangeSecretPlan) &&
				d.str("resource") == string(model.ResourceChangeSecretPlan) && d.str("operation") == model.AuditOpHostIdentityStop
			return "change_secret_host_identity_stop", nil, ok
		}},
	{Codes: []string{"change_secret_reauthorize"},
		Match: func(in AuditReasonInput, d reasonDetails) (string, reasonParams, bool) {
			ok := in.Resource == string(model.ResourceChangeSecretPlan) &&
				d.str("resource") == string(model.ResourceChangeSecretPlan) && d.str("operation") == "reauthorize"
			return "change_secret_reauthorize", nil, ok
		}},
	{Codes: []string{"asset_group_deleted"},
		Match: func(in AuditReasonInput, d reasonDetails) (string, reasonParams, bool) {
			ok := in.Action == string(model.ActionDelete) && in.Resource == string(model.ResourceAsset) && d["asset_node_name"] != nil
			return "asset_group_deleted", reasonParams{"name": opaque(d.str("asset_node_name")),
				"revoked": d.numOr("revoked_authorizations", "0")}, ok
		}},
	{Codes: []string{"user_group_deleted"},
		Match: func(in AuditReasonInput, d reasonDetails) (string, reasonParams, bool) {
			ok := in.Action == string(model.ActionDelete) && in.Resource == string(model.ResourceUserGroup) && d["group_name"] != nil
			return "user_group_deleted", reasonParams{"name": opaque(d.str("group_name")),
				"revoked": d.numOr("revoked_authorizations", "0")}, ok
		}},
	{Codes: []string{"agent_self_created"},
		Match: func(in AuditReasonInput, d reasonDetails) (string, reasonParams, bool) {
			selfService, _ := d["self_service"].(bool)
			return "agent_self_created", nil, selfService && in.Action == string(model.ActionCreate)
		}},
	{Codes: []string{"audit_export_requester_revoked"},
		Match: func(in AuditReasonInput, d reasonDetails) (string, reasonParams, bool) {
			ok := in.Resource == string(model.ResourceAuditExport) && d.str("reason") == model.ExportJobErrRequesterRevoked
			return "audit_export_requester_revoked", reasonParams{"job_id": opaque(d.str("job_id"))}, ok
		}},
	// 授權拒絕（能力不足、目標不在可管理範圍）：只看 denial 值，不看其餘鍵。
	// kind_unmapped 的回應雖為 403，denial 仍是 scope。
	{Codes: []string{"authz_capability_denied"},
		Match: func(_ AuditReasonInput, d reasonDetails) (string, reasonParams, bool) {
			return "authz_capability_denied", nil, d.str("denial") == "capability"
		}},
	{Codes: []string{"authz_scope_denied"},
		Match: func(_ AuditReasonInput, d reasonDetails) (string, reasonParams, bool) {
			return "authz_scope_denied", nil, d.str("denial") == "scope"
		}},
	// 資產刪除時資料層留下的列：沒有 details、沒有路徑
	{Codes: []string{"asset_deleted"},
		Match: func(in AuditReasonInput, _ reasonDetails) (string, reasonParams, bool) {
			ok := in.Action == string(model.ActionDelete) && in.Resource == string(model.ResourceAsset) &&
				strings.TrimSpace(in.Details) == "" && in.Path == "" && in.ErrorMsg == ""
			return "asset_deleted", nil, ok
		}},
}
