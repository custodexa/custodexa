package notifycat

import "github.com/custodexa/backend/internal/model"

// 系統告警的出站通知事件。
//
// 每個系統告警類型對應一個事件，事件識別字即類型鍵（webhook 收端契約，不可改）。
// 所有事件共用 actor 與 severity 兩個必要參數，其餘參數與 audit 模組的類型目錄逐鍵一致
// （目錄測試雙向比對）。tokens 型參數在這裡以 opaque 承接。

func systemAlertSeverityEnum() []string {
	return []string{model.AlertSeverityHigh, model.AlertSeverityMedium, model.AlertSeverityLow}
}

const (
	EventSystemAlertAssetAddressChanged          Event = "asset_address_changed"
	EventSystemAlertTransportVerificationRelaxed Event = "transport_verification_relaxed"
	EventSystemAlertAccessPolicyRelaxed          Event = "access_policy_relaxed"
	EventSystemAlertCustomSecretUsed             Event = "custom_secret_used"
	EventSystemAlertIdentitySourceChanged        Event = "identity_source_changed"
	EventSystemAlertSecurityAdminAccountOperated Event = "security_admin_account_operated"
	EventSystemAlertSelfPrivilegeIncreased       Event = "self_privilege_increased"
	EventSystemAlertSelfPrivilegeDecreased       Event = "self_privilege_decreased"
	EventSystemAlertManagementRoleGranted        Event = "management_role_granted"
	EventSystemAlertRetentionShortened           Event = "retention_shortened"
	EventSystemAlertOffsiteOrSyslogChanged       Event = "offsite_or_syslog_changed"
	EventSystemAlertKeyTopologyChanged           Event = "key_topology_changed"
	EventSystemAlertRecordingFailcloseDisabled   Event = "recording_failclose_disabled"
	EventSystemAlertRecordingDeleted             Event = "recording_deleted"
	EventSystemAlertMappingRevalidationRelaxed   Event = "mapping_revalidation_relaxed"
	EventSystemAlertHostKeyMismatch              Event = "host_key_mismatch"
	EventSystemAlertHostKeyRecordChanged         Event = "host_key_record_changed"
	EventSystemAlertNotificationChannelChanged   Event = "notification_channel_changed"
	EventSystemAlertConcurrentInstanceDetected   Event = "concurrent_instance_detected"
	EventSystemAlertUnmanagedPrivilegedAccount   Event = "unmanaged_privileged_account"
	EventSystemAlertPrivilegedAPITokenCreated    Event = "privileged_api_token_created"
	EventSystemAlertAPITokenCredentialAttached   Event = "api_token_credential_attached"
)

func systemAlertEventSpecs() map[Event]EventSpec {
	return map[Event]EventSpec{
		EventSystemAlertAssetAddressChanged: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity, WireOnly: true},
			{Name: "changed_fields", Kind: KindOpaque, Required: true, Lexicon: LexiconAssetField, List: true},
			{Name: "asset_name", Kind: KindOpaque, NameOf: IDKindAsset},
		}},
		EventSystemAlertTransportVerificationRelaxed: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity, WireOnly: true},
			{Name: "relaxed_settings", Kind: KindOpaque, Required: true, Lexicon: LexiconAssetField, List: true},
			{Name: "asset_name", Kind: KindOpaque, NameOf: IDKindAsset},
		}},
		EventSystemAlertAccessPolicyRelaxed: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity, WireOnly: true},
			{Name: "relax_type", Kind: KindEnum, Required: true, Enum: []string{"override_lowered", "override_cleared", "default_lowered"}, Lexicon: LexiconPolicyRelaxType},
			{Name: "before_level", Kind: KindOpaque, Required: true, Lexicon: LexiconAccessTier},
			{Name: "after_level", Kind: KindOpaque, Required: true, Lexicon: LexiconAccessTier},
			{Name: "affected_assets", Kind: KindInt},
			{Name: "asset_name", Kind: KindOpaque, NameOf: IDKindAsset},
		}},
		EventSystemAlertCustomSecretUsed: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity, WireOnly: true},
			{Name: "entry", Kind: KindEnum, Required: true, Enum: []string{"change_password", "detach_shared", "declare_new_secret"}, Lexicon: LexiconCustomSecretEntry},
			{Name: "asset_name", Kind: KindOpaque, NameOf: IDKindAsset},
		}},
		EventSystemAlertIdentitySourceChanged: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity, WireOnly: true},
			{Name: "source_kind", Kind: KindEnum, Required: true, Enum: []string{"ldap", "oidc"}, Lexicon: LexiconIdentitySourceKind},
			{Name: "changed_fields", Kind: KindOpaque, Required: true, Lexicon: LexiconIdentitySourceField, List: true},
			{Name: "bind_password_changed", Kind: KindEnum, Enum: []string{"true", "false"}, Lexicon: LexiconYesNo},
			{Name: "super_admin_count", Kind: KindInt},
		}},
		EventSystemAlertSecurityAdminAccountOperated: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity, WireOnly: true},
			{Name: "action", Kind: KindEnum, Required: true, Enum: []string{"password_change", "mfa_disabled", "external_bound", "external_unbound", "rescue"}, Lexicon: LexiconSecurityAdminAction},
			// 被操作帳號的登入帳號（產生時以目標使用者識別碼在同一交易查得；查不到不帶）
			{Name: "target_username", Kind: KindOpaque},
		}},
		EventSystemAlertSelfPrivilegeIncreased: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity, WireOnly: true},
			{Name: "path", Kind: KindOpaque, Required: true},
			{Name: "roles_before", Kind: KindOpaque, Required: true},
			{Name: "roles_after", Kind: KindOpaque, Required: true},
			{Name: "manageable_before", Kind: KindInt},
			{Name: "manageable_after", Kind: KindInt},
			{Name: "connectable_before", Kind: KindInt},
			{Name: "connectable_after", Kind: KindInt},
			// 角色定義變更時受影響的其他持有者人數（排除操作者本人）；其他路徑不帶
			{Name: "other_holder_count", Kind: KindInt},
		}},
		EventSystemAlertSelfPrivilegeDecreased: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity, WireOnly: true},
			{Name: "path", Kind: KindOpaque, Required: true},
			{Name: "roles_before", Kind: KindOpaque, Required: true},
			{Name: "roles_after", Kind: KindOpaque, Required: true},
			{Name: "manageable_before", Kind: KindInt},
			{Name: "manageable_after", Kind: KindInt},
			{Name: "connectable_before", Kind: KindInt},
			{Name: "connectable_after", Kind: KindInt},
			// 角色定義變更時受影響的其他持有者人數（排除操作者本人）；其他路徑不帶
			{Name: "other_holder_count", Kind: KindInt},
		}},
		EventSystemAlertManagementRoleGranted: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity, WireOnly: true},
			{Name: "path", Kind: KindOpaque, Required: true},
			// 受發放者：角色定義變更的句型不使用（那時沒有單一受發放者），故為可選
			{Name: "recipient", Kind: KindOpaque},
			{Name: "role_name", Kind: KindOpaque, Required: true, NameOf: IDKindProducerOnly},
			{Name: "scope_summary", Kind: KindOpaque},
			{Name: "scope_node_ids", Kind: KindOpaque},
			{Name: "scope_node_count", Kind: KindInt},
			// 角色定義變更（path 為角色定義）時的受影響其他持有者人數（排除操作者本人）；
			// 帶值時改用角色定義變更的句型，不把角色名當成受發放者
			{Name: "other_holder_count", Kind: KindInt},
		}, PresenceVariants: map[string]string{"role_definition": "other_holder_count"}},
		EventSystemAlertRetentionShortened: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity, WireOnly: true},
			{Name: "data_class", Kind: KindEnum, Required: true, Enum: []string{"audit_log", "session_command", "alert", "recording"}, Lexicon: LexiconRetentionDataClass},
			{Name: "days_before", Kind: KindInt, Required: true},
			{Name: "days_after", Kind: KindInt, Required: true},
		}},
		EventSystemAlertOffsiteOrSyslogChanged: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity, WireOnly: true},
			{Name: "subject", Kind: KindEnum, Required: true, Enum: []string{"offsite", "syslog"}, Lexicon: LexiconOffsiteSubject},
			{Name: "change", Kind: KindEnum, Required: true, Enum: []string{"disabled", "destination_changed"}, Lexicon: LexiconOffsiteChange},
		}},
		EventSystemAlertKeyTopologyChanged: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity, WireOnly: true},
			{Name: "change_kind", Kind: KindOpaque, Required: true},
		}},
		EventSystemAlertRecordingFailcloseDisabled: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity, WireOnly: true},
		}},
		EventSystemAlertRecordingDeleted: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity, WireOnly: true},
			{Name: "session_id", Kind: KindInt, Required: true},
			{Name: "session_username", Kind: KindOpaque},
			{Name: "asset_name", Kind: KindOpaque, NameOf: IDKindAsset},
		}},
		EventSystemAlertMappingRevalidationRelaxed: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity, WireOnly: true},
			{Name: "hours_before", Kind: KindInt, Required: true},
			{Name: "hours_after", Kind: KindInt, Required: true},
		}},
		EventSystemAlertHostKeyMismatch: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity, WireOnly: true},
			{Name: "path", Kind: KindEnum, Required: true, Enum: []string{"terminal", "agent_terminal", "file_transfer", "connection_test", "credential_change", "credential_rotation", "account_inventory", "executor_login_check"}, Lexicon: LexiconHostKeyPath},
			{Name: "outcome", Kind: KindEnum, Required: true, Enum: []string{"allowed", "refused"}, Lexicon: LexiconHostKeyOutcome},
			{Name: "record_source", Kind: KindEnum, Required: true, Enum: []string{"own", "address"}, Lexicon: LexiconHostKeyRecordSource},
			{Name: "recorded_fingerprint", Kind: KindOpaque, Required: true},
			{Name: "observed_fingerprint", Kind: KindOpaque, Required: true},
			{Name: "observed_algorithm", Kind: KindOpaque, Required: true},
			{Name: "connection_ref", Kind: KindOpaque},
			{Name: "asset_name", Kind: KindOpaque, NameOf: IDKindAsset},
		}},
		EventSystemAlertHostKeyRecordChanged: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity, WireOnly: true},
			{Name: "change", Kind: KindEnum, Required: true, Enum: []string{"adopted", "reset"}, Lexicon: LexiconHostKeyRecordChange},
			{Name: "previous_fingerprint", Kind: KindOpaque, Required: true},
			{Name: "adopted_fingerprint", Kind: KindOpaque, Required: true},
			{Name: "asset_name", Kind: KindOpaque, NameOf: IDKindAsset},
		}},
		EventSystemAlertNotificationChannelChanged: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity, WireOnly: true},
			{Name: "change", Kind: KindEnum, Required: true, Enum: []string{"created", "updated", "disabled", "enabled", "deleted"}, Lexicon: LexiconChannelChange},
			{Name: "changed_fields", Kind: KindOpaque, Lexicon: LexiconChannelField, List: true},
			{Name: "url_before", Kind: KindOpaque, PairWith: "url_after"},
			{Name: "url_after", Kind: KindOpaque, PairWith: "url_before"},
			{Name: "channel_name", Kind: KindOpaque, NameOf: IDKindNotificationChannel},
			{Name: "target_before", Kind: KindOpaque, PairWith: "target_after"},
			{Name: "target_after", Kind: KindOpaque, PairWith: "target_before"},
			// 對個人派送因網址不在允許清單或型別不能以個人為對象而自動關閉
			{Name: "dm_auto_off", Kind: KindEnum, Enum: []string{DMAutoOffHost, DMAutoOffType}, Lexicon: LexiconDMAutoOff},
		}},
		EventSystemAlertConcurrentInstanceDetected: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity, WireOnly: true},
			{Name: "signal", Kind: KindEnum, Required: true, Enum: []string{"overridden", "peers"}},
			{Name: "peers_query", Kind: KindEnum, Required: true, Enum: []string{"ok", "failed"}, Lexicon: LexiconPeersQuery},
			{Name: "peers", Kind: KindInt},
			{Name: "confirm_source", Kind: KindEnum, Enum: []string{"env", "page"}, Lexicon: LexiconConfirmSource},
			{Name: "confirmed_by", Kind: KindOpaque},
		}, VariantParam: "signal"},
		EventSystemAlertUnmanagedPrivilegedAccount: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity, WireOnly: true},
			{Name: "new_count", Kind: KindInt, Required: true},
			{Name: "identity_mode", Kind: KindEnum, Required: true, Enum: []string{"default_account", "executor"}, Lexicon: LexiconIdentityMode},
			{Name: "asset_name", Kind: KindOpaque, NameOf: IDKindAsset},
		}},
		EventSystemAlertPrivilegedAPITokenCreated: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity, WireOnly: true},
			// 角色清單逐項附層級（{role}（唯讀）／{role}（讀寫））；層級參數與名稱清單同序
			{Name: "privileged_roles", Kind: KindOpaque, Required: true, Levels: "privileged_role_levels"},
			{Name: "privileged_role_levels", Kind: KindOpaque, Required: true},
			{Name: "token_name", Kind: KindOpaque, Required: true, NameOf: IDKindAPIToken},
			// token 擁有者的登入帳號（產生時以目標使用者識別碼在同一交易查得；查不到不帶）
			{Name: "owner_username", Kind: KindOpaque},
			{Name: "granted_roles", Kind: KindOpaque, Required: true, Levels: "granted_role_levels"},
			{Name: "granted_role_levels", Kind: KindOpaque, Required: true},
			// 層級彙總（read｜read_write｜mixed），只給 webhook
			{Name: "access", Kind: KindEnum, Required: true, Enum: []string{"read", "read_write", "mixed"}, WireOnly: true},
			{Name: "expiry", Kind: KindEnum, Required: true, Enum: []string{"at", "never"}},
			{Name: "expires_at", Kind: KindOpaque},
		}, VariantParam: "expiry"},
		// entry 同時決定模板（單筆四種入口共用同一句、匯入另一句）與括號內的掛載方式短語
		EventSystemAlertAPITokenCredentialAttached: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity, WireOnly: true},
			{Name: "token_name", Kind: KindOpaque, Required: true, NameOf: IDKindAPIToken},
			{Name: "entry", Kind: KindEnum, Required: true, Enum: []string{"asset_create", "account_create", "bind", "rebind", "import"}, Lexicon: LexiconCredentialAttachEntry},
			{Name: "credential_name", Kind: KindOpaque, NameOf: IDKindProducerOnly},
			{Name: "asset_name", Kind: KindOpaque, NameOf: IDKindAsset},
			{Name: "asset_count", Kind: KindInt},
			{Name: "credential_count", Kind: KindInt},
		}, VariantParam: "entry"},
	}
}

// systemAlertLink 系統安全告警的去處：告警記錄頁（明細在該頁開啟）。
var systemAlertLink = LinkSpec{Path: "/alerts", Label: LinkLabelAction}

// withSystemAlertEvents 把系統告警事件併入事件契約表；分級沿用類型目錄的有效分級，連結指向告警記錄頁。
func withSystemAlertEvents(base map[Event]EventSpec) map[Event]EventSpec {
	for ev, spec := range systemAlertEventSpecs() {
		spec.Severity = SeverityFromCatalog
		spec.Link = systemAlertLink
		base[ev] = spec
	}
	return base
}

// SystemAlertEvent 回傳類型鍵對應的通知事件；鍵不是已註冊的系統告警類型時 ok=false。
func SystemAlertEvent(typeKey string) (Event, bool) {
	ev := Event(typeKey)
	_, ok := systemAlertEventSpecs()[ev]
	return ev, ok
}
