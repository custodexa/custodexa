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
)

func systemAlertEventSpecs() map[Event]EventSpec {
	return map[Event]EventSpec{
		EventSystemAlertAssetAddressChanged: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity},
			{Name: "changed_fields", Kind: KindOpaque, Required: true},
			{Name: "asset_name", Kind: KindOpaque},
		}},
		EventSystemAlertTransportVerificationRelaxed: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity},
			{Name: "relaxed_settings", Kind: KindOpaque, Required: true},
			{Name: "asset_name", Kind: KindOpaque},
		}},
		EventSystemAlertAccessPolicyRelaxed: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity},
			{Name: "relax_type", Kind: KindEnum, Required: true, Enum: []string{"override_lowered", "override_cleared", "default_lowered"}},
			{Name: "before_level", Kind: KindOpaque, Required: true},
			{Name: "after_level", Kind: KindOpaque, Required: true},
			{Name: "affected_assets", Kind: KindInt},
			{Name: "asset_name", Kind: KindOpaque},
		}},
		EventSystemAlertCustomSecretUsed: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity},
			{Name: "entry", Kind: KindEnum, Required: true, Enum: []string{"change_password", "detach_shared", "declare_new_secret"}},
			{Name: "asset_name", Kind: KindOpaque},
		}},
		EventSystemAlertIdentitySourceChanged: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity},
			{Name: "source_kind", Kind: KindEnum, Required: true, Enum: []string{"ldap", "oidc"}},
			{Name: "changed_fields", Kind: KindOpaque, Required: true},
			{Name: "bind_password_changed", Kind: KindEnum, Enum: []string{"true", "false"}},
			{Name: "super_admin_count", Kind: KindInt},
		}},
		EventSystemAlertSecurityAdminAccountOperated: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity},
			{Name: "action", Kind: KindEnum, Required: true, Enum: []string{"password_change", "mfa_disabled", "external_bound", "external_unbound", "rescue"}},
		}},
		EventSystemAlertSelfPrivilegeIncreased: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity},
			{Name: "path", Kind: KindOpaque, Required: true},
			{Name: "roles_before", Kind: KindOpaque, Required: true},
			{Name: "roles_after", Kind: KindOpaque, Required: true},
			{Name: "manageable_before", Kind: KindInt},
			{Name: "manageable_after", Kind: KindInt},
			{Name: "connectable_before", Kind: KindInt},
			{Name: "connectable_after", Kind: KindInt},
		}},
		EventSystemAlertSelfPrivilegeDecreased: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity},
			{Name: "path", Kind: KindOpaque, Required: true},
			{Name: "roles_before", Kind: KindOpaque, Required: true},
			{Name: "roles_after", Kind: KindOpaque, Required: true},
			{Name: "manageable_before", Kind: KindInt},
			{Name: "manageable_after", Kind: KindInt},
			{Name: "connectable_before", Kind: KindInt},
			{Name: "connectable_after", Kind: KindInt},
		}},
		EventSystemAlertManagementRoleGranted: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity},
			{Name: "path", Kind: KindOpaque, Required: true},
			{Name: "recipient", Kind: KindOpaque, Required: true},
			{Name: "role_name", Kind: KindOpaque, Required: true},
			{Name: "scope_summary", Kind: KindOpaque},
		}},
		EventSystemAlertRetentionShortened: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity},
			{Name: "data_class", Kind: KindEnum, Required: true, Enum: []string{"audit_log", "session_command", "alert", "recording"}},
			{Name: "days_before", Kind: KindInt, Required: true},
			{Name: "days_after", Kind: KindInt, Required: true},
		}},
		EventSystemAlertOffsiteOrSyslogChanged: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity},
			{Name: "subject", Kind: KindEnum, Required: true, Enum: []string{"offsite", "syslog"}},
			{Name: "change", Kind: KindEnum, Required: true, Enum: []string{"disabled", "destination_changed"}},
		}},
		EventSystemAlertKeyTopologyChanged: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity},
			{Name: "change_kind", Kind: KindOpaque, Required: true},
		}},
		EventSystemAlertRecordingFailcloseDisabled: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity},
		}},
		EventSystemAlertRecordingDeleted: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity},
			{Name: "session_id", Kind: KindInt, Required: true},
		}},
		EventSystemAlertMappingRevalidationRelaxed: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity},
			{Name: "hours_before", Kind: KindInt, Required: true},
			{Name: "hours_after", Kind: KindInt, Required: true},
		}},
		EventSystemAlertHostKeyMismatch: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity},
			{Name: "path", Kind: KindEnum, Required: true, Enum: []string{"terminal", "agent_terminal", "file_transfer", "connection_test", "credential_change", "credential_rotation"}, Lexicon: LexiconHostKeyPath},
			{Name: "outcome", Kind: KindEnum, Required: true, Enum: []string{"allowed", "refused"}, Lexicon: LexiconHostKeyOutcome},
			{Name: "record_source", Kind: KindEnum, Required: true, Enum: []string{"own", "address"}},
			{Name: "recorded_fingerprint", Kind: KindOpaque, Required: true},
			{Name: "observed_fingerprint", Kind: KindOpaque, Required: true},
			{Name: "observed_algorithm", Kind: KindOpaque, Required: true},
			{Name: "connection_ref", Kind: KindOpaque},
		}},
		EventSystemAlertHostKeyRecordChanged: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity},
			{Name: "change", Kind: KindEnum, Required: true, Enum: []string{"adopted", "reset"}},
			{Name: "previous_fingerprint", Kind: KindOpaque, Required: true},
			{Name: "adopted_fingerprint", Kind: KindOpaque, Required: true},
		}},
		EventSystemAlertNotificationChannelChanged: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity},
			{Name: "change", Kind: KindEnum, Required: true, Enum: []string{"created", "updated", "disabled", "enabled", "deleted"}},
			{Name: "changed_fields", Kind: KindOpaque},
			{Name: "url_before", Kind: KindOpaque},
			{Name: "url_after", Kind: KindOpaque},
		}},
		EventSystemAlertConcurrentInstanceDetected: {Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "severity", Kind: KindEnum, Required: true, Enum: systemAlertSeverityEnum(), Lexicon: LexiconSeverity},
			{Name: "signal", Kind: KindEnum, Required: true, Enum: []string{"overridden", "peers"}},
			{Name: "peers_query", Kind: KindEnum, Required: true, Enum: []string{"ok", "failed"}},
			{Name: "peers", Kind: KindInt},
			{Name: "confirm_source", Kind: KindEnum, Enum: []string{"env", "page"}},
			{Name: "confirmed_by", Kind: KindOpaque},
		}, VariantParam: "signal"},
	}
}

// withSystemAlertEvents 把系統告警事件併入事件契約表。
func withSystemAlertEvents(base map[Event]EventSpec) map[Event]EventSpec {
	for ev, spec := range systemAlertEventSpecs() {
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
