package audit

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
)

// 系統告警類型目錄。
//
// 目錄是類型的唯一登錄處：鍵、分組、預設分級、允許的目標種類與宣告參數都在這裡。
// 目錄 API 與前端分組列表由本登錄產生，計數不寫死；測試把登錄與 port 的常數、
// 出站通知事件規格逐鍵比對，三處任何一處漏登都會轉紅。
// 預設分級以類型為單位：一個類型只有一個預設分級，需要不同預設時另立類型。

// SystemAlertGroup 目錄分組。
type SystemAlertGroup string

const (
	SystemAlertGroupAddressTransport  SystemAlertGroup = "address_transport"
	SystemAlertGroupSecret            SystemAlertGroup = "secret"
	SystemAlertGroupIdentityPrivilege SystemAlertGroup = "identity_privilege"
	SystemAlertGroupSecuritySettings  SystemAlertGroup = "security_settings"
	SystemAlertGroupNotification      SystemAlertGroup = "notification"
)

// SystemAlertParamKind 參數值域種類。
type SystemAlertParamKind string

const (
	// SystemAlertParamEnum 封閉允許清單。
	SystemAlertParamEnum SystemAlertParamKind = "enum"
	// SystemAlertParamInt 十進位整數（含負號）。
	SystemAlertParamInt SystemAlertParamKind = "int"
	// SystemAlertParamOpaque 自由字串，不翻譯，落地與出站前經共用淨化。
	SystemAlertParamOpaque SystemAlertParamKind = "opaque"
	// SystemAlertParamTokens 以逗號分隔的小寫代碼集合（欄位名、設定名這類由生產端凍結的值域）。
	SystemAlertParamTokens SystemAlertParamKind = "tokens"
)

// SystemAlertParamSpec 單一宣告參數。沒有任何秘密型：改密、綁定密碼這類只能以布林或動作類別表達，
// 網址只能是遮罩後的字串。
type SystemAlertParamSpec struct {
	Name     string
	Kind     SystemAlertParamKind
	Required bool
	Enum     []string
}

// SystemAlertTypeDef 一個系統告警類型的登錄項。
type SystemAlertTypeDef struct {
	Type            port.SystemAlertType
	Group           SystemAlertGroup
	DefaultSeverity string
	Targets         []port.SystemAlertTargetKind
	Params          []SystemAlertParamSpec
	// SystemActor 為真時，此類型的事件可由系統主體（行程自己，非任何使用者）產生。
	// 預設為假：其餘類型一律要有可指認的使用者操作者。
	SystemActor bool
}

func systemAlertCatalogData() []SystemAlertTypeDef {
	return []SystemAlertTypeDef{
		{
			Type:            port.SystemAlertAssetAddressChanged,
			Group:           SystemAlertGroupAddressTransport,
			DefaultSeverity: model.AlertSeverityHigh,
			Targets:         []port.SystemAlertTargetKind{port.SystemAlertTargetAsset},
			Params: []SystemAlertParamSpec{
				{Name: "changed_fields", Kind: SystemAlertParamTokens, Required: true},
				{Name: "asset_name", Kind: SystemAlertParamOpaque, Required: false},
			},
		},
		{
			Type:            port.SystemAlertTransportVerificationRelaxed,
			Group:           SystemAlertGroupAddressTransport,
			DefaultSeverity: model.AlertSeverityHigh,
			Targets:         []port.SystemAlertTargetKind{port.SystemAlertTargetAsset},
			Params: []SystemAlertParamSpec{
				{Name: "relaxed_settings", Kind: SystemAlertParamTokens, Required: true},
				{Name: "asset_name", Kind: SystemAlertParamOpaque, Required: false},
			},
		},
		{
			Type:            port.SystemAlertAccessPolicyRelaxed,
			Group:           SystemAlertGroupAddressTransport,
			DefaultSeverity: model.AlertSeverityHigh,
			Targets:         []port.SystemAlertTargetKind{port.SystemAlertTargetAsset, port.SystemAlertTargetSystemSetting},
			Params: []SystemAlertParamSpec{
				{Name: "relax_type", Kind: SystemAlertParamEnum, Required: true, Enum: []string{"override_lowered", "override_cleared", "default_lowered"}},
				{Name: "before_level", Kind: SystemAlertParamOpaque, Required: true},
				{Name: "after_level", Kind: SystemAlertParamOpaque, Required: true},
				{Name: "affected_assets", Kind: SystemAlertParamInt, Required: false},
				{Name: "asset_name", Kind: SystemAlertParamOpaque, Required: false},
			},
		},
		{
			Type:            port.SystemAlertCustomSecretUsed,
			Group:           SystemAlertGroupSecret,
			DefaultSeverity: model.AlertSeverityHigh,
			Targets:         []port.SystemAlertTargetKind{port.SystemAlertTargetAsset, port.SystemAlertTargetCredential},
			Params: []SystemAlertParamSpec{
				{Name: "entry", Kind: SystemAlertParamEnum, Required: true, Enum: []string{"change_password", "detach_shared", "declare_new_secret"}},
				{Name: "asset_name", Kind: SystemAlertParamOpaque, Required: false},
			},
		},
		{
			Type:            port.SystemAlertIdentitySourceChanged,
			Group:           SystemAlertGroupIdentityPrivilege,
			DefaultSeverity: model.AlertSeverityHigh,
			Targets:         []port.SystemAlertTargetKind{port.SystemAlertTargetIdentitySource},
			Params: []SystemAlertParamSpec{
				{Name: "source_kind", Kind: SystemAlertParamEnum, Required: true, Enum: []string{"ldap", "oidc"}},
				{Name: "changed_fields", Kind: SystemAlertParamTokens, Required: true},
				{Name: "bind_password_changed", Kind: SystemAlertParamEnum, Required: false, Enum: []string{"true", "false"}},
				{Name: "super_admin_count", Kind: SystemAlertParamInt, Required: false},
			},
		},
		{
			Type:            port.SystemAlertSecurityAdminAccountOperated,
			Group:           SystemAlertGroupIdentityPrivilege,
			DefaultSeverity: model.AlertSeverityHigh,
			Targets:         []port.SystemAlertTargetKind{port.SystemAlertTargetUser},
			Params: []SystemAlertParamSpec{
				{Name: "action", Kind: SystemAlertParamEnum, Required: true, Enum: []string{"password_change", "mfa_disabled", "external_bound", "external_unbound", "rescue"}},
			},
		},
		{
			Type:            port.SystemAlertSelfPrivilegeIncreased,
			Group:           SystemAlertGroupIdentityPrivilege,
			DefaultSeverity: model.AlertSeverityHigh,
			Targets:         []port.SystemAlertTargetKind{port.SystemAlertTargetUser},
			Params: []SystemAlertParamSpec{
				{Name: "path", Kind: SystemAlertParamOpaque, Required: true},
				{Name: "roles_before", Kind: SystemAlertParamOpaque, Required: true},
				{Name: "roles_after", Kind: SystemAlertParamOpaque, Required: true},
				{Name: "manageable_before", Kind: SystemAlertParamInt, Required: false},
				{Name: "manageable_after", Kind: SystemAlertParamInt, Required: false},
				{Name: "connectable_before", Kind: SystemAlertParamInt, Required: false},
				{Name: "connectable_after", Kind: SystemAlertParamInt, Required: false},
			},
		},
		{
			Type:            port.SystemAlertSelfPrivilegeDecreased,
			Group:           SystemAlertGroupIdentityPrivilege,
			DefaultSeverity: model.AlertSeverityLow,
			Targets:         []port.SystemAlertTargetKind{port.SystemAlertTargetUser},
			Params: []SystemAlertParamSpec{
				{Name: "path", Kind: SystemAlertParamOpaque, Required: true},
				{Name: "roles_before", Kind: SystemAlertParamOpaque, Required: true},
				{Name: "roles_after", Kind: SystemAlertParamOpaque, Required: true},
				{Name: "manageable_before", Kind: SystemAlertParamInt, Required: false},
				{Name: "manageable_after", Kind: SystemAlertParamInt, Required: false},
				{Name: "connectable_before", Kind: SystemAlertParamInt, Required: false},
				{Name: "connectable_after", Kind: SystemAlertParamInt, Required: false},
			},
		},
		{
			Type:            port.SystemAlertManagementRoleGranted,
			Group:           SystemAlertGroupIdentityPrivilege,
			DefaultSeverity: model.AlertSeverityMedium,
			Targets:         []port.SystemAlertTargetKind{port.SystemAlertTargetUser, port.SystemAlertTargetUserGroup, port.SystemAlertTargetRoleMapping, port.SystemAlertTargetRole},
			Params: []SystemAlertParamSpec{
				{Name: "path", Kind: SystemAlertParamOpaque, Required: true},
				{Name: "recipient", Kind: SystemAlertParamOpaque, Required: true},
				{Name: "role_name", Kind: SystemAlertParamOpaque, Required: true},
				{Name: "scope_summary", Kind: SystemAlertParamOpaque, Required: false},
				{Name: "scope_node_ids", Kind: SystemAlertParamOpaque, Required: false},
				{Name: "scope_node_count", Kind: SystemAlertParamInt, Required: false},
			},
		},
		{
			Type:            port.SystemAlertRetentionShortened,
			Group:           SystemAlertGroupSecuritySettings,
			DefaultSeverity: model.AlertSeverityHigh,
			Targets:         []port.SystemAlertTargetKind{port.SystemAlertTargetSystemSetting},
			Params: []SystemAlertParamSpec{
				{Name: "data_class", Kind: SystemAlertParamEnum, Required: true, Enum: []string{"audit_log", "session_command", "alert", "recording"}},
				{Name: "days_before", Kind: SystemAlertParamInt, Required: true},
				{Name: "days_after", Kind: SystemAlertParamInt, Required: true},
			},
		},
		{
			Type:            port.SystemAlertOffsiteOrSyslogChanged,
			Group:           SystemAlertGroupSecuritySettings,
			DefaultSeverity: model.AlertSeverityHigh,
			Targets:         []port.SystemAlertTargetKind{port.SystemAlertTargetSystemSetting},
			Params: []SystemAlertParamSpec{
				{Name: "subject", Kind: SystemAlertParamEnum, Required: true, Enum: []string{"offsite", "syslog"}},
				{Name: "change", Kind: SystemAlertParamEnum, Required: true, Enum: []string{"disabled", "destination_changed"}},
			},
		},
		{
			Type:            port.SystemAlertKeyTopologyChanged,
			Group:           SystemAlertGroupSecuritySettings,
			DefaultSeverity: model.AlertSeverityHigh,
			Targets:         []port.SystemAlertTargetKind{port.SystemAlertTargetSystemSetting},
			Params: []SystemAlertParamSpec{
				{Name: "change_kind", Kind: SystemAlertParamTokens, Required: true},
			},
		},
		{
			Type:            port.SystemAlertRecordingFailcloseDisabled,
			Group:           SystemAlertGroupSecuritySettings,
			DefaultSeverity: model.AlertSeverityHigh,
			Targets:         []port.SystemAlertTargetKind{port.SystemAlertTargetSystemSetting},
			Params:          []SystemAlertParamSpec{},
		},
		{
			Type:            port.SystemAlertRecordingDeleted,
			Group:           SystemAlertGroupSecuritySettings,
			DefaultSeverity: model.AlertSeverityHigh,
			Targets:         []port.SystemAlertTargetKind{port.SystemAlertTargetSession},
			Params: []SystemAlertParamSpec{
				{Name: "session_id", Kind: SystemAlertParamInt, Required: true},
			},
		},
		{
			Type:            port.SystemAlertMappingRevalidationRelaxed,
			Group:           SystemAlertGroupSecuritySettings,
			DefaultSeverity: model.AlertSeverityHigh,
			Targets:         []port.SystemAlertTargetKind{port.SystemAlertTargetSystemSetting},
			Params: []SystemAlertParamSpec{
				{Name: "hours_before", Kind: SystemAlertParamInt, Required: true},
				{Name: "hours_after", Kind: SystemAlertParamInt, Required: true},
			},
		},
		{
			Type:            port.SystemAlertHostKeyMismatch,
			Group:           SystemAlertGroupAddressTransport,
			DefaultSeverity: model.AlertSeverityHigh,
			Targets:         []port.SystemAlertTargetKind{port.SystemAlertTargetAsset},
			Params: []SystemAlertParamSpec{
				{Name: "path", Kind: SystemAlertParamEnum, Required: true, Enum: []string{"terminal", "agent_terminal", "file_transfer", "connection_test", "credential_change", "credential_rotation"}},
				{Name: "outcome", Kind: SystemAlertParamEnum, Required: true, Enum: []string{"allowed", "refused"}},
				{Name: "record_source", Kind: SystemAlertParamEnum, Required: true, Enum: []string{"own", "address"}},
				{Name: "recorded_fingerprint", Kind: SystemAlertParamOpaque, Required: true},
				{Name: "observed_fingerprint", Kind: SystemAlertParamOpaque, Required: true},
				{Name: "observed_algorithm", Kind: SystemAlertParamOpaque, Required: true},
				{Name: "connection_ref", Kind: SystemAlertParamOpaque, Required: false},
			},
		},
		{
			Type:            port.SystemAlertHostKeyRecordChanged,
			Group:           SystemAlertGroupAddressTransport,
			DefaultSeverity: model.AlertSeverityMedium,
			Targets:         []port.SystemAlertTargetKind{port.SystemAlertTargetAsset},
			Params: []SystemAlertParamSpec{
				{Name: "change", Kind: SystemAlertParamEnum, Required: true, Enum: []string{"adopted", "reset"}},
				{Name: "previous_fingerprint", Kind: SystemAlertParamOpaque, Required: true},
				{Name: "adopted_fingerprint", Kind: SystemAlertParamOpaque, Required: true},
			},
		},
		{
			Type:            port.SystemAlertNotificationChannelChanged,
			Group:           SystemAlertGroupNotification,
			DefaultSeverity: model.AlertSeverityHigh,
			Targets:         []port.SystemAlertTargetKind{port.SystemAlertTargetNotificationChannel},
			Params: []SystemAlertParamSpec{
				{Name: "change", Kind: SystemAlertParamEnum, Required: true, Enum: []string{"created", "updated", "disabled", "enabled", "deleted"}},
				{Name: "changed_fields", Kind: SystemAlertParamTokens, Required: false},
				{Name: "url_before", Kind: SystemAlertParamOpaque, Required: false},
				{Name: "url_after", Kind: SystemAlertParamOpaque, Required: false},
			},
		},
		{
			Type:            port.SystemAlertConcurrentInstanceDetected,
			Group:           SystemAlertGroupSecuritySettings,
			DefaultSeverity: model.AlertSeverityHigh,
			Targets:         []port.SystemAlertTargetKind{port.SystemAlertTargetSystemSetting},
			SystemActor:     true,
			Params: []SystemAlertParamSpec{
				{Name: "signal", Kind: SystemAlertParamEnum, Required: true, Enum: []string{"overridden", "peers"}},
				{Name: "peers_query", Kind: SystemAlertParamEnum, Required: true, Enum: []string{"ok", "failed"}},
				{Name: "peers", Kind: SystemAlertParamInt, Required: false},
				{Name: "confirm_source", Kind: SystemAlertParamEnum, Required: false, Enum: []string{"env", "page"}},
				{Name: "confirmed_by", Kind: SystemAlertParamOpaque, Required: false},
			},
		},
	}
}

const systemAlertMaxTokens = 12

// SystemAlertCatalog 回傳目錄的複本（順序即登錄順序）；呼叫端不得改動登錄本體。
func SystemAlertCatalog() []SystemAlertTypeDef {
	out := make([]SystemAlertTypeDef, len(systemAlertCatalogData()))
	for i, d := range systemAlertCatalogData() {
		out[i] = cloneSystemAlertDef(d)
	}
	return out
}

// LookupSystemAlertType 以鍵取登錄項。
func LookupSystemAlertType(t port.SystemAlertType) (SystemAlertTypeDef, bool) {
	for _, d := range systemAlertCatalogData() {
		if d.Type == t {
			return cloneSystemAlertDef(d), true
		}
	}
	return SystemAlertTypeDef{}, false
}

func cloneSystemAlertDef(d SystemAlertTypeDef) SystemAlertTypeDef {
	d.Targets = append([]port.SystemAlertTargetKind(nil), d.Targets...)
	params := make([]SystemAlertParamSpec, len(d.Params))
	for i, p := range d.Params {
		p.Enum = append([]string(nil), p.Enum...)
		params[i] = p
	}
	d.Params = params
	return d
}

// ValidSystemAlertSeverity 分級只接受 high／medium／low。
func ValidSystemAlertSeverity(s string) bool {
	return model.ValidAlertSeverity(s)
}

// validateSystemAlertEvent 在寫入前嚴格驗證事件；任何違規一律回錯，不降級投遞。
// 在產生點拒絕只會讓生產端測試變紅，不會讓告警靜默消失，因為業務變更同時回滾。
func validateSystemAlertEvent(ev port.SystemAlertEvent) (SystemAlertTypeDef, error) {
	def, ok := LookupSystemAlertType(ev.Type)
	if !ok {
		return def, fmt.Errorf("系統告警類型未登錄: %q", ev.Type)
	}
	if err := validateSystemAlertActor(def, ev.Actor); err != nil {
		return def, err
	}
	allowed := false
	for _, k := range def.Targets {
		if k == ev.Target.Kind {
			allowed = true
			break
		}
	}
	if !allowed {
		return def, fmt.Errorf("系統告警 %s 不接受目標種類 %q", ev.Type, ev.Target.Kind)
	}
	declared := map[string]SystemAlertParamSpec{}
	for _, p := range def.Params {
		declared[p.Name] = p
	}
	keys := make([]string, 0, len(ev.Params))
	for k := range ev.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p, ok := declared[k]
		if !ok {
			return def, fmt.Errorf("系統告警 %s 未宣告參數 %q", ev.Type, k)
		}
		if err := validateSystemAlertParam(ev.Type, p, ev.Params[k]); err != nil {
			return def, err
		}
	}
	for _, p := range def.Params {
		if p.Required && strings.TrimSpace(ev.Params[p.Name]) == "" {
			return def, fmt.Errorf("系統告警 %s 缺必要參數 %q", ev.Type, p.Name)
		}
	}
	return def, nil
}

// validateSystemAlertActor 操作者不得為零值；只有帶 SystemActor 旗標的類型接受系統主體
// （UserID 0 且名稱恰為 port.SystemAlertSystemActorName），旗標不放寬使用者名為空。
func validateSystemAlertActor(def SystemAlertTypeDef, actor port.SystemAlertActor) error {
	if strings.TrimSpace(actor.Username) == "" {
		return fmt.Errorf("系統告警 %s 的操作者不得為零值", def.Type)
	}
	if actor.UserID == 0 && !(def.SystemActor && actor.Username == port.SystemAlertSystemActorName) {
		return fmt.Errorf("系統告警 %s 的操作者不得為零值", def.Type)
	}
	return nil
}

func validateSystemAlertParam(t port.SystemAlertType, p SystemAlertParamSpec, v string) error {
	if v == "" {
		return nil // 空值視同未提供；必要性另行檢查
	}
	switch p.Kind {
	case SystemAlertParamEnum:
		for _, e := range p.Enum {
			if e == v {
				return nil
			}
		}
		return fmt.Errorf("系統告警 %s 參數 %q 的值不在允許清單內", t, p.Name)
	case SystemAlertParamInt:
		if _, err := strconv.ParseInt(v, 10, 64); err != nil {
			return fmt.Errorf("系統告警 %s 參數 %q 不是整數", t, p.Name)
		}
	case SystemAlertParamTokens:
		parts := strings.Split(v, ",")
		if len(parts) > systemAlertMaxTokens {
			return fmt.Errorf("系統告警 %s 參數 %q 的代碼過多", t, p.Name)
		}
		for _, part := range parts {
			if !validSystemAlertToken(part) {
				return fmt.Errorf("系統告警 %s 參數 %q 含不合規的代碼", t, p.Name)
			}
		}
	case SystemAlertParamOpaque:
		// 值域由出站通知規格的共用淨化處理
	default:
		return fmt.Errorf("系統告警 %s 參數 %q 的種類未知", t, p.Name)
	}
	return nil
}

// validSystemAlertToken 小寫英數與底線，長度 1 到 40。
func validSystemAlertToken(s string) bool {
	if len(s) < 1 || len(s) > 40 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '_' {
			return false
		}
	}
	return true
}
