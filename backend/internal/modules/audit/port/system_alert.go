package port

import (
	"errors"
	"time"

	"gorm.io/gorm"
)

// SystemAlertType 系統告警類型鍵。
//
// 常數即登錄鍵，類型目錄（audit 模組）逐鍵比對這組常數。新增類型只能先改目錄登錄
// （含三語文案與出站通知事件規格）再由生產端呼叫，不得在生產端自行編字串。
type SystemAlertType string

const (
	SystemAlertAssetAddressChanged          SystemAlertType = "asset_address_changed"
	SystemAlertTransportVerificationRelaxed SystemAlertType = "transport_verification_relaxed"
	SystemAlertAccessPolicyRelaxed          SystemAlertType = "access_policy_relaxed"
	SystemAlertCustomSecretUsed             SystemAlertType = "custom_secret_used"
	SystemAlertIdentitySourceChanged        SystemAlertType = "identity_source_changed"
	SystemAlertSecurityAdminAccountOperated SystemAlertType = "security_admin_account_operated"
	SystemAlertSelfPrivilegeIncreased       SystemAlertType = "self_privilege_increased"
	SystemAlertSelfPrivilegeDecreased       SystemAlertType = "self_privilege_decreased"
	SystemAlertManagementRoleGranted        SystemAlertType = "management_role_granted"
	SystemAlertRetentionShortened           SystemAlertType = "retention_shortened"
	SystemAlertOffsiteOrSyslogChanged       SystemAlertType = "offsite_or_syslog_changed"
	SystemAlertKeyTopologyChanged           SystemAlertType = "key_topology_changed"
	SystemAlertRecordingFailcloseDisabled   SystemAlertType = "recording_failclose_disabled"
	SystemAlertRecordingDeleted             SystemAlertType = "recording_deleted"
	SystemAlertMappingRevalidationRelaxed   SystemAlertType = "mapping_revalidation_relaxed"
	SystemAlertHostKeyMismatch              SystemAlertType = "host_key_mismatch"
	SystemAlertHostKeyRecordChanged         SystemAlertType = "host_key_record_changed"
	SystemAlertNotificationChannelChanged   SystemAlertType = "notification_channel_changed"
	SystemAlertConcurrentInstanceDetected   SystemAlertType = "concurrent_instance_detected"
)

// SystemAlertTargetKind 告警目標種類。每個類型在目錄中宣告自己允許的目標種類。
type SystemAlertTargetKind string

const (
	SystemAlertTargetAsset               SystemAlertTargetKind = "asset"
	SystemAlertTargetCredential          SystemAlertTargetKind = "credential"
	SystemAlertTargetUser                SystemAlertTargetKind = "user"
	SystemAlertTargetUserGroup           SystemAlertTargetKind = "user_group"
	SystemAlertTargetRoleMapping         SystemAlertTargetKind = "role_mapping"
	SystemAlertTargetRole                SystemAlertTargetKind = "role"
	SystemAlertTargetIdentitySource      SystemAlertTargetKind = "identity_source"
	SystemAlertTargetNotificationChannel SystemAlertTargetKind = "notification_channel"
	SystemAlertTargetSession             SystemAlertTargetKind = "session"
	SystemAlertTargetSystemSetting       SystemAlertTargetKind = "system_setting"
)

// SystemAlertSystemActorName 系統主體的操作者名（user_id 為 0）。只有目錄登錄項帶 SystemActor 旗標的類型接受。
const SystemAlertSystemActorName = "system"

// SystemAlertActor 操作者。系統告警一律要有可指認的操作者，零值回錯；
// 例外只有目錄登錄項帶 SystemActor 旗標的類型，可用系統主體（UserID 0、Username 為 SystemAlertSystemActorName）。
type SystemAlertActor struct {
	UserID   uint
	Username string
}

// SystemAlertTarget 告警目標；ID 為目標種類內的識別字串（可為空，視類型而定）。
type SystemAlertTarget struct {
	Kind SystemAlertTargetKind
	ID   string
}

// SystemAlertEvent 一筆待落地的系統告警。
//
// CorrelationID 與生產端同交易審計列 details 內的同名欄相同，供從告警回查操作日誌。
// Params 只能使用該類型在目錄中宣告的鍵；秘密不得入內，網址只能是遮罩後的值。
type SystemAlertEvent struct {
	Type  SystemAlertType
	Actor SystemAlertActor
	// ClientIP 操作來源位址。落地面不另存這一欄：明細呈現的來源位址取自同交易審計列
	// （以 CorrelationID 對應），生產端寫那筆審計列時用的是同一個位址。
	ClientIP      string
	OccurredAt    time.Time // 零值＝現在
	Target        SystemAlertTarget
	AssetID       *uint
	CorrelationID string
	Params        map[string]string
}

// SystemAlertReceipt 落地回執。
type SystemAlertReceipt struct {
	AlertID uint
	// Severity 產生當下的有效分級（覆寫或預設）；之後調整分級不改既有告警。
	Severity string
	// Destinations 排入投遞佇列的目的地數；沒有啟用通道時為 0（告警列仍存在）。
	Destinations int
	// Unreadable 啟用中但設定解不開（網址或密鑰密文無法解密）的通道數：不投遞、不擋業務操作，
	// 各留一筆立即放棄的投遞紀錄讓明細看得到。
	Unreadable int
}

// SystemAlertSink 交易內系統告警落地面。**同行程 internal port，不可跨行程。**
//
// # 契約
//
// 生產端在自己的業務交易內，於業務寫入與同交易審計之後呼叫；回錯即讓錯誤逸出交易閉包，
// 整筆回滾。告警列、明細與投遞佇列列與業務變更同交易提交，不存在「業務成立而告警沒寫」。
//
// # SHALL NOT
//
//   - 不得以 goroutine、提交後補寫或吞錯取代本呼叫。
//   - 不得以空實作當作預設注入：未注入一律以 ErrSystemAlertSinkMissing 失敗。
//   - 本介面不負責判定「這件事算不算該告警」，只保證類型與參數合乎目錄。
type SystemAlertSink interface {
	RaiseInTx(tx *gorm.DB, ev SystemAlertEvent) (SystemAlertReceipt, error)
}

// ErrSystemAlertSinkMissing 系統告警落地面未注入。
//
// 與 ErrTxSinkMissing 同理：生產上由組裝根的啟動自檢保證走不到這裡；測試與工具路徑以
// error 表達，讓呼叫端的 fail-close 語義原樣生效（業務交易回滾）。
var ErrSystemAlertSinkMissing = errors.New("系統告警落地面未注入（不得靜默略過）")

// RaiseInTx 是呼叫端使用 SystemAlertSink 的唯一合法形式。
//
// 最危險的退化是忘記注入：nil sink 若被實作成空操作，告警靜默消失而業務照樣成立。
// 本函式讓「沒接線」與「寫失敗」落在同一格，都回 error。不包裝錯誤。
func RaiseInTx(sink SystemAlertSink, tx *gorm.DB, ev SystemAlertEvent) (SystemAlertReceipt, error) {
	if sink == nil {
		return SystemAlertReceipt{}, ErrSystemAlertSinkMissing
	}
	return sink.RaiseInTx(tx, ev)
}
