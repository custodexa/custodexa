package model

import "time"

// 告警審閱處置分類（audit-workflows，PCI 10.4.1）
const (
	AlertDispositionPending   = "pending"   // 未審閱（預設）
	AlertDispositionBenign    = "benign"    // 已審閱：誤報/無害
	AlertDispositionEscalated = "escalated" // 已審閱：升級處理
)

// 告警的來源類別。
//
// **為什麼不是「種一條內建規則」**：規則是可 CRUD 停用／刪除的營運物件，
// 管理員一鍵就能靜默關掉一條規格要求的安全訊號；且內建規則數有硬斷言，
// 還得為它填一個永不匹配的 pattern＝在機器欄裡寫謊。
// 規格不變式不該掛在可 CRUD 的資料列上，故改以本欄分流來源。
const (
	// AlertKindRule 規則比對／阻斷產生的告警，rule_id 必為非空。
	AlertKindRule = "rule"
	// AlertKindAuditDegraded 指令審計降級產生的告警，rule_id 必為 NULL。
	AlertKindAuditDegraded = "audit_degraded"
	// AlertKindNewSourceIP 帳號首次自某來源位址建立協議會話的告警，rule_id 必為 NULL。
	// 不掛規則：管理員不得以停用規則的方式關掉這個訊號。位址由所屬會話承載
	// （session_id NOT NULL 保證可 join），本表不另存位址。
	AlertKindNewSourceIP = "new_source_ip"
)

// AlertReasonDegradedSpan 降級告警的機器碼：一段連續的降級輪次（span）開始。
//
// **一個 span 只發這一筆**，理由見 sshproxy/command_degrade_alert.go 的量測結論：
// 正常 vim 與偽標記攻擊的 span 在時長／輪數上**實測不可分**，
// 故不設「超過門檻升級」的第二筆——那個門檻會是編造的。
const AlertReasonDegradedSpan = "audit_degraded_span"

// AlertReasonNewSourceIPSession 新來源位址告警的機器碼：該（帳號, 位址）首次建線。
// 同一（帳號, 位址）之後再建線不重響——判定依據是基準表的首次建線時刻。
const AlertReasonNewSourceIPSession = "new_source_ip_session"

// CommandAlert 危險指令告警記錄（command-alerts）
// rule_name/severity 為觸發當下的快照冗餘：
// 規則之後改名、改級或刪除，不影響既有告警的可讀性（與 session_commands
// 冗餘 user_id/asset_id 同一設計取向：查詢免 JOIN、歷史不可變）
// 注意：本表由 migration v7.9 以原生 SQL 建立，不走 AutoMigrate；
// 審閱欄位（reviewed_*/disposition/note）由 20260703_audit_workflows_alert_review 加
type CommandAlert struct {
	ID uint `gorm:"primarykey" json:"id"`
	// RuleID **指標型**：降級告警沒有規則可指，DB 為 nullable
	//（本表刻意無 FK）。值型 uint 會把「無規則」寫成 0，而 0 不是任何一筆規則的 ID，
	// 卻在查詢與 JOIN 上看起來像個值。哪一類必須有規則由 DB CHECK 釘死
	//（command_alerts_kind_rule_ref）。
	RuleID *uint `json:"rule_id,omitempty"`
	// RuleName 觸發當下的規則名快照；**降級告警填的是機器碼**（同 alert_notifier 的
	// testRuleName 慣例：機器識別字，不譯不組字），因為那一類根本沒有規則名。
	// 使用者可見文案由前端依 kind／reason_code 對映，不取自本欄。
	RuleName string `gorm:"size:100;not null" json:"rule_name"`

	// Kind 告警來源類別（AlertKind* 之一）：規則比對／阻斷為 rule，
	// 指令審計降級為 audit_degraded。**存在的理由是後者不得掛在規則上**。
	Kind string `gorm:"size:20;not null" json:"kind"`
	// ReasonCode 非規則類告警的機器碼（值域見 AlertReason* 常數）；規則類為空字串。
	ReasonCode string `gorm:"size:64;not null" json:"reason_code"`

	SessionID uint  `gorm:"not null" json:"session_id"`
	UserID    uint  `gorm:"not null" json:"user_id"`
	AssetID   *uint `json:"asset_id,omitempty"` // 手動連線可能無資產，與 session_commands 一致為 nullable

	Command     string    `gorm:"type:text;not null" json:"command"`
	Severity    string    `gorm:"size:10;not null" json:"severity"`
	TriggeredAt time.Time `gorm:"type:timestamptz;not null" json:"triggered_at"`

	// 審閱處置（audit-workflows，PCI 10.4.1）：reviewed_at 為 NULL 即「未審閱」。
	// DB 層 NOT NULL DEFAULT 由 migration 設；struct 不用 gorm default tag（避免
	// GORM Create 對零值欄位改走 RETURNING 讀回，破壞既有 sqlmock 期望）。
	// 寫入端（AlertMatcher）顯式設 Disposition=pending
	ReviewedBy  *uint      `json:"reviewed_by,omitempty"`
	ReviewedAt  *time.Time `json:"reviewed_at,omitempty"`
	Disposition string     `gorm:"size:20;not null" json:"disposition"`
	Note        string     `gorm:"type:text;not null" json:"note"`

	// Blocked 觸發當下規則是否為阻斷型：payload 衛生——
	// command_blocker.go 改把「（已阻斷）」標示自 RuleName 移出，改用本欄結構化表達；
	// 觸發當下快照，同 RuleName/Severity 慣例，規則之後改 action 不影響既有告警
	Blocked bool `gorm:"not null;default:false" json:"blocked"`
}

// TableName 指定表名
func (CommandAlert) TableName() string {
	return "command_alerts"
}
