// Package notifycat 是後端出站通知的翻譯目錄。
//
// 職責邊界：只服務「出站 Slack 文案」的伺服端三語渲染與事件參數驗證。
// HTTP 錯誤走 internal/apierror 機器碼、WS/串流走碼化幀由前端查譯，兩者都不經本套件。
//
// 核心不變式：
//   - Event 為具名字串型別，事件常數與 EventSpec 註冊**同檔相鄰**（改一處必見另一處）。
//   - Event 字面量只允許出現在本套件內；呼叫端一律用匯出常數（AST 守衛強制，
//     見 event_literal_guard_test.go）。event 字串值即 webhook 收端契約，不可改。
//   - 未註冊 event 不拒發：Validate 回 *UnregisteredEventError 供呼叫端降級，
//     Render/RenderDegraded 產 generic 文案——合規告警永不因目錄問題消失。
//   - opaque 值不翻譯，僅過 SanitizeOpaque 去格式限長；事由全文不入 params（去識別紅線）。
package notifycat

import (
	"sort"

	"github.com/custodexa/backend/internal/model"
)

// Event 通知事件識別字。值＝webhook 收端契約，與現行呼叫點逐字一致，不可變更。
type Event string

// ParamKind 參數值域種類（值層策略）。
type ParamKind string

const (
	// KindEnum 封閉允許清單：值必須落在 ParamSpec.Enum 內。
	KindEnum ParamKind = "enum"
	// KindInt 十進位整數（含負號）：非數字即拒。
	KindInt ParamKind = "int"
	// KindOpaque 自由字串：不翻譯、不驗語義，只過 SanitizeOpaque 去格式限長。
	KindOpaque ParamKind = "opaque"
	// KindDateList YYYY-MM-DD 日期清單。參數值是字串（目錄的 params 一律字串對字串），
	// 內部以逗號串接傳遞，至多 MaxDateList 個；webhook 通道輸出時展開成 JSON 陣列
	// （WireParams），Slack 通道渲染成逐行清單。非日期值即拒。
	KindDateList ParamKind = "date_list"
)

// MaxDateList 日期清單參數的元素上限（一個月的量，Slack 訊息仍可讀）
const MaxDateList = 31

// ParamSpec 單一參數的宣告。Required=false 者多為 variant 專屬參數。
type ParamSpec struct {
	Name     string
	Kind     ParamKind
	Required bool
	Enum     []string // 僅 KindEnum 有值
	// Lexicon 非空＝該參數值是詞庫鍵，渲染時換成收件通道語系的短語
	// （見 lexicon.go）。宣告 Lexicon 的 enum 參數，其 Enum 集合必須與
	// 詞庫鍵集相等（TestLexiconCompleteness 守衛）。
	Lexicon Lexicon
	// Total 僅 KindDateList：另一個 int 參數的名字，其值是清單的真實總數。
	// 總數多於清單元素時，Slack 渲染在清單後加「另有 N 天」
	Total string
	// Levels 僅 KindOpaque 的逗號分隔清單：另一個 opaque 參數的名字，其值是同序的 API token 層級
	// （read｜read_write，逗號分隔）。渲染時每一項寫成該語系的「名稱（層級）」並以語系的分隔符連接
	// （詞庫 LexiconAPITokenLevel）；兩者項數不同時退回只列名稱。被指名的參數視同已被模板使用
	Levels string
	// WireOnly 只給 webhook 的結構化參數：模板不使用，不受「未被任何 variant 使用」的檢查
	WireOnly bool
	// List 僅宣告 Lexicon 的 KindOpaque：值是逗號分隔清單，每一項各自查詞庫（缺鍵回吐該項的機器碼），
	// 以詞庫 LexiconListFormat 的 sep 連接
	List bool
	// PairWith 前後值成對的另一個參數名（例如 url_before 與 url_after）：兩者都有值且相同時，文字渲染
	// 視同兩者都沒有值（含它們的可選段整段略過）；webhook 照樣輸出兩個參數
	PairWith string
	// Duration 僅 KindInt：值是分鐘數，Slack 渲染為該語系的時長（詞庫 LexiconDuration：整小時寫小時、
	// 不足一小時寫分鐘、其餘寫小時加分鐘）；webhook 照樣輸出整數
	Duration bool
	// NameOf 名稱參數對應的識別碼種類（僅 KindOpaque）：產生點可直接給名稱，或只給識別碼由分派解析。
	// 以 _name 結尾的參數一律要宣告（TestEventSpecNameParamsDeclareKind 守衛）
	NameOf IDKind
}

// IDKind 名稱參數對應的識別碼種類。
type IDKind string

const (
	// IDKindUser 使用者（含 AI agent 主體）；解析涵蓋已軟刪的列。
	IDKindUser IDKind = "user"
	// IDKindAsset 資產；解析涵蓋已軟刪的列。
	IDKindAsset IDKind = "asset"
	// IDKindAPIToken API token（撤銷後仍查得到名稱）。
	IDKindAPIToken IDKind = "api_token"
	// IDKindNotificationChannel 通知通道（硬刪，刪除後只留識別碼）。
	IDKindNotificationChannel IDKind = "notification_channel"
	// IDKindProducerOnly 只由產生點帶入、分派不解析的名稱（角色、憑證、通道以外的設定名稱等）。
	IDKindProducerOnly IDKind = "producer_only"
)

// 事件分級。系統事件各自宣告三值之一；系統安全告警事件宣告 SeverityFromCatalog（沿用類型目錄的有效分級）。
const (
	SeverityHigh        = model.AlertSeverityHigh
	SeverityMedium      = model.AlertSeverityMedium
	SeverityLow         = model.AlertSeverityLow
	SeverityFromCatalog = "catalog"
)

// LinkLabel 連結文字的種類：要人處理的事件用「前往處理」，告知性質的用「前往查看」。
type LinkLabel string

const (
	LinkLabelAction LinkLabel = "action"
	LinkLabelView   LinkLabel = "view"
)

// LinkSpec 事件的站內頁面路徑樣板。Path 以 / 開頭，可含固定字面的查詢字串；`{name}` 佔位只能引用
// KindInt 參數（TestEventSpecLinkTemplatesUseIntParams 守衛），代入值須為大於零的整數，否則整個連結省略。
type LinkSpec struct {
	Path  string
	Label LinkLabel
}

// EventSpec 單一事件的參數契約。
//
// VariantParam 非空時，該參數必須是本事件的必要 enum 參數，其值即模板 variant 鍵
// （locales 內 event 底下的次層鍵）；為空時 variant 鍵固定為 variantDefault。
type EventSpec struct {
	Params       []ParamSpec
	VariantParam string

	// Severity 分級（SeverityHigh／Medium／Low；系統安全告警事件為 SeverityFromCatalog）。
	// 只用於呈現、處理先後與 webhook 新物件；推送門檻對系統事件的作用維持現狀
	Severity string
	// Link 站內頁面路徑樣板；Path 為空＝這個事件不附連結
	Link LinkSpec
	// PresenceVariants variant 鍵到可選參數名的對照：VariantParam 為空時，第一個（依 variant 鍵排序）
	// 有值的參數決定 variant，都沒有值即 default。VariantParam 非空時，該可選參數有值則 variant 為
	// 「<VariantParam 的值>_<鍵>」（例如逐項核准的 manual_item），沒有值則為 VariantParam 的值。
	// 用於「逐項拒絕」這類由是否帶某參數決定的句型
	PresenceVariants map[string]string
	// LinkedVariants 每個 variant 另有一個 `<variant>_linked` 版本，供有連結時使用
	// （例如有連結時不再寫「詳見審核中心」）
	LinkedVariants bool
	// ExcludeTargetChannel 分派時不送往內容的目標通道（通知投遞已放棄：不送回送不出去的那個通道）
	ExcludeTargetChannel bool
	// AuditFailureFamily 稽核失效一族：走專屬排入入口，分派失敗不回報稽核失效（避免自我循環）
	AuditFailureFamily bool
}

// linkedSuffix 有連結版本的 variant 鍵後綴。
const linkedSuffix = "_linked"

// variantDefault 無 variant 事件的固定模板鍵。
const variantDefault = "default"

// ---- enum 值域常數（params map 值為 string，非 Event 型別，不受字面量守衛管轄）----

const (
	// ApprovalModeAuto 段位自動核准（access_request_service.go:233）
	ApprovalModeAuto = "auto"
	// ApprovalModeManual 審核人核准達門檻（access_request_service.go:466）
	ApprovalModeManual = "manual"

	// IntervalKnown 失效區間起訖皆可考（audit_failure_service.go:136 有 open event）
	IntervalKnown = "known"
	// IntervalUnknown DB 掛掉期間無列可回填，起點不明（同上，ErrRecordNotFound 分支）
	IntervalUnknown = "unknown"
)

// mechanismEnum 稽核機制允許清單。以 model 常數引用而非重打字面量：
// 常數改名即編譯失敗；新增機制未同步則由 TestMechanismEnumMatchesModel 攔截。
var mechanismEnum = []string{
	model.MechanismAuditWrite,
	model.MechanismSyslogForward,
	model.MechanismRecordingProbe,
	model.MechanismRecordingText,
	model.MechanismRecordingGraphics,
	model.MechanismSessionRecord,
	model.MechanismCommandBlocking,
	model.MechanismKEKRetirement,
	model.MechanismAADResidue,
	model.MechanismCheckpointAnchor,
	model.MechanismAuditChainStructure,
	model.MechanismAuditChainContent,
	model.MechanismAuditChainVerify,
	model.MechanismSourcePolicy,
	model.MechanismOffsiteUpload,
	model.MechanismRoleStateIntegrity,
	model.MechanismPrincipalStateIntegrity,
	model.MechanismDEKUnwrap,
	model.MechanismRestoreSeal,
	model.MechanismKeystrokeProbe,
	model.MechanismKeystrokeRecord,
	model.MechanismNotificationDelivery,
	model.MechanismNotificationDispatch,
}

// ---- 事件常數（值＝現行呼叫點字串，逐一與呼叫點實查對照）----

const (
	// EventAccessRequestCreated 新申請待審（access_request_service.go:235）
	EventAgentTaskReport      Event = "agent_task_report_submitted"
	EventAgentBreakerTripped  Event = "agent_breaker_tripped"
	EventAccessRequestCreated Event = "access_request.created"
	// EventAccessRequestApproved 申請核准；auto=段位自動核准(:233)、manual=票數達標(:466)
	EventAccessRequestApproved Event = "access_request.approved"
	// EventAccessRequestApprovalProgress 核准票數進度（access_request_service.go:468）
	EventAccessRequestApprovalProgress Event = "access_request.approval_progress"
	// EventAccessRequestRejected 申請遭拒（access_request_service.go:508）
	EventAccessRequestRejected Event = "access_request.rejected"
	// EventBreakGlassUsed 破窗緊急連線（access_request_service.go:944）
	EventBreakGlassUsed Event = "break_glass_used"
	// EventTicketRevoked 限時連線提前撤銷（access_request_service.go:1020）
	EventTicketRevoked Event = "ticket_revoked"
	// EventBreakGlassReviewOverdue 破窗補審逾期（access_request_service.go:1156）
	EventBreakGlassReviewOverdue Event = "break_glass_review_overdue"

	// EventAuditFailure 稽核機制失效（audit_failure_service.go:102）
	EventAuditFailure Event = "audit_failure"
	// EventAuditFailureResolved 稽核機制恢復（audit_failure_service.go:136）。
	// 注意：design v4 誤記為 audit_failure_recovered，實碼為 _resolved
	EventAuditFailureResolved Event = "audit_failure_resolved"
	// EventAuditFailureOngoing 失效持續中的週期重發（NotifyOngoing 唯一呼叫端
	// key_manager_degraded.go:123 傳入此字串）
	EventAuditFailureOngoing Event = "audit_failure_ongoing"

	// EventDailyReviewOverdue 每日審閱逾期（daily_review_service.go:190）
	EventDailyReviewOverdue Event = "daily_review_overdue"
	// EventTest 通道測試發送（測試發送同步單次投遞，不排入；webhook 的 event 欄為 "test"）
	EventTest Event = "test"

	// EventNotificationDeliveryAbandoned 通知投遞已放棄（投遞程序把紀錄標為放棄時產生，送往其他通道）
	EventNotificationDeliveryAbandoned Event = "notification_delivery_abandoned"

	// EventTargetedNotificationUndelivered 個人訊息未能送達（投遞程序在放棄個人訊息或分派時沒有收件人時產生，
	// 送往每個啟用中通道的頻道，同一通道 24 小時至多一則）
	EventTargetedNotificationUndelivered Event = "targeted_notification_undelivered"

	// EventKEKTopologyChanged 委託保管處設定變更（kek_topology_handler.go）。
	//
	// **為什麼是 notifycat 事件而不是 alert_rules 種子**：alert_rules 是危險
	// 指令的正則規則（Pattern／Protocols 皆為指令語義），拓撲變更不是指令事件；
	// 塞進去會污染規則表的語義，並使種子數守衛（釘死 12 條）失去意義。
	//
	// 參數只含**非秘密**的前後值摘要與變更者：憑證欄位不在其中，且變更的完整
	// 前後值以審計列為準——通知會經外部通道出站，審計不會。
	EventKEKTopologyChanged Event = "kek_topology_changed"

	// EventCredentialRotationAlert 改密工作的停止與失敗提醒（排程、逐帳號改密、憑證輪替與重試）。
	// 沒有對應的告警列：這些事件不是規則命中，不進告警審閱流程；事件本身的留痕由各產生點的審計負責。
	EventCredentialRotationAlert Event = "credential_rotation_alert"
)

// 改密工作提醒的種類（credential_rotation_alert 的 kind 參數；鍵集＝詞庫 LexiconRotationAlertKind）。
const (
	RotationAlertAuthzStopped           = "authz_stopped"
	RotationAlertPlanFailed             = "plan_failed"
	RotationAlertRecoveryVerify         = "recovery_verify"
	RotationAlertCandidateAbandoned     = "candidate_abandoned"
	RotationAlertCleanupPending         = "cleanup_pending"
	RotationAlertRestartInterrupted     = "restart_interrupted"
	RotationAlertPlanReauthIncomplete   = "plan_reauth_incomplete"
	RotationAlertScheduleReauthRequired = "schedule_reauth_required"
	RotationAlertHostIdentityStopped    = "host_identity_stopped"
)

// rotationAlertKindEnum 改密工作提醒的種類允許清單。
var rotationAlertKindEnum = []string{
	RotationAlertAuthzStopped, RotationAlertPlanFailed, RotationAlertRecoveryVerify,
	RotationAlertCandidateAbandoned, RotationAlertCleanupPending, RotationAlertRestartInterrupted,
	RotationAlertPlanReauthIncomplete, RotationAlertScheduleReauthRequired, RotationAlertHostIdentityStopped,
}

// ---- EventSpec 註冊（SHALL 與上方常數同檔相鄰）----

// requestScopeParams 連線申請族共用參數：單號必帶；資產名可能查不到（資產列不存在時為空字串），
// 故為可選＋模板可選段。申請人名稱、總台數、申請時長由產生點帶入或由分派解析，缺值時模板以可選段承接。
func requestScopeParams(extra ...ParamSpec) []ParamSpec {
	base := []ParamSpec{
		{Name: "request_id", Kind: KindInt, Required: true},
		{Name: "asset_name", Kind: KindOpaque, NameOf: IDKindAsset},
		{Name: "asset_count", Kind: KindInt},
		{Name: "requester_name", Kind: KindOpaque, NameOf: IDKindUser},
	}
	return append(base, extra...)
}

// 連線申請族、破窗與補審逾期的去處：審核中心的對應頁籤與那一張單。一律明寫 tab：
// 不帶 tab 的 `?request=` 是審核中心既有的「落在歷史頁籤」契約，不在這裡改變。
var (
	// 申請建立：待審頁籤（要人處理）
	approvalsPendingActionLink = LinkSpec{Path: "/approvals?tab=pending&request={request_id}", Label: LinkLabelAction}
	// 投票進度：待審頁籤（仍待其他審核者）
	approvalsPendingViewLink = LinkSpec{Path: "/approvals?tab=pending&request={request_id}", Label: LinkLabelView}
	// 核准、拒絕、提前撤銷：歷史頁籤（看結果）
	approvalsHistoryViewLink = LinkSpec{Path: "/approvals?tab=history&request={request_id}", Label: LinkLabelView}
	// 破窗使用、補審逾期：待補審頁籤
	approvalsReviewsActionLink = LinkSpec{Path: "/approvals?tab=reviews&request={request_id}", Label: LinkLabelAction}
)

// 稽核失效一族的去處：操作日誌的失效分頁。
var (
	auditFailureActionLink = LinkSpec{Path: "/audit-logs?tab=failures", Label: LinkLabelAction}
	auditFailureViewLink   = LinkSpec{Path: "/audit-logs?tab=failures", Label: LinkLabelView}
)

// itemVariant 逐項決定（拒絕或撤銷其中一項資產）的 variant：帶 item_asset_name 時使用。
var itemVariant = map[string]string{"item": "item_asset_name"}

// registry 事件契約表。新增事件＝同時加常數與此表條目，並補三語 locales
// （完備性守衛雙向比對，漏任一側即紅）。
var registry = withSystemAlertEvents(map[Event]EventSpec{
	EventAgentTaskReport: {
		Params: []ParamSpec{
			{Name: "owner_id", Kind: KindInt, Required: true, WireOnly: true},
			{Name: "request_id", Kind: KindInt, Required: true},
			{Name: "report_id", Kind: KindInt, Required: true, WireOnly: true},
			{Name: "version", Kind: KindInt, Required: true},
			{Name: "user_id", Kind: KindInt, Required: true},
			{Name: "agent_name", Kind: KindOpaque, NameOf: IDKindUser},
			{Name: "owner_name", Kind: KindOpaque, NameOf: IDKindUser},
			{Name: "token_name", Kind: KindOpaque, NameOf: IDKindAPIToken},
			{Name: "asset_name", Kind: KindOpaque, NameOf: IDKindAsset},
			{Name: "asset_count", Kind: KindInt},
		},
		Severity: SeverityLow,
		Link:     LinkSpec{Path: "/audit/agent-tasks/{request_id}", Label: LinkLabelView},
	},
	EventAgentBreakerTripped: {
		Params: []ParamSpec{
			{Name: "owner_id", Kind: KindInt, Required: true, WireOnly: true},
			{Name: "user_id", Kind: KindInt, Required: true},
			{Name: "token_id", Kind: KindInt, Required: true},
			{Name: "agent_name", Kind: KindOpaque, NameOf: IDKindUser},
			{Name: "owner_name", Kind: KindOpaque, NameOf: IDKindUser},
			{Name: "token_name", Kind: KindOpaque, NameOf: IDKindAPIToken},
			{Name: "asset_name", Kind: KindOpaque, NameOf: IDKindAsset},
			{Name: "distinct_count", Kind: KindInt},
			{Name: "window_minutes", Kind: KindInt},
		},
		Severity: SeverityHigh,
		Link:     LinkSpec{Path: "/agent-breakers?user_id={user_id}", Label: LinkLabelAction},
	},
	EventAccessRequestCreated: {
		Params: requestScopeParams(
			// duration_hours 只在整小時時帶（既有語義）；duration_minutes 一律帶，文字以它呈現時長
			ParamSpec{Name: "duration_hours", Kind: KindInt, WireOnly: true},
			ParamSpec{Name: "duration_minutes", Kind: KindInt, Duration: true},
		),
		Severity:       SeverityMedium,
		Link:           approvalsPendingActionLink,
		LinkedVariants: true,
	},

	EventAccessRequestApproved: {
		Params: requestScopeParams(
			ParamSpec{Name: "mode", Kind: KindEnum, Required: true, Enum: []string{ApprovalModeAuto, ApprovalModeManual}},
			ParamSpec{Name: "decider_name", Kind: KindOpaque, NameOf: IDKindUser},
			ParamSpec{Name: "duration_hours", Kind: KindInt, WireOnly: true},
			ParamSpec{Name: "duration_minutes", Kind: KindInt, Duration: true},
			// 逐項核准（這次核准沒有涵蓋整張申請的全部項目）：被核准的第一項、這次核准的項數（大於 1 才帶），
			// 及核准之後同一張申請仍待審的項數（大於 0 才帶）
			ParamSpec{Name: "item_asset_name", Kind: KindOpaque, NameOf: IDKindAsset},
			ParamSpec{Name: "approved_item_count", Kind: KindInt},
			ParamSpec{Name: "pending_item_count", Kind: KindInt},
		),
		VariantParam:     "mode",
		PresenceVariants: itemVariant,
		Severity:         SeverityLow,
		Link:             approvalsHistoryViewLink,
		LinkedVariants:   true,
	},

	EventAccessRequestApprovalProgress: {
		Params: requestScopeParams(
			ParamSpec{Name: "votes", Kind: KindInt, Required: true},
			ParamSpec{Name: "required", Kind: KindInt, Required: true},
			ParamSpec{Name: "decider_name", Kind: KindOpaque, NameOf: IDKindUser},
		),
		Severity:       SeverityLow,
		Link:           approvalsPendingViewLink,
		LinkedVariants: true,
	},

	EventAccessRequestRejected: {
		Params: requestScopeParams(
			ParamSpec{Name: "decider_name", Kind: KindOpaque, NameOf: IDKindUser},
			ParamSpec{Name: "item_asset_name", Kind: KindOpaque, NameOf: IDKindAsset},
		),
		PresenceVariants: itemVariant,
		Severity:         SeverityLow,
		Link:             approvalsHistoryViewLink,
		LinkedVariants:   true,
	},

	// 破窗的申請人即 username（產生點在手），不另帶 requester_name
	EventBreakGlassUsed: {
		Params: []ParamSpec{
			{Name: "request_id", Kind: KindInt, Required: true},
			{Name: "asset_name", Kind: KindOpaque, NameOf: IDKindAsset},
			{Name: "asset_count", Kind: KindInt},
			{Name: "username", Kind: KindOpaque, Required: true},
			{Name: "duration_minutes", Kind: KindInt, Required: true},
		},
		Severity:       SeverityHigh,
		Link:           approvalsReviewsActionLink,
		LinkedVariants: true,
	},

	EventTicketRevoked: {
		Params: requestScopeParams(
			ParamSpec{Name: "revoker_name", Kind: KindOpaque, NameOf: IDKindUser},
			ParamSpec{Name: "item_asset_name", Kind: KindOpaque, NameOf: IDKindAsset},
			// 撤銷後中斷的連線數（收線之後才知道；收線結果取不到時不帶）
			ParamSpec{Name: "disconnected_count", Kind: KindInt},
		),
		PresenceVariants: itemVariant,
		Severity:         SeverityMedium,
		Link:             approvalsHistoryViewLink,
		LinkedVariants:   true,
	},

	EventBreakGlassReviewOverdue: {
		Params: requestScopeParams(
			ParamSpec{Name: "timeout_hours", Kind: KindInt, Required: true},
		),
		Severity:       SeverityHigh,
		Link:           approvalsReviewsActionLink,
		LinkedVariants: true,
	},

	EventKEKTopologyChanged: {
		Params: []ParamSpec{
			{Name: "actor", Kind: KindOpaque, Required: true},
			{Name: "provider", Kind: KindOpaque, Required: true},
			// before 於首次設定時為「尚未設定」的字面摘要，故為必要而非可選
			// ——可選會讓「首次設定」與「摘要組不出來」在通知上無從分辨。
			{Name: "before", Kind: KindOpaque, Required: true},
			{Name: "after", Kind: KindOpaque, Required: true},
		},
		Severity: SeverityHigh,
	},

	EventAuditFailure: {
		Params: []ParamSpec{
			{Name: "mechanism", Kind: KindEnum, Required: true, Enum: mechanismEnum, Lexicon: LexiconMechanism},
			{Name: "started_at", Kind: KindOpaque, Required: true},
			// cause_code 為機器碼＋詞庫短語：出站只帶碼，forensic detail
			// 留在 DB 的 cause_params，不進 webhook（去識別紅線）
			{Name: "cause_code", Kind: KindEnum, Required: true,
				Enum: causeEnum, Lexicon: LexiconCause},
			// 鏈驗證告警的兩個計數：
			// **可選**——本事件是全部稽核機制共用的失效入口，多數機制沒有可數的
			// 失敗點或失敗區間；設為必要會讓其他機制的呼叫缺參被 Validate 拒而
			// 降級投遞（合規告警品質倒退）。模板以可選段承接，缺值即整段不出現。
			// KindInt 走既有型別驗證，結構上不可能挾帶字串——受影響的 seq 清單、
			// 紀錄編號區間與自由字串一律不出站，只落 cause_params 與驗證頁
			{Name: "failed_points", Kind: KindInt},
			{Name: "failed_intervals", Kind: KindInt},
		},
		Severity:           SeverityHigh,
		Link:               auditFailureActionLink,
		AuditFailureFamily: true,
	},

	EventAuditFailureResolved: {
		Params: []ParamSpec{
			{Name: "mechanism", Kind: KindEnum, Required: true, Enum: mechanismEnum, Lexicon: LexiconMechanism},
			{Name: "interval", Kind: KindEnum, Required: true,
				Enum: []string{IntervalKnown, IntervalUnknown}},
			// 僅 known variant 使用：unknown 時 DB 無列可考
			{Name: "started_at", Kind: KindOpaque},
			{Name: "ended_at", Kind: KindOpaque},
		},
		VariantParam:       "interval",
		Severity:           SeverityLow,
		Link:               auditFailureViewLink,
		AuditFailureFamily: true,
	},

	EventAuditFailureOngoing: {
		Params: []ParamSpec{
			{Name: "mechanism", Kind: KindEnum, Required: true, Enum: mechanismEnum, Lexicon: LexiconMechanism},
			{Name: "cause_code", Kind: KindEnum, Required: true,
				Enum: causeEnum, Lexicon: LexiconCause},
			// 回報時刻只給 webhook：Slack 文字的最後一行已有發生時間，句尾不再重複
			{Name: "reported_at", Kind: KindOpaque, Required: true, WireOnly: true},
			// 失效的起點：由失效回報服務以未結束的事件列補查，補列事件的起點是補列時刻、不是真實起點，
			// 不帶；查不到時省略。只給 webhook：Slack 文字的句型不變
			{Name: "started_at", Kind: KindOpaque, WireOnly: true},
			// backlog 待處理筆數：**可選**——本事件是泛用的
			// 週期重發入口，並非每個機制都有可數的積壓；設為必要會讓其他機制的
			// 呼叫缺參被 Validate 拒而降級投遞（合規告警品質倒退）。模板以可選段
			// 承接，缺值即整段不出現。
			// 只帶聚合筆數不帶明細：收尾錯誤原文等 forensic 仍只落 cause_params。
			{Name: "backlog", Kind: KindInt},
			// 鏈驗證的「異常範圍已變化」重發走本事件（不先結案再重開——偽造一次
			// 不存在的恢復會破壞失效區間的起訖證據），故同樣需要這兩個可選計數
			{Name: "failed_points", Kind: KindInt},
			{Name: "failed_intervals", Kind: KindInt},
		},
		Severity:           SeverityHigh,
		Link:               auditFailureActionLink,
		AuditFailureFamily: true,
	},

	// 每日簽核逾期：列出全部未簽日。date 保留為最早未簽日——只讀 date 的既有
	// 收端看到的仍是一個應處理的日期
	EventDailyReviewOverdue: {
		Params: []ParamSpec{
			{Name: "date", Kind: KindOpaque, Required: true},
			{Name: "pending_dates", Kind: KindDateList, Required: true, Total: "pending_count"},
			{Name: "pending_count", Kind: KindInt, Required: true},
			{Name: "overdue_count", Kind: KindInt, Required: true},
			{Name: "earliest_pending_date", Kind: KindOpaque, Required: true},
			{Name: "timezone", Kind: KindOpaque, Required: true},
		},
		Severity: SeverityMedium,
		Link:     LinkSpec{Path: "/audit-logs?tab=reviews", Label: LinkLabelAction},
	},

	EventTest: {
		Params: []ParamSpec{
			{Name: "product", Kind: KindOpaque, Required: true},
			{Name: "channel_name", Kind: KindOpaque, NameOf: IDKindNotificationChannel},
		},
		Severity: SeverityLow,
	},

	// 通知投遞已放棄：某通道的一筆待投遞紀錄重送到上限仍沒送到。不送回那個通道，
	// 同一通道 24 小時至多一則（節流在通道列上做）。筆數是「截至這則通知產生時」近 24 小時的放棄數
	EventNotificationDeliveryAbandoned: {
		Params: []ParamSpec{
			{Name: "channel_name", Kind: KindOpaque, NameOf: IDKindNotificationChannel},
			{Name: "abandoned_24h", Kind: KindInt, Required: true},
			{Name: "reason", Kind: KindEnum, Required: true, Enum: deliveryReasonEnum, Lexicon: LexiconDeliveryReason},
		},
		Severity:             SeverityMedium,
		Link:                 LinkSpec{Path: "/notification-channels", Label: LinkLabelAction},
		ExcludeTargetChannel: true,
	},

	// 個人訊息未能送達：原因屬個別收件人的放棄時帶截至產生當下的去重人數（default 句型）；
	// 原因為沒有收件人或無法判定收件人時不帶人數，改帶事件種類與單號（no_recipient 句型；每日審閱沒有單號）
	EventTargetedNotificationUndelivered: {
		Params: []ParamSpec{
			{Name: "channel_name", Kind: KindOpaque, NameOf: IDKindNotificationChannel},
			{Name: "reason", Kind: KindEnum, Required: true, Enum: TargetedUndeliveredReasons(), Lexicon: LexiconDMUndeliveredReason},
			{Name: "count", Kind: KindInt},
			{Name: "event_kind", Kind: KindEnum, Enum: TargetedEventKinds(), Lexicon: LexiconDMEventKind},
			{Name: "request_id", Kind: KindInt},
		},
		PresenceVariants: map[string]string{"no_recipient": "event_kind"},
		Severity:         SeverityMedium,
		Link:             LinkSpec{Path: "/notification-channels", Label: LinkLabelAction},
	},

	// 改密工作提醒：kind 經詞庫成句；detail 是產生點組的處置說明（機器碼與識別碼，不含遠端原文與秘密）
	EventCredentialRotationAlert: {
		Params: []ParamSpec{
			{Name: "kind", Kind: KindEnum, Required: true, Enum: rotationAlertKindEnum, Lexicon: LexiconRotationAlertKind},
			{Name: "detail", Kind: KindOpaque},
		},
		Severity: SeverityHigh,
	},
})

// Spec 取事件契約；未註冊回 ok=false。
func Spec(event Event) (EventSpec, bool) {
	spec, ok := registry[event]
	return spec, ok
}

// Events 回傳所有已註冊事件（守衛與診斷用；順序不保證）。
func Events() []Event {
	out := make([]Event, 0, len(registry))
	for e := range registry {
		out = append(out, e)
	}
	return out
}

// param 取單一參數宣告。
func (s EventSpec) param(name string) (ParamSpec, bool) {
	for _, p := range s.Params {
		if p.Name == name {
			return p, true
		}
	}
	return ParamSpec{}, false
}

// variants 該事件的合法 variant 鍵集（無 VariantParam 時為 {default} 加 PresenceVariants 的鍵；
// LinkedVariants 時每個鍵另有 `_linked` 版本）。
func (s EventSpec) variants() []string {
	var base []string
	if s.VariantParam == "" {
		base = []string{variantDefault}
		for v := range s.PresenceVariants {
			base = append(base, v)
		}
		sort.Strings(base)
	} else {
		p, ok := s.param(s.VariantParam)
		if !ok {
			return nil
		}
		base = append([]string(nil), p.Enum...)
		presence := make([]string, 0, len(s.PresenceVariants))
		for k := range s.PresenceVariants {
			presence = append(presence, k)
		}
		sort.Strings(presence)
		for _, e := range p.Enum {
			for _, k := range presence {
				base = append(base, e+"_"+k)
			}
		}
	}
	if !s.LinkedVariants {
		return base
	}
	out := append([]string(nil), base...)
	for _, v := range base {
		out = append(out, v+linkedSuffix)
	}
	return out
}
