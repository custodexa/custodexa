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

import "github.com/custodexa/backend/internal/model"

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
)

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
}

// EventSpec 單一事件的參數契約。
//
// VariantParam 非空時，該參數必須是本事件的必要 enum 參數，其值即模板 variant 鍵
// （locales 內 event 底下的次層鍵）；為空時 variant 鍵固定為 variantDefault。
type EventSpec struct {
	Params       []ParamSpec
	VariantParam string
}

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

// mechanismEnum 審計機制允許清單。以 model 常數引用而非重打字面量：
// 常數改名即編譯失敗；新增機制未同步則由 TestMechanismEnumMatchesModel 攔截。
var mechanismEnum = []string{
	model.MechanismAuditWrite,
	model.MechanismSyslogForward,
	model.MechanismRecordingProbe,
	model.MechanismRecordingText,
	model.MechanismRecordingGraphics,
	model.MechanismSessionRecord,
	model.MechanismKEKRetirement,
	model.MechanismAADResidue,
	model.MechanismCheckpointAnchor,
	model.MechanismAuditChainStructure,
	model.MechanismAuditChainContent,
	model.MechanismAuditChainVerify,
	model.MechanismSourcePolicy,
}

// ---- 事件常數（值＝現行呼叫點字串，逐一與呼叫點實查對照）----

const (
	// EventAccessRequestCreated 新申請待審（access_request_service.go:235）
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

	// EventAuditFailure 審計機制失效（audit_failure_service.go:102）
	EventAuditFailure Event = "audit_failure"
	// EventAuditFailureResolved 審計機制恢復（audit_failure_service.go:136）。
	// 注意：design v4 誤記為 audit_failure_recovered，實碼為 _resolved
	EventAuditFailureResolved Event = "audit_failure_resolved"
	// EventAuditFailureOngoing 失效持續中的週期重發（NotifyOngoing 唯一呼叫端
	// key_manager_degraded.go:123 傳入此字串）
	EventAuditFailureOngoing Event = "audit_failure_ongoing"

	// EventDailyReviewOverdue 每日審閱逾期（daily_review_service.go:190）
	EventDailyReviewOverdue Event = "daily_review_overdue"
	// EventTest 通道測試發送（alert_notifier.go:449 buildChannelBody 的 event="test"）
	EventTest Event = "test"
)

// ---- EventSpec 註冊（SHALL 與上方常數同檔相鄰）----

// requestScopeParams 連線申請族共用參數：單號必帶，資產名可能查不到（assetName()
// 於資產列不存在時回空字串，access_request_service.go:782-788），故為可選＋模板可選段。
func requestScopeParams(extra ...ParamSpec) []ParamSpec {
	base := []ParamSpec{
		{Name: "request_id", Kind: KindInt, Required: true},
		{Name: "asset_name", Kind: KindOpaque},
	}
	return append(base, extra...)
}

// registry 事件契約表。新增事件＝同時加常數與此表條目，並補三語 locales
// （完備性守衛雙向比對，漏任一側即紅）。
var registry = map[Event]EventSpec{
	EventAccessRequestCreated: {Params: requestScopeParams()},

	EventAccessRequestApproved: {
		Params: requestScopeParams(ParamSpec{
			Name: "mode", Kind: KindEnum, Required: true,
			Enum: []string{ApprovalModeAuto, ApprovalModeManual},
		}),
		VariantParam: "mode",
	},

	EventAccessRequestApprovalProgress: {
		Params: requestScopeParams(
			ParamSpec{Name: "votes", Kind: KindInt, Required: true},
			ParamSpec{Name: "required", Kind: KindInt, Required: true},
		),
	},

	EventAccessRequestRejected: {Params: requestScopeParams()},

	EventBreakGlassUsed: {
		Params: requestScopeParams(
			ParamSpec{Name: "username", Kind: KindOpaque, Required: true},
			ParamSpec{Name: "duration_minutes", Kind: KindInt, Required: true},
		),
	},

	EventTicketRevoked: {Params: requestScopeParams()},

	EventBreakGlassReviewOverdue: {
		Params: requestScopeParams(
			ParamSpec{Name: "timeout_hours", Kind: KindInt, Required: true},
		),
	},

	EventAuditFailure: {
		Params: []ParamSpec{
			{Name: "mechanism", Kind: KindEnum, Required: true, Enum: mechanismEnum},
			{Name: "started_at", Kind: KindOpaque, Required: true},
			// cause_code 為機器碼＋詞庫短語：出站只帶碼，forensic detail
			// 留在 DB 的 cause_params，不進 webhook（去識別紅線）
			{Name: "cause_code", Kind: KindEnum, Required: true,
				Enum: causeEnum, Lexicon: LexiconCause},
			// 鏈驗證告警的兩個計數：
			// **可選**——本事件是全部審計機制共用的失效入口，多數機制沒有可數的
			// 失敗點或失敗區間；設為必要會讓其他機制的呼叫缺參被 Validate 拒而
			// 降級投遞（合規告警品質倒退）。模板以可選段承接，缺值即整段不出現。
			// KindInt 走既有型別驗證，結構上不可能挾帶字串——受影響的 seq 清單、
			// 紀錄編號區間與自由字串一律不出站，只落 cause_params 與驗證頁
			{Name: "failed_points", Kind: KindInt},
			{Name: "failed_intervals", Kind: KindInt},
		},
	},

	EventAuditFailureResolved: {
		Params: []ParamSpec{
			{Name: "mechanism", Kind: KindEnum, Required: true, Enum: mechanismEnum},
			{Name: "interval", Kind: KindEnum, Required: true,
				Enum: []string{IntervalKnown, IntervalUnknown}},
			// 僅 known variant 使用：unknown 時 DB 無列可考
			{Name: "started_at", Kind: KindOpaque},
			{Name: "ended_at", Kind: KindOpaque},
		},
		VariantParam: "interval",
	},

	EventAuditFailureOngoing: {
		Params: []ParamSpec{
			{Name: "mechanism", Kind: KindEnum, Required: true, Enum: mechanismEnum},
			{Name: "cause_code", Kind: KindEnum, Required: true,
				Enum: causeEnum, Lexicon: LexiconCause},
			{Name: "reported_at", Kind: KindOpaque, Required: true},
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
	},

	EventDailyReviewOverdue: {
		Params: []ParamSpec{{Name: "date", Kind: KindOpaque, Required: true}},
	},

	EventTest: {
		Params: []ParamSpec{{Name: "product", Kind: KindOpaque, Required: true}},
	},
}

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

// variants 該事件的合法 variant 鍵集（無 VariantParam 時為 {default}）。
func (s EventSpec) variants() []string {
	if s.VariantParam == "" {
		return []string{variantDefault}
	}
	p, ok := s.param(s.VariantParam)
	if !ok {
		return nil
	}
	return append([]string(nil), p.Enum...)
}
