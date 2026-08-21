package gatewayapi

import (
	"context"
	"time"
)

// Actor 操作者身分快照（audit_logs 反正規化欄，避免查詢 JOIN）。
type Actor struct {
	UserID uint
	// Username 反正規化的操作者名。系統路徑（改密 runner、seed 遷移）記 "system"、
	// UserID 記 0——現況 internal/model/audit_log.go 的 UserFromContext 即此語義，
	// 系統操作同樣要留痕，不得因無 HTTP 脈絡而不寫。
	Username string
}

// RequestMeta 請求脈絡。**全欄可為零值**——交易內產生點（TxSink 19 點）多半只填
// ClientIP，其餘欄位無 HTTP 脈絡；HTTP 中介層產生點（AsyncSink）才會填滿。
type RequestMeta struct {
	Method     string
	Path       string
	ClientIP   string
	StatusCode int
	// DurationMS 響應時間（毫秒）。對齊 model.AuditLog.Duration 的既有單位，
	// 不用 time.Duration——落地欄本身就是毫秒整數，換型別會在轉換點製造精度爭議。
	DurationMS int
	RequestID  string
	// Body 已脫敏的請求內容（對應 model.AuditLog.RequestBody）。
	Body string
}

// AuditEvent 是 audit_logs 一列的傳輸形狀，AsyncSink 與 TxSink 共用。
// 欄位對齊 internal/service/AuditLogEntry 與 internal/model.AuditLog，差異只在去 GORM 化。
//
// # 欄位充分性（對照 openspec/changes/archive/2026-08-11-modular-architecture/research/manifest-audit-points.md
//（隨公開快照出門）的 19 個 TxSink 點）
//
// 逐點核對結論：19 點實際寫入的欄位聯集 ＝
// {CreatedAt, UserID, Username, Action, Resource, ResourceID, Status, Details, ClientIP}，
// 全數由本結構承載（CreatedAt→OccurredAt、UserID/Username→Actor、ClientIP→Request.ClientIP）。
// 分組證據：
//
//	AP-22／AP-26／AP-27（model 層落地側 3）：CreatedAt, UserID, Username, Action,
//	  Resource, ResourceID, Status, Details（internal/model/asset_account_audit.go:95、
//	  internal/model/asset_audit.go:216／:242）。
//	AP-30…AP-35／AP-38…AP-42（T-2 呼叫點 11）：不自建列，透過上述三個函式落地，
//	  故欄位需求與該組相同。
//	AP-36／AP-37／AP-60（T-1 交易內 fail-close 3）：Action, Resource, ResourceID,
//	  Status, UserID, Username, **ClientIP**, Details（internal/service/
//	  asset_group_service.go:318／:529、user_group_service.go:130）。
//	AP-50／AP-51（R3.1 漏列的 fail-close 2）：AP-50 同上再加 ClientIP
//	  （ldap_directory_service.go:760）；AP-51 只填 UserID=0／Username="system"／
//	  Action／Resource／Status／Details（ldap_seed_migration.go:311）。
//
// 無任一 TxSink 點需要本結構未涵蓋的欄位。刻意未納入的兩欄各有理由：
//
//	ErrorMsg  納入（AsyncSink 側 handler 事後審計會填），TxSink 19 點目前全不填。
//	IdempotencyUUID 不納入：唯二使用者 AP-56／AP-57（封印回灌）在 manifest 中標
//	  「不進 sink」——它們是 audit 模組自身的落地入口，不經任何 sink。無生產者、
//	  無消費者的欄位不進契約（同 SessionLimits.RecordingRequired 的紀律）。
type AuditEvent struct {
	// OccurredAt 事件發生時刻，對應 model.AuditLog.CreatedAt。
	// 零值時由落地器補 time.Now()——現況 TxSink 點半數自填、半數留給 GORM，
	// 兩種都要能表達。
	OccurredAt time.Time

	Actor Actor

	// Action／Resource／Status 為 string 而非 model.AuditAction 等具名型別：
	// 具名型別在 internal/model，帶進來即破型別純淨。合法值域仍以 model 的常數為準，
	// 由落地器負責轉型。
	Action     string
	Resource   string
	ResourceID *uint
	Status     string

	// AssetID 資產主體鍵，對應 model.AuditLog.AssetID（auditor-workbench D4）。
	//
	// **不能由落地器從 (Resource, ResourceID) 推導**：那正是 D1.3(a) 判定會產生假事件的
	// 做法——同一組 (asset, 130) 可能來自改密計畫 130 或授權列 130。主體只有產生點知道，
	// 故它必須是傳輸形狀的一部分；少了這欄，經 sink 的產生點就沒有任何管道表達主體，
	// 而「表達不了」會被誤讀成「這動作與資產無關」。
	//
	// **指標型**（同 ResourceID）：多數審計列與資產無關，值型的 0 分不出「無資產」
	// 與「資產 0」，且會讓資產樞紐的 `asset_id IS NOT NULL` 納入原則整個失效。
	AssetID *uint

	Request RequestMeta

	// Details 變更／操作詳情，對應 model.AuditLog.Details（TEXT 欄）。
	//
	// **型別是 string 而非 json.RawMessage**（訂正 R3 §2.3 的欄位型別）：現況並非
	// 每個產生點都寫 JSON——internal/service/recording_failure_report.go:49 的
	// Details 走 causeText()，產物是 zh-TW 散文（audit_failure_service.go:128）。
	// 宣告成 json.RawMessage 等於在契約上聲稱「這裡一定是 JSON」，而該點會使它成為
	// 謊言；空字串（無詳情）在 json.RawMessage 下也不是合法 JSON。string 是零失真的
	// 表達，且落地時 model.AuditLog.Details 本就是 string，少一層轉換即少一處失真點。
	Details string

	// ErrorMsg 錯誤訊息（如有）。
	ErrorMsg string
}

// AsyncSink 非同步審計投遞面（進程序邊界，可跨行程消費）。
//
// # 投遞語義：at-most-once（硬性契約，SHALL NOT 被誤讀為可靠投遞）
//
// 入列即返回。**「不投遞」是合法終態**——現況實作
// （internal/service/audit_log_service.go:117 開關關閉即靜默 return、:154 佇列滿載丟棄）
// 就是這個語義，本介面誠實表達它而不假裝更強。呼叫端 SHALL NOT 據此 fail-close，
// 亦 SHALL NOT 寫出「一定送達」的斷言（會在將來介面演進時被既有測試綁死）。
// 未投遞的偵測由 AuditFailureService 另路上報。
//
// # 它承載不了什麼（W4 的 Critical#1 教訓）
//
// **強制審計（交易內 fail-close）SHALL NOT 走本介面。** 那類寫入需要吃呼叫方的
// `*gorm.DB` 並同步回 error，語義與此處相反；誤分派的後果是回滾語義靜默退化為
// fail-open，**而且測試會更綠**（原本會失敗的路徑變成永遠成功），編譯器與既有測試
// 皆零保護。該類寫入一律走 internal/modules/audit/port.TxSink。
// 逐點分派見 openspec/changes/archive/2026-08-11-modular-architecture/research/manifest-audit-points.md
//（隨公開快照出門，唯一權威）。
//
// # 跨行程落地前必須先完成的演進條件（S4 codex 部分採納項 #3）
//
// 同行程本機 sink 不需要下列機制，故本 change 不實作；但契約先寫清楚，避免將來被
// 誤以為它已能承載強制審計。一般 error 分不出「未收到」與「已收但回應遺失」，
// 因此跨行程交付前 SHALL 先完成四件事：
//
//  1. AuditEvent 帶 EventID（確定性事件識別，供去重與追查）；
//  2. 投遞語義自 at-most-once 升為至少一次；
//  3. 消費端依 EventID 去重（升至至少一次後必然出現重送）；
//  4. durable-accept 確認（sink 回 OK 的意義改為「已持久化」，而非「已收下」）。
//
// 四項未全數完成前，SHALL NOT 把任何 fail-close 需求改掛到本介面上。
type AsyncSink interface {
	// Submit 入列一筆審計事件。回 error 表示「入列失敗」，不表示「未落地」；
	// 回 nil 亦不保證已落地（at-most-once）。
	Submit(ctx context.Context, ev AuditEvent) error
}
