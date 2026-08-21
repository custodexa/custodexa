package audit

import (
	"context"
	"log"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
)

// 非同步審計投遞面的兩個實作（modular-architecture W4 任務 4.2／4.6）。
//
// 介面契約見 pkg/gatewayapi/audit.go 的 AsyncSink：at-most-once、「不投遞」是合法終態。
//
// # 為何是兩個實作而不是一個
//
// manifest（openspec/changes/archive/2026-08-11-modular-architecture/research/manifest-audit-points.md，隨公開快照出門）把 35 個非交易內產生點全標 AsyncSink，
// 但其中**兩點現況不受 AuditLogEnabled 管制**（AP-04 `internal/api/asset_handler.go`
// 的 k8s 檔案操作審計、AP-28 `internal/proxy/file_tap.go` 的檔案傳輸審計）——它們
// 走的是 `database.DB.Create` / `db.Create` 直寫，從未經過 AuditLogService.Log
// 的開關分支。若把它們接到 AuditLogService 上，開關關閉時這兩類留痕會**新增**
// 消失行為；那是行為變更，且方向是「少留痕」，踩在「全操作審計」紅線上。
// 故 W4 4.6 的收口方式是：改走 AsyncSink 介面（拿掉對 model.AuditLog 的直接建構），
// 但落地實作是 DirectSink——繞過開關、逐筆同步寫、錯誤原樣回傳，
// 行為與收口前逐位相同。

// AuditLogService 是 AsyncSink 的主實作（受 AuditLogEnabled／AsyncAuditEnabled 管制）。
var _ gatewayapi.AsyncSink = (*AuditLogService)(nil)

// Submit 入列一筆審計事件（W4 4.2）。
//
// **現況 Log 的包裝，語義不變**：開關關閉即靜默丟棄、佇列滿載即丟棄或落檔，
// 皆為 AsyncSink 契約明載的合法終態。回傳恆為 nil——Log 沒有回傳值，
// 這裡若憑空生出 error 會讓呼叫端以為取得了投遞保證。
//
// ctx 目前未被使用：Log 是非阻塞入列，沒有可取消的等待點。**刻意保留參數**
// 而不改介面——AsyncSink 是進程序邊界，跨行程實作必然需要 ctx。
func (s *AuditLogService) Submit(_ context.Context, ev gatewayapi.AuditEvent) error {
	s.logAt(entryOf(ev), ev.OccurredAt)
	return nil
}

// entryOf 由傳輸形狀組出 AuditLogEntry（欄位對應同 tx_sink.go 的 auditRowOf）。
func entryOf(ev gatewayapi.AuditEvent) *AuditLogEntry {
	return &AuditLogEntry{
		UserID:      ev.Actor.UserID,
		Username:    ev.Actor.Username,
		Action:      model.AuditAction(ev.Action),
		Resource:    model.AuditResource(ev.Resource),
		ResourceID:  ev.ResourceID,
		// 資產主體鍵（auditor-workbench D4）：漏這一行，走 sink 的產生點
		// 就算在上游填了 asset_id 也會在此被靜默丟棄，而資產樞紐只會少事件、
		// 不會報錯——是最難察覺的一種缺口
		AssetID:     ev.AssetID,
		Status:      model.AuditStatus(ev.Status),
		Method:      ev.Request.Method,
		Path:        ev.Request.Path,
		ClientIP:    ev.Request.ClientIP,
		StatusCode:  ev.Request.StatusCode,
		Duration:    time.Duration(ev.Request.DurationMS) * time.Millisecond,
		RequestBody: ev.Request.Body,
		RequestID:   ev.Request.RequestID,
		ErrorMsg:    ev.ErrorMsg,
		Details:     ev.Details,
	}
}

// directSink 不受 AuditLogEnabled 管制的直寫落地面（W4 4.6，C-plain 兩點專用）。
//
// # 它存在的理由，以及它 SHALL NOT 被擴散使用
//
// 只有 manifest 標記為「現況不受 AuditLogEnabled 管制」的產生點可以用它——目前
// 恰為 AP-04 與 AP-28 兩點。任何新的審計產生點都 SHALL 走 AuditLogService
// （受開關與佇列管制）或 TxSink（交易內 fail-close）；拿 DirectSink 當
// 「比較好寫的 sink」用，等於在旁邊開一條無管制的第三條寫入路徑。
//
// # 這條約束實際被守住多少（誠實界定，勿據此略過人工審查）
//
// 被守住的有兩件，都是**下界**：
//
//   - 建構點收在組裝根——cmd/server/audit_sink_boundary_guard_test.go 的
//     TestDirectSinkIsConstructedOnlyAtAssemblyRoot 以 AST 掃全庫的
//     `NewDirectSink` 呼叫，非測試檔中只允許出現在
//     directSinkAllowedConstructionFiles 列名的 cmd/server/stage2.go。
//   - 既有兩條接線不被沉默拆除——cmd/server/sink_wiring_guard_test.go 的
//     TestRequiredSinksAreWiredToConsumers 依 sinkWiringRegistry 逐條斷言
//     `auditDirectSink` 到 `connHandler.AuditSink`（AP-28）與 routeServices
//     結構欄位（AP-04）的接線仍在。
//
// **沒有被守住的是「消費者恰為這兩點」**：上述第二道只檢查登記表已列的接線是否
// 存在，不做封閉集合比對，多出第三個消費者不會使它轉紅；第一道管的是誰能呼叫
// 建構子，組裝根把同一個 auditDirectSink 變數再交給第三個服務、或某處以
// gatewayapi.AsyncSink 介面型別把它轉手出去，全庫測試皆綠。要擴散 DirectSink
// 的改動 SHALL 靠人工審查攔下——這裡沒有東西會替你擋。
//
// # 錯誤語義
//
// 同步寫、error 原樣回傳。呼叫端維持收口前的處置（AP-04 完全不檢查 error＝H-5 既有缺陷，
// AP-28 只記 log）——**W4 不修這兩處的錯誤處置**，那是行為變更，不在等價搬遷範圍內。
type directSink struct {
	db *gorm.DB
}

var _ gatewayapi.AsyncSink = (*directSink)(nil)

// NewDirectSink 建立直寫落地面。db 為 nil 時 Submit 一律回錯（不靜默丟棄）。
//
// **回傳介面、實作型別不匯出（export budget）**：唯一消費者是組裝根，且它只需要
// gatewayapi.AsyncSink。守衛 TestDirectSinkIsConstructedOnlyAtAssemblyRoot 釘住
// 「只有組裝根可呼叫本建構子」。
func NewDirectSink(db *gorm.DB) gatewayapi.AsyncSink { return &directSink{db: db} }

// Submit 直寫一筆審計列，不看任何開關。
func (s *directSink) Submit(_ context.Context, ev gatewayapi.AuditEvent) error {
	if s == nil || s.db == nil {
		// 未注入即回錯，不靜默成功——C-plain 兩點的呼叫端雖不 fail-close，
		// 至少 log 得出「審計沒寫進去」，而不是以為寫了。
		log.Printf("[Audit] DirectSink 未注入 DB 句柄，審計列未落地 (action=%s resource=%s)", ev.Action, ev.Resource)
		return errDirectSinkNoDB
	}
	return s.db.Create(auditRowOf(ev)).Error
}

// errDirectSinkNoDB directSink 未接線。
var errDirectSinkNoDB = directSinkError("審計直寫落地面未注入 DB 句柄")

type directSinkError string

func (e directSinkError) Error() string { return string(e) }
