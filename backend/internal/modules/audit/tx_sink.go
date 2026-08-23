package audit

import (
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"gorm.io/gorm"
)

// txSink 交易內同步審計落地器。
//
// 介面契約見 internal/modules/audit/port/txsink.go；本型別是它在同行程的唯一實作。
//
// # 三條硬性語義（逐條對應 port 契約的 SHALL NOT）
//
//  1. **不受 AuditLogEnabled 管制**。現況這批交易內直寫本就不看該旗標（它們不經
//     AuditLogService.Log），加上去即行為變更——而且是最壞的那種：一個設定旗標
//     能讓「強制審計」整批消失，業務操作照樣成立。
//  2. **不吞 error**。tx.Create 的錯誤原樣上拋，呼叫端 `return err` 即整筆回滾。
//     本型別**刻意不做**錯誤包裝——現況各呼叫點的包裝詞（「審計留痕失敗: %w」、
//     「寫入 LDAP seed 審計失敗: %w」…）各不相同且已被測試斷言，包裝留在呼叫端
//     才能讓收口前後的錯誤字串逐字相同。
//  3. **不自開交易、不換 session**。寫入一律用傳入的 tx；若在此 `Session(&gorm.Session{NewDB:true})`
//     或 `Begin()`，fail-close 會靜默退化成「審計寫成功但業務回滾」或反之。
//
// # 無狀態
//
// 本型別不持有 *gorm.DB——句柄由呼叫端隨每次寫入傳入（那正是「同一筆交易」的載體）。
// 故它是零欄位型別，可安全複製、可被多個服務共用一份。
type txSink struct{}

// 編譯期斷言：本型別滿足 audit 模組的 internal port。
// 斷言寫在實作側（audit）而非 port 側——port 是被依賴方，不該認識實作。
var _ port.TxSink = txSink{}

// NewTxSink 建立交易內同步落地器。
//
// **回傳介面、實作型別不匯出（export budget）**：消費者只需要 port.TxSink，
// 具體型別是實作細節；匯出它等於把「audit 有一個叫 TxSink 的 struct」固化成跨包 API。
// 型別本身是**零欄位值型別**——無狀態、無需身分，同一個 sink 被多個服務持有
// 不可能產生共享可變狀態。
func NewTxSink() port.TxSink { return txSink{} }

// WriteInTx 在 tx 的交易內同步寫入一筆審計列。
func (txSink) WriteInTx(tx *gorm.DB, ev port.AuditEvent) error {
	return tx.Create(auditRowOf(ev)).Error
}

// auditRowOf 由傳輸形狀組出落地列。
//
// **欄位對應是契約的一部分**（gatewayapi.AuditEvent 的註解逐欄列了來源）：
// CreatedAt←OccurredAt、UserID/Username←Actor、ClientIP 等←Request。
// OccurredAt 為零值時**不填** CreatedAt，交由 GORM 的 autoCreateTime 補——現況
// 交易內 5 個產生點都不自填時刻，硬補 time.Now() 會讓「誰決定時刻」這件事
// 從 ORM 悄悄搬到本函式（兩者取值幾乎相同，但落點不同即是行為變更的入口）。
func auditRowOf(ev port.AuditEvent) *model.AuditLog {
	row := &model.AuditLog{
		UserID:      ev.Actor.UserID,
		Username:    ev.Actor.Username,
		Action:      model.AuditAction(ev.Action),
		Resource:    model.AuditResource(ev.Resource),
		ResourceID:  ev.ResourceID,
		// 資產主體鍵：漏這一行，走 sink 的產生點
		// 就算在上游填了 asset_id 也會在此被靜默丟棄，而資產樞紐只會少事件、
		// 不會報錯——是最難察覺的一種缺口
		AssetID:     ev.AssetID,
		Status:      model.AuditStatus(ev.Status),
		Method:      ev.Request.Method,
		Path:        ev.Request.Path,
		ClientIP:    ev.Request.ClientIP,
		StatusCode:  ev.Request.StatusCode,
		Duration:    ev.Request.DurationMS,
		RequestBody: ev.Request.Body,
		RequestID:   ev.Request.RequestID,
		ErrorMsg:    ev.ErrorMsg,
		Details:     ev.Details,
	}
	if !ev.OccurredAt.IsZero() {
		row.CreatedAt = ev.OccurredAt
	}
	return row
}
