// Package port 是 audit 模組的同行程 internal port（modular-architecture W1 任務 1.6）。
//
// # 為何 TxSink 在這裡而不在 pkg/gatewayapi（S4 codex 採納項 #2）
//
// TxSink 的簽名必然帶 `*gorm.DB`。若把它宣告在 pkg/gatewayapi，那個公開包就整包相依
// GORM——即使註解標了「不跨行程」，依賴事實仍在，將來 gateway 行程 import 該包就會把
// ORM 一起拖進去。註解攔不住 import。故 TxSink 落在 internal port，
// 而 pkg/gatewayapi 得以維持零 model／零 gorm／零 gin，**無任何具名例外**。
//
// 守衛 TestGatewayAPITypePurity 反向釘住這件事：TxSink 一旦出現在 pkg/gatewayapi 即紅。
package port

import (
	"errors"

	"gorm.io/gorm"

	"github.com/custodexa/backend/pkg/gatewayapi"
)

// AuditEvent 與 AsyncSink 共用同一個事件形狀（型別別名，非另一個型別）。
//
// 別名而非複製：同一筆審計列不該因為走哪個 sink 而有兩種記憶體形狀，那會在 W4 收口時
// 製造一層無意義的轉換與一個失真點。方向上是 internal port 相依 pkg/gatewayapi，
// 與拓樸序一致，不污染公開包。
type AuditEvent = gatewayapi.AuditEvent

// TxSink 交易內同步審計落地面。**同行程 internal port，刻意不可跨行程。**
//
// # 契約
//
// 在呼叫方進行中的交易內同步寫審計；回 error，呼叫方 `return err` 即整筆回滾。
// 這是「強制審計」的唯一合法落地路徑——審計寫不進去，業務操作就不許成立。
// 現況已有多處以註解自陳此語義，例如
// internal/modules/asset/asset_group_service.go:315-316「與變更同交易——審計失敗即回滾」、
// internal/service/user_group_service.go:128「留痕失敗即回滾（授權變更不可無痕）」。
//
// # 為何不帶額外的 ctx（S4 codex 採納項 #2）
//
// 簽名刻意是 `WriteInTx(tx, ev)`，不是 `WriteInTx(ctx, tx, ev)`。兩個理由：
//
//  1. 現況的 fail-close 函式本就沒有 ctx（例如
//     `nodeAudit(tx *gorm.DB, ...)`，asset_group_service.go:317）。硬補一個 ctx 會
//     引入**額外的取消來源**——該 ctx 在交易期間被取消，將導致原本不會回滾的交易回滾。
//     那是行為變更，不是重構。
//  2. 交易自身已攜帶它的 context，沿用即可，不需要第二個。
//
// # SHALL NOT
//
//   - SHALL NOT 以 gatewayapi.AsyncSink 替代本介面。AsyncSink 是 at-most-once、
//     開關關閉即靜默丟棄、無回傳語義；換過去的後果是 fail-close 靜默退化為 fail-open，
//     **而且測試會更綠**（原本會失敗的路徑變成永遠成功）。W4 的驗收核心即以突變自檢
//     證明「把 TxSink 換成 AsyncSink 會讓測試變紅」。
//   - 實作 SHALL NOT 受 `AuditLogEnabled` 管制。現況這批交易內直寫本就不看該旗標
//     （它們不經 AuditLogService.Log），加上去即行為變更。
//   - 實作 SHALL NOT 吞掉 tx.Create 的 error。
//
// # 誰該走這個介面
//
// openspec/changes/archive/2026-08-11-modular-architecture/research/manifest-audit-points.md
//（隨公開快照出門，唯一權威）逐點分派：**凡「呼叫方交易內＝是」者
// 一律 TxSink**，實測 19 點，零例外。分派規則不看 fail-close 與否——只要寫入吃的是
// `tx`，它就需要 `*gorm.DB` 參數，AsyncSink 的簽名表達不了。其中 3 點
// （AP-39／AP-41／AP-42）呼叫方現況刻意 fail-open，收口時保持現況，不得順手改判。
type TxSink interface {
	// WriteInTx 在 tx 的交易內同步寫入一筆審計列。
	// 回非 nil error 時，呼叫方 SHALL 讓該 error 逸出交易閉包，使整筆操作回滾。
	WriteInTx(tx *gorm.DB, ev AuditEvent) error
}

// ErrTxSinkMissing 交易內審計落地面未注入（modular-architecture W4 4.4／4.7）。
//
// **不是 panic**：生產上由組裝根的啟動自檢（cmd/server/audit_sinks.go 的
// requireAuditTxSink）保證走不到這裡；在測試與工具路徑上以 error 表達，
// 可讓呼叫端的 fail-close 語義原樣生效（業務交易回滾），
// 而 panic 會把「審計沒寫成」升級成「整個行程死掉」，那是另一種行為變更。
var ErrTxSinkMissing = errors.New("交易內審計落地面未注入（強制審計不得靜默略過）")

// WriteInTx 是呼叫端使用 TxSink 的**唯一合法形式**。
//
// # 為何要一層包裝，而不是讓呼叫端直接 sink.WriteInTx
//
// 最危險的退化不是把 TxSink 換成 AsyncSink（那個有 manifest 守衛擋），而是
// **忘記注入**：一個 nil sink 若被實作成 no-op，審計靜默消失、業務照樣成立、
// 所有測試更綠。本函式讓「沒接線」與「寫失敗」落在同一格——都回 error，
// 呼叫端 `return err` 即整筆回滾。
//
// **本函式 SHALL NOT 包裝錯誤**：各呼叫點的包裝詞（「審計留痕失敗: %w」、
// 「寫入 LDAP seed 審計失敗: %w」…）各不相同且已被既有測試斷言，
// 包裝留在呼叫端才能讓收口前後的錯誤字串逐字相同。
func WriteInTx(sink TxSink, tx *gorm.DB, ev AuditEvent) error {
	if sink == nil {
		return ErrTxSinkMissing
	}
	return sink.WriteInTx(tx, ev)
}
