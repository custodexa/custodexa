package sshproxy

import (
	"context"
	"log"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 指令審計降級的告警發射器（command-audit-altscreen-bypass design §6.3）。
//
// # 為什麼是專用路徑而不是一條規則
//
// 規則是可 CRUD 停用／刪除的營運物件——把規格要求的安全訊號掛上去，
// 等於交出「管理員一鍵靜默」的開關。降級告警因此不經規則表：它由本檔在
// 指令批次 flush **成功之後**發出，落地一律經 gatewayapi.AlertSink，
// 於是通知與 syslog 離機轉發自動接上（與阻斷路徑同一個落地面）。
//
// # 為什麼是 span 而不是逐列
//
// 真 vim 一次編輯會產生數十筆降級列（每一輪一筆）。逐列告警＝告警疲勞，
// 而疲勞的告警等於沒有告警。故以「一段連續的降級輪次」為單位，一個 span 一筆。
//
// # 為什麼**沒有**「超過門檻升級為 high」的第二筆
//
// design §6.3 原訂「span 開啟發 medium、超過門檻再發一筆 high」，門檻依實測填。
// 2026-08-19 真 WS 量測（9 條會話，正常側 vim／nano ×4、攻擊側 ×5）的結論是
// **兩者的 span 在時長、輪數、reason 組成上都落在同一個分佈裡**：
// 正常 vim 的降級列全部由佇列在結算那一刻一次發出（時間戳相同、輪數 4–13），
// 而只要令對端不再回顯，攻擊會話的降級列會**完全同形**（實測：時間戳相同、輪數 7，
// 且六條指令確實在目標主機執行）。
// 任何以時長或輪數畫的門檻都無法把兩者分開，填一個看起來能分的數值是**編造判準**。
// 據實改為較弱形式：**降級 span 本身即發一次告警**，不宣稱已區分日常與異常。

// degradeSpan 會話內「連續降級輪次」的聚合狀態。
//
// 只由 writeLoop 這一個 goroutine 讀寫（觀測點在 flush 內），故無鎖。
// span 跨批次存活：一次 vim 編輯的降級列可能分落多個批次，
// 逐批重新開 span 會讓「一個 span 一筆」退化成「一批一筆」。
type degradeSpan struct {
	// open 目前是否在一段連續降級中。開啟的那一刻即發出**該 span 唯一的一筆**告警，
	// 其後同一 span 內的降級列不再發。
	open bool
}

// observeDegraded 在批次入庫成功後更新 span 並在 span 開啟時發出告警。
//
// **順序在既有規則比對之後**：規則路徑的行為一個字都不變。
//
// 一筆非降級列即關閉 span：使用者又打出了可信重組的指令，代表這段降級結束了。
// 受限定的文字列（Degraded=false 且 DegradeReason 非空）同樣關閉 span——
// 它有文字、不是「無法還原」那一類（design §6.6：兩個值域刻意不合併）。
func (s *CommandStore) observeDegraded(batch []model.SessionCommand) {
	for i := range batch {
		if !batch[i].Degraded {
			s.span = degradeSpan{}
			continue
		}
		if s.span.open {
			continue
		}
		s.span.open = true
		s.emitDegradeAlert(batch[i])
	}
}

// emitDegradeAlert 發出一筆降級 span 告警。
//
// **Command 恆為空字串**：降級的定義就是沒有可信的指令文字，
// 告警列裡填任何推測出來的文字都是捏造（與降級紀錄本身同一條紀律）。
//
// 未注入落地面時 gatewayapi.RecordAlert 回 ErrAlertSinkMissing 並留下 log，
// **SHALL NOT 靜默 no-op**——靜默的後果是「告警系統看起來正常但一筆都沒發」。
func (s *CommandStore) emitDegradeAlert(row model.SessionCommand) {
	alert := gatewayapi.CommandAlert{
		Kind: model.AlertKindAuditDegraded,
		// RuleID 留 nil：本類告警沒有規則可指，DB CHECK 亦不允許它有
		RuleID: nil,
		// RuleName 填機器碼（同 alert_notifier 的 testRuleName 慣例）：
		// 本類無規則名可快照，而該欄 NOT NULL 且會進通知 payload。
		// 使用者可見文案由消費端依 kind／reason_code 對映，不取自本欄。
		RuleName:   model.AlertReasonDegradedSpan,
		ReasonCode: model.AlertReasonDegradedSpan,
		SessionID:  s.sessionID,
		Actor:      gatewayapi.Actor{UserID: s.userID},
		AssetID:    s.assetID,
		Command:    "",
		// medium 而非 high：降級同時是日常事件與異常訊號，本版本不宣稱已分離兩者。
		// 給 high 等於宣稱「這一定是攻擊」，而量測結論不支持那句話。
		Level: "medium",
		// 取該輪降級列的時刻，與指令流對齊（同 matcher 路徑取 cmd.ExecutedAt 的理由）
		OccurredAt:  row.ExecutedAt,
		Disposition: model.AlertDispositionPending,
		// Blocked 留 false：降級不阻斷任何東西
	}
	// ctx 取 Background：本函式在寫入 goroutine 上同步呼叫，沒有請求級 ctx 可承接；
	// 綁會話 ctx 會讓「會話正在結束」變成「最後一段降級的告警發不出去」，
	// 而會話在降級中結束**正是**最需要留痕的形態。
	if err := gatewayapi.RecordAlert(context.Background(), s.alerts, alert); err != nil {
		log.Printf("[SSHProxy] 指令審計降級告警落地失敗 (SessionID=%d): %v", s.sessionID, err)
	}
}
