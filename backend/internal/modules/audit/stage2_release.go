package audit

import (
	"log"
	"sync"
)

// 段 2 服務圖的資源收束入口（盤點依據 internal/seal/RESOURCES.md）。
//
// **為何集中一檔**：這些函式的存在理由完全相同——段 2 是可重跑的
// （B 模式每次解封都重建一次完整圖），而現況的套件級單例、全域 hook 與
// 常駐明文材料都假設「一個行程只建構一次」。不清單例，舊持有者的物件會在
// 封印期間仍被 GORM 直寫路徑呼叫；不歸零材料，被丟棄的服務圖仍握著 KEK 衍生
// 明文。兩者都是要擋的「兩份服務圖同時持有資源」的實際形態。
//
// 兩個阻擋項（changeSecretScheduler 的 Stop 不等 in-flight、以及各 Stop() 的
// 冪等性）屬另一批工作的範圍，本檔不代辦；AlertNotifier 的停止路徑已於下方補上。
//
// **拆檔紀錄**：原檔 `:92-131` 的兩個 keyvault
// 型別方法（`(*KeyManagerService).ZeroizeForRelease`／`(*ExportSigningService).ZeroizeForRelease`）
// 已遷入 `internal/modules/keyvault/release.go`（Go 要求方法與型別同包）。
// 本檔保留的 4 個 audit 側釋放函式待後續一併處理。**釋放登記順序未變**——
// 拆檔只改宣告位置，組裝根的登記序逐位與
// `openspec/changes/archive/2026-08-11-modular-architecture/research/manifest-lifecycle.md`
//（隨公開快照出門的 lifecycle manifest）§7 相同。

// ResetAuditFailureSingleton 清除審計失效事件服務單例。
func ResetAuditFailureSingleton() {
	auditFailureMu.Lock()
	auditFailureInstance = nil
	auditFailureMu.Unlock()
}

// ResetAuditIntegritySingleton 清除審計完整性服務單例。
// 呼叫端 SHALL 於此之前先 model.SetAuditCreateHooks(nil, nil) 解除建立 hook，
// 否則 GORM 直寫路徑仍會打到已釋放的物件。
func ResetAuditIntegritySingleton() { registerAuditIntegrity(nil) }

// alertNotifierStopMu 使同一物件的收束序列化（兩條路徑可能同時抵達：
// 段 2 重試的 bag 釋放與行程收尾）。
var alertNotifierStopMu sync.Mutex

// StopAlertNotifierForRelease 收束一個推送器：解單例 → 歸零通道明文 → 停 worker。
//
// **順序是契約**：
//
//  1. 先解單例——Enqueue／NotifyEvent 的取用端一律走 GetAlertNotifier()，
//     解除後新的投遞不再落到本物件，故關閉佇列不會被後續 send 撞上。
//  2. 再歸零通道快取——URL 與 secret 是解密後的 KEK 衍生材料，段 2 每重試一次
//     就多留一份在被丟棄的圖上。
//  3. 最後關佇列使 worker 返回。
//
// **呼叫端 SHALL 先停排程器**：ResourceBag 以 LIFO 釋放，而 changeSecret／
// accessRequest 兩個排程器登記於本項之後，故必然先停——它們是唯二持有本物件
// 直接參考（不經單例）的路徑。此順序若被打破，in-flight 的 Enqueue 會對已關閉的
// 佇列 send 而 panic。
func StopAlertNotifierForRelease(n *AlertNotifier) {
	if n == nil {
		return
	}
	alertNotifierMu.Lock()
	if alertNotifierInstance == n {
		alertNotifierInstance = nil
	}
	alertNotifierMu.Unlock()

	n.mu.Lock()
	// 明文欄位逐一置空後整段丟棄：string 不可覆寫，能做的是不再持有參考，
	// 與 api.SealUnsealPayload.Zeroize 的誠實邊界同一條界線。
	for i := range n.channels {
		n.channels[i].URL = ""
		n.channels[i].Secret = ""
	}
	n.channels = nil
	n.mu.Unlock()

	alertNotifierStopMu.Lock()
	defer alertNotifierStopMu.Unlock()
	// **冪等以 recover 承載，而非以「已停止集合」承載**：後者要長期持有物件
	// 指標，等於讓每一代被丟棄的推送器都無法被 GC——為了冪等而製造記憶體洩漏，
	// 恰好是本項要修的那類問題。重複釋放是例外路徑，用例外處理是相稱的。
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[AlertNotifier] 推送佇列已處於關閉狀態（重複收束，已忽略）: %v", r)
		}
	}()
	close(n.queue)
}

// ResetAlertMatcherSingleton 清除告警比對器單例。
func ResetAlertMatcherSingleton() {
	alertMatcherMu.Lock()
	alertMatcherInstance = nil
	alertMatcherMu.Unlock()
}
