package audit

import (
	"github.com/custodexa/backend/internal/model"
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
func ResetAuditIntegritySingleton() {
	model.SetAgentToolCallStampHook(nil)
	registerAuditIntegrity(nil)
}

// StopAlertNotifierForRelease 收束一個排入介面：解除單例，之後的取用端（一律走 GetAlertNotifier()）
// 不再落到本物件。排入介面沒有常駐的 worker 或佇列；稽核失效退路的通道清單隨物件被回收。
func StopAlertNotifierForRelease(n *AlertNotifier) {
	if n == nil {
		return
	}
	alertNotifierMu.Lock()
	if alertNotifierInstance == n {
		alertNotifierInstance = nil
	}
	alertNotifierMu.Unlock()
}

// ResetAlertMatcherSingleton 清除告警比對器單例。
func ResetAlertMatcherSingleton() {
	alertMatcherMu.Lock()
	alertMatcherInstance = nil
	alertMatcherMu.Unlock()
}
