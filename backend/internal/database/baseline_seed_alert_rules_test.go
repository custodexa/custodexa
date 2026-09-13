package database

import "testing"

// 內建告警規則種子數的守衛（任務 5.5 的反向條件）。
//
// 拓撲變更的告警走 notifycat 事件目錄，**不動 alert_rules**：該表是危險指令的
// 正則規則（Pattern／Protocols 皆為指令語義），拓撲變更不是指令事件；塞進去會污染
// 規則表的語義，並使這個數字失去意義。本測試釘住「這次沒有人偷偷往那張表加東西」。
func TestSeedBuiltinAlertRulesCountUnchanged(t *testing.T) {
	if len(builtinAlertRules) != 12 {
		t.Fatalf("內建告警規則應為 12 條，得 %d——"+
			"拓撲變更告警走 notifycat 事件目錄，不得進 alert_rules", len(builtinAlertRules))
	}
}
