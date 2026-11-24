package audit

import (
	"testing"
)

// 段 2 資源收束的驗收。

// TestStopAlertNotifierForRelease 排入介面的收束：解單例、可重入。
//
// 缺此收束時，B 模式每重試一次解封，舊單例仍會被產生點取用、寫到已丟棄的圖。
func TestStopAlertNotifierForRelease(t *testing.T) {
	n := NewAlertNotifier(nil, nil)
	alertNotifierMu.Lock()
	alertNotifierInstance = n
	alertNotifierMu.Unlock()

	StopAlertNotifierForRelease(n)

	if got := GetAlertNotifier(); got != nil {
		t.Fatal("收束後單例仍指向已丟棄的排入介面——產生點會繼續寫到舊圖")
	}

	// 冪等：行程收尾與段 2 重試是兩條各自成立的路徑，重複收束不得 panic。
	StopAlertNotifierForRelease(n)
	StopAlertNotifierForRelease(nil)
}
