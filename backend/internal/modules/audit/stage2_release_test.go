package audit

import (
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 段 2 資源收束的驗收。

// TestStopAlertNotifierForRelease 推送器的收束：停 worker、清材料、解單例、可重入。
//
// 缺此收束時，B 模式每重試一次解封就多留一條持有解密後通道 URL／secret 的
// worker goroutine，且舊單例仍會被告警路徑取用——被丟棄的服務圖照樣在投遞。
func TestStopAlertNotifierForRelease(t *testing.T) {
	n := NewAlertNotifier(nil, nil)
	n.Start()
	// 快取一組帶明文的啟用通道（模擬 LoadChannels 之後的狀態）。
	n.setChannels([]model.NotificationChannel{
		{Name: "ops", Enabled: true, URL: "https://hooks.example/aaa", Secret: "s3cr3t"},
	})
	alertNotifierMu.Lock()
	alertNotifierInstance = n
	alertNotifierMu.Unlock()

	if len(n.snapshotChannels()) != 1 {
		t.Fatal("前提不成立：通道快取未載入")
	}

	StopAlertNotifierForRelease(n)

	if got := GetAlertNotifier(); got != nil {
		t.Fatal("收束後單例仍指向已丟棄的推送器——告警路徑會繼續投遞到舊圖")
	}
	if chs := n.snapshotChannels(); len(chs) != 0 {
		t.Fatalf("收束後仍快取 %d 條通道（含解密後的 URL／secret）", len(chs))
	}

	// worker 必須真的返回：佇列已關閉是可觀察的證據。
	select {
	case _, open := <-n.queue:
		if open {
			t.Fatal("收束後推送佇列仍開啟——worker goroutine 隨圖洩漏")
		}
	case <-time.After(time.Second):
		t.Fatal("收束後推送佇列既未關閉也無資料——worker 未停止")
	}

	// 冪等：行程收尾與段 2 重試是兩條各自成立的路徑，重複收束不得 panic。
	StopAlertNotifierForRelease(n)
	StopAlertNotifierForRelease(nil)
}

// TestStopAlertNotifierForReleaseHandlesNeverStarted 未啟動過的推送器同樣可收束。
func TestStopAlertNotifierForReleaseHandlesNeverStarted(t *testing.T) {
	n := NewAlertNotifier(nil, nil)
	StopAlertNotifierForRelease(n)
	if _, open := <-n.queue; open {
		t.Fatal("未啟動的推送器收束後佇列仍開啟")
	}
}
