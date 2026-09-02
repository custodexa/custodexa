package dbconsole

import (
	"strings"
	"testing"
	"time"
)

// 事件 ID 的三條性質：固定 26 字元、字典序＝時間序、同毫秒內嚴格遞增。
//
// 第三條最容易在實作上漏掉，而它的失效形態沒有症狀——ID 仍然唯一、DB 仍然收，
// 只是同一次送出的多個批次在畫面與轉錄上排出隨機的先後順序。

func TestNewEventIDShape(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 2000; i++ {
		id, err := NewEventID()
		if err != nil {
			t.Fatalf("產生事件 ID 失敗: %v", err)
		}
		if len(id) != ULIDLength {
			t.Fatalf("長度 = %d, want %d（DB 的 CHECK 與匯出 URL 的解析都假設這個長度）", len(id), ULIDLength)
		}
		for _, r := range id {
			if !strings.ContainsRune(crockfordAlphabet, r) {
				t.Fatalf("字元 %q 不在 Crockford base32 字母表內：%s", r, id)
			}
		}
		if seen[id] {
			t.Fatalf("事件 ID 重複：%s——DB 的 partial unique 會把第二筆擋在門外", id)
		}
		seen[id] = true
	}
}

// TestEventIDMonotonicWithinSameMillisecond 同一毫秒內嚴格遞增。
//
// 直接餵同一個時戳，不靠「跑很快所以應該會落在同一毫秒」——後者在慢一點的機器上
// 會靜默退化成「每次都是新毫秒」，於是這條測試永遠不會驗到它要驗的東西。
func TestEventIDMonotonicWithinSameMillisecond(t *testing.T) {
	var s ulidState
	fixed := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)

	prev := ""
	for i := 0; i < 1000; i++ {
		id, err := s.next(fixed)
		if err != nil {
			t.Fatalf("第 %d 次產生失敗: %v", i, err)
		}
		if prev != "" && id <= prev {
			t.Fatalf("第 %d 個 ID %s 未大於前一個 %s：同毫秒的單調性失效，"+
				"同一次送出的多個批次會排出隨機的先後順序", i, id, prev)
		}
		if id[:10] != prev[:min(10, len(prev))] && prev != "" {
			t.Fatalf("同一毫秒的兩個 ID 時戳段不同：%s vs %s", prev, id)
		}
		prev = id
	}
}

// TestEventIDSortsByTime 字典序即時間序。
func TestEventIDSortsByTime(t *testing.T) {
	var s ulidState
	base := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)

	prev := ""
	for i := 0; i < 50; i++ {
		id, err := s.next(base.Add(time.Duration(i) * 7 * time.Millisecond))
		if err != nil {
			t.Fatalf("產生失敗: %v", err)
		}
		if prev != "" && id <= prev {
			t.Fatalf("較晚的 ID %s 未大於較早的 %s：稽核列按 ID 排序就不是執行順序", id, prev)
		}
		prev = id
	}
}

// TestEventIDClockRewindKeepsMonotonic 時戳回退（校時、閏秒）不破壞單調性。
func TestEventIDClockRewindKeepsMonotonic(t *testing.T) {
	var s ulidState
	base := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)

	first, err := s.next(base)
	if err != nil {
		t.Fatalf("產生失敗: %v", err)
	}
	second, err := s.next(base.Add(-5 * time.Second))
	if err != nil {
		t.Fatalf("產生失敗: %v", err)
	}
	if second <= first {
		t.Errorf("時戳回退後的 ID %s 未大於 %s：系統校時就會讓事件順序倒過來", second, first)
	}
}

// TestEntropyIncrementOverflow 亂數加一的溢位處理。
func TestEntropyIncrementOverflow(t *testing.T) {
	var e [10]byte
	for i := range e {
		e[i] = 0xFF
	}
	if incrementEntropy(&e) {
		t.Error("全 0xFF 加一應回報溢位")
	}

	e = [10]byte{}
	e[9] = 0xFF
	if !incrementEntropy(&e) {
		t.Fatal("非溢位的加一應回報成功")
	}
	if e[8] != 1 || e[9] != 0 {
		t.Errorf("進位錯誤：%v", e)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
