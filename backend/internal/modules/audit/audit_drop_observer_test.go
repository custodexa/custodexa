package audit

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/model"
)

// 審計佇列滿載的可觀測性。
//
// **這條路徑原先唯一的痕跡是 log.Printf**——不可查詢、不可告警、容器重啟即失。
// `audit-failure-alerting` 的「審計機制失效事件記錄」條文其涵蓋範圍明文限定為
// 「audit 寫庫失敗（fallback 檔案觸發時）」，故佇列滿載直接丟棄的分支不記
// audit_failure_events，是條文的誠實邊界而非違規。本 change 不改該語義，
// 只使其可觀測。
//
// **測試必須證明注入確實發生**（「故障注入沒觸發」教訓）：若前置條件使程式
// 根本走不到滿載分支，觀測器零觸發，而斷言「計數為 0」會恆真通過。
// 故本測試先斷言「滿載前不觸發」，再斷言「滿載後觸發」——兩側都驗，
// 單側斷言證明不了因果。

// newSaturatedService 建一個佇列容量為 1 且**無 worker 消費**的審計服務。
//
// 不走 NewAuditLogService：它會起 worker，worker 會把列取走，滿載就再也構造不出來
// ——那正是「注入器從未觸發」的典型成因。容量取 1 而非 1000 是為了讓滿載可靠發生，
// 判定分支與生產同一條（`select` 的 default）。
func newSaturatedService(t *testing.T, fallbackToFile bool) *AuditLogService {
	t.Helper()
	return &AuditLogService{
		cfg: &config.FeatureFlags{
			// AuditLogEnabled 必須為真：`logAt` 開頭即以它早退。
			// 漏設會使兩次 Log 全部在入列前返回，滿載分支永不執行，
			// 而「觀測器未被呼叫」的斷言仍然通過——本測試的前置斷言
			// （滿載前深度為 1）正是為了讓這種零觸發現形
			AuditLogEnabled:     true,
			AsyncAuditEnabled:   true,
			AuditFallbackToFile: fallbackToFile,
		},
		logChan:     make(chan *model.AuditLog, 1),
		fallbackDir: t.TempDir(),
	}
}

type dropRecorder struct {
	mu    sync.Mutex
	calls []bool
}

func (r *dropRecorder) observe(fellBackToFile bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, fellBackToFile)
}

func (r *dropRecorder) snapshot() []bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]bool(nil), r.calls...)
}

func TestQueueSaturationNotifiesDropObserver(t *testing.T) {
	for _, tc := range []struct {
		name           string
		fallbackToFile bool
	}{
		{"檔案降級開啟：資料仍可事後回收", true},
		{"檔案降級關閉：資料永久遺失", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSaturatedService(t, tc.fallbackToFile)
			rec := &dropRecorder{}
			s.SetDropObserver(rec.observe)

			// 第一筆填滿容量 1 的佇列——**此時不得觸發**。
			// 缺了這個前置斷言，後面的「有觸發」可能只是觀測器被無條件呼叫
			s.Log(&AuditLogEntry{Username: "u1", Action: "login", Resource: "auth"})
			require.Empty(t, rec.snapshot(), "佇列未滿時不得通知丟棄觀測器")
			require.Equal(t, 1, s.QueueDepth(), "前置條件：佇列已滿（容量 1）")

			// 第二筆撞上 default 分支
			s.Log(&AuditLogEntry{Username: "u2", Action: "login", Resource: "auth"})

			calls := rec.snapshot()
			require.Len(t, calls, 1, "滿載後應恰好通知一次")
			require.Equal(t, tc.fallbackToFile, calls[0],
				"降級寫檔與直接丟棄必須可區分——前者資料仍在檔案內，後者永久遺失")
		})
	}
}

// TestQueueDepthReflectsPending 佇列深度指標的資料源。
func TestQueueDepthReflectsPending(t *testing.T) {
	s := newSaturatedService(t, false)

	require.Equal(t, 0, s.QueueDepth())
	s.Log(&AuditLogEntry{Username: "u", Action: "a", Resource: "r"})
	require.Equal(t, 1, s.QueueDepth())
}

// TestDropObserverAbsentIsSafe 未注入觀測器時不得 panic——
// 觀測是旁路，缺席不該讓審計路徑本身出事。
func TestDropObserverAbsentIsSafe(t *testing.T) {
	s := newSaturatedService(t, false)

	require.NotPanics(t, func() {
		s.Log(&AuditLogEntry{Username: "u1", Action: "a", Resource: "r"})
		s.Log(&AuditLogEntry{Username: "u2", Action: "a", Resource: "r"})
	})
}
