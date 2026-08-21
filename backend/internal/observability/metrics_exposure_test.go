package observability

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// 曝光路徑的兩條補測：高成本指標與採集頻率脫鉤、活躍會話數依協議分曝光。
//
// 兩者原本都只有結構性保證（用 Gauge 而非 GaugeFunc、SetActiveSessions 內含 Reset），
// 結構本身不會在被改壞時發聲；本檔即為那一刻的煞車。

// TestHighCostMetricsAreNotQueriedPerScrape
// spec Scenario「高成本指標不隨採集同步查詢」。
//
// 採集間隔由外部 Prometheus 的設定決定（可低至 15 秒），本系統無從約束。若這些指標
// 於採集當下同步查詢，採集端的一行設定就會被放大成本系統的 DB 查詢與檔案系統遍歷負載
// ——成本的控制權落在系統外部，這正是背景刷新設計存在的理由。
//
// 故此處斷言的不是「值正確」，而是「資料源呼叫次數與採集次數脫鉤」。
func TestHighCostMetricsAreNotQueriedPerScrape(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var mu sync.Mutex
	calls := map[string]int{}
	count := func(name string) {
		mu.Lock()
		calls[name]++
		mu.Unlock()
	}
	snapshot := func() map[string]int {
		mu.Lock()
		defer mu.Unlock()
		out := make(map[string]int, len(calls))
		for k, v := range calls {
			out[k] = v
		}
		return out
	}

	m := New()
	m.SetSealStateSource(func() (string, []string) { return "unsealed", []string{"unsealed"} })
	m.RegisterStage2()

	// interval 取一小時：ticker 在本測試期間不可能觸發，故啟動時的首刷是刷新路徑唯一的
	// 呼叫來源。呼叫次數若仍增長，剩下的唯一來源就是採集路徑本身
	stop := StartRefresher(m, RefreshSources{
		ActiveSessions: func() (map[string]float64, error) {
			count("sessions")
			return map[string]float64{"ssh": 2}, nil
		},
		RecordingStorage: func() (float64, error) {
			count("recording")
			return 4096, nil
		},
		PendingAlerts: func() (map[string]float64, error) {
			count("alerts")
			return map[string]float64{"high": 1}, nil
		},
	}, time.Hour)
	t.Cleanup(func() { _ = stop(context.Background()) })

	// —— 前置條件一：資料源確實會被背景刷新呼叫 ——
	// 少了這一步，一個從未被任何路徑呼叫的資料源當然不會隨採集增長，
	// 下方的「次數不變」就成了恆真式
	waitFor(t, 3*time.Second, "背景刷新未呼叫高成本資料源（本測試的脫鉤斷言將由假前提成立）",
		func() bool {
			c := snapshot()
			return c["sessions"] >= 1 && c["recording"] >= 1 && c["alerts"] >= 1
		})

	r := gin.New()
	r.GET(MetricsPath, m.Handler(""))

	// —— 前置條件二：刷新的值確實流進了採集端看得到的內容 ——
	// 若指標根本沒被曝光，「採集不觸發查詢」同樣是廢話
	first := scrape(t, r, "")
	require.Equal(t, http.StatusOK, first.Code)
	require.Contains(t, first.Body.String(), "custodexa_recording_storage_bytes 4096",
		"背景刷新的值未出現在曝光內容——本測試的「採集讀的是快取值」前提不成立")

	before := snapshot()

	const scrapes = 20
	for i := 0; i < scrapes; i++ {
		require.Equal(t, http.StatusOK, scrape(t, r, "").Code)
	}

	require.Equal(t, before, snapshot(),
		"連續 %d 次採集使高成本資料源被額外呼叫：採集頻率已直接放大為 DB 與檔案系統負載", scrapes)

	// 脫鉤不得以「查不到就不輸出」的方式達成——快取值在多次採集後仍須完好
	last := scrape(t, r, "").Body.String()
	require.Contains(t, last, "custodexa_recording_storage_bytes 4096")
	require.Contains(t, last, `custodexa_active_sessions{protocol="ssh"} 2`)
	require.Contains(t, last, `custodexa_command_alerts_pending{severity="high"} 1`)
}

// TestActiveSessionsExposedPerProtocol
// spec Requirement「營運指標最小集合」的「曝光內容 SHALL 至少涵蓋：活躍會話數（依協議分）」，
// 其歸零語義同 Scenario「告警全數審閱後歸零而非停在舊值」（同一個 Reset 形態）。
//
// 既有測試只在封印期的「不得曝光」清單裡點到這個指標名，沒有任何一處證明它在有會話時
// 真的帶 protocol 標籤出現。分協議是實質需求：文字終端與圖形協議的容量成本差一個數量級，
// 合併成單一總數答不出「是哪一類會話把容量吃掉了」。
func TestActiveSessionsExposedPerProtocol(t *testing.T) {
	m := New()
	m.SetSealStateSource(func() (string, []string) { return "unsealed", []string{"unsealed"} })
	m.RegisterStage2()

	m.SetActiveSessions(map[string]float64{"ssh": 3, "rdp": 2, "vnc": 1})

	body := gatherBody(t, m)
	for _, tc := range []struct{ protocol, value string }{
		{"ssh", "3"}, {"rdp", "2"}, {"vnc", "1"},
	} {
		require.Contains(t, body, `custodexa_active_sessions{protocol="`+tc.protocol+`"} `+tc.value,
			"協議 %s 未以獨立序列曝光其會話數", tc.protocol)
	}

	// —— 歸零：某協議的會話全數結束後，其序列須消失，不得停在舊值 ——
	// 上一段已證明三條序列確實存在，故此處的「消失」是真的消失，而非從未出現。
	// 停在舊值等於指標說謊：監控會持續看到早已結束的會話
	m.SetActiveSessions(map[string]float64{"ssh": 1})

	body = gatherBody(t, m)
	require.Contains(t, body, `custodexa_active_sessions{protocol="ssh"} 1`,
		"仍有會話的協議須更新為新值")
	require.NotContains(t, body, `custodexa_active_sessions{protocol="rdp"}`,
		"會話歸零的協議其序列須消失或為 0，不得停在 2")
	require.NotContains(t, body, `custodexa_active_sessions{protocol="vnc"}`,
		"會話歸零的協議其序列須消失或為 0，不得停在 1")
}
