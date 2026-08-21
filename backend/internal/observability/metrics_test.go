package observability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

// 指標盤的值斷言與封印期縮減盤（observability-lite D2／D4／D8）。
//
// 以 testutil 做值斷言而非字串比對：字串比對會被 `# HELP` 文案的措辭變動打紅，
// 那是噪音而非訊號。

func TestAuditDroppedDistinguishesReason(t *testing.T) {
	m := New()
	m.RegisterStage2()

	m.ObserveAuditDropped(AuditDropReasonFallbackFile)
	m.ObserveAuditDropped(AuditDropReasonDiscarded)
	m.ObserveAuditDropped(AuditDropReasonDiscarded)

	require.Equal(t, 1.0, testutil.ToFloat64(
		m.auditDropped.WithLabelValues(AuditDropReasonFallbackFile)))
	// **兩個 reason 必須分開計數**：降級寫檔的資料仍可事後回收，直接丟棄則是
	// 永久遺失。合併計數會使「到底有沒有掉資料」答不出來，而那是本指標的唯一存在理由
	require.Equal(t, 2.0, testutil.ToFloat64(
		m.auditDropped.WithLabelValues(AuditDropReasonDiscarded)))
}

func TestPendingAlertsResetOnRefresh(t *testing.T) {
	m := New()
	m.RegisterStage2()

	m.SetPendingAlerts(map[string]float64{"high": 3, "low": 1})
	require.Equal(t, 3.0, testutil.ToFloat64(m.commandAlertsPending.WithLabelValues("high")))

	// 全數審閱完畢後的刷新：high 必須歸零／消失，不得停在 3——
	// 停在舊值會讓「已處理完」看起來像「還有一批沒人看」
	m.SetPendingAlerts(map[string]float64{"low": 1})
	require.Equal(t, 0.0, testutil.ToFloat64(m.commandAlertsPending.WithLabelValues("high")))
	require.Equal(t, 1.0, testutil.ToFloat64(m.commandAlertsPending.WithLabelValues("low")))
}

func TestSealStateExposesEveryStateAsEnum(t *testing.T) {
	m := New()
	all := []string{"sealed", "unsealing", "unsealed", "sealed-faulted"}
	m.SetSealStateSource(func() (string, []string) { return "unsealing", all })

	body := gatherBody(t, m)

	for _, state := range all {
		want := `custodexa_seal_state{state="` + state + `"} `
		require.Contains(t, body, want, "每個態都要有序列：%s", state)
	}
	require.Contains(t, body, `custodexa_seal_state{state="unsealing"} 1`,
		"目前所處的態應為 1")
	require.Contains(t, body, `custodexa_seal_state{state="sealed"} 0`,
		"非目前態應為 0")
}

// TestSealStateWithoutSourceExposesNothing 資料源未注入時不得輸出猜測值。
//
// 監控據封印指標判斷要不要派人去解封；猜錯的代價是實際封印中卻無人知曉。
func TestSealStateWithoutSourceExposesNothing(t *testing.T) {
	m := New()

	body := gatherBody(t, m)

	require.NotContains(t, body, "custodexa_seal_state{",
		"未注入資料源時不得曝光任何封印狀態序列")
}

// TestSealedPhaseExposesReducedSet 封印期縮減盤（D4）。
//
// 段 1 註冊完整路由樹（見 sealedStageOneDeps 說明），故封印期的請求解析得出
// 路由模板。若此時曝光 HTTP 指標，其 path 標籤即端點清單全集——等於在未解封
// 狀態下洩漏整份路由表，正是本 change 要消滅的形態。
//
// 段 2 服務的指標必須**缺席而非為 0**：0 值會讓採集端把「服務不存在」讀成
// 「服務正常且計數為零」，而缺值在 PromQL 中可由 absent() 明確偵測。
func TestSealedPhaseExposesReducedSet(t *testing.T) {
	m := New()
	m.SetSealStateSource(func() (string, []string) {
		return "sealed", []string{"sealed", "unsealed"}
	})
	// 刻意不呼叫 RegisterStage2——這正是封印期的狀態

	body := gatherBody(t, m)

	// 封印期應有的
	require.Contains(t, body, "custodexa_seal_state", "封印狀態須可採集")
	require.Contains(t, body, "go_goroutines", "行程執行期指標須可採集")

	// 封印期不該有的（逐項點名，避免「少了一個沒人發現」）
	for _, name := range []string{
		"custodexa_http_requests_total",
		"custodexa_http_request_duration_seconds",
		"custodexa_active_sessions",
		"custodexa_active_connections",
		"custodexa_audit_queue_depth",
		"custodexa_audit_dropped_total",
		"custodexa_recording_storage_bytes",
		"custodexa_command_alerts_pending",
	} {
		require.NotContains(t, body, name,
			"封印期不得曝光段 2 服務的指標：%s", name)
	}
}

func TestStage2ExposesFullSet(t *testing.T) {
	m := New()
	m.SetSealStateSource(func() (string, []string) { return "unsealed", []string{"unsealed"} })
	m.RegisterStage2()
	m.SetConnectionSource(func() float64 { return 7 })
	m.SetAuditQueueSource(func() float64 { return 3 })

	body := gatherBody(t, m)

	require.Contains(t, body, "custodexa_active_connections 7")
	require.Contains(t, body, "custodexa_audit_queue_depth 3")
}

// TestRegisterStage2IsIdempotent B 模式下每次解封都會走到 RegisterStage2；
// 重複註冊會使 MustRegister panic，整個行程隨之終止。
func TestRegisterStage2IsIdempotent(t *testing.T) {
	m := New()
	require.NotPanics(t, func() {
		m.RegisterStage2()
		m.RegisterStage2()
		m.RegisterStage2()
	})
}

// TestUnmatchedRouteDoesNotGrowSeries cardinality 守衛。
//
// 未匹配路由若以實際 URL 入標籤，掃描器每打一個不存在的路徑就多一條時間序列
// ——記憶體耗盡面，且把請求方塞來的任意字串帶進指標名空間。
func TestUnmatchedRouteDoesNotGrowSeries(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := New()
	m.RegisterStage2()

	r := gin.New()
	r.Use(m.HTTPMiddleware())
	r.GET("/api/v1/assets/:id", func(c *gin.Context) { c.Status(http.StatusOK) })

	for _, p := range []string{"/nope-1", "/nope-2", "/nope-3", "/totally/other/path"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		r.ServeHTTP(httptest.NewRecorder(), req)
	}
	// 同一路由模板的不同 ID 也只能是一條序列
	for _, p := range []string{"/api/v1/assets/1", "/api/v1/assets/2", "/api/v1/assets/999"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		r.ServeHTTP(httptest.NewRecorder(), req)
	}

	body := gatherBody(t, m)

	require.Equal(t, 1, strings.Count(body, `custodexa_http_requests_total{method="GET",path="`+UnmatchedPath+`"`),
		"四個不存在的路徑須歸入單一序列")
	require.NotContains(t, body, "/nope-1", "實際路徑不得進入指標標籤")
	require.NotContains(t, body, "/totally/other/path", "實際路徑不得進入指標標籤")
	require.Equal(t, 1, strings.Count(body, `path="/api/v1/assets/:id",status="200"`),
		"同一路由模板的不同 ID 須歸入單一序列")
	require.NotContains(t, body, `path="/api/v1/assets/999"`, "實際 ID 不得進入指標標籤")
}

// gatherBody 以真實曝光路徑取得內容，而非直接讀 collector。
//
// 走完整路徑才驗得到「有沒有被註冊進 registry」——那正是封印期縮減盤的機制所在。
func gatherBody(t *testing.T, m *Metrics) string {
	t.Helper()
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.GET(MetricsPath, m.Handler(""))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, MetricsPath, nil))
	require.Equal(t, http.StatusOK, w.Code)
	return w.Body.String()
}
