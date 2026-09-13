package observability

import (
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// 資料金鑰解封的四條序列。
//
// 本組唯一的非顯而易見之處是「未設定＝序列缺席」：0 在這個設定上剛好是最嚴格的
// 值（不留快取），用 0 表達「沒有設定」會讓採集端讀到語義相反的結論。

func dekMetricsRouter(t *testing.T, m *Metrics) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET(MetricsPath, m.Handler(""))
	return r
}

// TestDekCacheTTLSeriesAbsentWhenUnset 未設定的部署抓 /metrics 查無設定值序列，
// 而不是拿到一個 0。
func TestDekCacheTTLSeriesAbsentWhenUnset(t *testing.T) {
	m := New()
	m.RegisterDEKUnwrap()
	r := dekMetricsRouter(t, m)

	body := scrape(t, r, "").Body.String()
	require.NotContains(t, body, "custodexa_dek_cache_ttl_seconds",
		"未設定存活期卻曝光了設定值序列：0 在本鍵是「不留快取」，採集端會讀成語義相反的結論")

	// 對照：設定之後必須看得到，否則上面的 NotContains 可能只是因為根本沒註冊
	m.SetCacheTTL(300, true)
	body = scrape(t, r, "").Body.String()
	require.Contains(t, body, "custodexa_dek_cache_ttl_seconds 300")

	// 設 0 是一個真實的設定值，此時序列必須存在且為 0
	m.SetCacheTTL(0, true)
	body = scrape(t, r, "").Body.String()
	require.Contains(t, body, "custodexa_dek_cache_ttl_seconds 0")
}

// TestDekUnwrapSeriesExposeResultsAndInflight 成功／失敗（依原因分）、
// 延遲分佈與在途數都曝光。
func TestDekUnwrapSeriesExposeResultsAndInflight(t *testing.T) {
	m := New()
	m.RegisterDEKUnwrap()
	r := dekMetricsRouter(t, m)

	m.ObserveUnwrap("success", "", 12*time.Millisecond)
	m.ObserveUnwrap("failure", "unavailable", 5*time.Second)
	m.ObserveUnwrap("failure", "denied", 3*time.Millisecond)
	m.SetUnwrapInflight(2)

	res := scrape(t, r, "")
	require.Equal(t, http.StatusOK, res.Code)
	body := res.Body.String()
	require.Contains(t, body, `custodexa_dek_unwrap_total{reason="",result="success"} 1`)
	require.Contains(t, body, `custodexa_dek_unwrap_total{reason="unavailable",result="failure"} 1`)
	require.Contains(t, body, `custodexa_dek_unwrap_total{reason="denied",result="failure"} 1`,
		"失敗未依原因分：「保管處連不上」與「保管處拒絕」的處置對象完全不同")
	require.Contains(t, body, "custodexa_dek_unwrap_duration_seconds_count 3")
	require.Contains(t, body, "custodexa_dek_unwrap_inflight 2")
}

// TestDekUnwrapSeriesAbsentBeforeStage2 封印期未註冊即整組缺席，不以 0 冒充。
func TestDekUnwrapSeriesAbsentBeforeStage2(t *testing.T) {
	m := New()
	r := dekMetricsRouter(t, m)
	body := scrape(t, r, "").Body.String()
	require.NotContains(t, body, "custodexa_dek_unwrap_total")
	require.NotContains(t, body, "custodexa_dek_unwrap_inflight")
}

// TestRegisterDEKUnwrapIsIdempotent B 模式每次解封都會走到註冊點，
// 重複 MustRegister 會 panic 並終止行程。
func TestRegisterDEKUnwrapIsIdempotent(t *testing.T) {
	m := New()
	m.RegisterDEKUnwrap()
	require.NotPanics(t, func() { m.RegisterDEKUnwrap() })
}
