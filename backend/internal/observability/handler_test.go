package observability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// 指標端點的暴露面與保護。

func newMetricsRouter(t *testing.T, token string) (*gin.Engine, *Metrics) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	m := New()
	m.SetSealStateSource(func() (string, []string) {
		return "unsealed", []string{"sealed", "unsealed"}
	})
	m.RegisterStage2()

	r := gin.New()
	r.GET(MetricsPath, m.Handler(token))
	return r, m
}

func scrape(t *testing.T, r *gin.Engine, authHeader string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, MetricsPath, nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// TestMetricsPathIsNotUnderAPIPrefix 釘住「指標端點不在 `/api` 之下」這條結構保證。
//
// **這是本 change 的安全核心**：正式版 edge 只代理 `/api` 與 `/ws`，指標端點因此
// 預設自外部不可達。前身 `/api/v1/internal/metrics` 自稱「內部使用、無需認證」，
// 而它落在被代理的 `/api` 段內——該前提在正式部署下並不成立，未認證者可據此
// 列舉端點清單與各功能使用量。
//
// 若日後有人把本端點搬進 `/api/v1`，安全性就從「拓撲保證」退化為「記得掛認證」，
// 本測試即為那一刻的煞車。
func TestMetricsPathIsNotUnderAPIPrefix(t *testing.T) {
	require.False(t, strings.HasPrefix(MetricsPath, "/api"),
		"指標端點不得位於 /api 之下——edge 整段代理 /api，搬進去即等同對外開放")
	require.True(t, strings.HasPrefix(MetricsPath, "/"),
		"路徑須為絕對路徑")
}

func TestMetricsWithoutTokenIsOpen(t *testing.T) {
	r, _ := newMetricsRouter(t, "")

	w := scrape(t, r, "")

	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), "custodexa_seal_state",
		"未設 token 時應正常曝光指標")
}

// TestMetricsTokenEnforced token 已設時的三種請求形態。
//
// **回應體不含任何指標名是實質斷言**：只驗狀態碼會漏掉「回 401 但仍把指標寫進
// body」的形態，而對取用方而言那與 200 無異。
func TestMetricsTokenEnforced(t *testing.T) {
	const token = "s3cr3t-metrics-token"
	r, _ := newMetricsRouter(t, token)

	t.Run("正確 token 放行", func(t *testing.T) {
		w := scrape(t, r, "Bearer "+token)
		require.Equal(t, http.StatusOK, w.Code)
		require.Contains(t, w.Body.String(), "custodexa_seal_state")
	})

	for _, tc := range []struct {
		name   string
		header string
	}{
		{"未帶 token", ""},
		{"token 錯誤", "Bearer wrong-token"},
		{"缺 Bearer 前綴", token},
		{"前綴大小寫不符", "bearer " + token},
		{"空 Bearer", "Bearer "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := scrape(t, r, tc.header)
			require.Equal(t, http.StatusUnauthorized, w.Code)
			require.NotContains(t, w.Body.String(), "custodexa_",
				"401 回應體不得含任何指標內容")
			require.NotContains(t, w.Body.String(), "go_goroutines",
				"401 回應體不得含任何指標內容（含 runtime 指標）")
		})
	}
}

// TestUnauthorizedResponseDoesNotDistinguishFailureCause 401 不得洩漏失敗原因。
//
// 區分「未帶」與「帶錯」等於告訴探測者「格式對了、只差值」，
// 同 auth-session 既有的不洩漏語義。
func TestUnauthorizedResponseDoesNotDistinguishFailureCause(t *testing.T) {
	r, _ := newMetricsRouter(t, "real-token")

	missing := scrape(t, r, "")
	wrong := scrape(t, r, "Bearer not-the-token")

	require.Equal(t, missing.Code, wrong.Code)
	require.Equal(t, missing.Body.String(), wrong.Body.String(),
		"未帶 token 與 token 錯誤的回應不得可區分")
}
