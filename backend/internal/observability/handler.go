package observability

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricsPath 指標曝光端點的路徑。
//
// **刻意不在 `/api` 之下**：正式版 edge 只代理 `location /api` 與 `/ws`
// （`docker/frontend/nginx.conf`），故此端點在預設部署下自 edge 打不到——安全性
// 由拓撲保證，而非由「有沒有記得掛上認證中介層」這種每次改路由都可能失手的人為保證。
//
// 前身 `/api/v1/internal/metrics` 正是反例：它自稱「內部使用、無需認證」，
// 而 edge 整段代理 `/api` 使該前提在正式部署下不成立。
//
// 路徑值同時是 Prometheus 採集端 `metrics_path` 的預設值，設成別的等於要求
// 每個使用者改設定。
const MetricsPath = "/metrics"

// bearerPrefix Authorization 標頭的預期前綴。
const bearerPrefix = "Bearer "

// Handler 回傳指標曝光的 gin handler。
//
// token 為空字串時免認證曝光（同 Prometheus 生態與同類產品的形態，安全性由
// 「edge 不代理」承擔）；非空時強制比對。
func (m *Metrics) Handler(token string) gin.HandlerFunc {
	promHandler := promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})

	return func(c *gin.Context) {
		if token != "" && !bearerTokenMatches(c.GetHeader("Authorization"), token) {
			// **回應體不得含任何指標內容**：只設狀態碼而仍寫出指標，
			// 對取用方而言與 200 無異。
			//
			// 不區分「未帶 token」與「token 不正確」——區分等於告知探測者
			// 「格式對了、只差值」，同 auth-session 既有的不洩漏語義。
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		promHandler.ServeHTTP(c.Writer, c.Request)
	}
}

// bearerTokenMatches 以常數時間比對 Authorization 標頭。
//
// 常數時間是必要的：一般字串比較在首個相異位元組即返回，回應時間因此隨「猜對了
// 幾個字元」單調變化，可被逐位元組還原出整個 token。
func bearerTokenMatches(header, expected string) bool {
	if !strings.HasPrefix(header, bearerPrefix) {
		return false
	}
	got := strings.TrimPrefix(header, bearerPrefix)
	return subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}
