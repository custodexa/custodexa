package observability

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// UnmatchedPath 未匹配任何路由時的固定路徑標籤值。
//
// **不可改為記錄實際 URL**：實際路徑由請求方任意指定，掃描器每打一個不存在的路徑
// 就會產生一條新的時間序列，是一條記憶體耗盡面；且會把請求方塞進來的任意字串
// 帶進指標名空間。以單一固定值歸集，序列數與掃描次數無關。
const UnmatchedPath = "<unmatched>"

// HTTPMiddleware 記錄請求計數與耗時分佈。
//
// 取代 `middleware.Metrics`。**掛載位置即原位置**——
// 全域中間件順序是契約（`cmd/server/main.go` 的 registerRoutes 說明），
// 且封印閘必須維持在最外層。
//
// 記錄恆進行，是否**曝光**由 registry 的分階段註冊決定：封印期
// 這些 collector 尚未註冊進 registry，故此期間的計數不出現在曝光內容中。
func (m *Metrics) HTTPMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		// 路由模板而非實際 URL：`/api/v1/assets/:id` 是一條序列，
		// `/api/v1/assets/1`…`/api/v1/assets/9999` 會是九千條
		path := c.FullPath()
		if path == "" {
			path = UnmatchedPath
		}

		method := c.Request.Method
		m.httpRequests.WithLabelValues(method, path, strconv.Itoa(c.Writer.Status())).Inc()
		m.httpDuration.WithLabelValues(method, path).Observe(time.Since(start).Seconds())
	}
}
