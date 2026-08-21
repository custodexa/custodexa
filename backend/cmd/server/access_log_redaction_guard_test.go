package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/config"
)

// access log 憑證遮蔽的**接線**守衛。
//
// internal/middleware 的單測證明遮蔽器本身正確；本測證明 production 的 engine
// 真的用了它。缺這一條時，任何人把 newEngine 改回 gin.Default() 都能讓憑證
// 重新逐字進 access log，而 middleware 那包測試依然全綠——正是守衛假綠的
// 典型形態（元件對了、接線斷了）。
//
// 斷言對象刻意是「newEngine 的產物跑一次真實請求後的輸出」，不是「main.go
// 的原始碼含某個字串」：前者換寫法也仍在守同一件事，後者一改寫法就形同虛設。
func TestNewEngineAccessLogMasksCredentials(t *testing.T) {
	const secret = "a4154a8bdeadbeefcafef00d1234567890abcdef"

	prevMode := gin.Mode()
	gin.SetMode(gin.TestMode)
	t.Cleanup(func() { gin.SetMode(prevMode) })

	// gin 的 logger 在建構當下就捕捉 gin.DefaultWriter，故必須先改寫再建 engine。
	var buf bytes.Buffer
	prevWriter := gin.DefaultWriter
	gin.DefaultWriter = &buf
	t.Cleanup(func() { gin.DefaultWriter = prevWriter })

	r, err := newEngine(&stage1{cfg: &config.Config{}}, false)
	if err != nil {
		t.Fatalf("newEngine 失敗: %v", err)
	}
	r.GET("/api/v1/recordings/stream", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/api/v1/recordings/stream?rtoken="+secret, nil)
	r.ServeHTTP(httptest.NewRecorder(), req)

	out := buf.String()
	if strings.Contains(out, secret) {
		t.Fatalf("newEngine 的 access log 印出了 rtoken 明文——取證通行證外洩到會被轉存的日誌面\naccess log: %s", out)
	}
	if !strings.Contains(out, "rtoken=***") {
		t.Errorf("access log 未見遮蔽後的 `rtoken=***`；遮蔽須遮值留鍵，運維仍要看得出有人打了這支端點\naccess log: %s", out)
	}
	if !strings.Contains(out, "/api/v1/recordings/stream") {
		t.Errorf("access log 遺失端點路徑——遮蔽只該遮憑證值，不是讓整條 URL 消失\naccess log: %s", out)
	}
}
