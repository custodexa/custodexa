package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/gin-gonic/gin"
)

// 測試發送分辨平台錯誤（回 200 帶平台錯誤碼）、3xx（回 200 只帶狀態碼）與連不上（維持 502）。
func TestNotificationChannelTestReportsPlatformError(t *testing.T) {
	db := channelHandlerDB(t)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := NewNotificationChannelHandler(audit.NewNotificationChannelService(db, nil))
	r.POST("/api/v1/notification-channels/:id/test", h.Test)

	serve := func(status int, body string) string {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			_, _ = io.ReadAll(req.Body)
			if status >= 300 && status < 400 {
				w.Header().Set("Location", "http://127.0.0.1:1/elsewhere")
			}
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}))
		t.Cleanup(srv.Close)
		return srv.URL
	}
	create := func(url string) uint {
		ch := model.NotificationChannel{Name: "app-" + url, Type: model.NotificationChannelTypeSlackApp, URL: url,
			Secret: "xoxb-stored-token", Target: "C1", Enabled: true, Language: "zh-TW", MinSeverity: "low"}
		if err := db.Create(&ch).Error; err != nil {
			t.Fatal(err)
		}
		return ch.ID
	}
	call := func(id uint) (int, map[string]any, string) {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/notification-channels/"+itoa(id)+"/test", nil))
		var body map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		return w.Code, body, w.Body.String()
	}

	code, body, raw := call(create(serve(http.StatusOK, `{"ok":false,"error":"not_in_channel"}`)))
	if code != http.StatusOK || body["success"] != false || body["platform_error"] != "not_in_channel" || body["status_code"] != float64(200) {
		t.Fatalf("平台錯誤應回 200 帶錯誤碼: %d %s", code, raw)
	}
	if strings.Contains(raw, "xoxb-") {
		t.Fatalf("回應不得含 token: %s", raw)
	}

	code, body, raw = call(create(serve(http.StatusOK, `{"ok":false,"error":"Not A Code!"}`)))
	if code != http.StatusOK || body["platform_error"] != "unparseable_response" {
		t.Fatalf("不合格的錯誤碼應淨化: %d %s", code, raw)
	}

	code, body, raw = call(create(serve(http.StatusFound, ``)))
	if _, has := body["platform_error"]; code != http.StatusOK || body["success"] != false || body["status_code"] != float64(302) || has ||
		body["reason_code"] != "redirect_not_followed" {
		t.Fatalf("3xx 應回 200、只帶狀態碼: %d %s", code, raw)
	}

	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := closed.URL
	closed.Close()
	code, _, raw = call(create(closedURL))
	if code != http.StatusBadGateway || !strings.Contains(raw, "INTERNAL_CHANNEL_TEST_CONN_FAILED") {
		t.Fatalf("連不上應維持 502: %d %s", code, raw)
	}
}

// 測試發送遇轉址次數過多時回 200 並帶投遞紀錄的原因代碼，不回「無法連線」；不跟隨的 3xx 帶 redirect_not_followed。
func TestNotificationChannelTestRedirectReasons(t *testing.T) {
	db := channelHandlerDB(t)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := NewNotificationChannelHandler(audit.NewNotificationChannelService(db, nil))
	r.POST("/api/v1/notification-channels/:id/test", h.Test)
	var loop *httptest.Server
	loop = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.ReadAll(req.Body)
		http.Redirect(w, req, loop.URL+"/again", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(loop.Close)
	ch := model.NotificationChannel{Name: "loop", Type: model.NotificationChannelTypeWebhook, URL: loop.URL + "/hook",
		Enabled: true, Language: "zh-TW", MinSeverity: "low"}
	if err := db.Create(&ch).Error; err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/notification-channels/"+itoa(ch.ID)+"/test", nil))
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != http.StatusOK || body["success"] != false || body["reason_code"] != "redirect_too_many" {
		t.Fatalf("轉址次數過多應回 200 帶 redirect_too_many: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), loop.URL) {
		t.Fatalf("回應不得含網址: %s", w.Body.String())
	}
}

// 投遞紀錄的狀態篩選（值域外回 400 與機器碼）與未送達筆數。
func TestNotificationChannelDeliveriesStateFilter(t *testing.T) {
	db := channelHandlerDB(t)
	ch := model.NotificationChannel{Name: "w", Type: model.NotificationChannelTypeWebhook, URL: "https://hooks.example.test/x",
		Enabled: true, Language: "zh-TW", MinSeverity: "low"}
	if err := db.Create(&ch).Error; err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := NewNotificationChannelHandler(audit.NewNotificationChannelService(db, nil))
	r.GET("/api/v1/notification-channels/:id/deliveries", h.Deliveries)
	get := func(q string) (int, string) {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/notification-channels/"+itoa(ch.ID)+"/deliveries"+q, nil))
		return w.Code, w.Body.String()
	}
	for _, q := range []string{"?state=done", "?state=pending,bogus", "?state=pending,"} {
		code, raw := get(q)
		if code != http.StatusBadRequest || !strings.Contains(raw, "VALIDATION_DELIVERY_STATE") {
			t.Fatalf("%s 應回 400 VALIDATION_DELIVERY_STATE: %d %s", q, code, raw)
		}
	}
	code, raw := get("?state=pending,retrying&page=1&page_size=50")
	if code != http.StatusOK {
		t.Fatalf("合法篩選應回 200: %d %s", code, raw)
	}
	var body struct {
		Data          []map[string]any `json:"data"`
		Total         int64            `json:"total"`
		PendingCounts map[string]int64 `json:"pending_counts"`
	}
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatal(err)
	}
	if body.PendingCounts == nil {
		t.Fatalf("回應應帶 pending_counts: %s", raw)
	}
	if _, ok := body.PendingCounts["general"]; !ok {
		t.Fatalf("pending_counts 應有 general: %s", raw)
	}
	if _, ok := body.PendingCounts["system_security_alert"]; !ok {
		t.Fatalf("pending_counts 應有 system_security_alert: %s", raw)
	}
}
