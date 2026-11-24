package audit

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// pathRecorder 記錄收到的請求路徑並回固定本文的替身伺服器。
type pathRecorder struct {
	mu    sync.Mutex
	paths []string
	srv   *httptest.Server
}

func newPathRecorder(t *testing.T, status int, body string) *pathRecorder {
	t.Helper()
	r := &pathRecorder{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.ReadAll(req.Body)
		r.mu.Lock()
		r.paths = append(r.paths, req.URL.Path)
		r.mu.Unlock()
		if status >= 300 && status < 400 {
			w.Header().Set("Location", "http://127.0.0.1:1/elsewhere")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *pathRecorder) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.paths...)
}

// slack_app 保存 API 基底，送出時接上方法名；已保存完整方法網址的通道不重複接上。
func TestSlackAppMethodURL(t *testing.T) {
	cases := map[string]string{
		"https://slack.com/api":                    "https://slack.com/api/chat.postMessage",
		"https://slack.com/api/":                   "https://slack.com/api/chat.postMessage",
		"https://slack.com/api/chat.postMessage":   "https://slack.com/api/chat.postMessage",
		"https://slack.com/api/chat.postMessage/":  "https://slack.com/api/chat.postMessage/",
		"https://proxy.example.test/slack/api":     "https://proxy.example.test/slack/api/chat.postMessage",
		"https://proxy.example.test":               "https://proxy.example.test/chat.postMessage",
		"https://proxy.example.test/api?team=T001": "https://proxy.example.test/api/chat.postMessage?team=T001",
	}
	for saved, want := range cases {
		if got := slackMethodURL(saved, slackPostMessageMethod); got != want {
			t.Errorf("slackMethodURL(%q) = %q, want %q", saved, got, want)
		}
	}
	if d, _ := ChannelType(model.NotificationChannelTypeSlackApp); d.Fields.DefaultURL != "https://slack.com/api" {
		t.Fatalf("預設網址應為 API 基底，得 %q", d.Fields.DefaultURL)
	}
	// 實際送出：基底與完整方法網址都只打到一次 /chat.postMessage
	for _, suffix := range []string{"", "/chat.postMessage"} {
		rec := newPathRecorder(t, http.StatusOK, `{"ok":true}`)
		ch := &model.NotificationChannel{Type: model.NotificationChannelTypeSlackApp, URL: rec.srv.URL + suffix,
			Secret: testSlackToken, Target: "C1", Language: "zh-TW"}
		if status, err := deliverOnce(newNotificationHTTPClient(ch.Type, ch.URL, notifyHTTPTimeout, nil, nil), ch, []byte(`{}`)); err != nil || status != http.StatusOK {
			t.Fatalf("suffix %q: status=%d err=%v", suffix, status, err)
		}
		if got := rec.got(); len(got) != 1 || got[0] != "/chat.postMessage" {
			t.Fatalf("suffix %q: 路徑應為 /chat.postMessage，得 %v", suffix, got)
		}
	}
	// webhook 與 slack 照保存的網址送出，不接方法名
	rec := newPathRecorder(t, http.StatusOK, `ok`)
	ch := &model.NotificationChannel{Type: model.NotificationChannelTypeWebhook, URL: rec.srv.URL + "/hook/abc"}
	if _, err := deliverOnce(newNotificationHTTPClient(ch.Type, ch.URL, notifyHTTPTimeout, nil, nil), ch, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if got := rec.got(); len(got) != 1 || got[0] != "/hook/abc" {
		t.Fatalf("webhook 路徑應原樣，得 %v", got)
	}
}

// 平台錯誤以 ChannelPlatformError 回報（帶淨化後的錯誤碼）；3xx 只回狀態碼；連線失敗是一般錯誤。
func TestDeliverOncePlatformErrorKinds(t *testing.T) {
	send := func(url string) (int, error) {
		ch := &model.NotificationChannel{Type: model.NotificationChannelTypeSlackApp, URL: url, Secret: testSlackToken, Target: "C1"}
		return deliverOnce(newNotificationHTTPClient(ch.Type, ch.URL, notifyHTTPTimeout, nil, nil), ch, []byte(`{}`))
	}
	rec := newPathRecorder(t, http.StatusOK, `{"ok":false,"error":"channel_not_found"}`)
	status, err := send(rec.srv.URL)
	var pe *ChannelPlatformError
	if !errors.As(err, &pe) || pe.Code != "channel_not_found" || pe.Status != http.StatusOK || status != http.StatusOK {
		t.Fatalf("ok:false 應回平台錯誤 channel_not_found: status=%d err=%v", status, err)
	}
	if err.Error() != "platform error: channel_not_found" {
		t.Fatalf("錯誤文字應維持原格式（原因代碼的判讀依賴它）: %q", err.Error())
	}
	rec = newPathRecorder(t, http.StatusOK, `{"ok":false,"error":"Bad\nCode"}`)
	if _, err := send(rec.srv.URL); !errors.As(err, &pe) || pe.Code != platformErrorUnparseable {
		t.Fatalf("不合格的錯誤碼應淨化為 %s: %v", platformErrorUnparseable, err)
	}
	rec = newPathRecorder(t, http.StatusFound, `<html>moved</html>`)
	status, err = send(rec.srv.URL)
	if err != nil || status != http.StatusFound {
		t.Fatalf("3xx 應只回狀態碼、不當平台錯誤: status=%d err=%v", status, err)
	}
	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := closed.URL
	closed.Close()
	if _, err := send(closedURL); err == nil || errors.As(err, &pe) {
		t.Fatalf("連不上應是一般錯誤、不是平台錯誤: %v", err)
	}
}

// 系統安全告警明細的送達項帶原因代碼、已遮蔽的最近錯誤、終態原因與來源通道是否停用。
func TestSystemAlertDetailDeliveryReasonFields(t *testing.T) {
	e := newRulesEnv(t)
	srv := newStubSrv(t, e.clock, nil)
	enabled := e.channel("on", "webhook", srv.srv.URL, true, "low")
	disabled := e.channel("off", "webhook", srv.srv.URL, true, "low")
	if err := e.db.Model(&model.NotificationChannel{}).Where("id = ?", disabled.ID).Update("enabled", false).Error; err != nil {
		t.Fatal(err)
	}
	row := e.snapshotRow(enabled.ID, srv.srv.URL, 0, 0)
	// 同一則告警的第二個送達項：來源通道已停用、已放棄、最近錯誤含 token
	second := row
	second.ID = 0
	key, _ := newDeliveryKey()
	second.DeliveryKey = key
	chID := disabled.ID
	second.SourceChannelID = &chID
	second.State = model.NotificationDeliveryAbandoned
	second.EndReason = model.NotificationEndMaxAttempts
	second.LastError = "HTTP 404 from " + testSlackToken
	if err := e.db.Create(&second).Error; err != nil {
		t.Fatal(err)
	}
	view, err := NewSystemAlertCatalogService(e.db, NewTxSink()).Detail(*row.AlertID)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Deliveries) != 2 {
		t.Fatalf("應有兩個送達項，得 %d", len(view.Deliveries))
	}
	first, last := view.Deliveries[0], view.Deliveries[1]
	if first.ChannelDisabled || first.ReasonCode != "" || first.LastError != "" || first.EndReason != "" {
		t.Fatalf("未失敗、通道啟用中的送達項不應帶原因或停用: %+v", first)
	}
	if !last.ChannelDisabled {
		t.Fatalf("來源通道已停用應標示: %+v", last)
	}
	if last.EndReason != model.NotificationEndMaxAttempts || last.ReasonCode != DeliveryReasonOf(model.NotificationEndMaxAttempts, second.LastError) || last.ReasonCode == "" {
		t.Fatalf("終態原因與原因代碼不符: %+v", last)
	}
	if last.LastError == "" || last.LastError == second.LastError {
		t.Fatalf("最近錯誤應抹除 token: %q", last.LastError)
	}
	// 來源通道刪除後不再標示停用
	if err := e.db.Delete(&model.NotificationChannel{}, disabled.ID).Error; err != nil {
		t.Fatal(err)
	}
	view, err = NewSystemAlertCatalogService(e.db, NewTxSink()).Detail(*row.AlertID)
	if err != nil {
		t.Fatal(err)
	}
	if view.Deliveries[1].ChannelDisabled {
		t.Fatal("通道已刪除時不標示停用")
	}
}
