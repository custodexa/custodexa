package audit

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
)

// slackStub 本機替身：記下每個請求的本文與標頭，回應 {"ok":true}（slack_app 需要本文表明成功）。
type slackStub struct {
	mu      sync.Mutex
	bodies  [][]byte
	headers []http.Header
	got     chan struct{}
	url     string
}

func newSlackStub(t *testing.T) *slackStub {
	t.Helper()
	s := &slackStub{got: make(chan struct{}, 16)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.bodies = append(s.bodies, body)
		s.headers = append(s.headers, r.Header.Clone())
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
		select {
		case s.got <- struct{}{}:
		default:
		}
	}))
	t.Cleanup(srv.Close)
	s.url = srv.URL
	return s
}

func (s *slackStub) await(t *testing.T) ([]byte, http.Header) {
	t.Helper()
	select {
	case <-s.got:
	case <-time.After(3 * time.Second):
		t.Fatal("3 秒內替身沒有收到請求")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bodies[0], s.headers[0]
}

// withNotificationBaseURL 測試期間設定對外基準網址，結束後還原為未設定。
func withNotificationBaseURL(t *testing.T, raw string) {
	t.Helper()
	_ = SetNotificationBaseURL(raw)
	t.Cleanup(func() { _ = SetNotificationBaseURL("") })
}

// TestSlackBodiesDisableUnfurlAndCarryDate 以本機替身收下 slack 與 slack_app 各一則：
// 本文兩個自動抓取旗標為 false、文字含 Slack 日期語法與以「 UTC>」結尾的退回文字；
// 未設基準網址時文字不含連結語法或孤立標點。
func TestSlackBodiesDisableUnfurlAndCarryDate(t *testing.T) {
	withNotificationBaseURL(t, "")
	plain, app := newSlackStub(t), newSlackStub(t)
	n := newTestNotifier()
	n.setChannels([]model.NotificationChannel{
		{ID: 1, Name: "slack", Type: model.NotificationChannelTypeSlack, URL: plain.url, Enabled: true, Language: model.NotificationChannelLanguageZhTW},
		{ID: 2, Name: "slack-app", Type: model.NotificationChannelTypeSlackApp, URL: app.url, Secret: "xoxb-test-token", Target: "C0123ABCD", Enabled: true, Language: model.NotificationChannelLanguageEnUS},
	})
	n.NotifyEvent(notifycat.EventDailyReviewOverdue, map[string]string{
		"date": "2026-11-18", "pending_dates": "2026-11-18,2026-11-19", "pending_count": "2", "overdue_count": "1",
		"earliest_pending_date": "2026-11-18", "timezone": "Asia/Taipei",
	})

	for name, stub := range map[string]*slackStub{"slack": plain, "slack_app": app} {
		raw, hdr := stub.await(t)
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("%s 本文不是 JSON: %v", name, err)
		}
		if body["unfurl_links"] != false || body["unfurl_media"] != false {
			t.Errorf("%s 本文的自動抓取旗標不是 false: %s", name, raw)
		}
		text, _ := body["text"].(string)
		lines := strings.Split(text, "\n")
		last := lines[len(lines)-1]
		if !strings.Contains(last, "<!date^") || !strings.HasSuffix(last, " UTC>") {
			t.Errorf("%s 最後一行不是日期語法加 UTC 退回文字: %q", name, last)
		}
		for _, bad := range []string{"<http", "|>", " · \n", "· <", "()", "（）"} {
			if strings.Contains(text, bad) {
				t.Errorf("%s 未設基準網址時文字含 %q: %q", name, bad, text)
			}
		}
		if name == "slack_app" {
			if body["channel"] != "C0123ABCD" || hdr.Get("Authorization") != "Bearer xoxb-test-token" || hdr.Get(signatureHeaderKey) != "" {
				t.Errorf("slack_app 請求的目標或標頭不符: channel=%v has_auth=%v", body["channel"], hdr.Get("Authorization") != "")
			}
		} else if _, has := body["channel"]; has {
			t.Errorf("slack 型的本文不應帶 channel: %s", raw)
		}
	}
}

// TestSlackLinkUsesBaseURLWhenSet 設定基準網址後，系統事件的文字最後附上前往連結；連線申請族改用不含「詳見審核中心」的句型。
func TestSlackLinkUsesBaseURLWhenSet(t *testing.T) {
	withNotificationBaseURL(t, "https://bastion.example.com/sub/")
	stub := newSlackStub(t)
	n := newTestNotifier()
	n.setChannels([]model.NotificationChannel{
		{ID: 1, Name: "slack", Type: model.NotificationChannelTypeSlack, URL: stub.url, Enabled: true, Language: model.NotificationChannelLanguageZhTW},
	})
	n.NotifyEvent(notifycat.EventAccessRequestCreated, map[string]string{"request_id": "12", "asset_name": "db-1"})
	raw, _ := stub.await(t)
	var body slackBodyFields
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	text := body["text"]
	if !strings.Contains(text, "<https://bastion.example.com/sub/approvals?tab=pending&amp;request=12|前往處理>") {
		t.Fatalf("文字沒有附上前往連結: %q", text)
	}
	if strings.Contains(text, "詳見審核中心") {
		t.Fatalf("有連結時仍寫「詳見審核中心」: %q", text)
	}
	if !strings.Contains(text, " · 中風險") {
		t.Fatalf("第一行缺事件規格宣告的分級標籤: %q", text)
	}
}

// TestCommandAlertContextUsesSlackDate 指令告警的脈絡行時間改為 Slack 日期語法，有會話時連結指向會話頁。
func TestCommandAlertContextUsesSlackDate(t *testing.T) {
	withNotificationBaseURL(t, "https://h")
	text := buildSlackText("zh-TW", alertEventCommandAlert, sampleAlert(), alertSubjectNames{User: "alice"})
	if !strings.Contains(text, "<!date^") || strings.Contains(text, "2026-06-12T08:00:00Z") {
		t.Fatalf("脈絡行時間不是日期語法: %q", text)
	}
	if !strings.HasSuffix(text, " · <https://h/sessions/7|前往處理>") {
		t.Fatalf("脈絡行沒有以會話頁連結結尾: %q", text)
	}
}

// TestTestNotificationSlackText 測試通知的 Slack 文字：第一行表明是測試，帶通道名稱，沒有 #0、沒有虛構指令、不附連結。
func TestTestNotificationSlackText(t *testing.T) {
	withNotificationBaseURL(t, "https://h")
	ch := &model.NotificationChannel{Name: "ops-alerts", Type: model.NotificationChannelTypeSlack, Language: model.NotificationChannelLanguageZhTW}
	raw, err := buildChannelBody(ch, alertEventTest, model.CommandAlert{TriggeredAt: time.Now()}, alertSubjectNames{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var body slackBodyFields
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	text := body["text"]
	first := strings.SplitN(text, "\n", 2)[0]
	if !strings.Contains(first, "測試") || !strings.Contains(first, "不需處理") {
		t.Fatalf("測試通知第一行沒有表明是測試: %q", first)
	}
	for _, bad := range []string{"#0", "```", "<https://"} {
		if strings.Contains(text, bad) {
			t.Fatalf("測試通知文字含 %q: %q", bad, text)
		}
	}
	if !strings.Contains(text, "ops-alerts") {
		t.Fatalf("測試通知沒有帶通道名稱: %q", text)
	}
}

// TestNotificationBaseURLValidation 對外基準網址的驗證：不合格者視同未設定（文字不含連結）並記一行警告；可帶路徑前綴。
func TestNotificationBaseURLValidation(t *testing.T) {
	t.Cleanup(func() { _ = SetNotificationBaseURL("") })
	rejected := []string{
		"https://u:p@h", "https://h/?a=1", "https://h/#x", "https://h/a|b", "https://h/a>b", "https://h/a b",
		"https://h/a<b", "ftp://h", "https://", "https://h/\x01",
	}
	for _, raw := range rejected {
		var buf bytes.Buffer
		prev := log.Writer()
		log.SetOutput(&buf)
		err := SetNotificationBaseURL(raw)
		log.SetOutput(prev)
		if err == nil {
			t.Errorf("%q 應判為不合格", raw)
			continue
		}
		if n := strings.Count(buf.String(), "對外基準網址不合格"); n != 1 {
			t.Errorf("%q 的警告 log 次數 = %d，want 1（log=%q）", raw, n, buf.String())
		}
		if strings.Contains(buf.String(), "u:p") || strings.Contains(buf.String(), "a=1") {
			t.Errorf("警告 log 帶出了設定值: %q", buf.String())
		}
		alert := sampleAlert()
		alert.SessionID = 0
		text := buildSlackText("zh-TW", alertEventCommandAlert, alert, alertSubjectNames{})
		if strings.Contains(text, "<http") {
			t.Errorf("%q 不合格時渲染的 Slack 文字仍含連結: %q", raw, text)
		}
	}
	if err := SetNotificationBaseURL("https://h/sub/"); err != nil {
		t.Fatalf("帶路徑前綴的基準網址應合格: %v", err)
	}
	if got := composeNotificationLink("/alerts"); got != "https://h/sub/alerts" {
		t.Fatalf("連結 = %q，want https://h/sub/alerts", got)
	}
	if err := SetNotificationBaseURL(""); err != nil || composeNotificationLink("/alerts") != "" {
		t.Fatal("未設定時不應附連結")
	}
}
