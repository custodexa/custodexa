package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
)

// Slack 應用程式型別：通道設定、目的地規則與送出。

const testSlackToken = "xoxb-1111-2222-abcdefSECRET"

// slackAppChannel 建一個 slack_app 通道（明文；codec 為 nil）。
func (e *ndlEnv) slackAppChannel(name, url, token, target string) model.NotificationChannel {
	e.t.Helper()
	ch := e.channel(name, model.NotificationChannelTypeSlackApp, url, true, "low")
	if err := e.db.Model(&model.NotificationChannel{}).Where("id = ?", ch.ID).
		Updates(map[string]any{"secret": token, "target": target}).Error; err != nil {
		e.t.Fatal(err)
	}
	ch.Secret, ch.Target = token, target
	return ch
}

func respondJSON(code int, body string) func(int, http.ResponseWriter, *http.Request) {
	return func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
	}
}

// ---- 7.1 型別描述與回應判讀 ----

func TestSlackAppRequestAndResponse(t *testing.T) {
	t.Run("(a) 請求帶授權標頭、不帶簽章、channel 等於目標", func(t *testing.T) {
		e := newNDLEnv(t)
		srv := newStubSrv(t, e.clock, respondJSON(200, `{"ok":true}`))
		ch := e.slackAppChannel("app", srv.srv.URL, testSlackToken, "C0123ABC")
		row := e.liveRow(ch.ID, model.AlertSeverityMedium, 0)
		e.w.RunOnce()
		if srv.count() != 1 {
			t.Fatalf("替身應收到 1 個請求，得 %d", srv.count())
		}
		h := srv.header(0)
		if h.Get("Authorization") != "Bearer "+testSlackToken {
			t.Fatalf("授權標頭不符: %q", h.Get("Authorization"))
		}
		if h.Get(signatureHeaderKey) != "" {
			t.Fatal("slack_app 不得附簽章標頭")
		}
		var body struct {
			Channel string `json:"channel"`
		}
		if err := json.Unmarshal(srv.body(0), &body); err != nil || body.Channel != "C0123ABC" {
			t.Fatalf("本文 channel 應為目標: %s", srv.body(0))
		}
		if r := e.row(row.ID); r.State != model.NotificationDeliveryDelivered {
			t.Fatalf("state = %s", r.State)
		}
	})

	t.Run("(b) ok:false 與非 2xx 都判失敗", func(t *testing.T) {
		e := newNDLEnv(t)
		notIn := newStubSrv(t, e.clock, respondJSON(200, `{"ok":false,"error":"not_in_channel"}`))
		down := newStubSrv(t, e.clock, respondJSON(500, `{"ok":true}`))
		a := e.slackAppChannel("a", notIn.srv.URL, testSlackToken, "C1")
		b := e.slackAppChannel("b", down.srv.URL, testSlackToken, "C2")
		ra := e.liveRow(a.ID, model.AlertSeverityMedium, 0)
		rb := e.liveRow(b.ID, model.AlertSeverityMedium, 0)
		e.w.RunOnce()
		got := e.row(ra.ID)
		if got.State != model.NotificationDeliveryRetrying || !strings.Contains(got.LastError, "not_in_channel") {
			t.Fatalf("ok:false 應重試且記錄錯誤碼: state=%s last_error=%q", got.State, got.LastError)
		}
		if g := e.row(rb.ID); g.State != model.NotificationDeliveryRetrying {
			t.Fatalf("HTTP 500 而 ok:true 也應判失敗: state=%s", g.State)
		}
	})

	t.Run("(c) 回應最多讀 64 KiB、錯誤碼淨化", func(t *testing.T) {
		long := strings.Repeat("x", 200)
		huge := `{"ok":false,"error":"bad\n\u001b[31m` + long + `","pad":"` + strings.Repeat("p", 1<<20) + `"}`
		counter := &countingReader{r: strings.NewReader(huge)}
		res := readSlackAppResult(&http.Response{StatusCode: 200, Body: io.NopCloser(counter), Header: http.Header{}})
		if counter.n > channelResponseReadLimit {
			t.Fatalf("讀取 %d 位元組，超過上限 %d", counter.n, channelResponseReadLimit)
		}
		if res.PlatformError != platformErrorUnparseable && len(res.PlatformError) > 64 {
			t.Fatalf("平台錯誤碼過長: %d", len(res.PlatformError))
		}
		// 經投遞程序：last_error 不含換行與跳脫序列。小於上限、可解析但錯誤碼不合格的回應也一樣。
		e := newNDLEnv(t)
		bad := `{"ok":false,"error":"bad\n\u001b[31m` + long + `"}`
		srv := newStubSrv(t, e.clock, respondJSON(200, bad))
		ch := e.slackAppChannel("c", srv.srv.URL, testSlackToken, "C3")
		row := e.liveRow(ch.ID, model.AlertSeverityMedium, 0)
		e.w.RunOnce()
		got := e.row(row.ID)
		if strings.ContainsAny(got.LastError, "\n\x1b") || !strings.Contains(got.LastError, platformErrorUnparseable) {
			t.Fatalf("last_error 未淨化: %q", got.LastError)
		}
	})

	t.Run("(d) 429 依 Retry-After 排下次", func(t *testing.T) {
		e := newNDLEnv(t)
		srv := newStubSrv(t, e.clock, func(_ int, w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"ok":false,"error":"ratelimited"}`)
		})
		ch := e.slackAppChannel("d", srv.srv.URL, testSlackToken, "C4")
		row := e.liveRow(ch.ID, model.AlertSeverityMedium, 0)
		start := e.clock.now()
		e.w.RunOnce()
		got := e.row(row.ID)
		if got.NextAttemptAt.Before(start.Add(30 * time.Second)) {
			t.Fatalf("next_attempt_at %v 早於 30 秒後", got.NextAttemptAt)
		}
	})
}

// tokenEchoTransport 把請求的授權標頭寫進錯誤文字的傳輸層替身。
type tokenEchoTransport struct{}

func (tokenEchoTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, errors.New("proxy refused request with " + r.Header.Get("Authorization"))
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// ---- 7.4 遮蔽 ----

func TestChannelTokenScrubbed(t *testing.T) {
	msg := "dial tcp: lookup x: token=" + testSlackToken + " and xoxb-other-9 trailing"
	if scrubbed := ScrubChannelTokens(msg, testSlackToken); strings.Contains(scrubbed, "xoxb-") || strings.Contains(scrubbed, "SECRET") {
		t.Fatalf("未抹除 token: %q", scrubbed)
	}
	if s := SanitizeChannelError(errors.New("Post \"https://slack.example/api?t="+testSlackToken+"\": EOF"), "https://slack.example/api", testSlackToken); strings.Contains(s, "xoxb-") {
		t.Fatalf("SanitizeChannelError 未抹除 token: %q", s)
	}

	// 經投遞程序：渲染錯誤夾帶 token 時，落庫錯誤、log、投遞紀錄回應都不含 token。
	e := newNDLEnv(t)
	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prev) })
	srv := newStubSrv(t, e.clock, respondJSON(200, `{"ok":true}`))
	ch := e.slackAppChannel("mask", srv.srv.URL, testSlackToken, "C9")
	row := e.liveRow(ch.ID, model.AlertSeverityMedium, 0)
	// 讓送出錯誤夾帶 token 字面：傳輸層回一個文字含 token 的錯誤（例如代理伺服器把授權標頭寫進錯誤訊息）
	e.w.transport = tokenEchoTransport{}
	e.w.RunOnce()
	got := e.row(row.ID)
	if got.LastError == "" {
		t.Fatal("應記錄失敗原因")
	}
	if strings.Contains(got.LastError, "xoxb-") {
		t.Fatalf("last_error 含 token: %q", got.LastError)
	}
	if strings.Contains(logs.String(), "xoxb-") {
		t.Fatal("log 含 token")
	}
	svc := newChannelSvc(t, e.db, nil)
	pg, err := svc.ListDeliveries(ch.ID, ChannelDeliveryQuery{Page: 1, PageSize: 20})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(pg.Rows)
	if strings.Contains(string(raw), "xoxb-") {
		t.Fatalf("投遞紀錄回應含 token: %s", raw)
	}
	// 直接把含 token 的錯誤寫進資料列（模擬升級前的殘值），回應同樣抹除
	e.db.Model(&model.NotificationDelivery{}).Where("id = ?", row.ID).Update("last_error", "platform error from "+testSlackToken)
	pg, _ = svc.ListDeliveries(ch.ID, ChannelDeliveryQuery{Page: 1, PageSize: 20})
	raw, _ = json.Marshal(pg.Rows)
	if strings.Contains(string(raw), "xoxb-") {
		t.Fatalf("投遞紀錄回應含 token: %s", raw)
	}
}

// ---- 8.1 新物件 ----

func TestWebhookNotificationObject(t *testing.T) {
	asset := uint(7)
	e := newNDLEnv(t)
	e.db.Exec(`INSERT INTO users (id, username) VALUES (3, 'alice')`)
	e.db.Exec(`INSERT INTO assets (id, name) VALUES (7, 'db-prod-01')`)
	// 400 是單筆失敗：兩則各自重送，同一紀錄的兩次請求可以比對投遞識別
	hook := newStubSrv(t, e.clock, respondStatus(400))
	e.channel("hook", "webhook", hook.srv.URL, true, "low")
	a := model.CommandAlert{RuleName: "r", Command: "ls", Severity: model.AlertSeverityHigh, SessionID: 31, UserID: 3, AssetID: &asset,
		TriggeredAt: e.clock.now(), Disposition: "pending", Kind: model.AlertKindRule}
	e.db.Create(&a)
	e.enqueueAlert(a)
	e.enqueueEvent(notifycat.EventAccessRequestApprovalProgress, map[string]string{"request_id": "12", "votes": "1", "required": "2"})
	e.w.RunOnce()
	e.clock.advance(10 * time.Second)
	e.w.RunOnce()
	if hook.count() < 4 {
		t.Fatalf("兩則通知各應送兩次，得 %d", hook.count())
	}
	type obj struct {
		Notification map[string]any `json:"notification"`
		Params       map[string]any `json:"params"`
	}
	ids := map[string][]string{}
	for i := 0; i < hook.count(); i++ {
		var o obj
		if err := json.Unmarshal(hook.body(i), &o); err != nil {
			t.Fatal(err)
		}
		n := o.Notification
		for _, k := range []string{"version", "category", "type", "severity", "occurred_at", "sent_at", "delivery_id", "params"} {
			if _, ok := n[k]; !ok {
				t.Fatalf("新物件缺 %s: %s", k, hook.body(i))
			}
		}
		for _, k := range []string{"occurred_at", "sent_at"} {
			if s, _ := n[k].(string); !strings.HasSuffix(s, "Z") {
				t.Fatalf("%s 應為 UTC（Z 結尾）: %v", k, n[k])
			}
		}
		if len(n["delivery_id"].(string)) != 32 {
			t.Fatalf("delivery_id 長度: %v", n["delivery_id"])
		}
		ids[n["category"].(string)] = append(ids[n["category"].(string)], n["delivery_id"].(string))
		if n["category"] == model.NotificationCategorySystemEvent {
			np := n["params"].(map[string]any)
			if _, isNum := np["votes"].(float64); !isNum {
				t.Fatalf("notification.params.votes 應為數字: %#v", np["votes"])
			}
			if _, isStr := o.Params["votes"].(string); !isStr {
				t.Fatalf("既有 params.votes 應維持字串: %#v", o.Params["votes"])
			}
		}
		if n["category"] == model.NotificationCategoryCommandAlert {
			actor := n["actor"].(map[string]any)
			target := n["target"].(map[string]any)
			if actor["name"] != "alice" || target["name"] != "db-prod-01" || target["id"] != "7" {
				t.Fatalf("指令告警的 actor／target 不符: %v %v", actor, target)
			}
		}
	}
	for cat, list := range ids {
		if len(list) < 2 || list[0] != list[1] {
			t.Fatalf("%s 同一紀錄兩次請求的 delivery_id 應相同: %v", cat, list)
		}
	}
}

// ---- 8.2 系統安全告警的降級 ----

func TestSystemAlertDegradedDelivery(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(e *ndlEnv, alertID uint)
	}{
		{"明細損毀", func(e *ndlEnv, id uint) {
			e.db.Model(&model.SystemAlertDetail{}).Where("alert_id = ?", id).Update("params", "{not json")
		}},
		{"類型未登錄", func(e *ndlEnv, id uint) {
			e.db.Model(&model.SystemAlertDetail{}).Where("alert_id = ?", id).Update("alert_type", "retired_alert_type")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newNDLEnv(t)
			hook := newStubSrv(t, e.clock, nil)
			slack := newStubSrv(t, e.clock, nil)
			ch := e.channel("c", "webhook", hook.srv.URL, true, "low")
			row := e.snapshotRow(ch.ID, hook.srv.URL, 0, 0)
			sch := e.channel("s", model.NotificationChannelTypeSlack, slack.srv.URL, true, "low")
			srow := e.snapshotRow(sch.ID, slack.srv.URL, 0, 0)
			e.db.Model(&model.NotificationDelivery{}).Where("id = ?", srow.ID).Update("dest_type", model.NotificationChannelTypeSlack)
			tc.mutate(e, *row.AlertID)
			tc.mutate(e, *srow.AlertID)
			e.w.RunOnce()
			if hook.count() != 1 || slack.count() != 1 {
				t.Fatalf("降級仍應送出: hook=%d slack=%d", hook.count(), slack.count())
			}
			var p struct {
				Event string `json:"event"`
				Alert struct {
					Params map[string]any `json:"params"`
				} `json:"alert"`
				Notification struct {
					Degraded bool `json:"degraded"`
				} `json:"notification"`
			}
			if err := json.Unmarshal(hook.body(0), &p); err != nil {
				t.Fatal(err)
			}
			if p.Event != systemAlertWebhookEvent || p.Alert.Params == nil || len(p.Alert.Params) != 0 || !p.Notification.Degraded {
				t.Fatalf("降級形狀不符: %s", hook.body(0))
			}
			if r := e.row(row.ID); r.State != model.NotificationDeliveryDelivered {
				t.Fatalf("state = %s", r.State)
			}
			if r := e.row(srow.ID); r.State != model.NotificationDeliveryDelivered {
				t.Fatalf("slack state = %s", r.State)
			}
		})
	}
}

// ---- 8.3 測試發送的形狀 ----

func TestSendTestNotificationShapes(t *testing.T) {
	e := newNDLEnv(t)
	hook := newStubSrv(t, e.clock, nil)
	ch := model.NotificationChannel{ID: 1, Name: "t", Type: "webhook", URL: hook.srv.URL, Language: "zh-TW"}
	var outboxBefore, msgBefore int64
	e.db.Model(&model.NotificationDelivery{}).Count(&outboxBefore)
	e.db.Model(&model.NotificationMessage{}).Count(&msgBefore)
	want := map[string][]string{
		"":                           {"alert", "event", "notification", "session"},
		TestShapeCommandAlert:        {"alert", "event", "notification", "session"},
		TestShapeSystemSecurityAlert: {"alert", "delivery_id", "event", "notification", "sent_at"},
		TestShapeSystemEvent:         {"event", "notification", "params", "sent_at"},
	}
	i := 0
	for _, shape := range []string{"", TestShapeCommandAlert, TestShapeSystemSecurityAlert, TestShapeSystemEvent} {
		if status, err := SendTestNotificationShape(&ch, shape); err != nil || status != 200 {
			t.Fatalf("shape %q: status=%d err=%v", shape, status, err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(hook.body(i), &m); err != nil {
			t.Fatal(err)
		}
		var keys []string
		for k := range m {
			keys = append(keys, k)
		}
		sortStrings(keys)
		if strings.Join(keys, ",") != strings.Join(want[shape], ",") {
			t.Fatalf("shape %q 頂層鍵 %v，應為 %v", shape, keys, want[shape])
		}
		var n struct {
			Notification struct {
				Category string `json:"category"`
			} `json:"notification"`
		}
		_ = json.Unmarshal(hook.body(i), &n)
		if n.Notification.Category != "test" {
			t.Fatalf("shape %q 新物件的 category 應為 test", shape)
		}
		i++
	}
	if _, err := SendTestNotificationShape(&ch, "bogus"); err == nil {
		t.Fatal("不支援的形狀應回錯")
	}
	var outboxAfter, msgAfter int64
	e.db.Model(&model.NotificationDelivery{}).Count(&outboxAfter)
	e.db.Model(&model.NotificationMessage{}).Count(&msgAfter)
	if outboxAfter != outboxBefore || msgAfter != msgBefore {
		t.Fatalf("測試發送不得建立紀錄: outbox %d→%d, messages %d→%d", outboxBefore, outboxAfter, msgBefore, msgAfter)
	}
	// Slack 兩型忽略 shape：送文字本文
	slack := newStubSrv(t, e.clock, nil)
	sch := model.NotificationChannel{Name: "s", Type: model.NotificationChannelTypeSlack, URL: slack.srv.URL, Language: "zh-TW"}
	if _, err := SendTestNotificationShape(&sch, TestShapeSystemEvent); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(slack.body(0)), `"text"`) || strings.Contains(string(slack.body(0)), `"notification"`) {
		t.Fatalf("Slack 型應忽略 shape: %s", slack.body(0))
	}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
