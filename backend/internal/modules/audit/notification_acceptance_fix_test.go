package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
)

// 投遞層的四項行為：送達後仍保留最近失敗原因、轉址的原因代碼、網址未變不寫網址段、
// 錯誤文字只回遮蔽後的版本。

// P3：一筆紀錄失敗後才送達，通道列表的「最近失敗」仍帶原因與原因代碼，紀錄本身也看得出曾經失敗的原因。
func TestChannelHealthKeepsReasonAfterDelivery(t *testing.T) {
	e := newRulesEnv(t)
	srv := newStubSrv(t, e.clock, respondStatus(500))
	ch := e.channel("h", "webhook", srv.srv.URL+"/hook/x", true, "low")
	row := e.liveRow(ch.ID, model.AlertSeverityMedium, 0)
	e.w.RunOnce()
	if got := e.row(row.ID); got.State != model.NotificationDeliveryRetrying {
		t.Fatalf("第一次應失敗進入重送: %s", got.State)
	}
	srv.respond = respondStatus(200)
	e.clock.advance(time.Hour)
	e.w.RunOnce()
	got := e.row(row.ID)
	if got.State != model.NotificationDeliveryDelivered {
		t.Fatalf("第二次應送達: %s", got.State)
	}
	if !strings.Contains(got.LastError, "HTTP 500") || got.LastFailedAt == nil {
		t.Fatalf("送達後應保留最近一次失敗的時間與原因: last_error=%q last_failed_at=%v", got.LastError, got.LastFailedAt)
	}
	// 升級前送達時錯誤文字已被清空的列（有失敗時間、沒有原因）較新，也不得蓋掉有原因的那一筆
	legacy := e.liveRow(ch.ID, model.AlertSeverityMedium, 0)
	later := e.clock.now().Add(time.Minute)
	e.db.Model(&model.NotificationDelivery{}).Where("id = ?", legacy.ID).
		Updates(map[string]any{"state": model.NotificationDeliveryDelivered, "delivered_at": later, "last_failed_at": later, "last_error": ""})
	chs, err := e.svc.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range chs {
		if c.ID != ch.ID {
			continue
		}
		if c.Health == nil || c.Health.LastFailureReason != "HTTP 500" || c.Health.LastFailureCode != "http_5xx" {
			t.Fatalf("最近失敗應為 HTTP 500（不得是空原因）: %+v", c.Health)
		}
		return
	}
	t.Fatal("列表沒有這個通道")
}

// P9：錯誤文字的對外版本只留 HTTP 狀態碼與平台錯誤碼，連線錯誤的主機與位址一律不回。
func TestDisplayDeliveryError(t *testing.T) {
	cases := map[string]string{
		`Post "http://host.docker.internal:28080/hook": dial tcp 10.0.0.7:28080: connect: connection refused`: "",
		"HTTP 404": "HTTP 404",
		"HTTP 404 Not Found from hooks.example.test":    "HTTP 404",
		"HTTP 200, platform error: not_in_channel":      "HTTP 200, platform error: not_in_channel",
		"platform error: invalid_auth":                  "platform error: invalid_auth",
		"HTTP 3xx（不跟隨轉址）":                               "",
		"context deadline exceeded (Client.Timeout)":    "",
		"platform error from " + testSlackToken:         "",
		"HTTP 500 " + testSlackToken + " hooks.example": "HTTP 500",
	}
	for raw, want := range cases {
		if got := DisplayDeliveryError(raw); got != want {
			t.Errorf("DisplayDeliveryError(%q) = %q, want %q", raw, got, want)
		}
	}

	// 投遞紀錄與系統安全告警明細都回同一個版本
	e := newRulesEnv(t)
	srv := newStubSrv(t, e.clock, nil)
	ch := e.channel("d", "webhook", srv.srv.URL, true, "low")
	row := e.snapshotRow(ch.ID, srv.srv.URL, 0, 0)
	raw := `Post "http://host.docker.internal:28080/hook": dial tcp 10.0.0.7:28080: connect: connection refused`
	e.db.Model(&model.NotificationDelivery{}).Where("id = ?", row.ID).
		Updates(map[string]any{"state": model.NotificationDeliveryRetrying, "attempts": 1, "last_error": raw, "last_failed_at": e.clock.now()})
	pg, err := e.svc.ListDeliveries(ch.ID, ChannelDeliveryQuery{Page: 1, PageSize: 20})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(pg.Rows)
	if strings.Contains(string(body), "host.docker.internal") || strings.Contains(string(body), "10.0.0.7") {
		t.Fatalf("投遞紀錄不得含主機或位址: %s", body)
	}
	if pg.Rows[0].ReasonCode != "connect" {
		t.Fatalf("原因代碼應為 connect: %+v", pg.Rows[0])
	}
	view, err := NewSystemAlertCatalogService(e.db, NewTxSink()).Detail(*row.AlertID)
	if err != nil {
		t.Fatal(err)
	}
	if view.Deliveries[0].LastError != pg.Rows[0].LastError || view.Deliveries[0].ReasonCode != pg.Rows[0].ReasonCode {
		t.Fatalf("系統安全告警明細應與投遞紀錄一致: %+v vs %+v", view.Deliveries[0], pg.Rows[0])
	}
}

// P5：轉址規則擋下的錯誤對應到投遞紀錄的原因代碼；其他錯誤沒有原因代碼。
func TestChannelTestRedirectReason(t *testing.T) {
	wrap := func(err error) error { return &url.Error{Op: "Post", URL: "http://x/", Err: err} }
	if got := ChannelTestRedirectReason(wrap(errRedirectTooMany)); got != "redirect_too_many" {
		t.Fatalf("轉址次數過多: %q", got)
	}
	if got := ChannelTestRedirectReason(wrap(errRedirectPolicy)); got != "redirect_policy" {
		t.Fatalf("轉址不符傳輸政策: %q", got)
	}
	if got := ChannelTestRedirectReason(fmt.Errorf("dial: %w", errors.New("connection refused"))); got != "" {
		t.Fatalf("連線錯誤不應有轉址原因: %q", got)
	}
	if ChannelTestStatusReason(302) != "redirect_not_followed" || ChannelTestStatusReason(200) != "" || ChannelTestStatusReason(404) != "" {
		t.Fatal("3xx 才有不跟隨轉址的原因代碼")
	}
	for _, code := range []string{"redirect_too_many", "redirect_policy", "redirect_not_followed"} {
		found := false
		for _, c := range notifycat.DeliveryReasonCodes() {
			found = found || c == code
		}
		if !found {
			t.Fatalf("%s 應是投遞紀錄既有的原因代碼", code)
		}
	}
}

// P7／N1：只改網址以外的欄位時，webhook 參數照舊帶前後網址（鍵集合與升級前相同），Slack 文字略過網址段；改網址時兩者都有。
func TestChannelChangeNoticeURLOnlyWhenChanged(t *testing.T) {
	e := newRulesEnv(t)
	a := newStubSrv(t, nil, nil)
	b := newStubSrv(t, nil, nil)
	r := e.req("w")
	r.URL = a.srv.URL + "/hook/aaaa"
	created, err := e.svc.Create(r)
	if err != nil {
		t.Fatal(err)
	}
	lastChangeParams := func() map[string]string {
		var d model.SystemAlertDetail
		if err := e.db.Where("alert_type = ?", string(notifycat.EventSystemAlertNotificationChannelChanged)).Order("alert_id DESC").First(&d).Error; err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		_ = json.Unmarshal([]byte(d.Params), &out)
		return out
	}
	lang := "en-US"
	u := e.req("w")
	u.Language = &lang
	if _, err := e.svc.Update(created.ID, u); err != nil {
		t.Fatal(err)
	}
	p := lastChangeParams()
	if p["changed_fields"] != "language" {
		t.Fatalf("應只變更語系: %v", p)
	}
	// webhook 參數鍵集合與升級前相同：網址未變也照樣帶前後網址（兩者相同）
	keys := map[string]bool{}
	for k := range notifycat.WireParams(notifycat.EventSystemAlertNotificationChannelChanged, p) {
		keys[k] = true
	}
	// 升級前（本 change 之前）這一則的參數鍵：actor、change、changed_fields、url_before、url_after；
	// 本 change 只新增名稱參數 channel_name
	want := map[string]bool{"actor": true, "change": true, "changed_fields": true, "url_before": true, "url_after": true, "channel_name": true}
	for k := range want {
		if !keys[k] {
			t.Fatalf("webhook 參數應帶 %s（與升級前一致）: %v", k, keys)
		}
	}
	for k := range keys {
		if !want[k] {
			t.Fatalf("webhook 參數多了 %s: %v", k, keys)
		}
	}
	if p["url_before"] == "" || p["url_before"] != p["url_after"] {
		t.Fatalf("網址未變時前後網址相同: %v", p)
	}
	// Slack 文字在前後相同時略過網址段（三語）
	for _, lang := range notifycat.SupportedLangs {
		_, text := notifycat.Render(lang, notifycat.EventSystemAlertNotificationChannelChanged, p)
		if strings.Contains(text, "****aaaa") || strings.Contains(text, "→") {
			t.Fatalf("%s 網址未變時文字不得有網址段: %s", lang, text)
		}
	}
	u = e.req("w")
	u.URL = b.srv.URL + "/hook/bbbb"
	if _, err := e.svc.Update(created.ID, u); err != nil {
		t.Fatal(err)
	}
	p = lastChangeParams()
	if p["url_before"] == "" || p["url_after"] == "" || p["url_before"] == p["url_after"] {
		t.Fatalf("改網址應帶前後值: %v", p)
	}
	if _, text := notifycat.Render("zh-TW", notifycat.EventSystemAlertNotificationChannelChanged, p); !strings.Contains(text, "→") {
		t.Fatalf("改網址時文字應有網址段: %s", text)
	}
}
