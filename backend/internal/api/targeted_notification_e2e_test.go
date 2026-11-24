package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/notifycat"
)

// 定向通知的端到端：真的收件人判定（授權模組）經投遞程序的對外埠登錄，配本機 Slack 替身（經 NOTIFY_DM_EXTRA_HOSTS
// 放行，不對外送出請求）。涵蓋以真的判定執行收件人與了結判定、私訊內容（不含事由、申請人以登入帳號呈現）、
// 傳給我自己的端點行為。

const e2eToken = "xoxb-5555-e2e-TOKEN"

type e2eSlackCall struct {
	method string
	email  string
	auth   string
	body   []byte
}

type e2eSlack struct {
	mu      sync.Mutex
	srv     *httptest.Server
	calls   []e2eSlackCall
	postErr string // 非空時個人訊息回 ok:false
}

func newE2ESlack(t *testing.T) *e2eSlack {
	t.Helper()
	s := &e2eSlack{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		method := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		c := e2eSlackCall{method: method, auth: r.Header.Get("Authorization"), body: body}
		if method == "users.lookupByEmail" {
			f, _ := url.ParseQuery(string(body))
			c.email = f.Get("email")
		}
		s.mu.Lock()
		s.calls = append(s.calls, c)
		postErr := s.postErr
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch method {
		case "users.lookupByEmail":
			_, _ = fmt.Fprintf(w, `{"ok":true,"user":{"id":"U%s","profile":{"display_name":"%s 的 Slack"}}}`,
				strings.ToUpper(strings.Split(c.email, "@")[0]), strings.Split(c.email, "@")[0])
		case "chat.postMessage":
			var b struct{ Channel string }
			_ = json.Unmarshal(body, &b)
			if postErr != "" && b.Channel != "C0E2E" {
				_, _ = fmt.Fprintf(w, `{"ok":false,"error":%q}`, postErr)
				return
			}
			_, _ = io.WriteString(w, `{"ok":true}`)
		}
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *e2eSlack) posts() []struct{ Channel, Text string } {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []struct{ Channel, Text string }
	for _, c := range s.calls {
		if c.method != "chat.postMessage" {
			continue
		}
		var b struct{ Channel, Text string }
		_ = json.Unmarshal(c.body, &b)
		out = append(out, b)
	}
	return out
}

func (s *e2eSlack) lookups() []e2eSlackCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []e2eSlackCall
	for _, c := range s.calls {
		if c.method == "users.lookupByEmail" {
			out = append(out, c)
		}
	}
	return out
}

type e2eEnv struct {
	*tnEnv
	slack   *e2eSlack
	worker  *audit.SystemAlertOutboxWorker
	notify  *audit.AlertNotifier
	channel model.NotificationChannel
}

func setupTargetedE2E(t *testing.T) *e2eEnv {
	t.Helper()
	e := setupTargetedEnv(t)
	if err := e.db.AutoMigrate(&model.NotificationMessage{}, &model.NotificationDelivery{}, &model.SystemAlertDetail{},
		&model.CommandAlert{}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NOTIFY_DM_EXTRA_HOSTS", "127.0.0.1")
	s := newE2ESlack(t)
	ch := model.NotificationChannel{Name: "dm-app", Type: model.NotificationChannelTypeSlackApp, URL: s.srv.URL, Secret: e2eToken,
		Target: "C0E2E", Enabled: true, Language: "zh-TW", MinSeverity: "low", DirectMessageEnabled: true}
	if err := e.db.Create(&ch).Error; err != nil {
		t.Fatal(err)
	}
	w := audit.NewSystemAlertOutboxWorker(e.db, nil)
	for ev, j := range e.svc.TargetedJudges() {
		if err := w.UseTargetedJudge(ev, j); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, ev := range []notifycat.Event{notifycat.EventAccessRequestCreated, notifycat.EventBreakGlassUsed, notifycat.EventBreakGlassReviewOverdue} {
			audit.RegisterDeliveryPrecheck(ev, nil)
		}
	})
	return &e2eEnv{tnEnv: e, slack: s, worker: w, notify: audit.NewAlertNotifier(e.db, nil), channel: ch}
}

// enqueue 以產生點相同的形狀排入（參數只帶單號與時長，名稱以識別碼參照交給分派解析）。
func (e *e2eEnv) enqueue(t *testing.T, event notifycat.Event, requestID uint, requester string, extra map[string]string) {
	t.Helper()
	params := map[string]string{"request_id": fmt.Sprint(requestID)}
	for k, v := range extra {
		params[k] = v
	}
	n := audit.SystemEventNotice(event, params)
	key := "requester_name"
	if event == notifycat.EventBreakGlassUsed {
		key = "username"
	}
	n.NameRefs = map[string]audit.NotificationNameRef{
		key:          {Kind: notifycat.IDKindUser, ID: e.ids[requester]},
		"asset_name": {Kind: notifycat.IDKindAsset, ID: e.assets["a1"]},
	}
	if err := e.notify.EnqueueStandalone(n); err != nil {
		t.Fatal(err)
	}
}

// drain 跑到沒有到期紀錄為止（個人訊息每秒上限約 0.83 則，以真實時鐘等待）。
func (e *e2eEnv) drain(t *testing.T, rounds int) {
	t.Helper()
	for i := 0; i < rounds; i++ {
		e.worker.RunOnce()
		var due int64
		e.db.Model(&model.NotificationDelivery{}).Where("state IN ?", []string{"pending", "retrying"}).Count(&due)
		if due == 0 {
			return
		}
		time.Sleep(1300 * time.Millisecond)
	}
}

func (e *e2eEnv) userRows(t *testing.T, requestMsg uint) map[string]model.NotificationDelivery {
	t.Helper()
	var rows []model.NotificationDelivery
	e.db.Where("audience = ? AND message_id = ?", "user", requestMsg).Find(&rows)
	out := map[string]model.NotificationDelivery{}
	for _, r := range rows {
		out[e.names[*r.RecipientUserID]] = r
	}
	return out
}

func (e *e2eEnv) lastMessageID(t *testing.T) uint {
	t.Helper()
	var m model.NotificationMessage
	e.db.Where("event_key <> ?", string(notifycat.EventTargetedNotificationUndelivered)).Order("id DESC").First(&m)
	return m.ID
}

func TestTargetedNotificationEndToEnd(t *testing.T) {
	e := setupTargetedE2E(t)
	// 申請人自設一段含網址的顯示名稱；事由含可辨識的字串
	evil := "http://evil.example/claim"
	if err := e.db.Model(&model.User{}).Where("id = ?", e.ids["requester"]).Update("local_display_name", evil).Error; err != nil {
		t.Fatal(err)
	}
	rid := e.request(t, "requester", "", map[string]model.AccessRequestStatus{"a1": model.AccessRequestPending}, e.now)
	e.db.Model(&model.AccessRequest{}).Where("id = ?", rid).Update("reason", "SECRET-REASON-XYZ")
	want, err := e.svc.TargetedAccessRequestRecipients(e.db, rid, time.Now())
	if err != nil || len(want) == 0 {
		t.Fatalf("前提：應有收件人: %v %v", want, err)
	}

	t.Run("3.5 私訊送給判定的收件人、第一行為定向標題、不含事由、申請人以登入帳號呈現", func(t *testing.T) {
		e.enqueue(t, notifycat.EventAccessRequestCreated, rid, "requester", map[string]string{"duration_minutes": "60"})
		e.drain(t, 20)
		dmTargets := map[string]bool{}
		var channelText string
		for _, p := range e.slack.posts() {
			if strings.Contains(p.Text, "SECRET-REASON") || strings.Contains(p.Text, "evil.example") {
				t.Fatalf("訊息不應含事由或顯示名稱: %q", p.Text)
			}
			if !strings.Contains(p.Text, "requester") {
				t.Fatalf("申請人應以登入帳號呈現: %q", p.Text)
			}
			if p.Channel == "C0E2E" {
				channelText = p.Text
				continue
			}
			dmTargets[p.Channel] = true
			if first := strings.SplitN(p.Text, "\n", 2)[0]; !strings.Contains(first, "待你審核 · ") {
				t.Fatalf("私訊第一行應為定向標題: %q", first)
			}
		}
		if channelText == "" || strings.Contains(strings.SplitN(channelText, "\n", 2)[0], "待你審核") {
			t.Fatalf("頻道訊息應照送且不帶定向標題: %q", channelText)
		}
		if len(dmTargets) != len(want) {
			t.Fatalf("私訊對象數 %d 應等於收件人數 %d", len(dmTargets), len(want))
		}
		for _, id := range want {
			if !dmTargets["U"+strings.ToUpper(e.names[id])] {
				t.Fatalf("收件人 %s 沒有收到私訊", e.names[id])
			}
		}
		for _, l := range e.slack.lookups() {
			if l.auth != "Bearer "+e2eToken {
				t.Fatalf("查詢應帶通道 token: %q", l.auth)
			}
		}
	})

	t.Run("3.3 (a) 收件人投完票其紀錄以 request_resolved 取消、其他人照送；單被核准後全部取消", func(t *testing.T) {
		rid2 := e.request(t, "requester", "", map[string]model.AccessRequestStatus{"a1": model.AccessRequestPending}, e.now)
		e.slack.mu.Lock()
		e.slack.postErr = "not_in_channel"
		e.slack.mu.Unlock()
		e.enqueue(t, notifycat.EventAccessRequestCreated, rid2, "requester", nil)
		msg2 := e.lastMessageID(t)
		e.drain(t, 1)
		e.vote(t, rid2, "a1", "asset")
		e.slack.mu.Lock()
		e.slack.postErr = ""
		e.slack.mu.Unlock()
		time.Sleep(1100 * time.Millisecond)
		e.drain(t, 20)
		rows := e.userRows(t, msg2)
		if r := rows["asset"]; r.State != model.NotificationDeliveryCanceled || r.EndReason != model.NotificationEndRequestResolved {
			t.Fatalf("投完票者應以 request_resolved 取消: state=%s end=%q", r.State, r.EndReason)
		}
		delivered := 0
		for name, r := range rows {
			if name != "asset" && r.State == model.NotificationDeliveryDelivered {
				delivered++
			}
		}
		if delivered == 0 {
			t.Fatalf("其他收件人應照送: %+v", rows)
		}

		rid3 := e.request(t, "requester", "", map[string]model.AccessRequestStatus{"a1": model.AccessRequestPending}, e.now)
		e.slack.mu.Lock()
		e.slack.postErr = "not_in_channel"
		e.slack.mu.Unlock()
		e.enqueue(t, notifycat.EventAccessRequestCreated, rid3, "requester", nil)
		msg3 := e.lastMessageID(t)
		e.drain(t, 1)
		e.db.Model(&model.AccessRequest{}).Where("id = ?", rid3).Update("status", model.AccessRequestApproved)
		e.db.Model(&model.AccessRequestItem{}).Where("request_id = ?", rid3).Update("status", model.AccessRequestApproved)
		e.slack.mu.Lock()
		e.slack.postErr = ""
		e.slack.mu.Unlock()
		time.Sleep(1100 * time.Millisecond)
		e.drain(t, 20)
		for name, r := range e.userRows(t, msg3) {
			if r.State == model.NotificationDeliveryDelivered {
				continue // 第一輪就送達的那一筆（失敗前已送出的不收回）
			}
			if r.State != model.NotificationDeliveryCanceled || r.EndReason != model.NotificationEndRequestResolved {
				t.Fatalf("%s: 單已核准後應以 request_resolved 取消: state=%s end=%q", name, r.State, r.EndReason)
			}
		}
	})

	t.Run("3.3 (d) 收件人帳號停用後其紀錄以 recipient_ineligible 取消", func(t *testing.T) {
		rid4 := e.request(t, "requester", "", map[string]model.AccessRequestStatus{"a1": model.AccessRequestPending}, e.now)
		e.slack.mu.Lock()
		e.slack.postErr = "not_in_channel"
		e.slack.mu.Unlock()
		e.enqueue(t, notifycat.EventAccessRequestCreated, rid4, "requester", nil)
		msg4 := e.lastMessageID(t)
		e.drain(t, 1)
		if err := e.db.Model(&model.User{}).Where("id = ?", e.ids["asset"]).Updates(map[string]any{"active": false, "credential_epoch": 1}).Error; err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { e.db.Model(&model.User{}).Where("id = ?", e.ids["asset"]).Update("active", true) })
		e.slack.mu.Lock()
		e.slack.postErr = ""
		e.slack.mu.Unlock()
		time.Sleep(1100 * time.Millisecond)
		e.drain(t, 20)
		r, ok := e.userRows(t, msg4)["asset"]
		if !ok {
			t.Fatal("前提：停用者原本應是收件人")
		}
		if r.State == model.NotificationDeliveryDelivered {
			t.Skip("第一輪已送達這一筆（失敗前已送出），無從觀察重驗")
		}
		if r.State != model.NotificationDeliveryCanceled || r.EndReason != model.NotificationEndRecipientIneligible {
			t.Fatalf("停用者應以 recipient_ineligible 取消: state=%s end=%q", r.State, r.EndReason)
		}
	})

	t.Run("3.3 (b) 破窗：臨時授權到期、補審仍待補審時照送；補審完成後取消", func(t *testing.T) {
		bg := e.breakGlass(t, "requester", "a1")
		past := time.Now().Add(-time.Minute)
		e.db.Model(&model.AssetAuthorization{}).Where("id IN (SELECT authorization_id FROM access_request_items WHERE request_id = ? AND authorization_id IS NOT NULL)", bg).
			Update("date_expired", past)
		e.enqueue(t, notifycat.EventBreakGlassUsed, bg, "requester", map[string]string{"duration_minutes": "30"})
		msg := e.lastMessageID(t)
		e.drain(t, 20)
		rows := e.userRows(t, msg)
		if len(rows) == 0 {
			t.Fatal("破窗應有個人紀錄")
		}
		for name, r := range rows {
			if r.State != model.NotificationDeliveryDelivered {
				t.Fatalf("%s: 臨時授權到期但仍待補審時應照送: %s %q", name, r.State, r.EndReason)
			}
		}
		// 補審完成後的逾期提醒：收件人為空且已不需處理，不建立個人紀錄
		if _, err := e.svc.Review(e.ids["asset"], false, bg, model.BreakGlassDispositionConfirmed, "ok"); err != nil {
			t.Fatalf("Review: %v", err)
		}
		e.enqueue(t, notifycat.EventBreakGlassReviewOverdue, bg, "requester", map[string]string{"timeout_hours": "24"})
		msg2 := e.lastMessageID(t)
		e.drain(t, 5)
		if n := len(e.userRows(t, msg2)); n != 0 {
			t.Fatalf("補審完成後不應有個人紀錄，得 %d", n)
		}
	})
}

// ---- 4.2 傳給我自己的端點 ----

func TestNotificationChannelTestToSelfEndpoint(t *testing.T) {
	e := setupTargetedE2E(t)
	h := NewNotificationChannelHandler(audit.NewNotificationChannelService(e.db, nil))
	call := func(t *testing.T, user string, chID uint, body string) (int, map[string]any) {
		t.Helper()
		r := gin.New()
		r.Use(func(c *gin.Context) { c.Set("userID", e.ids[user]); c.Set("username", user) })
		r.POST("/api/v1/notification-channels/:id/test", h.Test)
		r.GET("/api/v1/notification-channels/:id/deliveries", h.Deliveries)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/notification-channels/%d/test", chID), strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}

	t.Run("(d)(f) 本文另帶 email、recipient_user_id、slack_user_id、url 時只用請求者自己的電子郵件與已存網址；回應帶顯示名稱、不含電子郵件與識別碼", func(t *testing.T) {
		other := newE2ESlack(t)
		code, out := call(t, "asset", e.channel.ID, fmt.Sprintf(`{"to_self":true,"email":"victim@t.local","recipient_user_id":%d,"slack_user_id":"UVICTIM","url":%q}`,
			e.ids["voted"], other.srv.URL))
		if code != http.StatusOK || out["success"] != true || out["result"] != audit.SelfTestDelivered {
			t.Fatalf("status=%d body=%v", code, out)
		}
		if out["display_name"] != "asset 的 Slack" {
			t.Fatalf("應帶請求者本人的顯示名稱: %v", out)
		}
		raw, _ := json.Marshal(out)
		if strings.Contains(string(raw), "@") || strings.Contains(string(raw), "UASSET") {
			t.Fatalf("回應不應含電子郵件或識別碼: %s", raw)
		}
		ls := e.slack.lookups()
		if len(ls) != 1 || ls[0].email != "asset@t.local" {
			t.Fatalf("查詢應只含請求者自己的電子郵件: %+v", ls)
		}
		if len(other.calls) != 0 {
			t.Fatal("本文的網址不應收到請求")
		}
		code, out = call(t, "voted", e.channel.ID, `{"to_self":true}`)
		if code != http.StatusOK || out["result"] != audit.SelfTestDelivered {
			t.Fatalf("另一位使用者: %d %v", code, out)
		}
		if ls := e.slack.lookups(); ls[len(ls)-1].email != "voted@t.local" {
			t.Fatal("另一位使用者應用他自己的電子郵件")
		}
		var outbox int64
		e.db.Model(&model.NotificationDelivery{}).Count(&outbox)
		if outbox != 0 {
			t.Fatalf("不應建立待投遞紀錄，得 %d", outbox)
		}
	})

	t.Run("(c)(g) webhook 與 slack 型通道、網址不在允許清單時回 400 與可讀的錯誤碼", func(t *testing.T) {
		for _, typ := range []string{model.NotificationChannelTypeWebhook, model.NotificationChannelTypeSlack} {
			ch := model.NotificationChannel{Name: "x-" + typ, Type: typ, URL: e.slack.srv.URL, Enabled: true, Language: "zh-TW", MinSeverity: "low"}
			e.db.Create(&ch)
			code, out := call(t, "asset", ch.ID, `{"to_self":true}`)
			if code != http.StatusBadRequest || out["code"] != "VALIDATION_CHANNEL_DM_TYPE_UNSUPPORTED" {
				t.Fatalf("%s: %d %v", typ, code, out)
			}
		}
		before := len(e.slack.lookups())
		t.Setenv("NOTIFY_DM_EXTRA_HOSTS", "")
		code, out := call(t, "asset", e.channel.ID, `{"to_self":true}`)
		if code != http.StatusBadRequest || out["code"] != "VALIDATION_CHANNEL_DM_URL_NOT_ALLOWED" {
			t.Fatalf("網址不在清單內: %d %v", code, out)
		}
		if len(e.slack.lookups()) != before {
			t.Fatal("替身不應收到請求")
		}
	})

	t.Run("投遞紀錄的收件對象篩選值不合格回 400", func(t *testing.T) {
		r := gin.New()
		r.GET("/api/v1/notification-channels/:id/deliveries", h.Deliveries)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/notification-channels/%d/deliveries?audience=all", e.channel.ID), nil))
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "VALIDATION_DELIVERY_AUDIENCE") {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
	})
}

// TestTargetedDailyReviewJudgeVerdict 每日審閱的判定經對外埠包裝後，所列日子全部補簽、功能關閉時回「已了結」
// （投遞程序據此以 request_resolved 取消）；只有簽核權者回「不具資格」。
func TestTargetedDailyReviewJudgeVerdict(t *testing.T) {
	e := setupTargetedDailyReviewEnv(t)
	j := e.svc.TargetedJudge()
	sub := audit.TargetedSubject{Event: notifycat.EventDailyReviewOverdue, Params: tdrParams, Now: time.Now()}
	verdict := func(name string) audit.TargetedVerdict {
		v, err := j.Verdict(e.db, sub, e.ids[name])
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if v := verdict("custom"); v != audit.TargetedNeeded {
		t.Fatalf("前提：仍未簽時應照送，得 %v", v)
	}
	if v := verdict("signonly"); v != audit.TargetedIneligible {
		t.Fatalf("只有簽核權者應不具資格，得 %v", v)
	}
	now := time.Now()
	for _, d := range []string{"2026-10-08", "2026-10-09"} {
		log := model.DailyReviewLog{ReviewDate: d, ReviewerID: e.ids["custom"], ReviewerName: "custom", SnapshotJSON: "{}",
			SignedAt: now, Timezone: "Asia/Taipei", WindowStart: now, WindowEnd: now, DueAt: now,
			Coverage: model.DailyReviewCoverageFullDay, SourceStatus: model.DailyReviewSourceComplete, EnabledBasis: model.DailyReviewBasisRecorded}
		if err := e.db.Create(&log).Error; err != nil {
			t.Fatal(err)
		}
	}
	if v := verdict("custom"); v != audit.TargetedResolved {
		t.Fatalf("所列日子全部補簽後應為已了結，得 %v", v)
	}
	if aw, _ := j.Awaiting(e.db, sub); aw {
		t.Fatal("所列日子全部補簽後不應仍待處理")
	}

	e2 := setupTargetedDailyReviewEnv(t)
	if _, err := e2.pol.Update(policy.PolicyDailyReviewEnabled, "false", "admin"); err != nil {
		t.Fatal(err)
	}
	j2 := e2.svc.TargetedJudge()
	if v, err := j2.Verdict(e2.db, sub, e2.ids["custom"]); err != nil || v != audit.TargetedResolved {
		t.Fatalf("功能關閉時應為已了結，得 %v %v", v, err)
	}
}
