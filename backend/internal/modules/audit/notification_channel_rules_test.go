package audit

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
	"gorm.io/gorm"
)

// 通道服務的 token 與目的地規則、通道健康欄位、投遞放棄的通知。

type rulesEnv struct {
	*ndlEnv
	svc *NotificationChannelService
}

func newRulesEnv(t *testing.T) *rulesEnv {
	t.Helper()
	e := newNDLEnv(t)
	return &rulesEnv{ndlEnv: e, svc: newChannelSvc(t, e.db, nil)}
}

func (e *rulesEnv) req(name string) *NotificationChannelRequest {
	return &NotificationChannelRequest{Name: name, ActorID: 5, ActorName: "sec-admin", ActorIP: "10.1.1.1"}
}

func (e *rulesEnv) stored(id uint) model.NotificationChannel {
	e.t.Helper()
	var ch model.NotificationChannel
	if err := e.db.First(&ch, id).Error; err != nil {
		e.t.Fatal(err)
	}
	return ch
}

// deliverAll 以真實時鐘的投遞程序跑一輪（通道服務產生的紀錄以真實時鐘排定）。
func (e *rulesEnv) deliverAll() { fastWorker(e.db).RunOnce() }

// authorizedRequests 替身收到的帶授權標頭的請求數。
func authorizedRequests(s *stubSrv) int {
	n := 0
	for i := 0; i < s.count(); i++ {
		if s.header(i).Get("Authorization") != "" {
			n++
		}
	}
	return n
}

func (e *rulesEnv) createSlackApp(url, target string) model.NotificationChannel {
	e.t.Helper()
	r := e.req("app")
	r.Type, r.URL, r.Secret, r.Target = model.NotificationChannelTypeSlackApp, url, testSlackToken, target
	ch, err := e.svc.Create(r)
	if err != nil {
		e.t.Fatal(err)
	}
	return e.stored(ch.ID)
}

// ---- 7.2 token 只送往保存它時的網址、型別改變時秘密不沿用 ----

func TestChannelTokenStaysWithSavedURL(t *testing.T) {
	t.Run("(a) slack_app 改網址未帶 token 被拒、列不變、新網址收不到", func(t *testing.T) {
		e := newRulesEnv(t)
		a := newStubSrv(t, nil, respondJSON(200, `{"ok":true}`))
		b := newStubSrv(t, nil, respondJSON(200, `{"ok":true}`))
		ch := e.createSlackApp(a.srv.URL, "C1")
		r := e.req("app")
		r.URL = b.srv.URL
		if _, err := e.svc.Update(ch.ID, r); !errors.Is(err, ErrChannelURLChangeNeedsSecret) {
			t.Fatalf("err = %v, want ErrChannelURLChangeNeedsSecret", err)
		}
		if got := e.stored(ch.ID); !reflect.DeepEqual(got, ch) {
			t.Fatalf("通道列不應改變:\n%+v\n%+v", ch, got)
		}
		e.deliverAll()
		if b.count() != 0 {
			t.Fatalf("新網址不應收到請求，得 %d", b.count())
		}
		// 同一網址重存不算改網址；清除 token 被拒
		r = e.req("app")
		r.URL = a.srv.URL
		if _, err := e.svc.Update(ch.ID, r); err != nil {
			t.Fatalf("同網址重存應成功: %v", err)
		}
		r = e.req("app")
		r.ClearSecret = true
		if _, err := e.svc.Update(ch.ID, r); !errors.Is(err, ErrChannelSecretRequired) {
			t.Fatalf("清除 token 應被拒: %v", err)
		}
	})

	t.Run("(b)(c) webhook 改 slack_app：網址必填、token 必填", func(t *testing.T) {
		e := newRulesEnv(t)
		hook := newStubSrv(t, nil, nil)
		b := newStubSrv(t, nil, respondJSON(200, `{"ok":true}`))
		r := e.req("w")
		r.URL, r.Secret = hook.srv.URL, "sig-key"
		created, err := e.svc.Create(r)
		if err != nil {
			t.Fatal(err)
		}
		e.deliverAll()
		before := e.stored(created.ID)
		hookSeen := hook.count()

		r = e.req("w")
		r.Type, r.Secret, r.Target = model.NotificationChannelTypeSlackApp, testSlackToken, "C1"
		if _, err := e.svc.Update(created.ID, r); !errors.Is(err, ErrChannelTypeChangeNeedsURL) {
			t.Fatalf("err = %v, want ErrChannelTypeChangeNeedsURL", err)
		}
		if got := e.stored(created.ID); !reflect.DeepEqual(got, before) {
			t.Fatalf("通道列不應改變")
		}
		e.deliverAll()
		if hook.count() != hookSeen || authorizedRequests(hook) != 0 {
			t.Fatalf("原 webhook 替身不應收到新請求（含 token）: %d→%d", hookSeen, hook.count())
		}

		// (c) 不帶 token
		r = e.req("w")
		r.Type, r.URL, r.Target = model.NotificationChannelTypeSlackApp, b.srv.URL, "C1"
		if _, err := e.svc.Update(created.ID, r); !errors.Is(err, ErrChannelSecretRequired) {
			t.Fatalf("err = %v, want ErrChannelSecretRequired", err)
		}

		// 補上網址與 token 後成功
		r = e.req("w")
		r.Type, r.URL, r.Secret, r.Target = model.NotificationChannelTypeSlackApp, b.srv.URL, testSlackToken, "C1"
		if _, err := e.svc.Update(created.ID, r); err != nil {
			t.Fatalf("補上網址後應成功: %v", err)
		}
		got := e.stored(created.ID)
		if got.Type != model.NotificationChannelTypeSlackApp || got.Secret != testSlackToken || got.Target != "C1" {
			t.Fatalf("更新後的列不符: %+v", got)
		}
	})

	t.Run("(d) slack_app 改 webhook 不帶密鑰：秘密清除、送出不簽章", func(t *testing.T) {
		e := newRulesEnv(t)
		a := newStubSrv(t, nil, respondJSON(200, `{"ok":true}`))
		hook := newStubSrv(t, nil, nil)
		ch := e.createSlackApp(a.srv.URL, "C1")
		r := e.req("app")
		r.Type, r.URL = "webhook", hook.srv.URL
		if _, err := e.svc.Update(ch.ID, r); err != nil {
			t.Fatal(err)
		}
		got := e.stored(ch.ID)
		if got.Secret != "" || got.Target != "" {
			t.Fatalf("型別改變後秘密與目標應清除: secret=%q target=%q", got.Secret, got.Target)
		}
		e.deliverAll()
		e.liveRow(ch.ID, model.AlertSeverityMedium, 0)
		before := hook.count()
		e.deliverAll()
		if hook.count() <= before {
			t.Fatal("webhook 替身應收到通知")
		}
		for i := 0; i < hook.count(); i++ {
			if hook.header(i).Get(signatureHeaderKey) != "" || hook.header(i).Get("Authorization") != "" {
				t.Fatalf("不應有簽章或授權標頭: %v", hook.header(i))
			}
		}
	})

	t.Run("(e) 只改目標頻道：之後的請求帶原 token", func(t *testing.T) {
		e := newRulesEnv(t)
		a := newStubSrv(t, nil, respondJSON(200, `{"ok":true}`))
		ch := e.createSlackApp(a.srv.URL, "C1")
		r := e.req("app")
		r.Target = "C2"
		if _, err := e.svc.Update(ch.ID, r); err != nil {
			t.Fatal(err)
		}
		e.liveRow(ch.ID, model.AlertSeverityMedium, 0)
		// 同一目的地每秒 1 則：通道變更通知與這則一般通知可能分在不同輪
		found := false
		for round := 0; round < 4 && !found; round++ {
			if round > 0 {
				time.Sleep(1100 * time.Millisecond)
			}
			e.deliverAll()
			for i := 0; i < a.count(); i++ {
				var body struct {
					Channel string `json:"channel"`
					Text    string `json:"text"`
				}
				_ = json.Unmarshal(a.body(i), &body)
				if body.Channel == "C2" && !strings.Contains(body.Text, "通知通道已變更") {
					if a.header(i).Get("Authorization") != "Bearer "+testSlackToken {
						t.Fatalf("應以原 token 送往新頻道: %v", a.header(i))
					}
					found = true
				}
			}
		}
		if !found {
			t.Fatal("新頻道沒有收到一般通知")
		}
	})

	t.Run("建立 slack_app：token 與目標必填、格式驗證", func(t *testing.T) {
		e := newRulesEnv(t)
		r := e.req("x")
		r.Type, r.Target = model.NotificationChannelTypeSlackApp, "C1"
		if _, err := e.svc.Create(r); !errors.Is(err, ErrChannelSecretRequired) {
			t.Fatalf("缺 token: %v", err)
		}
		r.Secret = "xoxp-user-token"
		if _, err := e.svc.Create(r); !errors.Is(err, ErrInvalidChannelSecret) {
			t.Fatalf("token 格式: %v", err)
		}
		r.Secret, r.Target = testSlackToken, "C-1"
		if _, err := e.svc.Create(r); !errors.Is(err, ErrInvalidChannelTarget) {
			t.Fatalf("目標格式: %v", err)
		}
		r.Target = "C1"
		ch, err := e.svc.Create(r)
		if err != nil {
			t.Fatal(err)
		}
		if got := e.stored(ch.ID); got.URL != slackDefaultAPIURL {
			t.Fatalf("未填網址時應帶入預設的 Slack API 位址: %q", got.URL)
		}
	})
}

// ---- 7.3 目的地變更時間與版本 ----

func TestChannelDestinationVersion(t *testing.T) {
	t.Run("只改名稱不動、改目標加一", func(t *testing.T) {
		e := newRulesEnv(t)
		a := newStubSrv(t, nil, respondJSON(200, `{"ok":true}`))
		ch := e.createSlackApp(a.srv.URL, "C1")
		if ch.DestinationChangedAt != nil || ch.DestinationVersion != 0 {
			t.Fatalf("建立時 changed_at=%v version=%d", ch.DestinationChangedAt, ch.DestinationVersion)
		}
		r := e.req("renamed")
		if _, err := e.svc.Update(ch.ID, r); err != nil {
			t.Fatal(err)
		}
		if got := e.stored(ch.ID); got.DestinationChangedAt != nil || got.DestinationVersion != 0 {
			t.Fatalf("只改名稱不應變更: %v %d", got.DestinationChangedAt, got.DestinationVersion)
		}
		e.deliverAll()
		seen := a.count()
		r = e.req("renamed")
		r.Target = "C2"
		if _, err := e.svc.Update(ch.ID, r); err != nil {
			t.Fatal(err)
		}
		got := e.stored(ch.ID)
		if got.DestinationChangedAt == nil || got.DestinationVersion != 1 {
			t.Fatalf("改目標應更新: %v %d", got.DestinationChangedAt, got.DestinationVersion)
		}
		// 新舊兩個頻道各收到一則通道變更通知，都不含 token 字面
		e.deliverAll()
		channels := map[string]bool{}
		for i := seen; i < a.count(); i++ {
			var body struct {
				Channel string `json:"channel"`
				Text    string `json:"text"`
			}
			_ = json.Unmarshal(a.body(i), &body)
			channels[body.Channel] = true
			if strings.Contains(string(a.body(i)), "xoxb-") {
				t.Fatalf("通知含 token: %s", a.body(i))
			}
		}
		if !channels["C1"] || !channels["C2"] {
			t.Fatalf("新舊頻道都應收到通道變更通知: %v", channels)
		}
		// 審計列有前後目標、不含 token
		var logs []model.AuditLog
		e.db.Order("id").Find(&logs)
		last := logs[len(logs)-1]
		if !strings.Contains(last.Details, `"field":"target","old":"C1","new":"C2"`) || strings.Contains(last.Details, "xoxb-") {
			t.Fatalf("審計詳情不符: %s", last.Details)
		}
	})

	t.Run("改網址：告警給舊目的地的紀錄帶舊版本、新目的地帶新版本", func(t *testing.T) {
		e := newRulesEnv(t)
		oldS := newStubSrv(t, nil, nil)
		newS := newStubSrv(t, nil, nil)
		r := e.req("w")
		r.URL = oldS.srv.URL
		created, err := e.svc.Create(r)
		if err != nil {
			t.Fatal(err)
		}
		var maxID uint
		e.db.Model(&model.NotificationDelivery{}).Select("COALESCE(MAX(id),0)").Scan(&maxID)
		r = e.req("w")
		r.URL = newS.srv.URL
		if _, err := e.svc.Update(created.ID, r); err != nil {
			t.Fatal(err)
		}
		var rows []model.NotificationDelivery
		e.db.Where("id > ?", maxID).Order("id").Find(&rows)
		versions := map[string]int{}
		for _, row := range rows {
			versions[row.URLEnc] = row.DestVersion
		}
		if versions[oldS.srv.URL] != 0 || versions[newS.srv.URL] != 1 || len(rows) != 2 {
			t.Fatalf("dest_version 不符: %v（%d 筆）", versions, len(rows))
		}
	})

	t.Run("審計或告警寫入失敗時變更時間維持原值", func(t *testing.T) {
		e := newRulesEnv(t)
		a := newStubSrv(t, nil, nil)
		r := e.req("w")
		r.URL = a.srv.URL
		created, err := e.svc.Create(r)
		if err != nil {
			t.Fatal(err)
		}
		e.svc.SetAuditTxSink(failingTxSink{})
		r = e.req("w")
		r.URL = a.srv.URL + "/changed"
		if _, err := e.svc.Update(created.ID, r); err == nil {
			t.Fatal("審計寫入失敗應回錯")
		}
		if got := e.stored(created.ID); got.DestinationChangedAt != nil || got.DestinationVersion != 0 {
			t.Fatalf("失敗時不應變更: %v %d", got.DestinationChangedAt, got.DestinationVersion)
		}
		e.svc.SetAuditTxSink(NewTxSink())
		e.svc.SetSystemAlertSink(failingRaiser{})
		if _, err := e.svc.Update(created.ID, r); err == nil {
			t.Fatal("告警寫入失敗應回錯")
		}
		if got := e.stored(created.ID); got.DestinationChangedAt != nil || got.DestinationVersion != 0 {
			t.Fatalf("失敗時不應變更: %v %d", got.DestinationChangedAt, got.DestinationVersion)
		}
	})
}

// ---- 9.1 通道健康欄位 ----

func TestChannelHealthFields(t *testing.T) {
	e := newRulesEnv(t)
	srv := newStubSrv(t, e.clock, nil)
	ch := e.channel("h", "webhook", srv.srv.URL+"/hook/SECRETPATH", true, "low")
	delivered := e.liveRow(ch.ID, model.AlertSeverityMedium, 0)
	e.w.RunOnce()
	if e.row(delivered.ID).State != model.NotificationDeliveryDelivered {
		t.Fatal("第一筆應送達")
	}
	deliveredAt := e.row(delivered.ID).DeliveredAt
	srv.respond = respondStatus(404)
	sysRow := e.snapshotRow(ch.ID, srv.srv.URL, 0, 0)
	e.clock.advance(time.Minute)
	e.w.RunOnce()
	list := func() model.NotificationChannel {
		chs, err := e.svc.List()
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range chs {
			if c.ID == ch.ID {
				return c
			}
		}
		t.Fatal("列表沒有這個通道")
		return model.NotificationChannel{}
	}
	got := list()
	if got.Health == nil || got.Health.LastFailureReason != "HTTP 404" || got.Health.LastFailureCode != "http_404" {
		t.Fatalf("最近失敗應為 HTTP 404: %+v", got.Health)
	}
	if got.Health.LastDeliveredAt == nil || !got.Health.LastDeliveredAt.Equal(*deliveredAt) {
		t.Fatalf("最近送達應維持上一次成功值: %+v", got.Health)
	}
	failedAt := *got.Health.LastFailedAt

	// 改網址後，較早的系統安全告警紀錄再失敗一次：回應的最近失敗不變
	changed := e.clock.now().Add(time.Second)
	e.db.Model(&model.NotificationChannel{}).Where("id = ?", ch.ID).
		Updates(map[string]any{"destination_changed_at": changed, "destination_version": 1})
	e.clock.advance(time.Hour)
	srv.respond = respondStatus(500)
	e.w.RunOnce()
	if r := e.row(sysRow.ID); r.Attempts < 2 {
		t.Fatalf("較早的紀錄應再失敗一次: attempts=%d", r.Attempts)
	}
	got = list()
	if got.Health.LastFailedAt != nil || got.Health.LastFailureReason != "" || got.Health.LastDeliveredAt != nil {
		t.Fatalf("改網址後只統計之後建立的紀錄: %+v (原失敗時刻 %v)", got.Health, failedAt)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "SECRETPATH") || strings.Contains(string(raw), `"secret"`) {
		t.Fatalf("回應不得含網址或秘密: %s", raw)
	}
}

// ---- 9.2 投遞紀錄（服務層） ----

func TestListDeliveries(t *testing.T) {
	e := newRulesEnv(t)
	srv := newStubSrv(t, e.clock, nil)
	ch := e.channel("d", "webhook", srv.srv.URL, true, "low")
	old := e.snapshotRow(ch.ID, srv.srv.URL, 0, 0)
	live := e.liveRow(ch.ID, model.AlertSeverityMedium, 0)
	changed := e.clock.now().Add(time.Second)
	e.db.Model(&model.NotificationChannel{}).Where("id = ?", ch.ID).Updates(map[string]any{"destination_changed_at": changed, "destination_version": 1})
	e.clock.advance(2 * time.Second)
	newer := e.snapshotRow(ch.ID, srv.srv.URL, 1, 0)
	pg, err := e.svc.ListDeliveries(ch.ID, ChannelDeliveryQuery{Page: 1, PageSize: 20})
	if err != nil {
		t.Fatal(err)
	}
	rows, total := pg.Rows, pg.Total
	if total != 3 || len(rows) != 3 {
		t.Fatalf("total=%d len=%d", total, len(rows))
	}
	flags := map[uint]bool{}
	keys := map[uint]string{}
	for _, r := range rows {
		flags[r.ID] = r.SnapshotBeforeChange
		keys[r.ID] = r.EventKey
	}
	if !flags[old.ID] || flags[live.ID] || flags[newer.ID] {
		t.Fatalf("旗標只在系統安全告警且早於變更時間的列為真: %v", flags)
	}
	if keys[old.ID] != string(notifycat.EventSystemAlertManagementRoleGranted) || keys[live.ID] != string(notifycat.EventDailyReviewOverdue) {
		t.Fatalf("事件鍵不符: %v", keys)
	}
	raw, _ := json.Marshal(rows)
	for _, k := range []string{`"url"`, `"secret"`, `"params"`} {
		if strings.Contains(string(raw), k) {
			t.Fatalf("回應不得含 %s: %s", k, raw)
		}
	}
	if _, err := e.svc.ListDeliveries(9999, ChannelDeliveryQuery{Page: 1, PageSize: 20}); !errors.Is(err, ErrChannelNotFound) {
		t.Fatalf("不存在的通道: %v", err)
	}
}

// 投遞紀錄查詢：狀態篩選在伺服器端、未送達筆數不受篩選影響且分兩類、限流延後的起點。
func TestListDeliveriesStateFilterAndPendingCounts(t *testing.T) {
	e := newRulesEnv(t)
	srv := newStubSrv(t, e.clock, nil)
	ch := e.channel("d", "webhook", srv.srv.URL, true, "low")
	other := e.channel("o", "webhook", srv.srv.URL, true, "low")
	snapPending := e.snapshotRow(ch.ID, srv.srv.URL, 0, 0)
	snapDelivered := e.snapshotRow(ch.ID, srv.srv.URL, 0, 0)
	liveRetrying := e.liveRow(ch.ID, model.AlertSeverityMedium, 0)
	liveAbandoned := e.liveRow(ch.ID, model.AlertSeverityMedium, 0)
	livePending := e.liveRow(ch.ID, model.AlertSeverityMedium, 0)
	_ = e.liveRow(other.ID, model.AlertSeverityMedium, 0) // 別的通道不計
	since := e.clock.now().Add(-time.Minute).UTC().Truncate(time.Second)
	set := func(id uint, fields map[string]any) {
		if err := e.db.Model(&model.NotificationDelivery{}).Where("id = ?", id).Updates(fields).Error; err != nil {
			t.Fatal(err)
		}
	}
	set(snapPending.ID, map[string]any{"state": model.NotificationDeliveryPending})
	set(snapDelivered.ID, map[string]any{"state": model.NotificationDeliveryDelivered, "delivered_at": e.clock.now()})
	set(liveRetrying.ID, map[string]any{"state": model.NotificationDeliveryRetrying, "attempts": 2, "last_error": "HTTP 500"})
	set(liveAbandoned.ID, map[string]any{"state": model.NotificationDeliveryAbandoned, "end_reason": model.NotificationEndMaxAttempts, "ended_at": e.clock.now()})
	set(livePending.ID, map[string]any{"state": model.NotificationDeliveryPending, "throttled_since": since})

	ids := func(rows []ChannelDelivery) map[uint]bool {
		out := map[uint]bool{}
		for _, r := range rows {
			out[r.ID] = true
		}
		return out
	}
	pg, err := e.svc.ListDeliveries(ch.ID, ChannelDeliveryQuery{Page: 1, PageSize: 20, States: []string{"pending", "retrying"}})
	if err != nil {
		t.Fatal(err)
	}
	got := ids(pg.Rows)
	if pg.Total != 3 || len(got) != 3 || !got[snapPending.ID] || !got[liveRetrying.ID] || !got[livePending.ID] {
		t.Fatalf("篩選等待中與重送中應得三筆: total=%d rows=%v", pg.Total, got)
	}
	if pg.PendingCounts != (ChannelPendingCounts{General: 2, SystemSecurityAlert: 1}) {
		t.Fatalf("未送達筆數應為一般 2、系統安全告警 1: %+v", pg.PendingCounts)
	}
	pg, err = e.svc.ListDeliveries(ch.ID, ChannelDeliveryQuery{Page: 1, PageSize: 1, States: []string{"abandoned"}})
	if err != nil {
		t.Fatal(err)
	}
	if pg.Total != 1 || len(pg.Rows) != 1 || pg.Rows[0].ID != liveAbandoned.ID {
		t.Fatalf("篩選已放棄應只得那一筆: total=%d rows=%v", pg.Total, ids(pg.Rows))
	}
	if pg.PendingCounts != (ChannelPendingCounts{General: 2, SystemSecurityAlert: 1}) {
		t.Fatalf("未送達筆數不受狀態篩選影響: %+v", pg.PendingCounts)
	}
	pg, _ = e.svc.ListDeliveries(ch.ID, ChannelDeliveryQuery{Page: 1, PageSize: 20})
	for _, r := range pg.Rows {
		switch r.ID {
		case livePending.ID:
			if r.ThrottledSince == nil || !r.ThrottledSince.Equal(since) {
				t.Fatalf("限流延後的起點應為 %v，得 %v", since, r.ThrottledSince)
			}
		default:
			if r.ThrottledSince != nil {
				t.Fatalf("未被限流的紀錄不應帶起點: id=%d %v", r.ID, r.ThrottledSince)
			}
		}
	}
	for _, bad := range [][]string{{"done"}, {"pending", "PENDING"}, {""}} {
		if _, err := e.svc.ListDeliveries(ch.ID, ChannelDeliveryQuery{Page: 1, PageSize: 20, States: bad}); !errors.Is(err, ErrInvalidDeliveryState) {
			t.Fatalf("狀態 %q 應被拒: %v", bad, err)
		}
	}
}

// ---- 9.3 投遞放棄的通知 ----

func abandonNotices(e *ndlEnv) []model.NotificationMessage {
	var out []model.NotificationMessage
	e.db.Where("event_key = ?", string(notifycat.EventNotificationDeliveryAbandoned)).Order("id").Find(&out)
	return out
}

func TestDeliveryAbandonedNotice(t *testing.T) {
	t.Run("(a)(b)(c) 送往其他通道、24 小時一則、自己的紀錄被放棄不再產生", func(t *testing.T) {
		e := newNDLEnv(t)
		a := newStubSrv(t, e.clock, respondStatus(400))
		b := newStubSrv(t, e.clock, nil)
		c := newStubSrv(t, e.clock, nil)
		chA := e.channel("chan-A", "webhook", a.srv.URL, true, "low")
		chB := e.channel("chan-B", "webhook", b.srv.URL, true, "low")
		e.channel("chan-C", "webhook", c.srv.URL, true, "low")
		row := e.liveRow(chA.ID, model.AlertSeverityMedium, 47)
		e.w.RunOnce()
		if r := e.row(row.ID); r.State != model.NotificationDeliveryAbandoned {
			t.Fatalf("第 48 次失敗後應放棄: %s", r.State)
		}
		if n := len(abandonNotices(e)); n != 1 {
			t.Fatalf("應產生一則投遞放棄通知，得 %d", n)
		}
		e.w.RunOnce()
		for _, s := range []*stubSrv{b, c} {
			if s.count() != 1 || !strings.Contains(string(s.body(0)), "chan-A") || !strings.Contains(string(s.body(0)), `"abandoned_24h":"1"`) {
				t.Fatalf("B、C 應各收到一則帶通道 A 名稱與筆數的通知: %d %s", s.count(), s.body(0))
			}
		}
		var onA int64
		msgID := abandonNotices(e)[0].ID
		e.db.Model(&model.NotificationDelivery{}).Where("message_id = ? AND source_channel_id = ?", msgID, chA.ID).Count(&onA)
		if onA != 0 {
			t.Fatal("通道 A 不應有這則通知的紀錄")
		}
		// (b) 24 小時內再放棄四筆：仍只有一列
		for i := 0; i < 4; i++ {
			e.liveRow(chA.ID, model.AlertSeverityMedium, 47)
		}
		e.w.RunOnce()
		if n := len(abandonNotices(e)); n != 1 {
			t.Fatalf("24 小時內只應一則，得 %d", n)
		}
		e.clock.advance(24 * time.Hour)
		e.liveRow(chA.ID, model.AlertSeverityMedium, 47)
		e.w.RunOnce()
		notices := abandonNotices(e)
		if len(notices) != 2 {
			t.Fatalf("24 小時後應產生第二列，得 %d", len(notices))
		}
		// (c) 這則通知在通道 B 被放棄時不再產生新的內容列
		var bRow model.NotificationDelivery
		e.db.Where("message_id = ? AND source_channel_id = ?", notices[0].ID, chB.ID).First(&bRow)
		e.db.Model(&model.NotificationDelivery{}).Where("id = ?", bRow.ID).
			Updates(map[string]any{"state": model.NotificationDeliveryRetrying, "attempts": 48, "next_attempt_at": e.clock.now()})
		e.db.Model(&model.NotificationChannel{}).Where("id = ?", chB.ID).Update("abandon_notified_at", nil)
		e.w.RunOnce()
		if r := e.row(bRow.ID); r.State != model.NotificationDeliveryAbandoned {
			t.Fatalf("B 上的紀錄應被放棄: %s", r.State)
		}
		if n := len(abandonNotices(e)); n != 2 {
			t.Fatalf("投遞放棄通知自己的紀錄被放棄不應再產生，得 %d", n)
		}
	})

	t.Run("(e) 產生當下就放棄的系統安全告警不觸發", func(t *testing.T) {
		e := newNDLEnv(t)
		srv := newStubSrv(t, e.clock, nil)
		e.channel("ok", "webhook", srv.srv.URL, true, "low")
		// 網址是信封格式而落地面沒有解密器：產生當下就解不開
		e.channel("bad", "webhook", "enc:v1:broken", true, "low")
		sink := NewSystemAlertSink(nil)
		if err := e.db.Transaction(func(tx *gorm.DB) error {
			_, err := sink.RaiseInTx(tx, validGrantEvent())
			return err
		}); err != nil {
			t.Fatal(err)
		}
		var abandoned int64
		e.db.Model(&model.NotificationDelivery{}).Where("state = ? AND attempts = 0", model.NotificationDeliveryAbandoned).Count(&abandoned)
		if abandoned != 1 {
			t.Fatalf("應有一筆產生當下就放棄的紀錄，得 %d", abandoned)
		}
		for i := 0; i < 3; i++ {
			e.w.RunOnce()
		}
		if n := len(abandonNotices(e)); n != 0 {
			t.Fatalf("不應產生投遞放棄通知，得 %d", n)
		}
	})

	t.Run("(f) 內容列寫入失敗時仍放棄、節流欄維持原值", func(t *testing.T) {
		e := newNDLEnv(t)
		a := newStubSrv(t, e.clock, respondStatus(400))
		chA := e.channel("chan-A", "webhook", a.srv.URL, true, "low")
		row := e.liveRow(chA.ID, model.AlertSeverityMedium, 47)
		e.w.hooks.beforeAbandonNotice = func() error { return errors.New("注入的寫入失敗") }
		e.w.RunOnce()
		if r := e.row(row.ID); r.State != model.NotificationDeliveryAbandoned {
			t.Fatalf("放棄應照常記錄: %s", r.State)
		}
		var ch model.NotificationChannel
		e.db.First(&ch, chA.ID)
		if ch.AbandonNotifiedAt != nil {
			t.Fatalf("節流欄應維持原值: %v", ch.AbandonNotifiedAt)
		}
		if n := len(abandonNotices(e)); n != 0 {
			t.Fatalf("不應有內容列，得 %d", n)
		}
	})

	t.Run("通道已刪除時不觸發", func(t *testing.T) {
		e := newNDLEnv(t)
		snap := newStubSrv(t, e.clock, respondStatus(400))
		ch := e.channel("gone", "webhook", snap.srv.URL, true, "low")
		row := e.snapshotRow(ch.ID, snap.srv.URL, 0, 47)
		e.db.Delete(&model.NotificationChannel{}, ch.ID)
		e.w.RunOnce()
		if r := e.row(row.ID); r.State != model.NotificationDeliveryAbandoned {
			t.Fatalf("應放棄: %s", r.State)
		}
		if n := len(abandonNotices(e)); n != 0 {
			t.Fatalf("通道已刪除不應觸發，得 %d", n)
		}
	})
}
