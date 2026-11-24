package audit

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
)

// 通道的對個人派送設定與「傳給我自己」。

type tnlChannelEnv struct {
	*tnlEnv
	svc *NotificationChannelService
}

func newTNLChannelEnv(t *testing.T) *tnlChannelEnv {
	t.Helper()
	e := newTNLEnv(t)
	return &tnlChannelEnv{tnlEnv: e, svc: newChannelSvc(t, e.db, nil)}
}

func (e *tnlChannelEnv) req(name string) *NotificationChannelRequest {
	return &NotificationChannelRequest{Name: name, ActorID: 5, ActorName: "sec-admin", ActorIP: "10.1.1.1"}
}

// createApp 經服務建立 slack_app 通道（指向替身）；dm 為 true 時同時開啟對個人派送。
func (e *tnlChannelEnv) createApp(name string, dm bool) model.NotificationChannel {
	e.t.Helper()
	r := e.req(name)
	r.Type, r.URL, r.Secret, r.Target = model.NotificationChannelTypeSlackApp, e.slack.srv.URL, tnlToken, tnlTarget
	if dm {
		r.DirectMessageEnabled = boolp(true)
	}
	ch, err := e.svc.Create(r)
	if err != nil {
		e.t.Fatal(err)
	}
	return e.stored(ch.ID)
}

func (e *tnlChannelEnv) stored(id uint) model.NotificationChannel {
	e.t.Helper()
	var ch model.NotificationChannel
	if err := e.db.First(&ch, id).Error; err != nil {
		e.t.Fatal(err)
	}
	return ch
}

// setDM 只改對個人派送（其他欄位沿用）。
func (e *tnlChannelEnv) setDM(id uint, name string, on bool) error {
	r := e.req(name)
	r.DirectMessageEnabled = boolp(on)
	_, err := e.svc.Update(id, r)
	return err
}

// latestChangeAlert 最近一則通道變更告警的參數（系統告警明細）。
func (e *tnlChannelEnv) latestChangeAlert() map[string]string {
	e.t.Helper()
	var d model.SystemAlertDetail
	if err := e.db.Where("alert_type = ?", string(notifycat.EventSystemAlertNotificationChannelChanged)).Order("alert_id DESC").First(&d).Error; err != nil {
		e.t.Fatal(err)
	}
	p := map[string]string{}
	_ = json.Unmarshal([]byte(d.Params), &p)
	return p
}

// pendingUserRows 為通道建立 n 筆重送中的個人紀錄與一筆重送中的頻道紀錄。
func (e *tnlChannelEnv) pendingRows(chID uint, n int) (users []uint, channelRow uint) {
	e.t.Helper()
	var ids []uint
	for i := 0; i < n; i++ {
		ids = append(ids, e.user("p"+string(rune('a'+i)), emailOf("p"+string(rune('a'+i)))))
	}
	e.judge.recipients = ids
	e.created(1)
	e.w.dispatchPending()
	e.db.Model(&model.NotificationDelivery{}).Where("source_channel_id = ?", chID).
		Updates(map[string]any{"state": model.NotificationDeliveryRetrying, "attempts": 2, "next_attempt_at": e.clock.now().Add(time.Hour)})
	for _, r := range e.userRows() {
		users = append(users, r.ID)
	}
	return users, e.channelRows()[0].ID
}

func TestTargetedChannelSetting(t *testing.T) {
	t.Run("預設不派送：建立時未帶設定為關閉，申請只有頻道訊息", func(t *testing.T) {
		e := newTNLChannelEnv(t)
		ch := e.createApp("app", false)
		if ch.DirectMessageEnabled {
			t.Fatal("預設應為關閉")
		}
		e.judge.recipients = []uint{e.user("r1", emailOf("r1"))}
		e.created(1)
		e.w.dispatchPending()
		if n := len(e.userRows()); n != 0 {
			t.Fatalf("不應有個人紀錄，得 %d", n)
		}
	})

	t.Run("至多一個通道開啟：第二個被拒並指出已開啟的通道名稱", func(t *testing.T) {
		e := newTNLChannelEnv(t)
		a := e.createApp("通道甲", true)
		b := e.createApp("通道乙", false)
		err := e.setDM(b.ID, "通道乙", true)
		var conflict *DirectMessageConflictError
		if !errors.As(err, &conflict) || conflict.Name != "通道甲" || !errors.Is(err, ErrDirectMessageConflict) {
			t.Fatalf("應回已開啟的通道名稱: %v", err)
		}
		if e.stored(b.ID).DirectMessageEnabled || !e.stored(a.ID).DirectMessageEnabled {
			t.Fatal("通道設定不應改變")
		}
		r := e.req("通道丙")
		r.Type, r.URL, r.Secret, r.Target = model.NotificationChannelTypeSlackApp, e.slack.srv.URL, tnlToken, tnlTarget
		r.DirectMessageEnabled = boolp(true)
		if _, err := e.svc.Create(r); !errors.Is(err, ErrDirectMessageConflict) {
			t.Fatalf("建立時同樣檢查: %v", err)
		}
	})

	t.Run("設定變更留痕：審計記下前後值、產生通道變更告警；開關不遞增目的地版本", func(t *testing.T) {
		e := newTNLChannelEnv(t)
		ch := e.createApp("app", false)
		ver := ch.DestinationVersion
		if err := e.setDM(ch.ID, "app", true); err != nil {
			t.Fatal(err)
		}
		var a model.AuditLog
		e.db.Order("id DESC").First(&a)
		if !strings.Contains(a.Details, `"field":"direct_message_enabled","old":"false","new":"true"`) {
			t.Fatalf("審計應記下前後值: %s", a.Details)
		}
		if p := e.latestChangeAlert(); !strings.Contains(p["changed_fields"], "direct_message_enabled") || p["dm_auto_off"] != "" {
			t.Fatalf("通道變更告警應列出這個欄位: %v", p)
		}
		if got := e.stored(ch.ID); got.DestinationVersion != ver || got.DestinationChangedAt != nil {
			t.Fatalf("開關不應遞增目的地版本: %d → %d", ver, got.DestinationVersion)
		}
	})

	t.Run("不能以個人為對象的型別不得開啟", func(t *testing.T) {
		e := newTNLChannelEnv(t)
		for _, typ := range []string{model.NotificationChannelTypeWebhook, model.NotificationChannelTypeSlack} {
			r := e.req("w")
			r.Type, r.URL = typ, "https://hooks.example.test/x"
			r.DirectMessageEnabled = boolp(true)
			if _, err := e.svc.Create(r); !errors.Is(err, ErrDirectMessageUnsupportedType) {
				t.Fatalf("%s 建立時應被拒: %v", typ, err)
			}
			r.DirectMessageEnabled = nil
			ch, err := e.svc.Create(r)
			if err != nil {
				t.Fatal(err)
			}
			if err := e.setDM(ch.ID, "w", true); !errors.Is(err, ErrDirectMessageUnsupportedType) {
				t.Fatalf("%s 更新時應被拒: %v", typ, err)
			}
		}
	})

	t.Run("(c) 關閉時個人紀錄取消、頻道紀錄不變；關閉再開啟後仍是已取消；清掉該通道的對應快取", func(t *testing.T) {
		e := newTNLChannelEnv(t)
		ch := e.createApp("app", true)
		users, chRow := e.pendingRows(ch.ID, 3)
		dmCachePut(dmCacheKey{ChannelID: ch.ID, Email: "x"}, dmCacheEntry{userID: "U1", expires: e.clock.now().Add(time.Hour)})
		dmCachePut(dmCacheKey{ChannelID: ch.ID + 99, Email: "x"}, dmCacheEntry{userID: "U1", expires: e.clock.now().Add(time.Hour)})
		if err := e.setDM(ch.ID, "app", false); err != nil {
			t.Fatal(err)
		}
		for _, id := range users {
			if r := e.row(id); r.State != model.NotificationDeliveryCanceled || r.EndReason != model.NotificationEndDirectMessageDisabled {
				t.Fatalf("個人紀錄應取消: state=%s end=%q", r.State, r.EndReason)
			}
		}
		if r := e.row(chRow); r.State != model.NotificationDeliveryRetrying {
			t.Fatalf("頻道紀錄不應改變: %s", r.State)
		}
		if err := e.setDM(ch.ID, "app", true); err != nil {
			t.Fatal(err)
		}
		for _, id := range users {
			if r := e.row(id); r.State != model.NotificationDeliveryCanceled {
				t.Fatalf("重新開啟後仍應是已取消: %s", r.State)
			}
		}
		dmAddressCache.mu.Lock()
		_, mine := dmAddressCache.m[dmCacheKey{ChannelID: ch.ID, Email: "x"}]
		_, other := dmAddressCache.m[dmCacheKey{ChannelID: ch.ID + 99, Email: "x"}]
		dmAddressCache.mu.Unlock()
		if mine || !other {
			t.Fatalf("更新應只清掉該通道的快取: mine=%v other=%v", mine, other)
		}
	})

	t.Run("(e) 已被認領（有效租約）的個人紀錄在關閉後不被改成已取消", func(t *testing.T) {
		e := newTNLChannelEnv(t)
		ch := e.createApp("app", true)
		users, _ := e.pendingRows(ch.ID, 2)
		e.db.Model(&model.NotificationDelivery{}).Where("id = ?", users[0]).Update("lease_until", time.Now().UTC().Add(time.Minute))
		if err := e.setDM(ch.ID, "app", false); err != nil {
			t.Fatal(err)
		}
		if r := e.row(users[0]); r.State != model.NotificationDeliveryRetrying {
			t.Fatalf("處理中的那一筆不應被取消: %s", r.State)
		}
		if r := e.row(users[1]); r.State != model.NotificationDeliveryCanceled {
			t.Fatalf("未被認領的應取消: %s", r.State)
		}
	})

	t.Run("(f) 開啟中的 slack_app 改為 webhook（不帶旗標）：旗標為假、在途取消、告警記下；另一個 slack_app 隨即可以開啟", func(t *testing.T) {
		e := newTNLChannelEnv(t)
		ch := e.createApp("app", true)
		users, _ := e.pendingRows(ch.ID, 1)
		r := e.req("app")
		r.Type, r.URL = model.NotificationChannelTypeWebhook, "https://hooks.example.test/x"
		if _, err := e.svc.Update(ch.ID, r); err != nil {
			t.Fatal(err)
		}
		if e.stored(ch.ID).DirectMessageEnabled {
			t.Fatal("改型別後旗標應為假")
		}
		if row := e.row(users[0]); row.State != model.NotificationDeliveryCanceled || row.EndReason != model.NotificationEndDirectMessageDisabled {
			t.Fatalf("在途個人紀錄應取消: %s %q", row.State, row.EndReason)
		}
		if p := e.latestChangeAlert(); p["dm_auto_off"] != notifycat.DMAutoOffType || !strings.Contains(p["changed_fields"], "direct_message_enabled") {
			t.Fatalf("通道變更告警應註明自動關閉: %v", p)
		}
		var a model.AuditLog
		e.db.Order("id DESC").First(&a)
		if !strings.Contains(a.Details, `"direct_message_auto_off":"type"`) {
			t.Fatalf("審計應記下自動關閉: %s", a.Details)
		}
		other := e.createApp("app2", false)
		if err := e.setDM(other.ID, "app2", true); err != nil {
			t.Fatalf("另一個 slack_app 應可開啟: %v", err)
		}
	})

	t.Run("(g) 網址主機不在允許清單時開啟被拒；經 NOTIFY_DM_EXTRA_HOSTS 加入後可開啟", func(t *testing.T) {
		e := newTNLChannelEnv(t)
		t.Setenv(dmExtraHostsEnv, "")
		ch := e.createApp("app", false)
		if err := e.setDM(ch.ID, "app", true); !errors.Is(err, ErrDirectMessageURLNotAllowed) {
			t.Fatalf("應被拒: %v", err)
		}
		if e.stored(ch.ID).DirectMessageEnabled {
			t.Fatal("通道設定不應改變")
		}
		t.Setenv(dmExtraHostsEnv, "other.example, 127.0.0.1")
		if err := e.setDM(ch.ID, "app", true); err != nil {
			t.Fatalf("加入允許清單後應可開啟: %v", err)
		}
	})

	t.Run("(h) 已開啟的通道改網址到清單外：同一交易旗標為假、告警註明自動關閉、新主機沒有收到帶電子郵件的請求", func(t *testing.T) {
		e := newTNLChannelEnv(t)
		ch := e.createApp("app", true)
		users, _ := e.pendingRows(ch.ID, 1)
		outside := newDMSlackStub(t, e.clock)
		r := e.req("app")
		r.URL, r.Secret = strings.Replace(outside.srv.URL, "127.0.0.1", "localhost", 1), tnlToken
		if _, err := e.svc.Update(ch.ID, r); err != nil {
			t.Fatal(err)
		}
		if e.stored(ch.ID).DirectMessageEnabled {
			t.Fatal("網址改到清單外後旗標應為假")
		}
		if p := e.latestChangeAlert(); p["dm_auto_off"] != notifycat.DMAutoOffHost {
			t.Fatalf("通道變更告警應註明因網址自動關閉: %v", p)
		}
		if row := e.row(users[0]); row.State != model.NotificationDeliveryCanceled {
			t.Fatalf("在途個人紀錄應取消: %s", row.State)
		}
		e.clock.advance(2 * time.Hour)
		e.rounds(3, 2*time.Second)
		if n := len(outside.callsOf(slackLookupByEmailMethod)); n != 0 {
			t.Fatalf("新主機不應收到查詢，得 %d", n)
		}
		// 已開啟、網址仍在清單內而請求明示開啟：照常成立
		r2 := e.req("app")
		r2.URL, r2.Secret = strings.Replace(outside.srv.URL, "127.0.0.1", "localhost", 1), tnlToken
		r2.DirectMessageEnabled = boolp(true)
		if _, err := e.svc.Update(ch.ID, r2); !errors.Is(err, ErrDirectMessageURLNotAllowed) {
			t.Fatalf("網址在清單外時明示開啟應被拒: %v", err)
		}
	})
}

// ---- 4.2 傳給我自己 ----

func TestTargetedTestToSelf(t *testing.T) {
	plainChannel := func(e *tnlChannelEnv, ch model.NotificationChannel) *model.NotificationChannel {
		got, err := e.svc.GetForDelivery(ch.ID)
		if err != nil {
			e.t.Fatal(err)
		}
		return got
	}

	t.Run("(a)(b)(f) 五種結果、待投遞表沒有新增列、成功時帶顯示名稱且不含電子郵件與識別碼", func(t *testing.T) {
		e := newTNLChannelEnv(t)
		ch := plainChannel(e, e.createApp("app", false))
		me := e.user("me", emailOf("me"))
		noEmail := e.user("noemail", nil)
		dup := e.user("dup", emailOf("dup"))
		_ = e.user("dup2", emailOf("dup"))
		notFound := e.user("nf", emailOf("nf"))
		e.slack.set(func(_ int, email string, w http.ResponseWriter) {
			switch email {
			case *emailOf("nf"):
				jsonReply(200, `{"ok":false,"error":"users_not_found"}`)(w)
			case *emailOf("scope"):
				jsonReply(200, `{"ok":false,"error":"missing_scope"}`)(w)
			default:
				jsonReply(200, `{"ok":true,"user":{"id":"UME1","profile":{"display_name":"Me \u001b[31m(me@reviewers.example)"}}}`)(w)
			}
		}, nil)
		scope := e.user("scope", emailOf("scope"))
		var before int64
		e.db.Model(&model.NotificationDelivery{}).Count(&before)

		res, err := e.svc.TestToSelf(ch, me)
		if err != nil || res.Outcome != SelfTestDelivered {
			t.Fatalf("成功: %+v %v", res, err)
		}
		if strings.Contains(res.DisplayName, "@") || strings.ContainsAny(res.DisplayName, "\x1b") || !strings.HasPrefix(res.DisplayName, "Me") {
			t.Fatalf("顯示名稱應經淨化且不含電子郵件: %q", res.DisplayName)
		}
		raw, _ := json.Marshal(res)
		if strings.Contains(string(raw), "UME1") || strings.Contains(string(raw), "reviewers.example") {
			t.Fatalf("結果不應含識別碼或電子郵件: %s", raw)
		}
		posts := e.slack.callsOf(slackPostMessageMethod)
		if len(posts) != 1 {
			t.Fatalf("應送出一則私訊，得 %d", len(posts))
		}
		if target, _, _, _ := postBody(t, posts[0]); target != "UME1" {
			t.Fatalf("私訊目的地應為對到的帳號: %s", target)
		}
		for uid, want := range map[uint]string{noEmail: SelfTestNoEmail, dup: SelfTestEmailAmbiguous, notFound: SelfTestRecipientNotFound} {
			if res, err := e.svc.TestToSelf(ch, uid); err != nil || res.Outcome != want {
				t.Fatalf("預期 %s: %+v %v", want, res, err)
			}
		}
		if res, err := e.svc.TestToSelf(ch, scope); err != nil || res.Outcome != SelfTestPlatformError || res.PlatformError != "missing_scope" {
			t.Fatalf("平台錯誤碼: %+v %v", res, err)
		}
		var after int64
		e.db.Model(&model.NotificationDelivery{}).Count(&after)
		if after != before {
			t.Fatalf("待投遞表不應新增列: %d → %d", before, after)
		}
		dmAddressCache.mu.Lock()
		n := len(dmAddressCache.m)
		dmAddressCache.mu.Unlock()
		if n != 0 {
			t.Fatalf("不應寫入快取，得 %d 筆", n)
		}
		lookups := e.slack.callsOf(slackLookupByEmailMethod)
		if lookups[0].Email != *emailOf("me") {
			t.Fatal("查詢應只含請求者自己的電子郵件")
		}
	})

	t.Run("(c)(g) slack 與 webhook 型通道、網址不在允許清單時被拒，替身沒有收到請求", func(t *testing.T) {
		e := newTNLChannelEnv(t)
		me := e.user("me", emailOf("me"))
		for _, typ := range []string{model.NotificationChannelTypeWebhook, model.NotificationChannelTypeSlack} {
			r := e.req("w")
			r.Type, r.URL = typ, e.slack.srv.URL
			ch, err := e.svc.Create(r)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := e.svc.TestToSelf(plainChannel(e, e.stored(ch.ID)), me); !errors.Is(err, ErrSelfTestUnsupportedType) {
				t.Fatalf("%s 應被拒: %v", typ, err)
			}
		}
		app := plainChannel(e, e.createApp("app", false))
		t.Setenv(dmExtraHostsEnv, "")
		if _, err := e.svc.TestToSelf(app, me); !errors.Is(err, ErrSelfTestURLNotAllowed) {
			t.Fatalf("網址不在清單內應被拒: %v", err)
		}
		if n := e.slack.total(); n != 0 {
			t.Fatalf("替身不應收到任何請求，得 %d", n)
		}
	})
}
