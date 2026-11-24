package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
	"gorm.io/gorm"
)

// 定向通知的投遞層。收件人判定以可設定的替身代替，真的授權判定接線另由 api 套件的整合測試涵蓋。

// ---- 3.1 分派時建立個人訊息紀錄 ----

func TestTargetedDispatchCreatesUserRows(t *testing.T) {
	t.Run("(a) 申請建立時兩位收件人各一筆個人紀錄，每個通道各一筆頻道紀錄", func(t *testing.T) {
		e := newTNLEnv(t)
		dm := e.dmChannel("dm")
		other := e.channel("hook", model.NotificationChannelTypeWebhook, "http://127.0.0.1:1/x", true, "low")
		a, b := e.user("r1", emailOf("r1")), e.user("r2", emailOf("r2"))
		e.judge.recipients = []uint{a, b}
		e.created(42)
		e.w.dispatchPending()
		users := e.userRows()
		if len(users) != 2 || *users[0].RecipientUserID != a || *users[1].RecipientUserID != b {
			t.Fatalf("個人紀錄不符: %+v", users)
		}
		for _, u := range users {
			if derefUint(u.SourceChannelID) != dm.ID || u.Category != model.NotificationCategorySystemEvent {
				t.Fatalf("個人紀錄的通道或類別不符: %+v", u)
			}
		}
		chans := e.channelRows()
		if len(chans) != 2 || derefUint(chans[0].SourceChannelID) != dm.ID || derefUint(chans[1].SourceChannelID) != other.ID {
			t.Fatalf("頻道紀錄應每個通道各一筆: %+v", chans)
		}
	})

	t.Run("(b) 核准、投票進度、拒絕、撤銷沒有個人紀錄，且不能登錄判定", func(t *testing.T) {
		e := newTNLEnv(t)
		e.dmChannel("dm")
		a := e.user("r1", emailOf("r1"))
		e.judge.recipients = []uint{a}
		for _, ev := range []notifycat.Event{notifycat.EventAccessRequestApproved, notifycat.EventAccessRequestApprovalProgress,
			notifycat.EventAccessRequestRejected, notifycat.EventTicketRevoked} {
			if err := e.w.UseTargetedJudge(ev, e.judge.judge()); err != ErrTargetedEventUnsupported {
				t.Fatalf("%s 不應能登錄判定: %v", ev, err)
			}
		}
		e.enqueueEvent(notifycat.EventAccessRequestApproved, map[string]string{"request_id": "7", "mode": "manual"})
		e.enqueueEvent(notifycat.EventAccessRequestApprovalProgress, map[string]string{"request_id": "7", "votes": "1", "required": "2"})
		e.enqueueEvent(notifycat.EventAccessRequestRejected, map[string]string{"request_id": "7"})
		e.enqueueEvent(notifycat.EventTicketRevoked, map[string]string{"request_id": "7"})
		e.w.dispatchPending()
		if n := len(e.userRows()); n != 0 {
			t.Fatalf("這四個事件不應有個人紀錄，得 %d", n)
		}
		if n := len(e.channelRows()); n != 4 {
			t.Fatalf("頻道紀錄應有 4 筆，得 %d", n)
		}
	})

	t.Run("(c) 沒有通道開啟、或開啟的通道已停用時沒有個人紀錄", func(t *testing.T) {
		e := newTNLEnv(t)
		ch := e.slackAppChannel("app", e.slack.srv.URL, tnlToken, tnlTarget)
		a := e.user("r1", emailOf("r1"))
		e.judge.recipients = []uint{a}
		e.created(1)
		e.w.dispatchPending()
		if n := len(e.userRows()); n != 0 {
			t.Fatalf("沒有通道開啟時不應有個人紀錄，得 %d", n)
		}
		e.db.Model(&model.NotificationChannel{}).Where("id = ?", ch.ID).Updates(map[string]any{"direct_message_enabled": true, "enabled": false})
		e.created(2)
		e.w.dispatchPending()
		if n := len(e.userRows()); n != 0 {
			t.Fatalf("開啟的通道已停用時不應有個人紀錄，得 %d", n)
		}
		if e.judge.recipCalls != 0 {
			t.Fatalf("沒有可送出的通道時不應求收件人，得 %d 次", e.judge.recipCalls)
		}
	})

	for _, tc := range []struct {
		name  string
		setup func(f *fakeJudge)
	}{
		{"回傳錯誤", func(f *fakeJudge) { f.err = errJudge }},
		{"panic", func(f *fakeJudge) { f.panicMsg = "boom" }},
	} {
		t.Run("(d) 判定"+tc.name+"時頻道照常、標已分派、沒有個人紀錄、產生一則彙總事件", func(t *testing.T) {
			e := newTNLEnv(t)
			e.dmChannel("dm")
			e.judge.recipients = []uint{e.user("r1", emailOf("r1"))}
			tc.setup(e.judge)
			e.created(42)
			e.w.dispatchPending()
			if n := len(e.userRows()); n != 0 {
				t.Fatalf("不應有個人紀錄，得 %d", n)
			}
			if n := len(e.channelRows()); n != 1 {
				t.Fatalf("頻道紀錄應照常建立，得 %d", n)
			}
			msgs := e.messages()
			if msgs[0].State != model.NotificationMessageDispatched {
				t.Fatalf("內容應標為已分派: %s", msgs[0].State)
			}
			und := e.undeliveredMessages()
			if len(und) != 1 {
				t.Fatalf("應產生一則彙總事件，得 %d", len(und))
			}
			p := msgParams(t, und[0])
			if p["reason"] != notifycat.TargetedReasonResolveFailed || p["event_kind"] != notifycat.TargetedKindAccessRequest || p["request_id"] != "42" {
				t.Fatalf("彙總事件參數不符: %v", p)
			}
		})
	}

	t.Run("(d') 個人紀錄寫入失敗時回到 savepoint、頻道紀錄仍在、產生彙總事件", func(t *testing.T) {
		e := newTNLEnv(t)
		e.dmChannel("dm")
		e.judge.recipients = []uint{e.user("r1", emailOf("r1"))}
		e.w.hooks.beforeTargetedRows = func(tx *gorm.DB) error {
			// 先寫一筆再失敗：回到 savepoint 後這一筆也要消失
			key, _ := newDeliveryKey()
			uid := uint(999)
			msgID := uint(1)
			if err := tx.Create(&model.NotificationDelivery{Category: model.NotificationCategorySystemEvent, MessageID: &msgID,
				State: model.NotificationDeliveryPending, NextAttemptAt: e.clock.now(), CreatedAt: e.clock.now(), DeliveryKey: key,
				Audience: deliveryAudienceUser, RecipientUserID: &uid, Severity: "medium"}).Error; err != nil {
				return err
			}
			return fmt.Errorf("寫入失敗（測試）")
		}
		e.created(42)
		e.w.dispatchPending()
		if n := len(e.userRows()); n != 0 {
			t.Fatalf("回到 savepoint 後不應有個人紀錄，得 %d", n)
		}
		if n := len(e.channelRows()); n != 1 {
			t.Fatalf("頻道紀錄應保留，得 %d", n)
		}
		if n := len(e.undeliveredMessages()); n != 1 {
			t.Fatalf("應產生一則彙總事件，得 %d", n)
		}
	})

	t.Run("(e) 業務交易回滾時連內容列都不存在", func(t *testing.T) {
		e := newTNLEnv(t)
		e.dmChannel("dm")
		e.judge.recipients = []uint{e.user("r1", emailOf("r1"))}
		_ = e.db.Transaction(func(tx *gorm.DB) error {
			if err := e.n.EnqueueInTx(tx, SystemEventNotice(notifycat.EventAccessRequestCreated, map[string]string{"request_id": "5"})); err != nil {
				t.Fatal(err)
			}
			return fmt.Errorf("業務失敗")
		})
		e.w.RunOnce()
		if n := len(e.messages()); n != 0 {
			t.Fatalf("內容列不應存在，得 %d", n)
		}
		if n := len(e.deliveries()); n != 0 {
			t.Fatalf("待投遞紀錄不應存在，得 %d", n)
		}
	})

	t.Run("(f) 分派的條件更新不成立而回滾時個人紀錄一併不存在", func(t *testing.T) {
		e := newTNLEnv(t)
		e.dmChannel("dm")
		e.judge.recipients = []uint{e.user("r1", emailOf("r1"))}
		e.w.hooks.beforeDispatchFinalize = func(tx *gorm.DB, id uint) {
			tx.Model(&model.NotificationMessage{}).Where("id = ?", id).Update("state", model.NotificationMessageDispatched)
		}
		e.created(42)
		e.w.dispatchPending()
		if n := len(e.deliveries()); n != 0 {
			t.Fatalf("回滾後不應有任何紀錄，得 %d", n)
		}
	})

	t.Run("(g) 連線池為 1 的 SQLite 上，有收件人的分派在 5 秒內完成", func(t *testing.T) {
		e := newTNLEnv(t)
		e.dmChannel("dm")
		e.judge.recipients = []uint{e.user("r1", emailOf("r1")), e.user("r2", emailOf("r2"))}
		e.judge.usedDB = true
		e.w.targetedTimeout = 8 * time.Second
		e.created(42)
		start := time.Now()
		e.w.dispatchPending()
		if d := time.Since(start); d > 5*time.Second {
			t.Fatalf("分派耗時 %s，超過 5 秒", d)
		}
		if n := len(e.userRows()); n != 2 {
			t.Fatalf("應有 2 筆個人紀錄，得 %d", n)
		}
	})

	t.Run("(h) 沒有收件人：單已不需處理時不產生彙總事件；仍待審時產生", func(t *testing.T) {
		e := newTNLEnv(t)
		e.dmChannel("dm")
		e.judge.awaiting = false
		e.created(42)
		e.w.dispatchPending()
		if n := len(e.undeliveredMessages()); n != 0 {
			t.Fatalf("單已被核准時不應產生彙總事件，得 %d", n)
		}
		e.judge.awaiting = true
		e.created(43)
		e.w.dispatchPending()
		und := e.undeliveredMessages()
		if len(und) != 1 {
			t.Fatalf("仍待審時應產生彙總事件，得 %d", len(und))
		}
		p := msgParams(t, und[0])
		if p["reason"] != notifycat.TargetedReasonNoRecipient || p["request_id"] != "43" || p["count"] != "" {
			t.Fatalf("沒有收件人時的參數不符: %v", p)
		}
	})
}

// ---- 3.2 送出前檢查登錄 ----

func TestTargetedPrecheckOnlyCancelsUserRows(t *testing.T) {
	e := newTNLEnv(t)
	e.dmChannel("dm")
	a := e.user("r1", emailOf("r1"))
	e.judge.recipients = []uint{a}
	e.created(42)
	e.w.dispatchPending()
	e.judge.setVerdict(a, TargetedResolved) // 申請已被核准
	e.rounds(2, 2*time.Second)
	ch, u := e.channelRows()[0], e.userRows()[0]
	if ch.State != model.NotificationDeliveryDelivered || ch.EndReason != "" {
		t.Fatalf("頻道紀錄應照送且沒有結束原因: state=%s end=%q", ch.State, ch.EndReason)
	}
	if u.State != model.NotificationDeliveryCanceled || u.EndReason != model.NotificationEndRequestResolved {
		t.Fatalf("個人紀錄應以 request_resolved 取消: state=%s end=%q", u.State, u.EndReason)
	}
	if n := len(e.slack.callsOf(slackLookupByEmailMethod)); n != 0 {
		t.Fatalf("取消的個人紀錄不應查詢帳號，得 %d", n)
	}
}

// ---- 3.3 重驗 ----

func TestTargetedRecheck(t *testing.T) {
	type setup struct {
		e *tnlEnv
		a uint
		u model.NotificationDelivery
	}
	prepare := func(t *testing.T) setup {
		e := newTNLEnv(t)
		e.dmChannel("dm")
		a := e.user("r1", emailOf("r1"))
		e.judge.recipients = []uint{a}
		e.created(42)
		e.w.dispatchPending()
		return setup{e: e, a: a, u: e.userRows()[0]}
	}

	for _, tc := range []struct {
		name   string
		v      TargetedVerdict
		reason string
	}{
		{"(a)(j) 已了結（已被決定、他已投完票、範圍內項目已由他人決定）", TargetedResolved, model.NotificationEndRequestResolved},
		{"(d) 收件人已不具資格（範圍移除、角色收回、停用、刪除）", TargetedIneligible, model.NotificationEndRecipientIneligible},
	} {
		t.Run(tc.name+"：認領前取消、次數不變", func(t *testing.T) {
			s := prepare(t)
			s.e.judge.setVerdict(s.a, tc.v)
			s.e.w.RunOnce()
			got := s.e.row(s.u.ID)
			if got.State != model.NotificationDeliveryCanceled || got.EndReason != tc.reason || got.Attempts != 0 {
				t.Fatalf("state=%s end=%q attempts=%d", got.State, got.EndReason, got.Attempts)
			}
		})
	}

	t.Run("(a) 一位收件人取消、另一位照送", func(t *testing.T) {
		e := newTNLEnv(t)
		e.dmChannel("dm")
		a, b := e.user("r1", emailOf("r1")), e.user("r2", emailOf("r2"))
		e.judge.recipients = []uint{a, b}
		e.created(42)
		e.w.dispatchPending()
		e.judge.setVerdict(a, TargetedResolved)
		e.rounds(4, 2*time.Second)
		rows := e.userRows()
		if rows[0].State != model.NotificationDeliveryCanceled || rows[0].EndReason != model.NotificationEndRequestResolved {
			t.Fatalf("投完票者應取消: %+v", rows[0])
		}
		if rows[1].State != model.NotificationDeliveryDelivered {
			t.Fatalf("其他人應照送: %s", rows[1].State)
		}
	})

	t.Run("(d) 收件人被刪除（查不到使用者）時取消為 recipient_ineligible", func(t *testing.T) {
		s := prepare(t)
		s.e.db.Exec(`DELETE FROM users WHERE id = ?`, s.a)
		s.e.judge.setVerdict(s.a, TargetedNeeded) // 即使判定照送，送出時查不到使用者也取消
		s.e.rounds(2, 2*time.Second)
		got := s.e.row(s.u.ID)
		if got.State != model.NotificationDeliveryCanceled || got.EndReason != model.NotificationEndRecipientIneligible {
			t.Fatalf("state=%s end=%q", got.State, got.EndReason)
		}
		if s.e.slack.total() != 1 { // 只有頻道訊息
			t.Fatalf("替身只應收到頻道訊息，得 %d", s.e.slack.total())
		}
	})

	t.Run("(e) 對個人派送關閉、或型別改成不能以個人為對象時取消", func(t *testing.T) {
		for _, mutate := range []map[string]any{{"direct_message_enabled": false}, {"type": model.NotificationChannelTypeWebhook}} {
			s := prepare(t)
			s.e.db.Model(&model.NotificationChannel{}).Where("id = ?", derefUint(s.u.SourceChannelID)).Updates(mutate)
			s.e.w.RunOnce()
			got := s.e.row(s.u.ID)
			if got.State != model.NotificationDeliveryCanceled || got.EndReason != model.NotificationEndDirectMessageDisabled || got.Attempts != 0 {
				t.Fatalf("%v: state=%s end=%q attempts=%d", mutate, got.State, got.EndReason, got.Attempts)
			}
		}
	})

	t.Run("(f) 每次重送都重驗：第一次送出失敗後申請被核准，第二次不送出", func(t *testing.T) {
		s := prepare(t)
		s.e.slack.set(nil, func(n int, w http.ResponseWriter) {
			jsonReply(200, `{"ok":false,"error":"not_in_channel"}`)(w)
		})
		s.e.w.RunOnce()
		if got := s.e.row(s.u.ID); got.State != model.NotificationDeliveryRetrying || got.Attempts != 1 {
			t.Fatalf("第一次應失敗重試: state=%s attempts=%d", got.State, got.Attempts)
		}
		posts := dmPosts(t, s.e)
		s.e.judge.setVerdict(s.a, TargetedResolved)
		s.e.clock.advance(time.Hour)
		s.e.w.RunOnce()
		got := s.e.row(s.u.ID)
		if got.State != model.NotificationDeliveryCanceled || got.EndReason != model.NotificationEndRequestResolved {
			t.Fatalf("第二次應取消: state=%s end=%q", got.State, got.EndReason)
		}
		if n := dmPosts(t, s.e); n != posts {
			t.Fatalf("取消後不應再送出個人訊息，送出數 %d → %d", posts, n)
		}
	})

	t.Run("(g) 外部查詢期間申請被核准：不送出、已取消、attempts 為 1、不再被認領", func(t *testing.T) {
		s := prepare(t)
		s.e.w.hooks.afterLookup = func(uint) { s.e.judge.setVerdict(s.a, TargetedResolved) }
		s.e.rounds(3, 2*time.Second)
		got := s.e.row(s.u.ID)
		if got.State != model.NotificationDeliveryCanceled || got.EndReason != model.NotificationEndRequestResolved || got.Attempts != 1 {
			t.Fatalf("state=%s end=%q attempts=%d", got.State, got.EndReason, got.Attempts)
		}
		for _, c := range s.e.slack.callsOf(slackPostMessageMethod) {
			if ch, _, _, _ := postBody(t, c); ch != tnlTarget {
				t.Fatalf("個人訊息不應送出（目的地 %s）", ch)
			}
		}
		if n := len(s.e.slack.callsOf(slackLookupByEmailMethod)); n != 1 {
			t.Fatalf("查詢應只有一次，得 %d", n)
		}
	})

	t.Run("(h) 第 1 次檢查取消時 attempts 不變", func(t *testing.T) {
		s := prepare(t)
		s.e.judge.setVerdict(s.a, TargetedResolved)
		s.e.w.RunOnce()
		if got := s.e.row(s.u.ID); got.Attempts != 0 {
			t.Fatalf("attempts = %d", got.Attempts)
		}
	})

	t.Run("(i) 第二次檢查 panic：以一次失敗收尾，反覆 panic 時在 48 次放棄", func(t *testing.T) {
		s := prepare(t)
		s.e.w.hooks.afterLookup = func(uint) {
			s.e.judge.mu.Lock()
			s.e.judge.panicVerdct = true
			s.e.judge.mu.Unlock()
		}
		s.e.w.RunOnce()
		got := s.e.row(s.u.ID)
		if got.State != model.NotificationDeliveryRetrying || got.Attempts != 1 {
			t.Fatalf("第一次 panic 後: state=%s attempts=%d", got.State, got.Attempts)
		}
		for i := 0; i < 200 && s.e.row(s.u.ID).State == model.NotificationDeliveryRetrying; i++ {
			s.e.clock.advance(3 * time.Hour)
			s.e.w.RunOnce()
		}
		got = s.e.row(s.u.ID)
		if got.State != model.NotificationDeliveryAbandoned || got.Attempts != notifyMaxAttempts || got.EndReason != model.NotificationEndMaxAttempts {
			t.Fatalf("應在 48 次放棄: state=%s attempts=%d end=%q", got.State, got.Attempts, got.EndReason)
		}
		for _, c := range s.e.slack.callsOf(slackPostMessageMethod) {
			if ch, _, _, _ := postBody(t, c); ch != tnlTarget {
				t.Fatal("檢查失敗時不應送出個人訊息")
			}
		}
	})

	t.Run("(k) 次數達上限而申請已被核准：掃描標為已取消、不產生彙總事件", func(t *testing.T) {
		s := prepare(t)
		s.e.db.Model(&model.NotificationDelivery{}).Where("id = ?", s.u.ID).
			Updates(map[string]any{"attempts": notifyMaxAttempts, "state": model.NotificationDeliveryRetrying})
		s.e.judge.setVerdict(s.a, TargetedResolved)
		s.e.w.scan()
		got := s.e.row(s.u.ID)
		if got.State != model.NotificationDeliveryCanceled || got.EndReason != model.NotificationEndRequestResolved {
			t.Fatalf("state=%s end=%q", got.State, got.EndReason)
		}
		if n := len(s.e.undeliveredMessages()); n != 0 {
			t.Fatalf("不應產生彙總事件，得 %d", n)
		}
	})
}

// ---- 3.4 電子郵件對應與快取 ----

func TestTargetedEmailMapping(t *testing.T) {
	t.Run("(a) 同一電子郵件一小時內只查一次；明確查無的十分鐘後重查", func(t *testing.T) {
		e := newTNLEnv(t)
		e.dmChannel("dm")
		a := e.user("r1", emailOf("r1"))
		e.judge.recipients = []uint{a}
		e.created(1)
		e.rounds(2, 2*time.Second)
		e.created(2)
		e.rounds(2, 2*time.Second)
		if n := len(e.slack.callsOf(slackLookupByEmailMethod)); n != 1 {
			t.Fatalf("一小時內應只查一次，得 %d", n)
		}
		if n := len(e.slack.callsOf(slackPostMessageMethod)); n != 4 {
			t.Fatalf("兩則通知應各有頻道與個人訊息，得 %d", n)
		}
		e.clock.advance(time.Hour)
		e.created(3)
		e.rounds(2, 2*time.Second)
		if n := len(e.slack.callsOf(slackLookupByEmailMethod)); n != 2 {
			t.Fatalf("過了一小時應重查，得 %d", n)
		}

		// 查無：十分鐘內不重查，之後重查
		b := e.user("r2", emailOf("r2"))
		e.slack.set(func(_ int, email string, w http.ResponseWriter) {
			jsonReply(200, `{"ok":false,"error":"users_not_found"}`)(w)
		}, nil)
		e.judge.recipients = []uint{b}
		e.created(4)
		e.rounds(2, 2*time.Second)
		before := len(e.slack.callsOf(slackLookupByEmailMethod))
		e.created(5)
		e.rounds(2, 2*time.Second)
		if n := len(e.slack.callsOf(slackLookupByEmailMethod)); n != before {
			t.Fatalf("十分鐘內不應重查查無的電子郵件: %d → %d", before, n)
		}
		e.clock.advance(10 * time.Minute)
		e.created(6)
		e.rounds(2, 2*time.Second)
		if n := len(e.slack.callsOf(slackLookupByEmailMethod)); n != before+1 {
			t.Fatalf("十分鐘後應重查: %d → %d", before, n)
		}
	})

	t.Run("(b) 電子郵件為空或不唯一時替身沒有收到任何請求、放棄且原因正確", func(t *testing.T) {
		e := newTNLEnv(t)
		e.dmChannel("dm")
		empty := e.user("noemail", nil)
		dup := e.user("dup1", emailOf("shared"))
		upper := " SHARED@reviewers.example "
		_ = e.user("dup2", &upper) // 正規化後相同、未刪除（不論是否啟用）
		disabledDup := e.user("dis1", emailOf("disabled"))
		_ = e.user("dis2", emailOf("disabled")) // 使用者表沒有啟用欄：未刪除即算
		softDel := e.user("soft1", emailOf("soft"))
		gone := e.user("soft2", emailOf("soft"))
		e.db.Exec(`UPDATE users SET deleted_at = ? WHERE id = ?`, e.clock.now(), gone)
		e.judge.recipients = []uint{empty, dup, disabledDup, softDel}
		e.created(1)
		e.rounds(6, 2*time.Second)
		rows := e.userRows()
		want := map[uint]string{empty: model.NotificationEndNoEmail, dup: model.NotificationEndEmailAmbiguous,
			disabledDup: model.NotificationEndEmailAmbiguous}
		for _, r := range rows {
			uid := *r.RecipientUserID
			if reason, ok := want[uid]; ok {
				if r.State != model.NotificationDeliveryAbandoned || r.EndReason != reason {
					t.Fatalf("收件人 %d: state=%s end=%q，預期放棄為 %s", uid, r.State, r.EndReason, reason)
				}
			} else if uid == softDel && r.State != model.NotificationDeliveryDelivered {
				t.Fatalf("與已軟刪帳號相同時應照常送出: %s", r.State)
			}
		}
		lookups := e.slack.callsOf(slackLookupByEmailMethod)
		if len(lookups) != 1 || lookups[0].Email != *emailOf("soft") {
			t.Fatalf("只有已軟刪重複的那一位應查詢，得 %d 次", len(lookups))
		}
	})

	t.Run("(c) 原位換 token 後正負快取都不再使用，改用新 token 查詢", func(t *testing.T) {
		e := newTNLEnv(t)
		ch := e.dmChannel("dm")
		a, b := e.user("r1", emailOf("r1")), e.user("r2", emailOf("r2"))
		e.slack.set(func(_ int, email string, w http.ResponseWriter) {
			if email == *emailOf("r2") {
				jsonReply(200, `{"ok":false,"error":"users_not_found"}`)(w)
				return
			}
			jsonReply(200, `{"ok":true,"user":{"id":"U0001"}}`)(w)
		}, nil)
		e.judge.recipients = []uint{a, b}
		e.created(1)
		e.rounds(4, 2*time.Second)
		if n := len(e.slack.callsOf(slackLookupByEmailMethod)); n != 2 {
			t.Fatalf("應各查一次，得 %d", n)
		}
		// 直接改資料列（不經服務，不清快取）：只靠鍵中的目的地版本避免沿用
		const newToken = "xoxb-1111-NEWTOKEN"
		e.db.Model(&model.NotificationChannel{}).Where("id = ?", ch.ID).
			Updates(map[string]any{"secret": newToken, "destination_version": gorm.Expr("destination_version + 1")})
		e.created(2)
		e.rounds(4, 2*time.Second)
		lookups := e.slack.callsOf(slackLookupByEmailMethod)
		if len(lookups) != 4 {
			t.Fatalf("換 token 後兩位都應重新查詢，總查詢 %d", len(lookups))
		}
		for _, c := range lookups[2:] {
			if c.Header.Get("Authorization") != "Bearer "+newToken {
				t.Fatalf("重新查詢應用新 token: %q", c.Header.Get("Authorization"))
			}
		}
	})

	for _, tc := range []struct {
		name    string
		respond func(http.ResponseWriter)
	}{
		{"未知錯誤碼", jsonReply(200, `{"ok":false,"error":"some_new_error"}`)},
		{"本文不是 JSON", jsonReply(200, `<html>oops</html>`)},
		{"HTTP 418", jsonReply(418, `{"ok":true,"user":{"id":"U1"}}`)},
	} {
		t.Run("(d) "+tc.name+"計次重送、不寫負快取、原因不是查無", func(t *testing.T) {
			e := newTNLEnv(t)
			e.dmChannel("dm")
			a := e.user("r1", emailOf("r1"))
			e.slack.set(func(_ int, _ string, w http.ResponseWriter) { tc.respond(w) }, nil)
			e.judge.recipients = []uint{a}
			e.created(1)
			e.w.RunOnce()
			u := e.userRows()[0]
			if u.State != model.NotificationDeliveryRetrying || u.Attempts != 1 || u.EndReason == model.NotificationEndRecipientNotFound {
				t.Fatalf("state=%s attempts=%d end=%q", u.State, u.Attempts, u.EndReason)
			}
			dmAddressCache.mu.Lock()
			n := len(dmAddressCache.m)
			dmAddressCache.mu.Unlock()
			if n != 0 {
				t.Fatalf("不應寫入快取，得 %d 筆", n)
			}
		})
	}

	for _, tc := range []struct {
		name string
		body string
	}{
		{"users_not_found", `{"ok":false,"error":"users_not_found"}`},
		{"已停用", `{"ok":true,"user":{"id":"U9","deleted":true}}`},
		{"機器人", `{"ok":true,"user":{"id":"U9","is_bot":true}}`},
	} {
		t.Run("(e) "+tc.name+"放棄為 recipient_not_found", func(t *testing.T) {
			e := newTNLEnv(t)
			e.dmChannel("dm")
			a := e.user("r1", emailOf("r1"))
			e.slack.set(func(_ int, _ string, w http.ResponseWriter) { jsonReply(200, tc.body)(w) }, nil)
			e.judge.recipients = []uint{a}
			e.created(1)
			e.rounds(2, 2*time.Second)
			u := e.userRows()[0]
			if u.State != model.NotificationDeliveryAbandoned || u.EndReason != model.NotificationEndRecipientNotFound {
				t.Fatalf("state=%s end=%q", u.State, u.EndReason)
			}
		})
	}

	t.Run("(f) 投遞紀錄、彙總事件、log 與 API 回應都不含電子郵件（含替身回顯）", func(t *testing.T) {
		e := newTNLEnv(t)
		ch := e.dmChannel("dm")
		email := emailOf("leak-check")
		a := e.user("r1", email)
		var buf bytes.Buffer
		prev := log.Writer()
		log.SetOutput(io.MultiWriter(&buf, prev))
		t.Cleanup(func() { log.SetOutput(prev) })
		e.slack.set(func(n int, em string, w http.ResponseWriter) {
			if n == 0 {
				jsonReply(500, `{"ok":false,"error":"internal `+em+`"}`)(w)
				return
			}
			jsonReply(200, `{"ok":false,"error":"`+em+`"}`)(w)
		}, nil)
		e.judge.recipients = []uint{a}
		e.created(1)
		e.rounds(3, 3*time.Second)
		e.slack.set(func(_ int, _ string, w http.ResponseWriter) {
			jsonReply(200, `{"ok":false,"error":"users_not_found"}`)(w)
		}, nil)
		e.clock.advance(time.Hour)
		e.rounds(2, 3*time.Second)
		svc := newChannelSvc(t, e.db, nil)
		page, err := svc.ListDeliveries(ch.ID, ChannelDeliveryQuery{})
		if err != nil {
			t.Fatal(err)
		}
		apiJSON, _ := json.Marshal(page)
		var dumps []string
		for _, r := range e.deliveries() {
			b, _ := json.Marshal(r)
			dumps = append(dumps, string(b))
		}
		for _, m := range e.messages() {
			b, _ := json.Marshal(m)
			dumps = append(dumps, string(b))
		}
		dumps = append(dumps, string(apiJSON), buf.String())
		for i, d := range dumps {
			if strings.Contains(strings.ToLower(d), strings.ToLower(*email)) {
				t.Fatalf("第 %d 份輸出含電子郵件", i)
			}
		}
		if len(e.undeliveredMessages()) != 1 {
			t.Fatal("應有一則彙總事件")
		}
	})

	t.Run("(g) 替身回 302 時不跟隨", func(t *testing.T) {
		e := newTNLEnv(t)
		e.dmChannel("dm")
		target := newStubSrv(t, nil, respondJSON(200, `{"ok":true,"user":{"id":"U1"}}`))
		a := e.user("r1", emailOf("r1"))
		e.slack.set(func(_ int, _ string, w http.ResponseWriter) {
			w.Header().Set("Location", target.srv.URL+"/api/users.lookupByEmail")
			w.WriteHeader(http.StatusFound)
		}, nil)
		e.judge.recipients = []uint{a}
		e.created(1)
		e.rounds(2, 2*time.Second)
		if target.count() != 0 {
			t.Fatalf("不應跟隨轉址，轉址目的地收到 %d 個請求", target.count())
		}
		if u := e.userRows()[0]; u.State != model.NotificationDeliveryRetrying || !strings.Contains(u.LastError, "3xx") {
			t.Fatalf("應為單筆失敗: state=%s last_error=%q", u.State, u.LastError)
		}
	})

	t.Run("(h) 網址改到清單外的主機：該主機沒有收到任何帶電子郵件的請求，個人紀錄以 direct_message_disabled 取消", func(t *testing.T) {
		e := newTNLEnv(t)
		ch := e.dmChannel("dm")
		a := e.user("r1", emailOf("r1"))
		e.judge.recipients = []uint{a}
		e.created(1)
		e.w.dispatchPending()
		outside := newDMSlackStub(t, e.clock)
		// localhost 不在 NOTIFY_DM_EXTRA_HOSTS（只列 127.0.0.1）
		outsideURL := strings.Replace(outside.srv.URL, "127.0.0.1", "localhost", 1)
		e.db.Model(&model.NotificationChannel{}).Where("id = ?", ch.ID).Update("url", outsideURL)
		e.rounds(2, 2*time.Second)
		if n := len(outside.callsOf(slackLookupByEmailMethod)); n != 0 {
			t.Fatalf("清單外主機不應收到查詢，得 %d", n)
		}
		if u := e.userRows()[0]; u.State != model.NotificationDeliveryCanceled || u.EndReason != model.NotificationEndDirectMessageDisabled {
			t.Fatalf("state=%s end=%q", u.State, u.EndReason)
		}
	})

	t.Run("(i) 送訊息回目的地使用者無效時計一次失敗，下一次重新查詢", func(t *testing.T) {
		e := newTNLEnv(t)
		e.dmChannel("dm")
		a := e.user("r1", emailOf("r1"))
		e.slack.set(nil, func(n int, w http.ResponseWriter) {
			// 第 0 則是頻道訊息，第 1 則是第一次個人訊息
			if n == 1 {
				jsonReply(200, `{"ok":false,"error":"channel_not_found"}`)(w)
				return
			}
			jsonReply(200, `{"ok":true}`)(w)
		})
		e.judge.recipients = []uint{a}
		e.created(1)
		e.w.RunOnce()
		if u := e.userRows()[0]; u.State != model.NotificationDeliveryRetrying || u.Attempts != 1 {
			t.Fatalf("應計一次失敗: state=%s attempts=%d", u.State, u.Attempts)
		}
		e.clock.advance(time.Minute)
		e.rounds(2, 2*time.Second)
		if n := len(e.slack.callsOf(slackLookupByEmailMethod)); n != 2 {
			t.Fatalf("下一次應重新查詢，查詢 %d 次", n)
		}
		if u := e.userRows()[0]; u.State != model.NotificationDeliveryDelivered {
			t.Fatalf("重新查詢後應送達: %s", u.State)
		}
	})
}

// ---- 3.5 私訊請求 ----

func TestTargetedDirectMessageRequest(t *testing.T) {
	e := newTNLEnv(t)
	e.dmChannel("dm")
	a := e.user("r1", emailOf("r1"))
	e.judge.recipients = []uint{a}
	e.created(42)
	e.rounds(3, 2*time.Second)
	posts := e.slack.callsOf(slackPostMessageMethod)
	if len(posts) != 2 {
		t.Fatalf("應有頻道與個人各一則，得 %d", len(posts))
	}
	var dmText, chText string
	for _, p := range posts {
		ch, text, ul, um := postBody(t, p)
		if ul || um {
			t.Fatal("兩個自動抓取旗標都應為 false")
		}
		if p.Header.Get("Authorization") != "Bearer "+tnlToken {
			t.Fatalf("授權標頭不符: %q", p.Header.Get("Authorization"))
		}
		switch ch {
		case e.slack.idFor(*emailOf("r1")):
			dmText = text
		case tnlTarget:
			chText = text
		default:
			t.Fatalf("非預期的目的地 %s", ch)
		}
	}
	dmFirst := strings.SplitN(dmText, "\n", 2)[0]
	if !strings.Contains(dmFirst, "待你審核 · ") {
		t.Fatalf("個人訊息第一行應帶定向標題: %q", dmFirst)
	}
	if strings.Contains(strings.SplitN(chText, "\n", 2)[0], "待你審核") {
		t.Fatalf("頻道訊息第一行不應帶定向標題: %q", chText)
	}
	if u := e.userRows()[0]; u.DestTarget != e.slack.idFor(*emailOf("r1")) {
		t.Fatalf("dest_target 應為解析出的 Slack 使用者識別碼: %q", u.DestTarget)
	}
}

// ---- 3.6 目的地分組 ----

func TestTargetedDestinationGrouping(t *testing.T) {
	setup := func(t *testing.T, n int) (*tnlEnv, model.NotificationChannel) {
		e := newTNLEnv(t)
		ch := e.dmChannel("dm")
		var ids []uint
		for i := 0; i < n; i++ {
			ids = append(ids, e.user(fmt.Sprintf("r%d", i), emailOf(fmt.Sprintf("r%d", i))))
		}
		e.judge.recipients = ids
		e.created(1)
		e.w.dispatchPending()
		return e, ch
	}

	t.Run("(a)(f) 一筆頻道紀錄與五十筆個人紀錄同時到期，頻道紀錄在第一輪送出、不受個人訊息節流影響", func(t *testing.T) {
		e, _ := setup(t, 50)
		e.w.RunOnce()
		if c := e.channelRows()[0]; c.State != model.NotificationDeliveryDelivered || c.ThrottledSince != nil {
			t.Fatalf("頻道紀錄應在第一輪送出且未被延後: state=%s throttled=%v", c.State, c.ThrottledSince)
		}
		// 之後才建立的頻道紀錄（編號在五十筆個人紀錄之後）也不排在個人訊息後面
		e.clock.advance(2 * time.Second)
		e.enqueueEvent(notifycat.EventAccessRequestApproved, map[string]string{"request_id": "1", "mode": "manual"})
		e.w.RunOnce()
		chans := e.channelRows()
		if last := chans[len(chans)-1]; last.State != model.NotificationDeliveryDelivered {
			t.Fatalf("後建立的頻道紀錄應在同一輪送出: state=%s", last.State)
		}
		pending := 0
		for _, u := range e.userRows() {
			if u.State == model.NotificationDeliveryPending {
				pending++
			}
		}
		if pending < 40 {
			t.Fatalf("前提：個人紀錄應大多仍在排隊，得 %d 筆等待中", pending)
		}
	})

	t.Run("(b) 個人訊息逾時：頻道紀錄不計次、個人紀錄此刻到期者各計一次", func(t *testing.T) {
		e, _ := setup(t, 3)
		e.w.httpTimeout = 300 * time.Millisecond
		e.slack.set(func(_ int, _ string, w http.ResponseWriter) {
			time.Sleep(600 * time.Millisecond)
			jsonReply(200, `{"ok":true,"user":{"id":"U1"}}`)(w)
		}, nil)
		e.w.RunOnce()
		if c := e.channelRows()[0]; c.State != model.NotificationDeliveryDelivered || c.Attempts != 1 {
			t.Fatalf("頻道紀錄: state=%s attempts=%d", c.State, c.Attempts)
		}
		for _, u := range e.userRows() {
			if u.Attempts != 1 || u.State != model.NotificationDeliveryRetrying {
				t.Fatalf("個人紀錄應各計一次: id=%d attempts=%d state=%s", u.ID, u.Attempts, u.State)
			}
		}
	})

	t.Run("(c) 個人訊息 429：只有被拒那一筆加一、其他延後 30 秒以上、頻道照送", func(t *testing.T) {
		e, _ := setup(t, 3)
		e.slack.set(func(_ int, _ string, w http.ResponseWriter) {
			w.Header().Set("Retry-After", "30")
			jsonReply(429, `{"ok":false,"error":"ratelimited"}`)(w)
		}, nil)
		t0 := e.clock.now()
		e.w.RunOnce()
		if c := e.channelRows()[0]; c.State != model.NotificationDeliveryDelivered {
			t.Fatalf("頻道紀錄應照送: %s", c.State)
		}
		rows := e.userRows()
		counted := 0
		for _, u := range rows {
			if u.Attempts == 1 {
				counted++
			} else if u.Attempts != 0 {
				t.Fatalf("其他個人紀錄不應計次: %d", u.Attempts)
			}
			if u.NextAttemptAt.Before(t0.Add(30 * time.Second)) {
				t.Fatalf("下次嘗試應不早於 30 秒後: %s", u.NextAttemptAt.Sub(t0))
			}
			if u.ThrottledSince == nil {
				t.Fatal("throttled_since 應已設")
			}
		}
		if counted != 1 {
			t.Fatalf("應只有一筆計次，得 %d", counted)
		}
	})

	t.Run("(d) 持續逾時下每筆次數隨時間增加並在 48 次放棄", func(t *testing.T) {
		e, _ := setup(t, 2)
		e.w.httpTimeout = 100 * time.Millisecond
		e.slack.set(func(_ int, _ string, w http.ResponseWriter) {
			time.Sleep(200 * time.Millisecond)
			jsonReply(200, `{}`)(w)
		}, nil)
		for i := 0; i < 120; i++ {
			done := true
			for _, u := range e.userRows() {
				if u.State != model.NotificationDeliveryAbandoned {
					done = false
				}
			}
			if done {
				break
			}
			e.w.RunOnce()
			e.clock.advance(3 * time.Hour)
		}
		for _, u := range e.userRows() {
			if u.State != model.NotificationDeliveryAbandoned || u.Attempts != notifyMaxAttempts || u.EndReason != model.NotificationEndMaxAttempts {
				t.Fatalf("id=%d state=%s attempts=%d end=%q", u.ID, u.State, u.Attempts, u.EndReason)
			}
		}
	})

	t.Run("(e) 持續限流下自第一次延後起 72 小時以 rate_limited 放棄並產生彙總事件", func(t *testing.T) {
		e, _ := setup(t, 2)
		e.slack.set(func(_ int, _ string, w http.ResponseWriter) {
			w.Header().Set("Retry-After", "3600")
			jsonReply(429, `{"ok":false,"error":"ratelimited"}`)(w)
		}, nil)
		for i := 0; i < 200; i++ {
			e.w.RunOnce()
			e.clock.advance(time.Hour)
			if rows := e.userRows(); rows[0].State == model.NotificationDeliveryAbandoned && rows[1].State == model.NotificationDeliveryAbandoned {
				break
			}
		}
		for _, u := range e.userRows() {
			if u.State != model.NotificationDeliveryAbandoned || u.EndReason != model.NotificationEndRateLimited {
				t.Fatalf("id=%d state=%s end=%q attempts=%d", u.ID, u.State, u.EndReason, u.Attempts)
			}
		}
		und := e.undeliveredMessages()
		if len(und) != 1 || msgParams(t, und[0])["reason"] != notifycat.TargetedReasonRateLimited {
			t.Fatalf("應產生一則 rate_limited 的彙總事件，得 %d", len(und))
		}
	})

	t.Run("(g) 快取全部未命中時查詢速率不超過每分鐘 50 次", func(t *testing.T) {
		e, _ := setup(t, 120)
		for i := 0; i < 200; i++ {
			e.w.RunOnce()
			e.clock.advance(time.Second)
		}
		lookups := e.slack.callsOf(slackLookupByEmailMethod)
		if len(lookups) < 50 {
			t.Fatalf("模擬 200 秒應有足夠的查詢可比對，得 %d", len(lookups))
		}
		for i := range lookups {
			n := 0
			for j := i; j < len(lookups) && lookups[j].At.Sub(lookups[i].At) < time.Minute; j++ {
				n++
			}
			if n > slackLookupPerMinute {
				t.Fatalf("自第 %d 次查詢起一分鐘內有 %d 次，超過 %d", i, n, slackLookupPerMinute)
			}
		}
	})
}

// ---- 3.7 未能送達事件 ----

func TestTargetedUndeliveredEvent(t *testing.T) {
	abandonFor := func(e *tnlEnv, emails ...*string) {
		var ids []uint
		for i, em := range emails {
			ids = append(ids, e.user(fmt.Sprintf("u%d", i), em))
		}
		e.judge.recipients = ids
	}

	t.Run("(a)(b)(e) 第一次產生一則、人數為去重收件人數、不含電子郵件與名稱；24 小時內不再產生", func(t *testing.T) {
		e := newTNLEnv(t)
		e.dmChannel("dm")
		abandonFor(e, nil, nil)
		e.created(1)
		e.rounds(3, 2*time.Second)
		und := e.undeliveredMessages()
		if len(und) != 1 {
			t.Fatalf("應產生一則，得 %d", len(und))
		}
		p := msgParams(t, und[0])
		if p["reason"] != notifycat.TargetedReasonNoEmail || p["event_kind"] != "" {
			t.Fatalf("參數不符: %v", p)
		}
		if p["count"] != "1" && p["count"] != "2" {
			t.Fatalf("人數應為截至當時的去重收件人數: %v", p)
		}
		raw := und[0].Params + und[0].NameRefs
		if strings.Contains(raw, "@") || strings.Contains(raw, "u0") || strings.Contains(raw, "u1") {
			t.Fatalf("事件不應含電子郵件或收件人名稱: %s", raw)
		}
		e.created(2)
		e.rounds(3, 2*time.Second)
		if n := len(e.undeliveredMessages()); n != 1 {
			t.Fatalf("24 小時內不應再產生，得 %d", n)
		}
		e.clock.advance(25 * time.Hour)
		e.created(3)
		e.rounds(3, 2*time.Second)
		und = e.undeliveredMessages()
		if len(und) != 2 {
			t.Fatalf("24 小時後應再產生，得 %d", len(und))
		}
	})

	t.Run("(d) 只有一個通道時它的頻道收到這則", func(t *testing.T) {
		e := newTNLEnv(t)
		dm := e.dmChannel("dm")
		abandonFor(e, nil)
		e.created(1)
		e.rounds(4, 2*time.Second)
		und := e.undeliveredMessages()
		if len(und) != 1 {
			t.Fatalf("應有一則，得 %d", len(und))
		}
		var row []model.NotificationDelivery
		e.db.Where("message_id = ?", und[0].ID).Find(&row)
		if len(row) != 1 || derefUint(row[0].SourceChannelID) != dm.ID || row[0].Audience != deliveryAudienceChannel {
			t.Fatalf("應送到那個通道的頻道: %+v", row)
		}
		if row[0].State != model.NotificationDeliveryDelivered {
			t.Fatalf("應已送達: %s", row[0].State)
		}
	})

	t.Run("(f) 個人紀錄放棄不產生投遞放棄通知、abandon_notified_at 不變；之後頻道紀錄放棄照常產生", func(t *testing.T) {
		e := newTNLEnv(t)
		dm := e.dmChannel("dm")
		abandonFor(e, nil)
		e.created(1)
		e.rounds(3, 2*time.Second)
		var abandonedNotices int64
		e.db.Model(&model.NotificationMessage{}).Where("event_key = ?", string(notifycat.EventNotificationDeliveryAbandoned)).Count(&abandonedNotices)
		if abandonedNotices != 0 {
			t.Fatalf("不應產生投遞放棄通知，得 %d", abandonedNotices)
		}
		var ch model.NotificationChannel
		e.db.First(&ch, dm.ID)
		if ch.AbandonNotifiedAt != nil {
			t.Fatal("abandon_notified_at 不應改變")
		}
		row := e.liveRow(dm.ID, model.AlertSeverityMedium, notifyMaxAttempts)
		e.w.scan()
		if got := e.row(row.ID); got.State != model.NotificationDeliveryAbandoned {
			t.Fatalf("頻道紀錄應放棄: %s", got.State)
		}
		e.db.Model(&model.NotificationMessage{}).Where("event_key = ?", string(notifycat.EventNotificationDeliveryAbandoned)).Count(&abandonedNotices)
		if abandonedNotices != 1 {
			t.Fatalf("頻道紀錄放棄應照常產生投遞放棄通知，得 %d", abandonedNotices)
		}
	})

	t.Run("(g) 掃描以 max_attempts 放棄且重驗仍成立時產生事件", func(t *testing.T) {
		e := newTNLEnv(t)
		e.dmChannel("dm")
		abandonFor(e, emailOf("x"))
		e.created(1)
		e.w.dispatchPending()
		u := e.userRows()[0]
		e.db.Model(&model.NotificationDelivery{}).Where("id = ?", u.ID).Updates(map[string]any{"attempts": notifyMaxAttempts, "state": model.NotificationDeliveryRetrying})
		e.w.scan()
		if got := e.row(u.ID); got.State != model.NotificationDeliveryAbandoned || got.EndReason != model.NotificationEndMaxAttempts {
			t.Fatalf("state=%s end=%q", got.State, got.EndReason)
		}
		und := e.undeliveredMessages()
		if len(und) != 1 || msgParams(t, und[0])["reason"] != notifycat.TargetedReasonMaxAttempts {
			t.Fatalf("應產生 max_attempts 的事件，得 %d", len(und))
		}
	})

	t.Run("(h) 沒有收件人或求得失敗時不帶人數、帶事件種類與單號，三語文案無空白欄位", func(t *testing.T) {
		for _, tc := range []struct {
			event notifycat.Event
			kind  string
			reqID string
		}{
			{notifycat.EventBreakGlassUsed, notifycat.TargetedKindBreakGlass, "9"},
			{notifycat.EventDailyReviewOverdue, notifycat.TargetedKindDailyReview, ""},
		} {
			e := newTNLEnv(t)
			e.dmChannel("dm")
			e.judge.err = errJudge
			params := map[string]string{"request_id": "9", "username": "bob", "duration_minutes": "30"}
			if tc.event == notifycat.EventDailyReviewOverdue {
				params = map[string]string{"date": "2026-11-19", "pending_dates": "2026-11-19", "pending_count": "1",
					"overdue_count": "1", "earliest_pending_date": "2026-11-19", "timezone": "Asia/Taipei"}
			}
			e.enqueueEvent(tc.event, params)
			e.w.dispatchPending()
			und := e.undeliveredMessages()
			if len(und) != 1 {
				t.Fatalf("%s: 應有一則，得 %d", tc.event, len(und))
			}
			p := msgParams(t, und[0])
			if p["count"] != "" || p["event_kind"] != tc.kind || p["request_id"] != tc.reqID {
				t.Fatalf("%s: 參數不符 %v", tc.event, p)
			}
			e.w.dispatchPending() // 分派彙總事件本身（解析通道名稱）
			var msg model.NotificationMessage
			e.db.First(&msg, und[0].ID)
			rp := msgParams(t, msg)
			for _, lang := range notifycat.SupportedLangs {
				title, text := notifycat.RenderLinked(lang, notifycat.EventTargetedNotificationUndelivered, rp, true)
				if title == "" || strings.Contains(text, "{") || strings.Contains(text, "「」") || strings.Contains(text, "\"\"") {
					t.Fatalf("%s %s 文案有空白欄位: %q", tc.event, lang, text)
				}
				if tc.reqID == "" && strings.Contains(text, "#") {
					t.Fatalf("每日審閱不應帶單號: %q", text)
				}
			}
		}
	})
}

// ---- 3.8 投遞紀錄與通道健康 ----

func TestTargetedDeliveryLogAndHealth(t *testing.T) {
	e := newTNLEnv(t)
	ch := e.dmChannel("dm")
	a := e.user("reviewer-a", emailOf("a"))
	b := e.user("reviewer-b", nil)
	e.judge.recipients = []uint{a, b}
	e.created(1)
	e.rounds(4, 2*time.Second)
	svc := newChannelSvc(t, e.db, nil)

	page, err := svc.ListDeliveries(ch.ID, ChannelDeliveryQuery{Audience: deliveryAudienceUser})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 {
		t.Fatalf("個人篩選應有 2 筆，得 %d", page.Total)
	}
	got := map[string]ChannelDelivery{}
	for _, r := range page.Rows {
		if r.Audience != deliveryAudienceUser {
			t.Fatalf("篩選後只應有個人紀錄: %s", r.Audience)
		}
		got[r.RecipientUsername] = r
	}
	if got["reviewer-a"].RecipientSlackID != e.slack.idFor(*emailOf("a")) || got["reviewer-a"].State != model.NotificationDeliveryDelivered {
		t.Fatalf("收件人 a 的列不符: %+v", got["reviewer-a"])
	}
	if got["reviewer-b"].EndReason != model.NotificationEndNoEmail || got["reviewer-b"].ReasonCode != "" {
		t.Fatalf("收件人 b 的列不符: %+v", got["reviewer-b"])
	}
	raw, _ := json.Marshal(page)
	if strings.Contains(string(raw), "@") || strings.Contains(string(raw), "reviewers.example") {
		t.Fatalf("回應不應含電子郵件: %s", raw)
	}
	if cp, _ := svc.ListDeliveries(ch.ID, ChannelDeliveryQuery{Audience: deliveryAudienceChannel}); cp.Total != int64(len(e.channelRows())) || cp.Total == 0 {
		t.Fatalf("頻道篩選筆數不符，得 %d", cp.Total)
	}
	if _, err := svc.ListDeliveries(ch.ID, ChannelDeliveryQuery{Audience: "everyone"}); err != ErrInvalidDeliveryAudience {
		t.Fatalf("不合格的篩選值應被拒: %v", err)
	}

	// 健康只統計頻道紀錄：個人紀錄放棄不影響放棄筆數與最近失敗
	list, err := svc.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range list {
		if c.ID == ch.ID {
			if c.Health == nil || c.Health.Abandoned7d != 0 || c.Health.LastFailedAt != nil || c.Health.LastDeliveredAt == nil {
				t.Fatalf("健康欄位不應受個人紀錄影響: %+v", c.Health)
			}
		}
	}
}

// dmPosts 替身收到的個人訊息（目的地不是通道目標頻道）數。
func dmPosts(t *testing.T, e *tnlEnv) int {
	t.Helper()
	n := 0
	for _, c := range e.slack.callsOf(slackPostMessageMethod) {
		if ch, _, _, _ := postBody(t, c); ch != tnlTarget {
			n++
		}
	}
	return n
}
