package authz

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/notifycat"
	"gorm.io/gorm"
)

// 連線申請族、破窗與補審逾期的通知內容（通知投遞層段 C）：排入時機、名稱參照與故障注入。

// noticeEnv 申請流服務接上排入介面，並可讓通知內容的 INSERT 失敗。
type noticeEnv struct {
	svc      *AccessRequestService
	policies *policy.SecurityPolicyService
	db       *gorm.DB
	fail     atomic.Bool
}

func newNoticeEnv(t *testing.T) *noticeEnv {
	t.Helper()
	svc, policies, db := setupAccessRequestEnv(t)
	seedRequestFixture(t, db)
	if err := db.AutoMigrate(&model.NotificationMessage{}, &model.NotificationDelivery{}, &model.SystemAlertDetail{}); err != nil {
		t.Fatal(err)
	}
	e := &noticeEnv{svc: svc, policies: policies, db: db}
	svc.notifier = audit.NewAlertNotifier(db, nil)
	name := "test:fail_request_notice"
	if err := db.Callback().Create().Before("gorm:create").Register(name, func(d *gorm.DB) {
		if e.fail.Load() && d.Statement != nil && d.Statement.Table == "notification_messages" {
			_ = d.AddError(errors.New("injected notification_messages insert failure"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	return e
}

// approvalAsset 新增一台需審核的資產並給 user 1 常設 connect。
func (e *noticeEnv) approvalAsset(t *testing.T, name string) uint {
	t.Helper()
	approval := model.AccessPolicyApproval
	a := model.Asset{Name: name, Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 3, AccessPolicy: &approval}
	if err := e.db.Create(&a).Error; err != nil {
		t.Fatal(err)
	}
	u := uint(1)
	if err := e.db.Create(&model.AssetAuthorization{UserID: &u, AssetID: &a.ID, Permission: model.PermissionConnect, GrantedBy: 3}).Error; err != nil {
		t.Fatal(err)
	}
	return a.ID
}

func (e *noticeEnv) messages(t *testing.T) []model.NotificationMessage {
	t.Helper()
	var rows []model.NotificationMessage
	if err := e.db.Order("id").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}

func noticeRefs(t *testing.T, m model.NotificationMessage) map[string]audit.NotificationNameRef {
	t.Helper()
	out := map[string]audit.NotificationNameRef{}
	if err := json.Unmarshal([]byte(m.NameRefs), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func noticeParams(t *testing.T, m model.NotificationMessage) map[string]string {
	t.Helper()
	out := map[string]string{}
	if err := json.Unmarshal([]byte(m.Params), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// dispatch 跑一輪投遞程序（沒有通道時只解析名稱並標為已分派）。
func (e *noticeEnv) dispatch(t *testing.T) []model.NotificationMessage {
	t.Helper()
	w := audit.NewSystemAlertOutboxWorker(e.db, nil)
	w.RunOnce()
	return e.messages(t)
}

func TestAccessRequestNoticeContent(t *testing.T) {
	t.Run("三項申請建立：台數 3、資產參照指向第一項、申請人參照、整小時帶時長", func(t *testing.T) {
		e := newNoticeEnv(t)
		a4, a5 := e.approvalAsset(t, "db-04"), e.approvalAsset(t, "db-05")
		req, err := e.svc.Submit(1, "requester", false, SubmitAccessRequestInput{Reason: "維護", DurationMinutes: 120,
			Items: []ItemInput{{AssetID: 1}, {AssetID: a4}, {AssetID: a5}}})
		if err != nil {
			t.Fatal(err)
		}
		msgs := e.messages(t)
		if len(msgs) != 1 || msgs[0].EventKey != string(notifycat.EventAccessRequestCreated) {
			t.Fatalf("應有一列建立通知: %+v", msgs)
		}
		p, refs := noticeParams(t, msgs[0]), noticeRefs(t, msgs[0])
		if p["asset_count"] != "3" || p["request_id"] != strconv.FormatUint(uint64(req.ID), 10) || p["duration_hours"] != "2" {
			t.Fatalf("參數不符: %v", p)
		}
		if refs["asset_name"].ID != 1 || refs["requester_name"].ID != 1 {
			t.Fatalf("名稱參照不符: %v", refs)
		}
		if _, ok := p["reason"]; ok {
			t.Fatal("通知不得帶申請事由")
		}
		got := e.dispatch(t)
		dp := noticeParams(t, got[0])
		if dp["asset_name"] != "a-approval" || dp["requester_name"] != "requester" {
			t.Fatalf("分派後名稱不符: %v", dp)
		}
	})

	t.Run("撤銷：帶收線中斷的連線數，沒有聯動收線時不帶", func(t *testing.T) {
		for _, withSessions := range []bool{true, false} {
			e := newNoticeEnv(t)
			if withSessions {
				e.svc.sessions = &itemTerminations{}
				if _, err := e.policies.Update(policy.PolicyAccessRevokeDisconnect, "true", "admin"); err != nil {
					t.Fatal(err)
				}
			}
			req := submitBasic(t, e.svc, 1, 1)
			if _, err := e.svc.Approve(3, true, req.ID, DecideInput{Note: "ok"}); err != nil {
				t.Fatal(err)
			}
			if _, err := e.svc.Revoke(3, true, "boss", req.ID, "人員異動"); err != nil {
				t.Fatal(err)
			}
			msgs := e.messages(t)
			last := msgs[len(msgs)-1]
			if last.EventKey != string(notifycat.EventTicketRevoked) {
				t.Fatalf("最後一列應為撤銷通知: %s", last.EventKey)
			}
			if last.ActorUserID == nil || *last.ActorUserID != 3 {
				t.Fatalf("撤銷通知的操作者應為撤銷者 3: %v", last.ActorUserID)
			}
			p := noticeParams(t, last)
			n, err := strconv.Atoi(p["disconnected_count"])
			switch {
			case withSessions && (err != nil || n < 1):
				t.Fatalf("聯動收線時應帶中斷的連線數: %v", p)
			case !withSessions && p["disconnected_count"] != "":
				t.Fatalf("沒有聯動收線時不應帶斷線數: %v", p)
			}
			if withSessions {
				title, text := notifycat.RenderLinked("zh-TW", notifycat.EventTicketRevoked, p, false)
				if !strings.Contains(text, "中斷 "+p["disconnected_count"]+" 條連線") {
					t.Fatalf("文字應含斷線數: %s %s", title, text)
				}
			}
		}
	})

	t.Run("人工核准：名稱參照含決定者，分派後 decider_name 為其登入帳號", func(t *testing.T) {
		e := newNoticeEnv(t)
		req := submitBasic(t, e.svc, 1, 1)
		if _, err := e.svc.Approve(3, true, req.ID, DecideInput{Note: "ok"}); err != nil {
			t.Fatal(err)
		}
		msgs := e.messages(t)
		last := msgs[len(msgs)-1]
		if last.EventKey != string(notifycat.EventAccessRequestApproved) {
			t.Fatalf("最後一列應為核准通知: %s", last.EventKey)
		}
		if refs := noticeRefs(t, last); refs["decider_name"].ID != 3 {
			t.Fatalf("決定者參照應為 3: %v", refs)
		}
		got := e.dispatch(t)
		if dp := noticeParams(t, got[len(got)-1]); dp["decider_name"] != "boss" || dp["mode"] != notifycat.ApprovalModeManual {
			t.Fatalf("分派後決定者名稱不符: %v", dp)
		}
	})

	t.Run("審核人下修時長：通知寫核准的時長，不寫申請時長", func(t *testing.T) {
		e := newNoticeEnv(t)
		req, err := e.svc.Submit(1, "requester", false, SubmitAccessRequestInput{AssetID: 1, Reason: "維護", DurationMinutes: 90})
		if err != nil {
			t.Fatal(err)
		}
		short := 30
		if _, err := e.svc.Approve(3, true, req.ID, DecideInput{DurationMinutes: &short, Note: "ok"}); err != nil {
			t.Fatal(err)
		}
		msgs := e.messages(t)
		last := msgs[len(msgs)-1]
		if last.EventKey != string(notifycat.EventAccessRequestApproved) {
			t.Fatalf("最後一列應為核准通知: %s", last.EventKey)
		}
		if p := noticeParams(t, last); p["duration_minutes"] != "30" || p["duration_hours"] != "" {
			t.Fatalf("核准通知的時長應為核准的 30 分鐘、不帶整小時參數: %v", p)
		}
		got := e.dispatch(t)
		dp := noticeParams(t, got[len(got)-1])
		_, zh := notifycat.RenderLinked("zh-TW", notifycat.EventAccessRequestApproved, dp, false)
		if !strings.Contains(zh, "可連線 30 分鐘") || strings.Contains(zh, "1 小時 30 分鐘") {
			t.Fatalf("文字應寫核准的 30 分鐘: %s", zh)
		}
	})

	t.Run("照申請內容核准：通知的時長等於申請時長", func(t *testing.T) {
		e := newNoticeEnv(t)
		req, err := e.svc.Submit(1, "requester", false, SubmitAccessRequestInput{AssetID: 1, Reason: "維護", DurationMinutes: 90})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.svc.Approve(3, true, req.ID, DecideInput{Note: "ok"}); err != nil {
			t.Fatal(err)
		}
		msgs := e.messages(t)
		if p := noticeParams(t, msgs[len(msgs)-1]); p["duration_minutes"] != "90" {
			t.Fatalf("照申請核准時時長應為 90 分鐘: %v", p)
		}
	})

	t.Run("一次核准兩項而時長不同：通知不帶時長，不以其中一項代表全部", func(t *testing.T) {
		e := newNoticeEnv(t)
		a4 := e.approvalAsset(t, "db-04")
		req, err := e.svc.Submit(1, "requester", false, SubmitAccessRequestInput{Reason: "維護", DurationMinutes: 120,
			Items: []ItemInput{{AssetID: 1}, {AssetID: a4}}})
		if err != nil {
			t.Fatal(err)
		}
		var items []model.AccessRequestItem
		e.db.Where("request_id = ?", req.ID).Order("id").Find(&items)
		d1, d2 := 30, 60
		if _, err := e.svc.Approve(3, true, req.ID, DecideInput{Note: "ok", Items: []ItemDecision{
			{ItemID: items[0].ID, DurationMinutes: &d1}, {ItemID: items[1].ID, DurationMinutes: &d2}}}); err != nil {
			t.Fatal(err)
		}
		msgs := e.messages(t)
		last := msgs[len(msgs)-1]
		if last.EventKey != string(notifycat.EventAccessRequestApproved) {
			t.Fatalf("最後一列應為核准通知: %s", last.EventKey)
		}
		if p := noticeParams(t, last); p["duration_minutes"] != "" || p["duration_hours"] != "" {
			t.Fatalf("各項時長不同時不應帶時長: %v", p)
		}
		got := e.dispatch(t)
		dp := noticeParams(t, got[len(got)-1])
		_, zh := notifycat.RenderLinked("zh-TW", notifycat.EventAccessRequestApproved, dp, false)
		if strings.Contains(zh, "可連線") {
			t.Fatalf("各項時長不同時文字不應寫可連線多久: %s", zh)
		}
		// 兩項下修成同一個時長：帶該時長
		e2 := newNoticeEnv(t)
		b4 := e2.approvalAsset(t, "db-04")
		req2, err := e2.svc.Submit(1, "requester", false, SubmitAccessRequestInput{Reason: "維護", DurationMinutes: 120,
			Items: []ItemInput{{AssetID: 1}, {AssetID: b4}}})
		if err != nil {
			t.Fatal(err)
		}
		var items2 []model.AccessRequestItem
		e2.db.Where("request_id = ?", req2.ID).Order("id").Find(&items2)
		same := 45
		if _, err := e2.svc.Approve(3, true, req2.ID, DecideInput{Note: "ok", Items: []ItemDecision{
			{ItemID: items2[0].ID, DurationMinutes: &same}, {ItemID: items2[1].ID, DurationMinutes: &same}}}); err != nil {
			t.Fatal(err)
		}
		msgs2 := e2.messages(t)
		if p := noticeParams(t, msgs2[len(msgs2)-1]); p["duration_minutes"] != "45" {
			t.Fatalf("兩項同為 45 分鐘時應帶 45: %v", p)
		}
	})

	t.Run("兩項申請只核准一項：逐項句型帶被核准的那一項與仍待審項數，操作者是決定者", func(t *testing.T) {
		e := newNoticeEnv(t)
		a4 := e.approvalAsset(t, "db-04")
		req, err := e.svc.Submit(1, "requester", false, SubmitAccessRequestInput{Reason: "維護", DurationMinutes: 120,
			Items: []ItemInput{{AssetID: 1}, {AssetID: a4}}})
		if err != nil {
			t.Fatal(err)
		}
		var items []model.AccessRequestItem
		e.db.Where("request_id = ?", req.ID).Order("id").Find(&items)
		if _, err := e.svc.Approve(3, true, req.ID, DecideInput{ItemID: items[1].ID, Note: "ok"}); err != nil {
			t.Fatal(err)
		}
		msgs := e.messages(t)
		last := msgs[len(msgs)-1]
		if last.EventKey != string(notifycat.EventAccessRequestApproved) {
			t.Fatalf("應為核准通知: %s", last.EventKey)
		}
		refs, p := noticeRefs(t, last), noticeParams(t, last)
		if refs["item_asset_name"].ID != a4 || refs["asset_name"].ID != 1 || refs["decider_name"].ID != 3 {
			t.Fatalf("逐項核准的參照不符: %v", refs)
		}
		if p["pending_item_count"] != "1" || p["asset_count"] != "2" || p["mode"] != notifycat.ApprovalModeManual {
			t.Fatalf("逐項核准的參數不符: %v", p)
		}
		if last.ActorUserID == nil || *last.ActorUserID != 3 {
			t.Fatalf("操作者應為決定者 3: %v", last.ActorUserID)
		}
		got := e.dispatch(t)
		dp := noticeParams(t, got[len(got)-1])
		for _, lang := range notifycat.SupportedLangs {
			_, text := notifycat.RenderLinked(lang, notifycat.EventAccessRequestApproved, dp, false)
			if !strings.Contains(text, "db-04") || !strings.Contains(text, "1") {
				t.Fatalf("%s 文字應指明被核准的那一項與仍待審項數: %s", lang, text)
			}
		}
		_, zh := notifycat.RenderLinked("zh-TW", notifycat.EventAccessRequestApproved, dp, false)
		if !strings.Contains(zh, "db-04 已由 boss 核准，這次核准不含其他項目") || !strings.Contains(zh, "另有 1 項仍待審") || strings.Contains(zh, "的申請已由") {
			t.Fatalf("逐項核准不得用整單措辭: %s", zh)
		}
		// 再單獨核准最後一項：這次核准仍沒有涵蓋整張申請，維持逐項句型，只是不再帶待審項數
		if _, err := e.svc.Approve(3, true, req.ID, DecideInput{ItemID: items[0].ID, Note: "ok"}); err != nil {
			t.Fatal(err)
		}
		msgs = e.messages(t)
		lastP, lastRefs := noticeParams(t, msgs[len(msgs)-1]), noticeRefs(t, msgs[len(msgs)-1])
		if lastP["pending_item_count"] != "" || lastRefs["item_asset_name"].ID != 1 {
			t.Fatalf("單獨核准最後一項：逐項句型、不帶待審項數: %v %v", lastP, lastRefs)
		}
	})

	// 逐項核准的三種涵蓋情形（驗收複驗 P1）
	approvedText := func(t *testing.T, e *noticeEnv) (map[string]string, map[string]audit.NotificationNameRef, map[string]string) {
		t.Helper()
		msgs := e.messages(t)
		last := msgs[len(msgs)-1]
		if last.EventKey != string(notifycat.EventAccessRequestApproved) {
			t.Fatalf("最後一列應為核准通知: %s", last.EventKey)
		}
		p, refs := noticeParams(t, last), noticeRefs(t, last)
		got := e.dispatch(t)
		dp := noticeParams(t, got[len(got)-1])
		texts := map[string]string{}
		for _, lang := range notifycat.SupportedLangs {
			_, texts[lang] = notifycat.RenderLinked(lang, notifycat.EventAccessRequestApproved, dp, false)
		}
		return p, refs, texts
	}
	t.Run("拒一核一：核准最後一項仍用逐項句型，看得出只核准這一項", func(t *testing.T) {
		e := newNoticeEnv(t)
		a4 := e.approvalAsset(t, "db-04")
		req, err := e.svc.Submit(1, "requester", false, SubmitAccessRequestInput{Reason: "維護", DurationMinutes: 120,
			Items: []ItemInput{{AssetID: 1}, {AssetID: a4}}})
		if err != nil {
			t.Fatal(err)
		}
		var items []model.AccessRequestItem
		e.db.Where("request_id = ?", req.ID).Order("id").Find(&items)
		if _, err := e.svc.RejectItem(3, true, req.ID, items[0].ID, "不需要"); err != nil {
			t.Fatal(err)
		}
		if _, err := e.svc.Approve(3, true, req.ID, DecideInput{ItemID: items[1].ID, Note: "ok"}); err != nil {
			t.Fatal(err)
		}
		p, refs, texts := approvedText(t, e)
		if refs["item_asset_name"].ID != a4 || p["pending_item_count"] != "" || p["approved_item_count"] != "" || p["asset_count"] != "2" {
			t.Fatalf("拒一核一的參數不符: %v %v", p, refs)
		}
		want := map[string]string{"zh-TW": "db-04 已由 boss 核准，這次核准不含其他項目", "en-US": "The db-04 item of the request from requester was approved by boss; this approval does not cover the other items",
			"ja-JP": "申請のうち db-04 が boss により承認されました。今回の承認にほかの項目は含まれません"}
		for lang, w := range want {
			if !strings.Contains(texts[lang], w) {
				t.Fatalf("%s 應含 %q: %s", lang, w, texts[lang])
			}
			if strings.Contains(texts[lang], "仍待審") || strings.Contains(texts[lang], "awaiting review") || strings.Contains(texts[lang], "審査待ち") {
				t.Fatalf("%s 沒有待審項時不寫待審: %s", lang, texts[lang])
			}
		}
	})

	t.Run("拒一核二：一次核准多項但不是全部，帶這次核准的項數", func(t *testing.T) {
		e := newNoticeEnv(t)
		a4, a5 := e.approvalAsset(t, "db-04"), e.approvalAsset(t, "db-05")
		req, err := e.svc.Submit(1, "requester", false, SubmitAccessRequestInput{Reason: "維護", DurationMinutes: 45,
			Items: []ItemInput{{AssetID: 1}, {AssetID: a4}, {AssetID: a5}}})
		if err != nil {
			t.Fatal(err)
		}
		var items []model.AccessRequestItem
		e.db.Where("request_id = ?", req.ID).Order("id").Find(&items)
		if _, err := e.svc.RejectItem(3, true, req.ID, items[0].ID, "不需要"); err != nil {
			t.Fatal(err)
		}
		if _, err := e.svc.Approve(3, true, req.ID, DecideInput{Items: []ItemDecision{{ItemID: items[1].ID}, {ItemID: items[2].ID}}, Note: "ok"}); err != nil {
			t.Fatal(err)
		}
		p, refs, texts := approvedText(t, e)
		if refs["item_asset_name"].ID != a4 || p["approved_item_count"] != "2" || p["pending_item_count"] != "" || p["asset_count"] != "3" {
			t.Fatalf("拒一核二的參數不符: %v %v", p, refs)
		}
		want := map[string]string{"zh-TW": "db-04 等 2 項已由 boss 核准，這次核准不含其他項目", "en-US": "The db-04 item (with others, 2 items in total)",
			"ja-JP": "db-04 ほか計 2 項目が boss により承認されました"}
		for lang, w := range want {
			if !strings.Contains(texts[lang], w) {
				t.Fatalf("%s 應含 %q: %s", lang, w, texts[lang])
			}
		}
	})

	t.Run("全部一次核准：整單句型，不帶逐項參數", func(t *testing.T) {
		e := newNoticeEnv(t)
		a4 := e.approvalAsset(t, "db-04")
		req, err := e.svc.Submit(1, "requester", false, SubmitAccessRequestInput{Reason: "維護", DurationMinutes: 120,
			Items: []ItemInput{{AssetID: 1}, {AssetID: a4}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.svc.Approve(3, true, req.ID, DecideInput{Note: "ok"}); err != nil {
			t.Fatal(err)
		}
		p, refs, texts := approvedText(t, e)
		if refs["item_asset_name"].ID != 0 || p["approved_item_count"] != "" || p["pending_item_count"] != "" {
			t.Fatalf("全部一次核准不帶逐項參數: %v %v", p, refs)
		}
		if !strings.Contains(texts["zh-TW"], "requester 的申請已由 boss 核准") || !strings.Contains(texts["ja-JP"], "requester の申請が boss により承認されました") {
			t.Fatalf("全部一次核准用整單句型: %v", texts)
		}
	})

	t.Run("申請時長以分鐘帶：不足一小時與非整小時都帶，整小時另帶既有的小時數", func(t *testing.T) {
		for _, tc := range []struct {
			minutes int
			hours   string
			zh, en  string
			ja      string
		}{
			{45, "", "45 分鐘", "45 minutes", "45 分"},
			{90, "", "1 小時 30 分鐘", "1 hour 30 minutes", "1 時間 30 分"},
			{120, "2", "2 小時", "2 hours", "2 時間"},
		} {
			e := newNoticeEnv(t)
			if _, err := e.svc.Submit(1, "requester", false, SubmitAccessRequestInput{Reason: "維護", DurationMinutes: tc.minutes,
				Items: []ItemInput{{AssetID: 1}}}); err != nil {
				t.Fatal(err)
			}
			msgs := e.messages(t)
			p := noticeParams(t, msgs[len(msgs)-1])
			if p["duration_minutes"] != strconv.Itoa(tc.minutes) || p["duration_hours"] != tc.hours {
				t.Fatalf("%d 分鐘：參數不符: %v", tc.minutes, p)
			}
			for lang, want := range map[string]string{"zh-TW": tc.zh, "en-US": tc.en, "ja-JP": tc.ja} {
				_, text := notifycat.RenderLinked(lang, notifycat.EventAccessRequestCreated, p, false)
				if !strings.Contains(text, want) {
					t.Fatalf("%d 分鐘 %s：文字應含 %q: %s", tc.minutes, lang, want, text)
				}
			}
		}
	})

	t.Run("逐項拒絕：被拒那一項的資產識別碼；整單拒絕不帶逐項資產", func(t *testing.T) {
		e := newNoticeEnv(t)
		a4 := e.approvalAsset(t, "db-04")
		req, err := e.svc.Submit(1, "requester", false, SubmitAccessRequestInput{Reason: "維護", DurationMinutes: 60,
			Items: []ItemInput{{AssetID: 1}, {AssetID: a4}}})
		if err != nil {
			t.Fatal(err)
		}
		var items []model.AccessRequestItem
		e.db.Where("request_id = ?", req.ID).Order("id").Find(&items)
		if _, err := e.svc.RejectItem(3, true, req.ID, items[1].ID, "不需要"); err != nil {
			t.Fatal(err)
		}
		msgs := e.messages(t)
		last := msgs[len(msgs)-1]
		if last.EventKey != string(notifycat.EventAccessRequestRejected) {
			t.Fatalf("應為拒絕通知: %s", last.EventKey)
		}
		refs := noticeRefs(t, last)
		if refs["item_asset_name"].ID != a4 || refs["asset_name"].ID != 1 || refs["decider_name"].ID != 3 {
			t.Fatalf("逐項拒絕的參照不符: %v", refs)
		}
		if p := noticeParams(t, last); p["asset_count"] != "2" {
			t.Fatalf("台數應為整單總數 2: %v", p)
		}
		if last.ActorUserID == nil || *last.ActorUserID != 3 {
			t.Fatalf("拒絕通知的操作者應為決定者 3: %v", last.ActorUserID)
		}
		if _, err := e.svc.Reject(3, true, req.ID, "整單不需要"); err != nil {
			t.Fatal(err)
		}
		msgs = e.messages(t)
		if refs := noticeRefs(t, msgs[len(msgs)-1]); refs["item_asset_name"].ID != 0 {
			t.Fatalf("整單拒絕不得帶逐項資產: %v", refs)
		}
	})

	t.Run("以移除方式拒掉的項目不產生內容列", func(t *testing.T) {
		e := newNoticeEnv(t)
		a4 := e.approvalAsset(t, "db-04")
		req, err := e.svc.Submit(1, "requester", false, SubmitAccessRequestInput{Reason: "維護", DurationMinutes: 60,
			Items: []ItemInput{{AssetID: 1}, {AssetID: a4}}})
		if err != nil {
			t.Fatal(err)
		}
		var items []model.AccessRequestItem
		e.db.Where("request_id = ?", req.ID).Order("id").Find(&items)
		before := len(e.messages(t))
		if _, err := e.svc.Approve(3, true, req.ID, DecideInput{ItemID: items[1].ID, Remove: true, Note: "移除"}); err != nil {
			t.Fatal(err)
		}
		if after := len(e.messages(t)); after != before {
			t.Fatalf("移除不應產生通知內容，前 %d 後 %d", before, after)
		}
	})

	t.Run("核准交易在後續步驟回滾時內容列為 0", func(t *testing.T) {
		e := newNoticeEnv(t)
		req := submitBasic(t, e.svc, 1, 1)
		before := len(e.messages(t))
		// 讓核准交易最後一步（寫決定備註）失敗：觸發器擋下 decision_note 的更新
		if err := e.db.Exec(`CREATE TRIGGER fail_decision_note BEFORE UPDATE OF decision_note ON access_requests
			BEGIN SELECT RAISE(ABORT, 'injected'); END`).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := e.svc.Approve(3, true, req.ID, DecideInput{Note: "ok"}); err == nil {
			t.Fatal("核准應失敗")
		}
		if after := len(e.messages(t)); after != before {
			t.Fatalf("回滾後不得留下內容列，前 %d 後 %d", before, after)
		}
	})

	t.Run("破窗的內容列寫不進去：破窗單與臨時授權已提交、回成功", func(t *testing.T) {
		e := newNoticeEnv(t)
		grantConnect(t, e.db, 1, 1)
		enableBreakGlass(t, e.policies)
		e.fail.Store(true)
		req, err := e.svc.BreakGlass(1, "requester", false, 1, "半夜事故")
		if err != nil {
			t.Fatalf("通知寫不進去不得讓破窗失敗: %v", err)
		}
		if req.Status != model.AccessRequestApproved || req.AuthorizationID == nil {
			t.Fatalf("破窗單應已核准並有臨時授權: %+v", req)
		}
		if n := len(e.messages(t)); n != 0 {
			t.Fatalf("內容列應為 0，得 %d", n)
		}
		e.fail.Store(false)
		req2, err := e.svc.BreakGlass(1, "requester", false, 2, "另一台")
		if err != nil {
			// 資產 2 為理由段（不需破窗）時改用第二台需審核資產
			a4 := e.approvalAsset(t, "db-04")
			grantConnect(t, e.db, 1, a4)
			if req2, err = e.svc.BreakGlass(1, "requester", false, a4, "另一台"); err != nil {
				t.Fatal(err)
			}
		}
		msgs := e.messages(t)
		if len(msgs) != 1 || msgs[0].EventKey != string(notifycat.EventBreakGlassUsed) {
			t.Fatalf("應有一列破窗通知: %+v", msgs)
		}
		refs := noticeRefs(t, msgs[0])
		if refs["username"].ID != 1 || refs["asset_name"].ID != req2.AssetID {
			t.Fatalf("破窗通知的參照不符: %v", refs)
		}
		got := e.dispatch(t)
		if dp := noticeParams(t, got[0]); dp["username"] != "requester" || got[0].Degraded {
			t.Fatalf("分派後破窗人應為登入帳號且不降級: %v degraded=%v", dp, got[0].Degraded)
		}
	})
}

func TestBreakGlassOverdueNoticeSharesThrottleTx(t *testing.T) {
	e := newNoticeEnv(t)
	grantConnect(t, e.db, 1, 1)
	enableBreakGlass(t, e.policies)
	req, err := e.svc.BreakGlass(1, "requester", false, 1, "半夜事故")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.policies.Update(policy.PolicyBreakGlassReviewTimeoutHours, "1", "admin"); err != nil {
		t.Fatal(err)
	}
	e.db.Where("event_key = ?", string(notifycat.EventBreakGlassUsed)).Delete(&model.NotificationMessage{})
	base := time.Now()

	e.fail.Store(true)
	notified, err := e.svc.NotifyOverdueReviews(base.Add(2 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var row model.AccessRequest
	e.db.First(&row, req.ID)
	if notified != 0 || row.ReviewOverdueNotifiedAt != nil {
		t.Fatalf("寫不進去時節流欄應維持原值: notified=%d at=%v", notified, row.ReviewOverdueNotifiedAt)
	}
	e.fail.Store(false)
	notified, err = e.svc.NotifyOverdueReviews(base.Add(2*time.Hour + 5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	e.db.First(&row, req.ID)
	msgs := e.messages(t)
	if notified != 1 || row.ReviewOverdueNotifiedAt == nil || len(msgs) != 1 {
		t.Fatalf("下一輪應兩者都寫入: notified=%d at=%v msgs=%d", notified, row.ReviewOverdueNotifiedAt, len(msgs))
	}
	if refs := noticeRefs(t, msgs[0]); refs["requester_name"].ID != 1 || refs["asset_name"].ID != 1 {
		t.Fatalf("逾期通知的參照不符: %v", refs)
	}
	again, err := e.svc.NotifyOverdueReviews(base.Add(3 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if again != 0 || len(e.messages(t)) != 1 {
		t.Fatalf("節流時間內不得產生第二列: again=%d msgs=%d", again, len(e.messages(t)))
	}
}

// TestRequestNoticeNamesAreLoginAccounts 人員名稱一律是登入帳號：申請人、破窗人、決定者改了自助顯示名稱，
// 分派後的參數仍是 users.username，不出現顯示名稱。
func TestRequestNoticeNamesAreLoginAccounts(t *testing.T) {
	e := newNoticeEnv(t)
	display := "https://evil.example.test 顯示名"
	e.db.Model(&model.User{}).Where("id IN ?", []uint{1, 3}).Update("local_display_name", display)
	grantConnect(t, e.db, 1, 1)
	enableBreakGlass(t, e.policies)
	req := submitBasic(t, e.svc, 1, 2)
	_ = req
	a4 := e.approvalAsset(t, "db-04")
	pending, err := e.svc.Submit(1, "requester", false, SubmitAccessRequestInput{AssetID: a4, Reason: "維護", DurationMinutes: 60})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Approve(3, true, pending.ID, DecideInput{Note: "ok"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.BreakGlass(1, "顯示名不該出現", false, 1, "事故"); err != nil {
		t.Fatal(err)
	}
	msgs := e.dispatch(t)
	if len(msgs) < 3 {
		t.Fatalf("應至少有三列通知，得 %d", len(msgs))
	}
	for _, m := range msgs {
		p := noticeParams(t, m)
		for _, key := range []string{"requester_name", "decider_name", "username"} {
			if v, ok := p[key]; ok && v != "requester" && v != "boss" {
				t.Fatalf("%s 的 %s 應為登入帳號，得 %q", m.EventKey, key, v)
			}
		}
		if raw := m.Params; strings.Contains(raw, "evil.example") || strings.Contains(raw, "顯示名") {
			t.Fatalf("%s 的參數出現顯示名稱: %s", m.EventKey, raw)
		}
	}
}
