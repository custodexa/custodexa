package audit

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
	"gorm.io/gorm"
)

// 定向通知投遞層的量測（只在 TNL_MEASURE=1 且設 TEST_PG_DSN 時執行，不進一般全套）。
//
//   - 量測一：分派交易全程（自開交易到提交：讀內容列、解析名稱、每個通道一筆、每位收件人一筆、收尾）在 2、50、200 位收件人下的真實耗時；
//     交易前的求得另計（判定以替身回傳固定名單，真實判定的求得耗時另有量測）。
//   - 量測二：通知吞吐量測的情境（一萬筆 high 指令告警、每分鐘一則 medium 系統事件 30 分鐘、三個通道其一逾時）
//     另加一個開啟對個人派送的 slack_app 通道，並在第 10 分鐘加入一則有 50 位收件人的申請：medium 系統事件
//     （頻道訊息）建立到送達的第 95 百分位，以及 50 則私訊全部送達所需的模擬時間。時間以可控時鐘模擬，規則同吞吐量測。
// 輸出寫到 NDL_MEASURE_OUT 指定的檔案（與地基的量測共用）。

func tnlMeasureEnabled(t *testing.T) {
	if os.Getenv("TNL_MEASURE") != "1" {
		t.Skip("量測測試：設 TNL_MEASURE=1 才執行")
	}
}

// measurePGTargeted 建 PG 環境並補上使用者的電子郵件欄與 n 位收件人。
func measurePGTargeted(t *testing.T, n int) (*ndlEnv, *fakeJudge, []uint) {
	e := newNDLEnvPG(t)
	if err := e.db.Exec(`ALTER TABLE users ADD COLUMN email TEXT`).Error; err != nil {
		t.Fatal(err)
	}
	if err := e.db.Exec(`INSERT INTO users (id, username, email) SELECT g, 'u' || g, 'u' || g || '@measure.example' FROM generate_series(1, ?) g`, n).Error; err != nil {
		t.Fatal(err)
	}
	t.Setenv(dmExtraHostsEnv, "127.0.0.1")
	resetDMCache()
	t.Cleanup(resetDMCache)
	t.Cleanup(func() {
		for ev := range targetedEventKind {
			RegisterDeliveryPrecheck(ev, nil)
		}
	})
	ids := make([]uint, n)
	for i := range ids {
		ids[i] = uint(i + 1)
	}
	j := &fakeJudge{awaiting: true}
	for ev := range targetedEventKind {
		if err := e.w.UseTargetedJudge(ev, j.judge()); err != nil {
			t.Fatal(err)
		}
	}
	return e, j, ids
}

func TestMeasureTargetedDispatchPG(t *testing.T) {
	tnlMeasureEnabled(t)
	out := &measureOut{}
	out.printf("== 定向通知量測一：分派交易全程（%s）", time.Now().Format(time.RFC3339))
	for _, n := range []int{2, 50, 200} {
		e, j, ids := measurePGTargeted(t, n)
		slack := newDMSlackStub(t, e.clock)
		ch := model.NotificationChannel{Name: "dm", Type: model.NotificationChannelTypeSlackApp, URL: slack.srv.URL, Secret: tnlToken,
			Target: tnlTarget, Enabled: true, Language: "zh-TW", MinSeverity: "low", DirectMessageEnabled: true}
		if err := e.db.Create(&ch).Error; err != nil {
			t.Fatal(err)
		}
		e.channel("hook1", "webhook", "http://127.0.0.1:1/h1", true, "low")
		e.channel("hook2", "webhook", "http://127.0.0.1:1/h2", true, "low")
		j.recipients = ids
		var txDur, prepDur []time.Duration
		for round := 0; round < 20; round++ {
			e.enqueueEvent(notifycat.EventAccessRequestCreated, map[string]string{"request_id": fmt.Sprint(round + 1)})
			var id uint
			e.db.Model(&model.NotificationMessage{}).Select("id").Where("state = ?", model.NotificationMessagePending).Order("id").Limit(1).Scan(&id)
			if !e.w.claimMessage(id, e.clock.now()) {
				t.Fatal("認領失敗")
			}
			ps := time.Now()
			plan := e.w.prepareTargeted(id)
			prepDur = append(prepDur, time.Since(ps))
			txStart := time.Now()
			if err := e.db.Transaction(func(tx *gorm.DB) error {
				_, _, err := e.w.dispatchInTx(tx, id, plan)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			txDur = append(txDur, time.Since(txStart))
		}
		var users int64
		e.db.Model(&model.NotificationDelivery{}).Where("audience = ?", deliveryAudienceUser).Count(&users)
		if users != int64(20*n) {
			t.Fatalf("個人紀錄應有 %d 筆，得 %d", 20*n, users)
		}
		out.printf("收件人 %d 位、三個通道：分派交易 %s；交易前準備（含通道查詢與替身判定）%s", n, percentiles(txDur), percentiles(prepDur))
	}
	out.printf("判準：分派交易 <= 200 毫秒")
	out.flush(t)
}

func TestMeasureTargetedLatencyPG(t *testing.T) {
	tnlMeasureEnabled(t)
	e, j, ids := measurePGTargeted(t, 50)
	out := &measureOut{}
	h1 := newStubSrv(t, nil, nil)
	h2 := newStubSrv(t, nil, nil)
	slack := newDMSlackStub(t, e.clock)
	e.channel("hook1", "webhook", h1.srv.URL, true, "low")
	e.channel("hook2", "webhook", h2.srv.URL, true, "low")
	bad := e.channel("D", "webhook", "http://127.0.0.1:1/timeout", true, "low")
	// TNL_MEASURE_NODM=1：同一情境但不開對個人派送、不加收件人（對照組，區分地基本身與本 change 的影響）
	noDM := os.Getenv("TNL_MEASURE_NODM") == "1"
	dm := model.NotificationChannel{Name: "dm", Type: model.NotificationChannelTypeSlackApp, URL: slack.srv.URL, Secret: tnlToken,
		Target: tnlTarget, Enabled: true, Language: "zh-TW", MinSeverity: "low", DirectMessageEnabled: !noDM}
	if err := e.db.Create(&dm).Error; err != nil {
		t.Fatal(err)
	}
	// 第 10 分鐘以前判定沒有收件人且單已不需處理（不建個人紀錄、不觸發彙總事件），背景事件與地基 5.7 相同
	j.recipients = nil
	j.awaiting = false
	events := []notifycat.Event{notifycat.EventAccessRequestCreated, notifycat.EventBreakGlassUsed}

	t0 := e.clock.now()
	if err := e.db.Exec(`INSERT INTO command_alerts (rule_name, user_id, command, severity, triggered_at, kind)
		SELECT 'r', 1, 'x', 'high', ?, 'rule' FROM generate_series(1, 10000)`, t0).Error; err != nil {
		t.Fatal(err)
	}
	if err := e.db.Exec(`INSERT INTO notification_messages (category, event_key, alert_id, severity, occurred_at, params, name_refs, state, created_at)
		SELECT 'command_alert', 'command_alert', id, 'high', ?, '{}', '{}', 'pending', ? FROM command_alerts`, t0, t0).Error; err != nil {
		t.Fatal(err)
	}
	nextEvent := t0
	sent := 0
	end := t0.Add(30 * time.Minute)
	bigAt := t0.Add(10 * time.Minute)
	bigQueued := false
	var bigMsg uint
	for round := 0; round < 6000; round++ {
		now := e.clock.now()
		for !nextEvent.After(now) && nextEvent.Before(end) {
			ev := events[sent%2]
			params := map[string]string{"request_id": fmt.Sprint(sent + 1), "asset_name": "db"}
			if ev == notifycat.EventBreakGlassUsed {
				params = map[string]string{"request_id": fmt.Sprint(sent + 1), "asset_name": "db", "requester": "u", "duration_minutes": "30"}
			}
			if err := e.n.EnqueueStandalone(NotificationNotice{Category: model.NotificationCategorySystemEvent, Event: ev,
				Severity: model.AlertSeverityMedium, Params: params, OccurredAt: nextEvent}); err != nil {
				t.Fatal(err)
			}
			sent++
			nextEvent = nextEvent.Add(time.Minute)
		}
		if !bigQueued && !now.Before(bigAt) {
			j.mu.Lock()
			j.recipients = ids
			j.awaiting = true
			j.mu.Unlock()
			if noDM {
				j.recipients = nil
			}
			if err := e.n.EnqueueStandalone(NotificationNotice{Category: model.NotificationCategorySystemEvent, Event: notifycat.EventAccessRequestCreated,
				Severity: model.AlertSeverityMedium, Params: map[string]string{"request_id": "9999", "asset_name": "db"}, OccurredAt: now}); err != nil {
				t.Fatal(err)
			}
			e.db.Model(&model.NotificationMessage{}).Select("MAX(id)").Scan(&bigMsg)
			sent++
			// 只有這一則有收件人：分派之後恢復成沒有收件人且不需處理
			e.w.RunOnce()
			j.mu.Lock()
			j.recipients = nil
			j.awaiting = false
			j.mu.Unlock()
			bigQueued = true
		}
		var badDue int64
		e.db.Model(&model.NotificationDelivery{}).Where("source_channel_id = ? AND state IN ? AND next_attempt_at <= ?", bad.ID, activeOutboxStates(), now).Count(&badDue)
		roundStart := e.clock.now()
		e.w.RunOnce()
		if next := roundStart.Add(2 * time.Second); next.After(e.clock.now()) {
			e.clock.advance(next.Sub(e.clock.now()))
		}
		if badDue > 0 {
			e.clock.advance(5 * time.Second)
		}
		if e.clock.now().After(end.Add(30 * time.Minute)) {
			break
		}
		if !e.clock.now().Before(end) {
			var pending int64
			e.db.Raw(`SELECT COUNT(*) FROM system_alert_outbox o WHERE o.category = 'system_event' AND o.source_channel_id <> ? AND o.state IN ('pending','retrying')`, bad.ID).Scan(&pending)
			var pendingMsg int64
			e.db.Model(&model.NotificationMessage{}).Where("category = ? AND state = ?", model.NotificationCategorySystemEvent, model.NotificationMessagePending).Count(&pendingMsg)
			if pending == 0 && pendingMsg == 0 {
				break
			}
		}
	}
	type lat struct {
		Audience  string
		ChannelID uint
		EventKey  string
		CreatedAt time.Time
		Delivered *time.Time
	}
	var rows []lat
	e.db.Raw(`SELECT o.audience, o.source_channel_id AS channel_id, m.event_key, m.created_at, o.delivered_at AS delivered
		FROM system_alert_outbox o JOIN notification_messages m ON m.id = o.message_id
		WHERE m.category = 'system_event' AND o.source_channel_id <> ? AND (o.audience = 'channel' OR o.message_id = ?)`, bad.ID, bigMsg).Scan(&rows)
	var chanLatBy = map[uint][]time.Duration{}
	for _, r := range rows {
		if r.Audience != deliveryAudienceUser && r.Delivered != nil {
			chanLatBy[r.ChannelID] = append(chanLatBy[r.ChannelID], r.Delivered.Sub(r.CreatedAt))
		}
	}
	var chanLat, dmLat []time.Duration
	undeliveredChan, undeliveredDM := 0, 0
	for _, r := range rows {
		if r.Audience == deliveryAudienceUser {
			if r.Delivered == nil {
				undeliveredDM++
				continue
			}
			dmLat = append(dmLat, r.Delivered.Sub(r.CreatedAt))
			continue
		}
		if r.Delivered == nil {
			undeliveredChan++
			continue
		}
		chanLat = append(chanLat, r.Delivered.Sub(r.CreatedAt))
	}
	out.printf("== 定向通知量測二：地基 5.7 情境＋開啟對個人派送的通道＋第 10 分鐘一則 50 位收件人的申請（%s）；對照組=%v", time.Now().Format(time.RFC3339), noDM)
	out.printf("模擬時長 %s，排入背景系統事件 %d 則，申請內容列 %d", e.clock.now().Sub(t0), sent, bigMsg)
	out.printf("medium 系統事件頻道訊息（三個健康通道）建立到送達: %s；未送達 %d", percentiles(append([]time.Duration(nil), chanLat...)), undeliveredChan)
	out.printf("50 則私訊建立到送達: %s；未送達 %d", percentiles(append([]time.Duration(nil), dmLat...)), undeliveredDM)
	for id, ls := range chanLatBy {
		out.printf("  通道 %d 的頻道訊息建立到送達: %s", id, percentiles(ls))
	}
	sort.Slice(chanLat, func(i, k int) bool { return chanLat[i] < chanLat[k] })
	verdict := "未達標"
	if len(chanLat) > 0 && chanLat[int(0.95*float64(len(chanLat))+0.5)-1] <= 60*time.Second {
		verdict = "達標"
	}
	out.printf("判準 medium 系統事件 p95 <= 60 秒：%s", verdict)
	out.printf("私訊查詢次數 %d、私訊送出 %d", len(slack.callsOf(slackLookupByEmailMethod)), dmPostsOf(slack))
	type brk struct {
		ChannelID uint
		Audience  string
		State     string
		EndReason string
		N         int
	}
	var bs []brk
	e.db.Raw(`SELECT o.source_channel_id AS channel_id, o.audience, o.state, o.end_reason, COUNT(*) AS n FROM system_alert_outbox o
		JOIN notification_messages m ON m.id = o.message_id
		GROUP BY o.source_channel_id, o.audience, o.state, o.end_reason ORDER BY 1, 2, 3`).Scan(&bs)
	for _, b := range bs {
		out.printf("全部紀錄分布（含指令告警）：通道 %d（逾時通道 %d、私訊通道 %d）%s %s %q：%d", b.ChannelID, bad.ID, dm.ID, b.Audience, b.State, b.EndReason, b.N)
	}
	out.flush(t)
}

func dmPostsOf(s *dmSlackStub) int {
	n := 0
	for _, c := range s.callsOf(slackPostMessageMethod) {
		if !containsTarget(c.Body) {
			n++
		}
	}
	return n
}

func containsTarget(b []byte) bool { return bytes.Contains(b, []byte(`"channel":"`+tnlTarget+`"`)) }
