package audit

import (
	"net/http"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
)

// 預留給指令告警以外紀錄的名額：選出後的順序不得把預留的紀錄排到高分級指令告警之後，
// 否則每秒上限低的目的地（slack_app 每秒 1 則）一輪只送前一兩筆，預留的紀錄永遠輪不到。

func TestPickDueCandidatesReservedSlotsComeFirst(t *testing.T) {
	ch := uint(1)
	var rows []dueCandidate
	id := uint(1)
	for i := 0; i < 10; i++ { // 十筆 high 指令告警，編號在前
		rows = append(rows, dueCandidate{ID: id, ChannelID: &ch, Audience: deliveryAudienceChannel, SevRank: 0, IsCommand: 1, Rn: i + 1})
		id++
	}
	for i := 0; i < 3; i++ { // 三則 medium 系統事件
		rows = append(rows, dueCandidate{ID: id, ChannelID: &ch, Audience: deliveryAudienceChannel, SevRank: 1, IsCommand: 0, Rn: i + 1})
		id++
	}
	got := pickDueCandidates(rows, 10, 5, 100)
	if len(got) != 10 {
		t.Fatalf("應選出 10 筆，得 %d", len(got))
	}
	for i, want := range []uint{11, 12, 13} {
		if got[i] != want {
			t.Fatalf("預留的系統事件應排在目的地最前面：第 %d 筆得 %d，want %d（全部 %v）", i, got[i], want, got)
		}
	}
	// 指令告警之間的先後不變（分級、編號）
	for i := 3; i < 10; i++ {
		if got[i] != uint(i-2) {
			t.Fatalf("指令告警的先後改變：第 %d 筆得 %d（全部 %v）", i, got[i], got)
		}
	}

	// 指令告警之間仍依分級：low 指令告警排在 high 之後；預留以外的名額照分級與編號補
	rows = []dueCandidate{
		{ID: 1, ChannelID: &ch, Audience: deliveryAudienceChannel, SevRank: 2, IsCommand: 1, Rn: 2},
		{ID: 2, ChannelID: &ch, Audience: deliveryAudienceChannel, SevRank: 0, IsCommand: 1, Rn: 1},
		{ID: 3, ChannelID: &ch, Audience: deliveryAudienceChannel, SevRank: 2, IsCommand: 0, Rn: 1},
	}
	got = pickDueCandidates(rows, 10, 5, 100)
	if len(got) != 3 || got[0] != 3 || got[1] != 2 || got[2] != 1 {
		t.Fatalf("得 %v，want [3 2 1]", got)
	}
}

// TestSlackAppSystemEventNotStarvedByCommandAlerts 每秒 1 則的 slack_app 通道積壓三百筆 high 指令告警時，
// 之後排入的 medium 系統事件在 60 秒內送出；指令告警照常依序送出。
func TestSlackAppSystemEventNotStarvedByCommandAlerts(t *testing.T) {
	e := newNDLEnv(t)
	srv := newStubSrv(t, e.clock, func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	ch := model.NotificationChannel{Name: "app", Type: model.NotificationChannelTypeSlackApp, URL: srv.srv.URL,
		Secret: "xoxb-reserved", Target: "C1", Enabled: true, Language: "zh-TW", MinSeverity: "low"}
	if err := e.db.Create(&ch).Error; err != nil {
		t.Fatal(err)
	}
	t0 := e.clock.now()
	if err := e.db.Exec(`WITH RECURSIVE s(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM s WHERE x < 300)
		INSERT INTO command_alerts (rule_name, user_id, command, severity, triggered_at, kind)
		SELECT 'r', 1, 'x', 'high', ?, 'rule' FROM s`, t0).Error; err != nil {
		t.Fatal(err)
	}
	if err := e.db.Exec(`INSERT INTO notification_messages (category, event_key, alert_id, severity, occurred_at, params, name_refs, state, created_at)
		SELECT 'command_alert', 'command_alert', id, 'high', ?, '{}', '{}', 'pending', ? FROM command_alerts`, t0, t0).Error; err != nil {
		t.Fatal(err)
	}
	tick := func() {
		start := e.clock.now()
		e.w.RunOnce()
		if next := start.Add(2 * time.Second); next.After(e.clock.now()) {
			e.clock.advance(next.Sub(e.clock.now()))
		}
	}
	for i := 0; i < 5; i++ {
		tick()
	}
	e.enqueueEvent(notifycat.EventAccessRequestCreated, map[string]string{"request_id": "1", "asset_name": "db"})
	enqueuedAt := e.clock.now()
	var sys model.NotificationDelivery
	for e.clock.now().Sub(enqueuedAt) <= 60*time.Second {
		tick()
		sys = model.NotificationDelivery{}
		e.db.Where("category = ?", model.NotificationCategorySystemEvent).First(&sys)
		if sys.State == model.NotificationDeliveryDelivered {
			break
		}
	}
	if sys.State != model.NotificationDeliveryDelivered {
		t.Fatalf("系統事件 60 秒內應送出：state=%q", sys.State)
	}
	var cmdDelivered int64
	e.db.Model(&model.NotificationDelivery{}).Where("category = ? AND state = ?", model.NotificationCategoryCommandAlert, model.NotificationDeliveryDelivered).Count(&cmdDelivered)
	if cmdDelivered == 0 {
		t.Fatal("指令告警也應照常送出")
	}
	// 已送出的指令告警依編號連續（同分級的先後不變）
	var ids []uint
	e.db.Model(&model.NotificationDelivery{}).Where("category = ? AND state = ?", model.NotificationCategoryCommandAlert, model.NotificationDeliveryDelivered).
		Order("delivered_at, id").Pluck("alert_id", &ids)
	for i := 1; i < len(ids); i++ {
		if ids[i] < ids[i-1] {
			t.Fatalf("指令告警的送出順序倒退：%v", ids)
		}
	}
}
