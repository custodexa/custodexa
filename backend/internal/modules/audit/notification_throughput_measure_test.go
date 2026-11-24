package audit

import (
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
)

// 投遞程序的吞吐與公平性量測（只在 NDL_MEASURE=1 且設 TEST_PG_DSN 時執行，不進一般全套）。
//
// 時間全部以可控時鐘模擬：每一輪推進 2 秒；逾時的目的地以「立即拒絕連線」代替真實等待，並在它被嘗試的那一輪
// 額外推進 5 秒（模擬 5 秒逾時佔掉的時間）。輸出寫到 NDL_MEASURE_OUT 指定的檔案。

func measureEnabled(t *testing.T) {
	if os.Getenv("NDL_MEASURE") != "1" {
		t.Skip("量測測試：設 NDL_MEASURE=1 才執行")
	}
}

type measureOut struct {
	mu    sync.Mutex
	lines []string
}

func (m *measureOut) printf(format string, args ...any) {
	m.mu.Lock()
	m.lines = append(m.lines, fmt.Sprintf(format, args...))
	m.mu.Unlock()
}

func (m *measureOut) flush(t *testing.T) {
	t.Helper()
	path := os.Getenv("NDL_MEASURE_OUT")
	text := strings.Join(m.lines, "\n") + "\n"
	t.Log(text)
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		_, _ = f.WriteString(text)
	}
}

func percentiles(ds []time.Duration) string {
	if len(ds) == 0 {
		return "n=0"
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	at := func(p float64) time.Duration {
		i := int(p*float64(len(ds))+0.5) - 1
		if i < 0 {
			i = 0
		}
		if i >= len(ds) {
			i = len(ds) - 1
		}
		return ds[i]
	}
	return fmt.Sprintf("n=%d p50=%s p95=%s p99=%s max=%s", len(ds), at(0.50), at(0.95), at(0.99), ds[len(ds)-1])
}

func TestMeasureNotificationThroughputPG(t *testing.T) {
	measureEnabled(t)
	measureThroughput(t, false)
}

// TestMeasureNotificationThroughputSlackAppPG 同量測一，另加一個每秒 1 則的 slack_app 通道（預留名額排序的回歸量測）：
// 該通道的 medium 系統事件 p95 同樣以 60 秒為判準，並列出它的指令告警送出是否依分級、編號前進。
func TestMeasureNotificationThroughputSlackAppPG(t *testing.T) {
	measureEnabled(t)
	measureThroughput(t, true)
}

func measureThroughput(t *testing.T, withSlackApp bool) {
	e := newNDLEnvPG(t)
	out := &measureOut{}
	h1 := newStubSrv(t, nil, nil)
	h2 := newStubSrv(t, nil, nil)
	e.channel("hook1", "webhook", h1.srv.URL, true, "low")
	e.channel("hook2", "webhook", h2.srv.URL, true, "low")
	bad := e.channel("D", "webhook", "http://127.0.0.1:1/timeout", true, "low")
	var app model.NotificationChannel
	if withSlackApp {
		appSrv := newStubSrv(t, nil, func(_ int, w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		})
		app = model.NotificationChannel{Name: "app", Type: model.NotificationChannelTypeSlackApp, URL: appSrv.srv.URL,
			Secret: "xoxb-measure", Target: "C1", Enabled: true, Language: "zh-TW", MinSeverity: "low"}
		if err := e.db.Create(&app).Error; err != nil {
			t.Fatal(err)
		}
	}

	t0 := e.clock.now()
	if err := e.db.Exec(`INSERT INTO command_alerts (rule_name, user_id, command, severity, triggered_at, kind)
		SELECT 'r', 1, 'x', 'high', ?, 'rule' FROM generate_series(1, 10000)`, t0).Error; err != nil {
		t.Fatal(err)
	}
	if err := e.db.Exec(`INSERT INTO notification_messages (category, event_key, alert_id, severity, occurred_at, params, name_refs, state, created_at)
		SELECT 'command_alert', 'command_alert', id, 'high', ?, '{}', '{}', 'pending', ? FROM command_alerts`, t0, t0).Error; err != nil {
		t.Fatal(err)
	}
	events := []notifycat.Event{notifycat.EventAccessRequestCreated, notifycat.EventBreakGlassUsed}
	nextEvent := t0
	sent := 0
	var roundDur, queryDur []time.Duration
	end := t0.Add(30 * time.Minute)
	for round := 0; round < 5000; round++ {
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
		qs := time.Now()
		if _, err := e.w.dueCandidateIDs(now); err != nil {
			t.Fatal(err)
		}
		queryDur = append(queryDur, time.Since(qs))
		var badDue int64
		e.db.Model(&model.NotificationDelivery{}).Where("source_channel_id = ? AND state IN ? AND next_attempt_at <= ?", bad.ID, activeOutboxStates(), now).Count(&badDue)
		rs := time.Now()
		roundStart := e.clock.now()
		e.w.RunOnce()
		roundDur = append(roundDur, time.Since(rs))
		if withSlackApp {
			// 正式迴圈以固定週期觸發：輪內為送出間隔等待而推進的時間計入下一輪的起點（同量測二）
			if next := roundStart.Add(2 * time.Second); next.After(e.clock.now()) {
				e.clock.advance(next.Sub(e.clock.now()))
			}
		} else {
			e.clock.advance(2 * time.Second)
		}
		if badDue > 0 {
			e.clock.advance(5 * time.Second)
		}
		if !e.clock.now().Before(end) {
			var pendingSys int64
			e.db.Raw(`SELECT COUNT(*) FROM system_alert_outbox o WHERE o.category = 'system_event' AND o.source_channel_id <> ? AND o.state IN ('pending','retrying')`, bad.ID).Scan(&pendingSys)
			var pendingMsg int64
			e.db.Model(&model.NotificationMessage{}).Where("category = ? AND state = ?", model.NotificationCategorySystemEvent, model.NotificationMessagePending).Count(&pendingMsg)
			if pendingSys == 0 && pendingMsg == 0 {
				break
			}
		}
	}
	type lat struct {
		Category  string
		Severity  string
		ChannelID uint
		CreatedAt time.Time
		Delivered *time.Time
	}
	var rows []lat
	e.db.Raw(`SELECT m.category, m.severity, o.source_channel_id AS channel_id, m.created_at, o.delivered_at AS delivered
		FROM system_alert_outbox o JOIN notification_messages m ON m.id = o.message_id WHERE o.source_channel_id <> ?`, bad.ID).Scan(&rows)
	groups := map[string][]time.Duration{}
	undelivered := map[string]int{}
	for _, r := range rows {
		k := r.Category + "/" + r.Severity
		if withSlackApp && r.ChannelID == app.ID {
			k += "@slack_app"
		}
		if r.Delivered == nil {
			undelivered[k]++
			continue
		}
		groups[k] = append(groups[k], r.Delivered.Sub(r.CreatedAt))
	}
	title := "量測一"
	if withSlackApp {
		title = "量測一（加每秒 1 則的 slack_app 通道，預留名額排序回歸）"
	}
	out.printf("== %s：一萬筆 high 指令告警＋每分鐘一則 medium 系統事件 30 分鐘，三通道其一逾時（%s）", title, time.Now().Format(time.RFC3339))
	out.printf("模擬時長 %s，輪數 %d，排入系統事件 %d 則", e.clock.now().Sub(t0), len(roundDur), sent)
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out.printf("建立到送達（兩個健康通道）%s: %s；量測結束時未送達 %d", k, percentiles(groups[k]), undelivered[k])
	}
	out.printf("每輪耗時（真實時間）: %s", percentiles(roundDur))
	out.printf("依目的地輪流取件查詢耗時（真實時間）: %s", percentiles(queryDur))
	sys := groups[model.NotificationCategorySystemEvent+"/"+model.AlertSeverityMedium]
	sort.Slice(sys, func(i, j int) bool { return sys[i] < sys[j] })
	verdict := "未達標"
	if len(sys) > 0 && sys[int(0.95*float64(len(sys))+0.5)-1] <= 60*time.Second {
		verdict = "達標"
	}
	out.printf("判準 medium 系統事件 p95 <= 60 秒：%s", verdict)
	if withSlackApp {
		appSys := groups[model.NotificationCategorySystemEvent+"/"+model.AlertSeverityMedium+"@slack_app"]
		sort.Slice(appSys, func(i, j int) bool { return appSys[i] < appSys[j] })
		appVerdict := "未達標"
		if len(appSys) > 0 && undelivered[model.NotificationCategorySystemEvent+"/"+model.AlertSeverityMedium+"@slack_app"] == 0 &&
			appSys[int(0.95*float64(len(appSys))+0.5)-1] <= 60*time.Second {
			appVerdict = "達標"
		}
		out.printf("判準 slack_app 通道 medium 系統事件 p95 <= 60 秒且全部送達：%s", appVerdict)
		var alertIDs []uint
		e.db.Raw(`SELECT alert_id FROM system_alert_outbox WHERE source_channel_id = ? AND category = 'command_alert' AND state = 'delivered'
			ORDER BY delivered_at, id`, app.ID).Scan(&alertIDs)
		inOrder := true
		for i := 1; i < len(alertIDs); i++ {
			if alertIDs[i] < alertIDs[i-1] {
				inOrder = false
				break
			}
		}
		out.printf("slack_app 通道已送出指令告警 %d 筆，依編號前進：%v", len(alertIDs), inOrder)
	}
	out.flush(t)
}

func TestMeasureSlackAppRateLimitPG(t *testing.T) {
	measureEnabled(t)
	e := newNDLEnvPG(t)
	out := &measureOut{}
	var mu sync.Mutex
	lastAccepted := time.Time{}
	rejected := 0
	srv := newStubSrv(t, e.clock, func(_ int, w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		now := e.clock.now()
		if !lastAccepted.IsZero() && now.Sub(lastAccepted) < time.Second {
			rejected++
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		lastAccepted = now
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	ch := model.NotificationChannel{Name: "app", Type: model.NotificationChannelTypeSlackApp, URL: srv.srv.URL,
		Secret: "xoxb-measure", Target: "C1", Enabled: true, Language: "zh-TW", MinSeverity: "low"}
	if err := e.db.Create(&ch).Error; err != nil {
		t.Fatal(err)
	}
	t0 := e.clock.now()
	if err := e.db.Exec(`INSERT INTO command_alerts (rule_name, user_id, command, severity, triggered_at, kind)
		SELECT 'r', 1, 'x', 'high', ?, 'rule' FROM generate_series(1, 1000)`, t0).Error; err != nil {
		t.Fatal(err)
	}
	if err := e.db.Exec(`INSERT INTO notification_messages (category, event_key, alert_id, severity, occurred_at, params, name_refs, state, created_at)
		SELECT 'command_alert', 'command_alert', id, 'high', ?, '{}', '{}', 'pending', ? FROM command_alerts`, t0, t0).Error; err != nil {
		t.Fatal(err)
	}
	rounds := 0
	for ; rounds < 5000; rounds++ {
		// 正式迴圈以固定週期的 ticker 觸發：本輪內為送出間隔等待而推進的時間，計入下一輪的起點。
		roundStart := e.clock.now()
		e.w.RunOnce()
		var active int64
		e.db.Model(&model.NotificationDelivery{}).Where("state IN ?", activeOutboxStates()).Count(&active)
		var pendingMsg int64
		e.db.Model(&model.NotificationMessage{}).Where("state = ?", model.NotificationMessagePending).Count(&pendingMsg)
		if active == 0 && pendingMsg == 0 {
			break
		}
		if next := roundStart.Add(2 * time.Second); next.After(e.clock.now()) {
			e.clock.advance(next.Sub(e.clock.now()))
		} else {
			e.clock.advance(0)
		}
	}
	var delivered, abandoned int64
	e.db.Model(&model.NotificationDelivery{}).Where("state = ?", model.NotificationDeliveryDelivered).Count(&delivered)
	e.db.Model(&model.NotificationDelivery{}).Where("state = ?", model.NotificationDeliveryAbandoned).Count(&abandoned)
	var last time.Time
	e.db.Raw(`SELECT MAX(delivered_at) FROM system_alert_outbox`).Scan(&last)
	out.printf("== 量測二：slack_app 每秒只接受 1 則（超過回 429、Retry-After: 1），積壓 1000 筆（%s）", time.Now().Format(time.RFC3339))
	out.printf("輪數 %d（輪與輪的起點相隔 2 秒，輪內的送出間隔等待計入時鐘），送達 %d，放棄 %d，最後一筆送達距建立 %s，429 回應 %d 次", rounds, delivered, abandoned, last.Sub(t0), rejected)
	ok := delivered == 1000 && abandoned == 0 && last.Sub(t0) <= 25*time.Minute && rejected <= 50
	out.printf("判準（全部送達、無放棄、25 分鐘內、429 不超過 50 次）：%v", map[bool]string{true: "達標", false: "未達標"}[ok])
	out.flush(t)
}
