package audit

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"gorm.io/gorm"
)

// failingTxSink 審計寫入一律失敗的落地面（驗證 fail-close）。
type failingTxSink struct{}

func (failingTxSink) WriteInTx(*gorm.DB, port.AuditEvent) error {
	return errors.New("注入的審計失敗")
}

// failingRaiser 系統告警產生一律失敗的落地面（內嵌真實實作以滿足 port 與內部變體介面）。
type failingRaiser struct{ *systemAlertSink }

func (failingRaiser) raise(*gorm.DB, port.SystemAlertEvent, []systemAlertDestination) (port.SystemAlertReceipt, error) {
	return port.SystemAlertReceipt{}, errors.New("注入的告警失敗")
}

var channelActor = ChannelActor{ID: 5, Name: "sec-admin", IP: "10.1.1.1"}

func strp(s string) *string { return &s }
func boolp(b bool) *bool    { return &b }

type changeEnv struct {
	db  *gorm.DB
	svc *NotificationChannelService
}

func newChangeEnv(t *testing.T) *changeEnv {
	t.Helper()
	db := setupSystemAlertDB(t)
	return &changeEnv{db: db, svc: newChannelSvc(t, db, nil)}
}

func (e *changeEnv) seed(t *testing.T, name, url, secret string, enabled bool) model.NotificationChannel {
	t.Helper()
	ch := model.NotificationChannel{Name: name, Type: "webhook", URL: url, Secret: secret,
		Enabled: true, Language: "zh-TW", MinSeverity: "low"}
	if err := e.db.Create(&ch).Error; err != nil {
		t.Fatal(err)
	}
	if !enabled {
		if err := e.db.Model(&model.NotificationChannel{}).Where("id = ?", ch.ID).Update("enabled", false).Error; err != nil {
			t.Fatal(err)
		}
		ch.Enabled = false
	}
	return ch
}

func (e *changeEnv) counts(t *testing.T) (alerts, details, outbox, audits int64) {
	t.Helper()
	e.db.Table("command_alerts").Count(&alerts)
	e.db.Table("system_alert_details").Count(&details)
	e.db.Table("system_alert_outbox").Count(&outbox)
	e.db.Model(&model.AuditLog{}).Count(&audits)
	return
}

// deliver 跑一輪投遞並回傳每個收端的收件數。
func (e *changeEnv) deliver() {
	fastWorker(e.db).RunOnce()
}

func bodyParams(t *testing.T, raw []byte) (typ string, params map[string]any) {
	t.Helper()
	var p struct {
		Alert struct {
			Type   string         `json:"type"`
			Params map[string]any `json:"params"`
		} `json:"alert"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	return p.Alert.Type, p.Alert.Params
}

func TestNotificationChannelChangeAlerts(t *testing.T) {
	t.Run("改網址時舊與新目的地與其他啟用通道都收到", func(t *testing.T) {
		e := newChangeEnv(t)
		oldS, newS, other := newStubReceiver(t, 0), newStubReceiver(t, 0), newStubReceiver(t, 0)
		a := e.seed(t, "a", oldS.srv.URL+"/hook/ABCDEFGHIJKL", "super-secret-token", true)
		e.seed(t, "other", other.srv.URL, "", true)
		_, err := e.svc.Update(a.ID, &NotificationChannelRequest{Name: "a", URL: newS.srv.URL + "/hook/MNOPQRSTUVWX",
			ActorID: channelActor.ID, ActorName: channelActor.Name, ActorIP: channelActor.IP})
		if err != nil {
			t.Fatal(err)
		}
		e.deliver()
		if oldS.count() != 1 || newS.count() != 1 || other.count() != 1 {
			t.Fatalf("舊 %d 新 %d 其他 %d，各應收到一則", oldS.count(), newS.count(), other.count())
		}
		typ, params := bodyParams(t, oldS.body(0))
		if typ != "notification_channel_changed" || params["change"] != "updated" ||
			!strings.Contains(params["changed_fields"].(string), "url") {
			t.Fatalf("payload 不符: %s %v", typ, params)
		}
		// 網址只以遮罩形出現，完整網址與 secret 不入 payload。
		raw := string(oldS.body(0))
		if strings.Contains(raw, "ABCDEFGHIJKL") || strings.Contains(raw, "MNOPQRSTUVWX") || strings.Contains(raw, "super-secret-token") {
			t.Fatalf("payload 含完整網址或 secret: %s", raw)
		}
	})

	t.Run("停用時本通道仍收到一則", func(t *testing.T) {
		e := newChangeEnv(t)
		s := newStubReceiver(t, 0)
		a := e.seed(t, "a", s.srv.URL, "", true)
		if _, err := e.svc.Update(a.ID, &NotificationChannelRequest{Name: "a", Enabled: boolp(false),
			ActorID: 5, ActorName: "sec-admin"}); err != nil {
			t.Fatal(err)
		}
		e.deliver()
		if s.count() != 1 {
			t.Fatalf("停用的通道應收到「已停用」: %d", s.count())
		}
		if _, params := bodyParams(t, s.body(0)); params["change"] != "disabled" {
			t.Fatalf("change = %v", params["change"])
		}
	})

	t.Run("刪除後舊目的地收到且通道列已不存在", func(t *testing.T) {
		e := newChangeEnv(t)
		s := newStubReceiver(t, 0)
		a := e.seed(t, "a", s.srv.URL, "", true)
		if err := e.svc.Delete(a.ID, channelActor); err != nil {
			t.Fatal(err)
		}
		var n int64
		e.db.Model(&model.NotificationChannel{}).Where("id = ?", a.ID).Count(&n)
		if n != 0 {
			t.Fatal("通道列應已刪除")
		}
		e.deliver()
		if s.count() != 1 {
			t.Fatalf("刪除後舊目的地應收到一則: %d", s.count())
		}
		if _, params := bodyParams(t, s.body(0)); params["change"] != "deleted" {
			t.Fatalf("change = %v", params["change"])
		}
	})

	t.Run("只改名稱或只改門檻時本通道只收一次", func(t *testing.T) {
		e := newChangeEnv(t)
		s := newStubReceiver(t, 0)
		a := e.seed(t, "a", s.srv.URL, "", true)
		if _, err := e.svc.Update(a.ID, &NotificationChannelRequest{Name: "renamed", ActorID: 5, ActorName: "sec-admin"}); err != nil {
			t.Fatal(err)
		}
		if _, err := e.svc.Update(a.ID, &NotificationChannelRequest{Name: "renamed", MinSeverity: strp("high"),
			ActorID: 5, ActorName: "sec-admin"}); err != nil {
			t.Fatal(err)
		}
		e.deliver()
		// 兩次變更各一則，每則在單一目的地只出現一次。
		if s.count() != 2 {
			t.Fatalf("兩次變更應共收到 2 則: %d", s.count())
		}
		// 每個告警在本通道只有一列佇列（前後快照與啟用通道三者去重）。
		var perAlert []int64
		e.db.Table("system_alert_outbox").Select("COUNT(*)").Group("alert_id").Pluck("COUNT(*)", &perAlert)
		for _, n := range perAlert {
			if n != 1 {
				t.Fatalf("同一告警對同一目的地應只有 1 列佇列: %v", perAlert)
			}
		}
	})

	t.Run("建立即停用的通道收到已建立", func(t *testing.T) {
		e := newChangeEnv(t)
		s := newStubReceiver(t, 0)
		if _, err := e.svc.Create(&NotificationChannelRequest{Name: "off", URL: s.srv.URL, Enabled: boolp(false),
			ActorID: 5, ActorName: "sec-admin"}); err != nil {
			t.Fatal(err)
		}
		e.deliver()
		if s.count() != 1 {
			t.Fatalf("建立即停用的通道應收到: %d", s.count())
		}
		if _, params := bodyParams(t, s.body(0)); params["change"] != "created" {
			t.Fatalf("change = %v", params["change"])
		}
	})

	t.Run("審計失敗或告警失敗時整筆回滾", func(t *testing.T) {
		for name, mutate := range map[string]func(*NotificationChannelService){
			"審計失敗": func(s *NotificationChannelService) { s.SetAuditTxSink(failingTxSink{}) },
			"告警失敗": func(s *NotificationChannelService) {
				s.SetSystemAlertSink(failingRaiser{NewSystemAlertSink(nil).(*systemAlertSink)})
			},
		} {
			t.Run(name, func(t *testing.T) {
				e := newChangeEnv(t)
				s := newStubReceiver(t, 0)
				a := e.seed(t, "a", s.srv.URL, "", true)
				// 推送快取：失敗路徑不得重載。
				notifier := InitAlertNotifier(e.db, nil)
				t.Cleanup(func() { StopAlertNotifierForRelease(notifier) })
				if err := notifier.LoadChannels(); err != nil {
					t.Fatal(err)
				}
				cacheBefore := notifier.snapshotChannels()
				al, de, ou, au := e.counts(t)

				mutate(e.svc)
				ops := map[string]func() error{
					"update": func() error {
						_, err := e.svc.Update(a.ID, &NotificationChannelRequest{Name: "changed", ActorID: 5, ActorName: "x"})
						return err
					},
					"create": func() error {
						_, err := e.svc.Create(&NotificationChannelRequest{Name: "new", URL: "https://x.example.test/h", ActorID: 5, ActorName: "x"})
						return err
					},
					"delete": func() error { return e.svc.Delete(a.ID, ChannelActor{ID: 5, Name: "x"}) },
				}
				for op, run := range ops {
					if err := run(); err == nil {
						t.Fatalf("%s 應回錯", op)
					}
				}
				var got model.NotificationChannel
				if err := e.db.First(&got, a.ID).Error; err != nil || got.Name != "a" || got.URL != a.URL {
					t.Fatalf("通道內容應不變: %+v %v", got, err)
				}
				var total int64
				e.db.Model(&model.NotificationChannel{}).Count(&total)
				if total != 1 {
					t.Fatalf("通道列數應不變: %d", total)
				}
				al2, de2, ou2, au2 := e.counts(t)
				if al != al2 || de != de2 || ou != ou2 || au != au2 {
					t.Fatalf("告警 %d→%d 明細 %d→%d 佇列 %d→%d 審計 %d→%d 應全不變", al, al2, de, de2, ou, ou2, au, au2)
				}
				cacheAfter := notifier.snapshotChannels()
				if len(cacheBefore) != len(cacheAfter) || cacheAfter[0].Name != cacheBefore[0].Name {
					t.Fatalf("推送快取應不變: %v → %v", cacheBefore, cacheAfter)
				}
			})
		}
	})

	t.Run("審計詳情不含 secret 與完整網址", func(t *testing.T) {
		e := newChangeEnv(t)
		s := newStubReceiver(t, 0)
		a := e.seed(t, "a", s.srv.URL+"/hook/ABCDEFGHIJKL", "super-secret-token", true)
		if _, err := e.svc.Update(a.ID, &NotificationChannelRequest{Name: "a", Secret: "another-secret-value",
			URL: s.srv.URL + "/hook/MNOPQRSTUVWX", ActorID: 5, ActorName: "sec-admin", ActorIP: "10.1.1.1"}); err != nil {
			t.Fatal(err)
		}
		var row model.AuditLog
		if err := e.db.Where("resource = ? AND action = ?", model.ResourceNotifyChannel, model.ActionUpdate).First(&row).Error; err != nil {
			t.Fatal(err)
		}
		for _, leak := range []string{"super-secret-token", "another-secret-value", "ABCDEFGHIJKL", "MNOPQRSTUVWX"} {
			if strings.Contains(row.Details, leak) {
				t.Fatalf("審計詳情洩漏 %q: %s", leak, row.Details)
			}
		}
		if row.UserID != 5 || row.Username != "sec-admin" || row.ClientIP != "10.1.1.1" ||
			row.ResourceID == nil || *row.ResourceID != a.ID {
			t.Fatalf("審計列歸屬不符: %+v", row)
		}
		var d channelAuditDetails
		if err := json.Unmarshal([]byte(row.Details), &d); err != nil || d.CorrelationID == "" ||
			d.URLBefore == "" || d.URLAfter == "" || d.Change != "updated" {
			t.Fatalf("詳情欄位不符: %+v %v", d, err)
		}
		// 同一個關聯識別出現在告警明細。
		var detail model.SystemAlertDetail
		if err := e.db.First(&detail).Error; err != nil || detail.CorrelationID != d.CorrelationID {
			t.Fatalf("關聯識別應一致: %+v vs %s (%v)", detail, d.CorrelationID, err)
		}
		if strings.Contains(detail.Params, "super-secret-token") || strings.Contains(detail.Params, "ABCDEFGHIJKL") {
			t.Fatalf("告警參數洩漏: %s", detail.Params)
		}
	})

	t.Run("測試發送不產生告警", func(t *testing.T) {
		e := newChangeEnv(t)
		s := newStubReceiver(t, 0)
		a := e.seed(t, "a", s.srv.URL, "", true)
		al, de, ou, _ := e.counts(t)
		if _, err := e.svc.GetForDelivery(a.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := SendTestNotification(&model.NotificationChannel{Type: "webhook", URL: s.srv.URL}); err != nil {
			t.Fatal(err)
		}
		al2, de2, ou2, _ := e.counts(t)
		if al != al2 || de != de2 || ou != ou2 {
			t.Fatal("測試發送不應產生系統告警或佇列列")
		}
	})
}
