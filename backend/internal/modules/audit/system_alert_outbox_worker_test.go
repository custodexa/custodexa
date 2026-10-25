package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"gorm.io/gorm"
)

// stubReceiver 測試用收端：記錄收到的 body 與簽章標頭，可注入前 n 次失敗。
type stubReceiver struct {
	mu       sync.Mutex
	srv      *httptest.Server
	bodies   [][]byte
	sigs     []string
	failLeft int
}

func newStubReceiver(t *testing.T, failFirst int) *stubReceiver {
	t.Helper()
	s := &stubReceiver{failLeft: failFirst}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.failLeft > 0 {
			s.failLeft--
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		s.bodies = append(s.bodies, b)
		s.sigs = append(s.sigs, r.Header.Get(signatureHeaderKey))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *stubReceiver) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.bodies)
}

func (s *stubReceiver) body(i int) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bodies[i]
}

func outboxTestSetup(t *testing.T, channels ...model.NotificationChannel) (*gorm.DB, port.SystemAlertSink) {
	t.Helper()
	db := setupSystemAlertDB(t)
	for _, ch := range channels {
		ch := ch
		if err := db.Create(&ch).Error; err != nil {
			t.Fatal(err)
		}
	}
	return db, NewSystemAlertSink(nil)
}

func raiseEvent(t *testing.T, db *gorm.DB, sink port.SystemAlertSink, typ port.SystemAlertType, params map[string]string) port.SystemAlertReceipt {
	t.Helper()
	ev := validGrantEvent()
	ev.Type = typ
	ev.Params = params
	var r port.SystemAlertReceipt
	if err := db.Transaction(func(tx *gorm.DB) error {
		var err error
		r, err = port.RaiseInTx(sink, tx, ev)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return r
}

func fastWorker(db *gorm.DB) *SystemAlertOutboxWorker {
	w := NewSystemAlertOutboxWorker(db, nil)
	w.backoffBase = time.Millisecond
	w.backoffMax = 4 * time.Millisecond
	w.tee = func(model.CommandAlert) {}
	return w
}

func outboxRows(t *testing.T, db *gorm.DB) []model.SystemAlertOutbox {
	t.Helper()
	var rows []model.SystemAlertOutbox
	if err := db.Order("id").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestSystemAlertOutboxDelivery(t *testing.T) {
	grant := map[string]string{"path": "direct_assign", "recipient": "bob", "role_name": "asset_admin"}

	t.Run("門檻為 high 的啟用通道收到中分級的系統告警", func(t *testing.T) {
		stub := newStubReceiver(t, 0)
		db, sink := outboxTestSetup(t, model.NotificationChannel{Name: "strict", Type: "webhook", URL: stub.srv.URL,
			Enabled: true, Language: "zh-TW", MinSeverity: "high"})
		raiseEvent(t, db, sink, port.SystemAlertManagementRoleGranted, grant) // 預設 medium
		raiseEvent(t, db, sink, port.SystemAlertSelfPrivilegeDecreased, map[string]string{
			"path": "direct_assign", "roles_before": "a", "roles_after": "b"}) // 預設 low
		w := fastWorker(db)
		if n := w.RunOnce(); n != 2 || stub.count() != 2 {
			t.Fatalf("低與中分級都應送出: 送達 %d 收到 %d", n, stub.count())
		}
		for _, r := range outboxRows(t, db) {
			if r.State != model.SystemAlertOutboxDelivered || r.DeliveredAt == nil {
				t.Fatalf("狀態不符: %+v", r)
			}
		}
	})

	t.Run("前兩次失敗第三次成功且重建 worker 後續送", func(t *testing.T) {
		stub := newStubReceiver(t, 2)
		db, sink := outboxTestSetup(t, model.NotificationChannel{Name: "c", Type: "webhook", URL: stub.srv.URL,
			Enabled: true, Language: "zh-TW", MinSeverity: "low"})
		raiseEvent(t, db, sink, port.SystemAlertManagementRoleGranted, grant)
		w := fastWorker(db)
		w.RunOnce()
		rows := outboxRows(t, db)
		if rows[0].State != model.SystemAlertOutboxRetrying || rows[0].Attempts != 1 || rows[0].LastError == "" {
			t.Fatalf("第一次失敗後應為 retrying: %+v", rows[0])
		}
		// 重建 worker（模擬行程重啟）：依資料庫狀態續送。
		time.Sleep(10 * time.Millisecond)
		w2 := fastWorker(db)
		w2.RunOnce()
		if r := outboxRows(t, db)[0]; r.State != model.SystemAlertOutboxRetrying || r.Attempts != 2 {
			t.Fatalf("第二次失敗後應仍為 retrying: %+v", r)
		}
		time.Sleep(10 * time.Millisecond)
		w2.RunOnce()
		r := outboxRows(t, db)[0]
		if r.State != model.SystemAlertOutboxDelivered || r.Attempts != 3 || stub.count() != 1 {
			t.Fatalf("第三次應成功: %+v 收到 %d", r, stub.count())
		}
	})

	t.Run("超過時窗標 abandoned 且不再投遞", func(t *testing.T) {
		stub := newStubReceiver(t, 0)
		db, sink := outboxTestSetup(t, model.NotificationChannel{Name: "c", Type: "webhook", URL: stub.srv.URL,
			Enabled: true, Language: "zh-TW", MinSeverity: "low"})
		raiseEvent(t, db, sink, port.SystemAlertManagementRoleGranted, grant)
		w := fastWorker(db)
		w.now = func() time.Time { return time.Now().UTC().Add(73 * time.Hour) }
		w.RunOnce()
		r := outboxRows(t, db)[0]
		if r.State != model.SystemAlertOutboxAbandoned || stub.count() != 0 {
			t.Fatalf("應標記放棄且不送: %+v 收到 %d", r, stub.count())
		}
	})

	t.Run("通道改址後重送仍送到快照網址", func(t *testing.T) {
		stub := newStubReceiver(t, 1)
		db, sink := outboxTestSetup(t, model.NotificationChannel{Name: "c", Type: "webhook", URL: stub.srv.URL,
			Enabled: true, Language: "zh-TW", MinSeverity: "low"})
		raiseEvent(t, db, sink, port.SystemAlertManagementRoleGranted, grant)
		w := fastWorker(db)
		w.RunOnce() // 失敗一次
		if err := db.Model(&model.NotificationChannel{}).Where("name = ?", "c").
			Update("url", "http://127.0.0.1:1/never").Error; err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
		w.RunOnce()
		if stub.count() != 1 {
			t.Fatalf("重送應送到快照網址: 收到 %d", stub.count())
		}
	})

	t.Run("webhook 為機器 payload 帶投遞識別且簽章可驗", func(t *testing.T) {
		stub := newStubReceiver(t, 0)
		db, sink := outboxTestSetup(t, model.NotificationChannel{Name: "c", Type: "webhook", URL: stub.srv.URL,
			Secret: "top-secret", Enabled: true, Language: "zh-TW", MinSeverity: "low"})
		r := raiseEvent(t, db, sink, port.SystemAlertManagementRoleGranted, grant)
		fastWorker(db).RunOnce()
		if stub.count() != 1 {
			t.Fatalf("收到 %d", stub.count())
		}
		body := stub.body(0)
		var got map[string]any
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		if got["event"] != "system_security_alert" {
			t.Fatalf("event: %v", got["event"])
		}
		if key, _ := got["delivery_id"].(string); key == "" || key != outboxRows(t, db)[0].DeliveryKey {
			t.Fatalf("delivery_id 應為佇列列上的投遞識別: %v", got["delivery_id"])
		}
		alert := got["alert"].(map[string]any)
		if uint(alert["id"].(float64)) != r.AlertID || alert["type"] != "management_role_granted" || alert["severity"] != "medium" {
			t.Fatalf("alert 欄位不符: %v", alert)
		}
		if alert["actor"].(map[string]any)["username"] != "alice" {
			t.Fatalf("actor: %v", alert["actor"])
		}
		params := alert["params"].(map[string]any)
		if _, ok := params["actor"]; ok || params["recipient"] != "bob" {
			t.Fatalf("params 不符: %v", params)
		}
		for _, k := range []string{"text", "title", "message"} {
			if _, ok := got[k]; ok {
				t.Fatalf("webhook 不得帶散文欄 %s", k)
			}
		}
		mac := hmac.New(sha256.New, []byte("top-secret"))
		mac.Write(body)
		if want := hex.EncodeToString(mac.Sum(nil)); stub.sigs[0] != want {
			t.Fatalf("簽章不符: %q != %q", stub.sigs[0], want)
		}
	})

	t.Run("Slack 文字依快照語系", func(t *testing.T) {
		zh := newStubReceiver(t, 0)
		en := newStubReceiver(t, 0)
		db, sink := outboxTestSetup(t,
			model.NotificationChannel{Name: "zh", Type: "slack", URL: zh.srv.URL, Enabled: true, Language: "zh-TW", MinSeverity: "low"},
			model.NotificationChannel{Name: "en", Type: "slack", URL: en.srv.URL, Enabled: true, Language: "en-US", MinSeverity: "low"})
		raiseEvent(t, db, sink, port.SystemAlertManagementRoleGranted, grant)
		fastWorker(db).RunOnce()
		if zh.count() != 1 || en.count() != 1 {
			t.Fatalf("收到 zh=%d en=%d", zh.count(), en.count())
		}
		var a, b map[string]string
		_ = json.Unmarshal(zh.body(0), &a)
		_ = json.Unmarshal(en.body(0), &b)
		if a["text"] == "" || b["text"] == "" || a["text"] == b["text"] {
			t.Fatalf("兩種語系的文字應不同: %q / %q", a["text"], b["text"])
		}
	})

	t.Run("同一明細離機轉發恰一次", func(t *testing.T) {
		db, sink := outboxTestSetup(t)
		raiseEvent(t, db, sink, port.SystemAlertManagementRoleGranted, grant)
		w := fastWorker(db)
		teed := 0
		w.tee = func(model.CommandAlert) { teed++ }
		w.RunOnce()
		w.RunOnce()
		w2 := fastWorker(db)
		w2.tee = func(model.CommandAlert) { teed++ }
		w2.RunOnce()
		if teed != 1 {
			t.Fatalf("離機轉發應恰一次: %d", teed)
		}
		var d model.SystemAlertDetail
		if err := db.First(&d).Error; err != nil || d.PublishedAt == nil {
			t.Fatalf("應標記轉發完成: %+v %v", d, err)
		}
	})

	t.Run("分級高者先送", func(t *testing.T) {
		stub := newStubReceiver(t, 0)
		db, sink := outboxTestSetup(t, model.NotificationChannel{Name: "c", Type: "webhook", URL: stub.srv.URL,
			Enabled: true, Language: "zh-TW", MinSeverity: "low"})
		raiseEvent(t, db, sink, port.SystemAlertSelfPrivilegeDecreased, map[string]string{
			"path": "direct_assign", "roles_before": "a", "roles_after": "b"}) // low，編號較小
		raiseEvent(t, db, sink, port.SystemAlertManagementRoleGranted, grant)                                        // medium
		raiseEvent(t, db, sink, port.SystemAlertSecurityAdminAccountOperated, map[string]string{"action": "rescue"}) // high，編號最大
		fastWorker(db).RunOnce()
		if stub.count() != 3 {
			t.Fatalf("收到 %d", stub.count())
		}
		var order []string
		for i := 0; i < 3; i++ {
			var p struct {
				Alert struct {
					Severity string `json:"severity"`
				} `json:"alert"`
			}
			_ = json.Unmarshal(stub.body(i), &p)
			order = append(order, p.Alert.Severity)
		}
		if order[0] != "high" || order[1] != "medium" || order[2] != "low" {
			t.Fatalf("送出順序應為高、中、低: %v", order)
		}
	})

	t.Run("租約未到期的列不被另一個 worker 重複認領", func(t *testing.T) {
		stub := newStubReceiver(t, 0)
		db, sink := outboxTestSetup(t, model.NotificationChannel{Name: "c", Type: "webhook", URL: stub.srv.URL,
			Enabled: true, Language: "zh-TW", MinSeverity: "low"})
		raiseEvent(t, db, sink, port.SystemAlertManagementRoleGranted, grant)
		lease := time.Now().UTC().Add(time.Hour)
		if err := db.Model(&model.SystemAlertOutbox{}).Where("1 = 1").Update("lease_until", lease).Error; err != nil {
			t.Fatal(err)
		}
		fastWorker(db).RunOnce()
		if stub.count() != 0 {
			t.Fatalf("租約中的列不應被認領: 收到 %d", stub.count())
		}
	})

	t.Run("停止後不再開始新的投遞，未啟動時 Stop 不阻塞", func(t *testing.T) {
		stub := newStubReceiver(t, 0)
		db, sink := outboxTestSetup(t, model.NotificationChannel{Name: "c", Type: "webhook", URL: stub.srv.URL,
			Enabled: true, Language: "zh-TW", MinSeverity: "low"})
		raiseEvent(t, db, sink, port.SystemAlertManagementRoleGranted, grant)
		w := fastWorker(db)
		w.Stop()
		w.RunOnce()
		if stub.count() != 0 || outboxRows(t, db)[0].State != model.SystemAlertOutboxPending {
			t.Fatal("停止後的 RunOnce 不應投遞，列保持待送")
		}
		w2 := fastWorker(db)
		w2.interval = 5 * time.Millisecond
		w2.Start()
		deadline := time.Now().Add(2 * time.Second)
		for stub.count() == 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		w2.Stop()
		if stub.count() != 1 {
			t.Fatalf("啟動後的背景迴圈應送出: %d", stub.count())
		}
	})
}
