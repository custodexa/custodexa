package keyvault_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/notifycat"
)

// Slack 應用程式通道的 token 沿用 notification_channels.secret 與待投遞紀錄的 secret_enc：
// DEK 輪替後兩者都可解，替身收到的授權標頭等於原 token。
func TestSlackAppTokenSurvivesDEKRotation(t *testing.T) {
	const token = "xoxb-rotation-test-token"
	db := newMigrationDB(t)
	// 換成完整的通道與待投遞表結構（輪替掃描登記的欄位不變）
	for _, s := range []string{`DROP TABLE notification_channels`, `DROP TABLE system_alert_outbox`,
		`CREATE TABLE command_alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id INTEGER, rule_name TEXT NOT NULL,
			session_id INTEGER, user_id INTEGER NOT NULL, asset_id INTEGER, command TEXT NOT NULL, severity TEXT NOT NULL,
			triggered_at DATETIME NOT NULL, reviewed_by INTEGER, reviewed_at DATETIME, disposition TEXT NOT NULL DEFAULT 'pending',
			note TEXT NOT NULL DEFAULT '', blocked BOOLEAN NOT NULL DEFAULT 0, kind TEXT NOT NULL DEFAULT 'rule',
			reason_code TEXT NOT NULL DEFAULT '')`} {
		if err := db.Exec(s).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.AutoMigrate(&model.NotificationChannel{}, &model.NotificationDelivery{}, &model.NotificationMessage{},
		&model.SystemAlertDetail{}, &model.SystemAlertSeverityOverride{}, &model.AuditLog{}); err != nil {
		t.Fatal(err)
	}
	km := newTestKeyManager(t, db, 1)

	var mu sync.Mutex
	var auth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		mu.Lock()
		auth = append(auth, r.Header.Get("Authorization"))
		mu.Unlock()
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(srv.Close)

	svc := audit.NewNotificationChannelService(db, km)
	svc.SetAuditTxSink(audit.NewTxSink())
	svc.SetSystemAlertSink(audit.NewSystemAlertSink(km))
	ch, err := svc.Create(&audit.NotificationChannelRequest{Name: "app", Type: model.NotificationChannelTypeSlackApp,
		URL: srv.URL, Secret: token, Target: "C1", ActorID: 1, ActorName: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	// 建立通道產生的通道變更告警是帶快照的紀錄（secret_enc 以待投遞表的欄位身分加密）
	var snap model.NotificationDelivery
	if err := db.Where("source_channel_id = ? AND category = ?", ch.ID, model.NotificationCategorySystemSecurityAlert).First(&snap).Error; err != nil {
		t.Fatal(err)
	}
	if snap.SecretEnc == "" || strings.Contains(snap.SecretEnc, token) {
		t.Fatalf("快照的 token 應為密文: %q", snap.SecretEnc)
	}
	n := audit.NewAlertNotifier(db, km)
	if err := n.EnqueueStandalone(audit.SystemEventNotice(notifycat.EventDailyReviewOverdue, map[string]string{})); err != nil {
		t.Fatal(err)
	}

	if _, err := km.RotateDataDEK(); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	var stored model.NotificationChannel
	db.First(&stored, ch.ID)
	db.First(&snap, snap.ID)
	for name, v := range map[string]string{"通道 secret": stored.Secret, "快照 secret_enc": snap.SecretEnc} {
		if !strings.HasPrefix(v, "enc:a1:v2:") {
			t.Fatalf("%s 輪替後應為 v2 密文: %.12q", name, v)
		}
	}

	w := audit.NewSystemAlertOutboxWorker(db, km)
	w.RunOnce()
	// slack_app 同一目的地每秒 1 則：第二則在下一秒的那一輪送出
	time.Sleep(1100 * time.Millisecond)
	w.RunOnce()
	mu.Lock()
	defer mu.Unlock()
	if len(auth) < 2 {
		t.Fatalf("快照紀錄與一般通知都應送達，得 %d 個請求", len(auth))
	}
	for _, a := range auth {
		if a != "Bearer "+token {
			t.Fatalf("授權標頭應等於原 token: %q", a)
		}
	}
}
