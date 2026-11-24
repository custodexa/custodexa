package database_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/testgate"
)

// TestUpgradeLegacyOutboxUnderAttemptCap 升級前已超過嘗試次數上限的待送紀錄在升級後第一輪放棄；
// 其餘沿用原投遞識別續送。
func TestUpgradeLegacyOutboxUnderAttemptCap(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	db := database.FreshSchemaForTest(t, dsn, fmt.Sprintf("ndl_upg_%d", time.Now().UnixNano()))
	database.ApplyMigrationsAroundNotificationDeliveryLayer(t, db, true)

	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	var channelID uint
	if err := db.Raw(`INSERT INTO notification_channels(name,type,url,secret,enabled,language,min_severity,created_at,updated_at) VALUES('c1','webhook',?,'',true,'zh-TW','low',now(),now()) RETURNING id`, srv.URL).Scan(&channelID).Error; err != nil {
		t.Fatal(err)
	}
	insert := func(attempts int, key string) uint {
		var alertID uint
		if err := db.Raw(`INSERT INTO command_alerts(kind,rule_id,rule_name,reason_code,session_id,user_id,command,severity,triggered_at,disposition,note) VALUES('system_security',NULL,'management_role_granted','management_role_granted',NULL,9,'','high',now(),'pending','') RETURNING id`).Scan(&alertID).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Exec(`INSERT INTO system_alert_details(alert_id,alert_type,target_kind,target_id,params,correlation_id,published_at,created_at) VALUES(?,'management_role_granted','user','9','{"path":"direct_assign","recipient":"bob","role_name":"asset_admin"}','',now(),now())`, alertID).Error; err != nil {
			t.Fatal(err)
		}
		var id uint
		if err := db.Raw(`INSERT INTO system_alert_outbox(alert_id,dest_type,dest_name,dest_language,source_channel_id,url_enc,secret_enc,state,attempts,next_attempt_at,last_error,created_at,delivery_key) VALUES(?,'webhook','c1','zh-TW',?,?,'','retrying',?,now() - interval '1 minute','HTTP 500',now() - interval '1 day',?) RETURNING id`,
			alertID, channelID, srv.URL, attempts, key).Scan(&id).Error; err != nil {
			t.Fatal(err)
		}
		return id
	}
	over := insert(60, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	keep := insert(3, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	database.ApplyMigrationsAroundNotificationDeliveryLayer(t, db, false)

	w := audit.NewSystemAlertOutboxWorker(db, nil)
	w.RunOnce()

	var rows []model.NotificationDelivery
	if err := db.Order("id").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		switch r.ID {
		case over:
			if r.State != model.NotificationDeliveryAbandoned || r.EndReason != model.NotificationEndMaxAttempts || r.Attempts != 60 {
				t.Fatalf("超過上限的既有紀錄應在第一輪放棄: %+v", r)
			}
		case keep:
			if r.State != model.NotificationDeliveryDelivered || r.Attempts != 4 {
				t.Fatalf("其餘應續送: %+v", r)
			}
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 1 || !strings.Contains(bodies[0], `"delivery_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"`) {
		t.Fatalf("收端應只收到續送的那一筆且投遞識別等於升級前的值: %v", bodies)
	}
}
