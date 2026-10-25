package audit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupSystemAlertDB 建立 sqlite 測試庫：command_alerts 手建等價 schema（timestamptz 在 sqlite 讀回會失敗），
// 其餘三張新表與通知通道走 AutoMigrate。級聯刪除與 CHECK 由 PG 版的遷移測試負責。
func setupSystemAlertDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	ensureSystemAlertTables(t, db)
	return db
}

// ensureSystemAlertTables 在 sqlite 測試庫補齊系統告警所需的資料表（已存在則略過）。
func ensureSystemAlertTables(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := db.Exec(`CREATE TABLE IF NOT EXISTS command_alerts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id INTEGER, rule_name TEXT NOT NULL,
		session_id INTEGER, user_id INTEGER NOT NULL, asset_id INTEGER,
		command TEXT NOT NULL, severity TEXT NOT NULL, triggered_at DATETIME NOT NULL,
		reviewed_by INTEGER, reviewed_at DATETIME,
		disposition TEXT NOT NULL DEFAULT 'pending', note TEXT NOT NULL DEFAULT '',
		blocked BOOLEAN NOT NULL DEFAULT 0,
		kind TEXT NOT NULL DEFAULT 'rule', reason_code TEXT NOT NULL DEFAULT ''
	)`).Error; err != nil {
		t.Fatalf("create command_alerts: %v", err)
	}
	if err := db.AutoMigrate(&model.SystemAlertDetail{}, &model.SystemAlertOutbox{},
		&model.SystemAlertSeverityOverride{}, &model.NotificationChannel{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
}

// recordingCodec 記錄每次加密用的欄位身分，並讓密文與明文可區分。
type recordingCodec struct{ refs []crypto.CipherRef }

func (c *recordingCodec) EncryptFor(_ context.Context, ref crypto.CipherRef, plaintext string) (string, error) {
	c.refs = append(c.refs, ref)
	return "sealed:" + ref.Table + "." + ref.Column + ":" + plaintext, nil
}

func (c *recordingCodec) DecryptFor(_ context.Context, ref crypto.CipherRef, ciphertext string) (string, error) {
	return strings.TrimPrefix(ciphertext, "sealed:"+ref.Table+"."+ref.Column+":"), nil
}

func seedChannels(t *testing.T, db *gorm.DB) {
	t.Helper()
	for _, ch := range []model.NotificationChannel{
		{Name: "ops", Type: "webhook", URL: "https://hook-a.example.test/x", Secret: "s1", Enabled: true, Language: "zh-TW", MinSeverity: "high"},
		{Name: "slack", Type: "slack", URL: "https://hook-b.example.test/y", Enabled: true, Language: "en-US", MinSeverity: "low"},
	} {
		if err := db.Create(&ch).Error; err != nil {
			t.Fatal(err)
		}
	}
	// 停用的通道不收產生當下的告警（它不是啟用中的目的地）。
	if err := db.Create(&model.NotificationChannel{Name: "off", Type: "webhook", URL: "https://hook-c.example.test/z",
		Enabled: false, Language: "zh-TW", MinSeverity: "low"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&model.NotificationChannel{}).Where("name = ?", "off").Update("enabled", false).Error; err != nil {
		t.Fatal(err)
	}
}

func validGrantEvent() port.SystemAlertEvent {
	return port.SystemAlertEvent{
		Type:          port.SystemAlertManagementRoleGranted,
		Actor:         port.SystemAlertActor{UserID: 7, Username: "alice"},
		ClientIP:      "10.0.0.1",
		Target:        port.SystemAlertTarget{Kind: port.SystemAlertTargetUser, ID: "9"},
		CorrelationID: "corr-1",
		Params:        map[string]string{"path": "direct_assign", "recipient": "bob", "role_name": "asset_admin"},
	}
}

func systemAlertRowCount(t *testing.T, db *gorm.DB, table string) int64 {
	t.Helper()
	var n int64
	if err := db.Table(table).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSystemAlertRaiseInTx(t *testing.T) {
	t.Run("同交易寫入告警列、明細與每個啟用通道一筆佇列列", func(t *testing.T) {
		db := setupSystemAlertDB(t)
		seedChannels(t, db)
		codec := &recordingCodec{}
		sink := NewSystemAlertSink(codec)
		var receipt port.SystemAlertReceipt
		if err := db.Transaction(func(tx *gorm.DB) error {
			var err error
			receipt, err = port.RaiseInTx(sink, tx, validGrantEvent())
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if receipt.AlertID == 0 || receipt.Severity != "medium" || receipt.Destinations != 2 {
			t.Fatalf("回執不符: %+v", receipt)
		}
		var alert model.CommandAlert
		if err := db.First(&alert, receipt.AlertID).Error; err != nil {
			t.Fatal(err)
		}
		if alert.Kind != model.AlertKindSystemSecurity || alert.RuleID != nil || alert.RuleName != "management_role_granted" ||
			alert.ReasonCode != "management_role_granted" || alert.Severity != "medium" || alert.UserID != 7 ||
			alert.Disposition != model.AlertDispositionPending || alert.Command != "" {
			t.Fatalf("告警列不符: %+v", alert)
		}
		var detail model.SystemAlertDetail
		if err := db.First(&detail, "alert_id = ?", receipt.AlertID).Error; err != nil {
			t.Fatal(err)
		}
		if detail.AlertType != "management_role_granted" || detail.TargetKind != "user" || detail.TargetID != "9" ||
			detail.CorrelationID != "corr-1" || detail.PublishedAt != nil {
			t.Fatalf("明細不符: %+v", detail)
		}
		var params map[string]string
		if err := json.Unmarshal([]byte(detail.Params), &params); err != nil || params["recipient"] != "bob" || params["role_name"] != "asset_admin" {
			t.Fatalf("明細參數不符: %q %v", detail.Params, err)
		}
		// 操作者名是產生當下的快照（告警列只存使用者編號），投遞時由投遞程序拆出；分級不重複存。
		if params["actor"] != "alice" {
			t.Fatalf("明細參數應帶操作者名快照: %v", params)
		}
		if _, leaked := params["severity"]; leaked {
			t.Fatal("明細參數不應含 severity 這類出站附加欄")
		}
		var outbox []model.SystemAlertOutbox
		if err := db.Order("id").Find(&outbox).Error; err != nil || len(outbox) != 2 {
			t.Fatalf("佇列列 %d: %v", len(outbox), err)
		}
		for _, o := range outbox {
			if o.State != model.SystemAlertOutboxPending || o.Attempts != 0 || o.AlertID != receipt.AlertID {
				t.Fatalf("佇列列狀態不符: %+v", o)
			}
			if strings.Contains(o.URLEnc, "https://") && !strings.HasPrefix(o.URLEnc, "sealed:system_alert_outbox.url_enc:") {
				t.Fatalf("目的地網址未以新欄位身分加密: %q", o.URLEnc)
			}
		}
		if outbox[0].DestName != "ops" || outbox[0].DestLanguage != "zh-TW" || !strings.HasSuffix(outbox[0].SecretEnc, ":s1") {
			t.Fatalf("目的地快照不符: %+v", outbox[0])
		}
		for _, ref := range codec.refs {
			if ref != keyvault.RefSystemAlertOutboxURL && ref != keyvault.RefSystemAlertOutboxSecret {
				t.Fatalf("加密使用了非預期的欄位身分: %+v", ref)
			}
		}
	})

	t.Run("交易回滾後三者皆不存在", func(t *testing.T) {
		db := setupSystemAlertDB(t)
		seedChannels(t, db)
		boom := errors.New("後續步驟失敗")
		err := db.Transaction(func(tx *gorm.DB) error {
			if _, err := port.RaiseInTx(NewSystemAlertSink(nil), tx, validGrantEvent()); err != nil {
				return err
			}
			return boom
		})
		if !errors.Is(err, boom) {
			t.Fatalf("應回傳後續錯誤: %v", err)
		}
		for _, tb := range []string{"command_alerts", "system_alert_details", "system_alert_outbox"} {
			if n := systemAlertRowCount(t, db, tb); n != 0 {
				t.Fatalf("%s 回滾後仍有 %d 列", tb, n)
			}
		}
	})

	t.Run("不合契約的事件一律回錯且不寫任何列", func(t *testing.T) {
		db := setupSystemAlertDB(t)
		seedChannels(t, db)
		mutate := map[string]func(*port.SystemAlertEvent){
			"未登錄類型":  func(e *port.SystemAlertEvent) { e.Type = "no_such_type" },
			"未宣告參數鍵": func(e *port.SystemAlertEvent) { e.Params["extra"] = "x" },
			"enum 越界": func(e *port.SystemAlertEvent) {
				e.Type = port.SystemAlertRetentionShortened
				e.Params = map[string]string{"data_class": "bogus", "days_before": "30", "days_after": "7"}
				e.Target.Kind = port.SystemAlertTargetSystemSetting
			},
			"int 非整數": func(e *port.SystemAlertEvent) {
				e.Type = port.SystemAlertRetentionShortened
				e.Params = map[string]string{"data_class": "alert", "days_before": "abc", "days_after": "7"}
				e.Target.Kind = port.SystemAlertTargetSystemSetting
			},
			"目標種類越界": func(e *port.SystemAlertEvent) { e.Target.Kind = port.SystemAlertTargetAsset },
			"缺必要參數":  func(e *port.SystemAlertEvent) { delete(e.Params, "role_name") },
			"操作者為零值": func(e *port.SystemAlertEvent) { e.Actor = port.SystemAlertActor{} },
			"操作者缺名稱": func(e *port.SystemAlertEvent) { e.Actor.Username = " " },
			"tokens 含非法字": func(e *port.SystemAlertEvent) {
				e.Type = port.SystemAlertKeyTopologyChanged
				e.Params = map[string]string{"change_kind": "Bad Value"}
				e.Target.Kind = port.SystemAlertTargetSystemSetting
			},
		}
		for name, fn := range mutate {
			ev := validGrantEvent()
			fn(&ev)
			err := db.Transaction(func(tx *gorm.DB) error {
				_, err := port.RaiseInTx(NewSystemAlertSink(nil), tx, ev)
				return err
			})
			if err == nil {
				t.Errorf("%s：應回錯", name)
			}
		}
		for _, tb := range []string{"command_alerts", "system_alert_details", "system_alert_outbox"} {
			if n := systemAlertRowCount(t, db, tb); n != 0 {
				t.Fatalf("%s 被寫入 %d 列", tb, n)
			}
		}
	})

	t.Run("sink 為 nil 回 ErrSystemAlertSinkMissing", func(t *testing.T) {
		db := setupSystemAlertDB(t)
		if _, err := port.RaiseInTx(nil, db, validGrantEvent()); !errors.Is(err, port.ErrSystemAlertSinkMissing) {
			t.Fatalf("應回 ErrSystemAlertSinkMissing: %v", err)
		}
	})

	t.Run("分級為產生當下的有效分級；覆寫為低仍寫入並排入佇列", func(t *testing.T) {
		db := setupSystemAlertDB(t)
		seedChannels(t, db)
		sink := NewSystemAlertSink(nil)
		raise := func() port.SystemAlertReceipt {
			var r port.SystemAlertReceipt
			if err := db.Transaction(func(tx *gorm.DB) error {
				var err error
				r, err = port.RaiseInTx(sink, tx, validGrantEvent())
				return err
			}); err != nil {
				t.Fatal(err)
			}
			return r
		}
		if err := db.Transaction(func(tx *gorm.DB) error {
			_, err := SetSystemAlertSeverityInTx(tx, port.SystemAlertManagementRoleGranted, "low", 1)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		low := raise()
		if low.Severity != "low" || low.Destinations != 2 {
			t.Fatalf("覆寫為低仍應產生並排入全部目的地: %+v", low)
		}
		if err := db.Transaction(func(tx *gorm.DB) error {
			_, err := SetSystemAlertSeverityInTx(tx, port.SystemAlertManagementRoleGranted, "high", 1)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		high := raise()
		if high.Severity != "high" {
			t.Fatalf("新覆寫應反映在之後的告警: %+v", high)
		}
		var first model.CommandAlert
		if err := db.First(&first, low.AlertID).Error; err != nil || first.Severity != "low" {
			t.Fatalf("改覆寫不得改既有告警列: %+v %v", first, err)
		}
	})

	t.Run("沒有啟用通道時佇列為零筆，告警列仍存在", func(t *testing.T) {
		db := setupSystemAlertDB(t)
		var r port.SystemAlertReceipt
		if err := db.Transaction(func(tx *gorm.DB) error {
			var err error
			r, err = port.RaiseInTx(NewSystemAlertSink(nil), tx, validGrantEvent())
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if r.Destinations != 0 || systemAlertRowCount(t, db, "system_alert_outbox") != 0 || systemAlertRowCount(t, db, "command_alerts") != 1 {
			t.Fatalf("回執 %+v、佇列 %d、告警 %d", r, systemAlertRowCount(t, db, "system_alert_outbox"), systemAlertRowCount(t, db, "command_alerts"))
		}
	})

	t.Run("額外目的地與啟用通道以類型網址密鑰去重", func(t *testing.T) {
		db := setupSystemAlertDB(t)
		seedChannels(t, db)
		extra := []systemAlertDestination{
			{Type: "webhook", Name: "ops-old", Language: "zh-TW", URL: "https://hook-a.example.test/x", Secret: "s1"}, // 與啟用通道相同
			{Type: "webhook", Name: "ops-old", Language: "zh-TW", URL: "https://old.example.test/h"},                  // 舊網址
		}
		var r port.SystemAlertReceipt
		if err := db.Transaction(func(tx *gorm.DB) error {
			var err error
			r, err = NewSystemAlertSink(nil).(*systemAlertSink).raise(tx, validGrantEvent(), extra)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if r.Destinations != 3 {
			t.Fatalf("應為 2 個啟用通道加 1 個舊網址: %+v", r)
		}
	})

	t.Run("系統安全告警不進記憶體推送佇列", func(t *testing.T) {
		n := newTestNotifier()
		n.Enqueue(model.CommandAlert{ID: 5, Kind: model.AlertKindSystemSecurity, RuleName: "x", Severity: "low"})
		if got := n.PendingNotifications(); got != 0 {
			t.Fatalf("系統告警進了推送佇列: pending=%d", got)
		}
	})
}
