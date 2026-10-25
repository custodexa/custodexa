package asset

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
)

// 憑證敏感事件接真實的系統告警落地面與持久投遞佇列（不是樁）：
// 目錄列出入口參數的三種情形；最低分級仍排入投遞；佇列寫入失敗整筆回滾、
// 重送同一操作只做一次遠端變更、只留一筆告警與一筆投遞。

func ensureRealAlertTables(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.Exec(`CREATE TABLE IF NOT EXISTS command_alerts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id INTEGER, rule_name TEXT NOT NULL,
		session_id INTEGER, user_id INTEGER NOT NULL, asset_id INTEGER,
		command TEXT NOT NULL, severity TEXT NOT NULL, triggered_at DATETIME NOT NULL,
		reviewed_by INTEGER, reviewed_at DATETIME,
		disposition TEXT NOT NULL DEFAULT 'pending', note TEXT NOT NULL DEFAULT '',
		blocked BOOLEAN NOT NULL DEFAULT 0,
		kind TEXT NOT NULL DEFAULT 'rule', reason_code TEXT NOT NULL DEFAULT ''
	)`).Error)
	require.NoError(t, db.AutoMigrate(&model.SystemAlertDetail{}, &model.SystemAlertOutbox{},
		&model.SystemAlertSeverityOverride{}, &model.NotificationChannel{}))
}

func tableRows(t *testing.T, db *gorm.DB, table string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Table(table).Count(&n).Error)
	return n
}

func TestCredentialAlertOutboxIntegration(t *testing.T) {
	t.Run("目錄列出三種入口參數", func(t *testing.T) {
		def, ok := audit.LookupSystemAlertType(port.SystemAlertCustomSecretUsed)
		require.True(t, ok)
		var enum []string
		for _, p := range def.Params {
			if p.Name == "entry" {
				enum = p.Enum
			}
		}
		assert.ElementsMatch(t, []string{secretEntryChangePassword, secretEntryDetachShared, secretEntryDeclareNew}, enum)
	})

	t.Run("最低分級與高門檻通道：仍排入投遞", func(t *testing.T) {
		f := setupRotationFixture(t)
		ensureRealAlertTables(t, f.db)
		real := audit.NewSystemAlertSink(nil)
		f.creds.WithSystemAlertSink(real)
		require.NoError(t, f.db.Create(&model.NotificationChannel{
			Name: "高門檻", Type: "webhook", URL: "https://example.invalid/hook",
			Enabled: true, Language: "zh-TW", MinSeverity: "high",
		}).Error)
		require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error {
			_, err := audit.SetSystemAlertSeverityInTx(tx, port.SystemAlertCustomSecretUsed, model.AlertSeverityLow, 1)
			return err
		}))
		credID, _ := f.sharedOn(t, "outbox-shared", "ops", "old-shared", "10.52.0.1", "10.52.0.2")

		_, err := f.creds.SetSecret(adminCtx(), credID, &SetCredentialSecretRequest{Password: "Declared-Secret-9x"})
		require.NoError(t, err)
		assert.EqualValues(t, 1, tableRows(t, f.db, "command_alerts"))
		assert.EqualValues(t, 1, tableRows(t, f.db, "system_alert_outbox"), "不看推送門檻，每個啟用通道一筆投遞")
	})

	t.Run("投遞佇列寫入失敗：整筆回滾且遠端零 I/O；重送同一操作只做一次", func(t *testing.T) {
		f := setupRotationFixture(t)
		ensureRealAlertTables(t, f.db)
		f.rotations.WithSystemAlertSink(audit.NewSystemAlertSink(nil))
		require.NoError(t, f.db.Create(&model.NotificationChannel{
			Name: "通道", Type: "webhook", URL: "https://example.invalid/hook",
			Enabled: true, Language: "zh-TW", MinSeverity: "low",
		}).Error)
		credID, accounts := f.sharedOn(t, "resend-shared", "ops", "old-shared", "10.52.1.1", "10.52.1.2")

		require.NoError(t, f.db.Migrator().DropTable(&model.SystemAlertOutbox{}))
		_, err := f.rotations.Detach(adminCtx(), credID, accounts[0],
			DetachCredentialRequest{Source: DetachSourceCustom, Password: "Declared-Secret-9x"})
		require.Error(t, err, "佇列寫入失敗必須讓整筆失敗")
		rotateCalls, verifyCalls := remoteCallCounts(f)
		assert.Zero(t, rotateCalls+verifyCalls, "遠端零 I/O")
		assert.EqualValues(t, 0, tableRows(t, f.db, "command_alerts"), "告警列隨交易回滾")
		assert.EqualValues(t, 0, tableRows(t, f.db, "change_secret_candidates"), "沒有候選")
		assert.Equal(t, credID, f.binding(t, accounts[0]).CredentialID)

		require.NoError(t, f.db.AutoMigrate(&model.SystemAlertOutbox{}))
		_, err = f.rotations.Detach(adminCtx(), credID, accounts[0],
			DetachCredentialRequest{Source: DetachSourceCustom, Password: "Declared-Secret-9x"})
		require.NoError(t, err)
		rotateCalls, _ = remoteCallCounts(f)
		assert.Equal(t, 1, rotateCalls, "重送後遠端只被改一次")
		assert.EqualValues(t, 1, tableRows(t, f.db, "command_alerts"))
		assert.EqualValues(t, 1, tableRows(t, f.db, "system_alert_outbox"))
	})
}

// remoteCallCounts 遠端樁的改密與驗證呼叫總數。
func remoteCallCounts(f *rotationFixture) (int, int) {
	_, rotate, verify := f.remote.snapshot()
	r, v := 0, 0
	for _, n := range rotate {
		r += n
	}
	for _, n := range verify {
		v += n
	}
	return r, v
}
