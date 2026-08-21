package audit

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// setupMatcherMockDB 建立 sqlmock 包裝的 gorm.DB（與 asset_authorization 測試同模式）
func setupMatcherMockDB(t *testing.T) (sqlmock.Sqlmock, *gorm.DB) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	gormDB, err := gorm.Open(postgres.New(postgres.Config{Conn: db}), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to create gorm DB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return mock, gormDB
}

// alertRuleRows 構造 alert_rules 查詢結果
func alertRuleRows(rules []model.AlertRule) *sqlmock.Rows {
	rows := sqlmock.NewRows([]string{"id", "name", "pattern", "severity", "enabled", "created_at", "updated_at"})
	for _, r := range rules {
		rows.AddRow(r.ID, r.Name, r.Pattern, r.Severity, r.Enabled, time.Now(), time.Now())
	}
	return rows
}

func TestAlertMatcher_Match(t *testing.T) {
	t.Run("命中啟用規則", func(t *testing.T) {
		m := NewAlertMatcher(nil, nil)
		m.setRules([]model.AlertRule{
			{ID: 1, Name: "遞迴強制刪除", Pattern: `rm\s+-(rf|fr)\b`, Severity: model.AlertSeverityHigh, Enabled: true},
		})

		matched := m.Match("rm -rf /data", "ssh")

		assert.Len(t, matched, 1)
		assert.Equal(t, "遞迴強制刪除", matched[0].Name)
		assert.Equal(t, model.AlertSeverityHigh, matched[0].Severity)
	})

	t.Run("未命中返回空", func(t *testing.T) {
		m := NewAlertMatcher(nil, nil)
		m.setRules([]model.AlertRule{
			{ID: 1, Name: "遞迴強制刪除", Pattern: `rm\s+-(rf|fr)\b`, Severity: model.AlertSeverityHigh, Enabled: true},
		})

		assert.Empty(t, m.Match("ls -la", "ssh"))
	})

	t.Run("停用規則不命中", func(t *testing.T) {
		m := NewAlertMatcher(nil, nil)
		m.setRules([]model.AlertRule{
			{ID: 1, Name: "遞迴強制刪除", Pattern: `rm\s+-(rf|fr)\b`, Severity: model.AlertSeverityHigh, Enabled: false},
		})

		assert.Empty(t, m.Match("rm -rf /data", "ssh"))
	})

	t.Run("無效 regex 規則被跳過且不影響其他規則", func(t *testing.T) {
		m := NewAlertMatcher(nil, nil)
		count := m.setRules([]model.AlertRule{
			{ID: 1, Name: "壞規則", Pattern: `rm -rf (`, Severity: model.AlertSeverityHigh, Enabled: true},
			{ID: 2, Name: "格式化檔案系統", Pattern: `\bmkfs`, Severity: model.AlertSeverityHigh, Enabled: true},
		})

		// 壞規則被跳過，僅 1 條進入快取；好規則照常命中
		assert.Equal(t, 1, count)
		matched := m.Match("mkfs.ext4 /dev/sdb1", "ssh")
		assert.Len(t, matched, 1)
		assert.Equal(t, "格式化檔案系統", matched[0].Name)
	})

	t.Run("一條指令可命中多條規則", func(t *testing.T) {
		m := NewAlertMatcher(nil, nil)
		m.setRules([]model.AlertRule{
			{ID: 1, Name: "遞迴強制刪除", Pattern: `rm\s+-(rf|fr)\b`, Severity: model.AlertSeverityHigh, Enabled: true},
			{ID: 2, Name: "刪 dev 目錄", Pattern: `/dev/`, Severity: model.AlertSeverityMedium, Enabled: true},
		})

		assert.Len(t, m.Match("rm -rf /dev/null", "ssh"), 2)
	})
}

func TestAlertMatcher_Reload(t *testing.T) {
	t.Run("Reload 後新規則生效、舊規則移除", func(t *testing.T) {
		mock, gormDB := setupMatcherMockDB(t)
		m := NewAlertMatcher(gormDB, NewAlertRecorder(gormDB))

		// 第一次載入：只有 rm 規則
		mock.ExpectQuery(`SELECT \* FROM "alert_rules"`).WillReturnRows(alertRuleRows([]model.AlertRule{
			{ID: 1, Name: "遞迴強制刪除", Pattern: `rm\s+-(rf|fr)\b`, Severity: model.AlertSeverityHigh, Enabled: true},
		}))
		assert.NoError(t, m.LoadRules())
		assert.Len(t, m.Match("rm -rf /data", "ssh"), 1)
		assert.Empty(t, m.Match("mkfs.ext4 /dev/sdb1", "ssh"))

		// Reload：規則換成 mkfs
		mock.ExpectQuery(`SELECT \* FROM "alert_rules"`).WillReturnRows(alertRuleRows([]model.AlertRule{
			{ID: 2, Name: "格式化檔案系統", Pattern: `\bmkfs`, Severity: model.AlertSeverityHigh, Enabled: true},
		}))
		assert.NoError(t, m.Reload())
		assert.Empty(t, m.Match("rm -rf /data", "ssh"))
		assert.Len(t, m.Match("mkfs.ext4 /dev/sdb1", "ssh"), 1)

		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Reload 失敗回傳錯誤且沿用舊快取", func(t *testing.T) {
		mock, gormDB := setupMatcherMockDB(t)
		m := NewAlertMatcher(gormDB, NewAlertRecorder(gormDB))
		m.setRules([]model.AlertRule{
			{ID: 1, Name: "遞迴強制刪除", Pattern: `rm\s+-(rf|fr)\b`, Severity: model.AlertSeverityHigh, Enabled: true},
		})

		mock.ExpectQuery(`SELECT \* FROM "alert_rules"`).WillReturnError(errors.New("db down"))

		assert.Error(t, m.Reload())
		// 舊快取仍可用：規則熱更新失敗不能讓告警全面失效
		assert.Len(t, m.Match("rm -rf /data", "ssh"), 1)
	})
}

// recordingAlertSink 記帳用的假落地面：把送進來的告警原樣留著供斷言。
//
// **存在的理由是「零告警」需要一個會失敗的斷言**：sqlmock 的
// ExpectationsWereMet 對「多出來的呼叫」是沉默的，拿它當零寫入的證明是假綠。
type recordingAlertSink struct {
	alerts []gatewayapi.CommandAlert
}

func (s *recordingAlertSink) RecordAlert(ctx context.Context, a gatewayapi.CommandAlert) error {
	return s.RecordAlerts(ctx, []gatewayapi.CommandAlert{a})
}

func (s *recordingAlertSink) RecordAlerts(_ context.Context, as []gatewayapi.CommandAlert) error {
	s.alerts = append(s.alerts, as...)
	return nil
}

func TestAlertMatcher_MatchAndStore(t *testing.T) {
	executedAt := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	cmds := []model.SessionCommand{
		{SessionID: 5, UserID: 1, Command: "ls -la", Seq: 1, ExecutedAt: executedAt},
		{SessionID: 5, UserID: 1, Command: "rm -rf /data", Seq: 2, ExecutedAt: executedAt},
	}

	t.Run("命中寫入 command_alerts（含規則快照欄位）", func(t *testing.T) {
		mock, gormDB := setupMatcherMockDB(t)
		m := NewAlertMatcher(gormDB, NewAlertRecorder(gormDB))
		m.setRules([]model.AlertRule{
			{ID: 7, Name: "遞迴強制刪除", Pattern: `rm\s+-(rf|fr)\b`, Severity: model.AlertSeverityHigh, Enabled: true},
		})

		mock.ExpectBegin()
		// audit-workflows D3：INSERT 補審閱欄 reviewed_by(nil)/reviewed_at(nil)/
		// disposition="pending"/note=""（新告警未審閱；批次 Create 含全部欄位）；
		// backend-i18n-unification D6：blocked 欄（AlertMatcher 走 alert 型規則，恆 false）
		// command-audit-altscreen-bypass §6.3：另補 kind（規則類為 "rule"）與
		// reason_code（規則類為空字串）兩欄，位置依 model 欄序在 rule_name 之後
		mock.ExpectQuery(`INSERT INTO "command_alerts"`).
			WithArgs(uint(7), "遞迴強制刪除", model.AlertKindRule, "", uint(5), uint(1), nil, "rm -rf /data", model.AlertSeverityHigh, executedAt, nil, nil, model.AlertDispositionPending, "", false).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
		mock.ExpectCommit()

		m.MatchAndStore(cmds, "ssh")

		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("無命中時不觸碰 DB", func(t *testing.T) {
		mock, gormDB := setupMatcherMockDB(t)
		m := NewAlertMatcher(gormDB, NewAlertRecorder(gormDB))
		m.setRules([]model.AlertRule{
			{ID: 7, Name: "格式化檔案系統", Pattern: `\bmkfs`, Severity: model.AlertSeverityHigh, Enabled: true},
		})

		m.MatchAndStore([]model.SessionCommand{
			{SessionID: 5, UserID: 1, Command: "ls -la", Seq: 1, ExecutedAt: executedAt},
		}, "ssh")

		// 未設定任何 expectation：有 DB 操作就會 fail
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	// TestDegradedRowsNeverEnterRuleMatching 的內聯版：降級列 SHALL NOT 進規則比對。
	//
	// **為什麼需要守衛**：降級列的 command 恆為空字串。內建規則不會命中空字串，
	// 所以「今天沒事」——但使用者可以自建 `.*` 這種規則（規則 API 只驗 regex 可編譯），
	// 屆時每一筆降級列都會生出一筆 Command="" 的告警。那是把「這一輪無法還原」
	// 呈現成「使用者執行了一條空指令」，即另一種捏造。
	// 把跳過那一行刪掉，本子測試即紅。
	// **不用 sqlmock 的 ExpectationsWereMet 當「零寫入」的斷言**：它只檢查
	// 「期望的呼叫都發生了」，**多出來的呼叫不會使它失敗**。突變自檢實測：
	// 把跳過那一行改成永遠不成立，整包照樣綠。改用會記帳的假落地面。
	t.Run("降級列不進規則比對（.* 規則也不得命中）", func(t *testing.T) {
		sink := &recordingAlertSink{}
		m := NewAlertMatcher(nil, sink)
		m.setRules([]model.AlertRule{
			{ID: 9, Name: "全部", Pattern: `.*`, Severity: model.AlertSeverityLow, Enabled: true},
		})

		// 一批只有降級列：全部 Command="" 且 Degraded=true
		m.MatchAndStore([]model.SessionCommand{
			{SessionID: 5, UserID: 1, Command: "", Seq: 1, ExecutedAt: executedAt,
				Degraded: true, DegradeReason: model.DegradeAltScreen},
			{SessionID: 5, UserID: 1, Command: "", Seq: 2, ExecutedAt: executedAt,
				Degraded: true, DegradeReason: model.DegradeQueueDiscarded},
		}, "ssh")

		assert.Empty(t, sink.alerts,
			"降級列生出了規則告警（Command 為空字串的假告警＝另一種捏造）")
	})

	t.Run("同一批中的正常指令仍照常比對（跳過不得誤傷）", func(t *testing.T) {
		sink := &recordingAlertSink{}
		m := NewAlertMatcher(nil, sink)
		m.setRules([]model.AlertRule{
			{ID: 7, Name: "遞迴強制刪除", Pattern: `rm\s+-(rf|fr)\b`, Severity: model.AlertSeverityHigh, Enabled: true},
			{ID: 9, Name: "全部", Pattern: `.*`, Severity: model.AlertSeverityLow, Enabled: true},
		})

		m.MatchAndStore([]model.SessionCommand{
			{SessionID: 5, UserID: 1, Command: "", Seq: 1, ExecutedAt: executedAt,
				Degraded: true, DegradeReason: model.DegradeAltScreen},
			{SessionID: 5, UserID: 1, Command: "rm -rf /data", Seq: 2, ExecutedAt: executedAt},
		}, "ssh")

		// 正常那一條命中兩條規則；降級那一條一筆都不得產生
		assert.Len(t, sink.alerts, 2)
		for _, a := range sink.alerts {
			assert.Equal(t, "rm -rf /data", a.Command)
			assert.Equal(t, model.AlertKindRule, a.Kind)
			assert.NotNil(t, a.RuleID, "規則類告警的 rule_id 不得為空")
		}
	})

	t.Run("寫入失敗僅記 log 不 panic（錯誤不擴散）", func(t *testing.T) {
		mock, gormDB := setupMatcherMockDB(t)
		m := NewAlertMatcher(gormDB, NewAlertRecorder(gormDB))
		m.setRules([]model.AlertRule{
			{ID: 7, Name: "遞迴強制刪除", Pattern: `rm\s+-(rf|fr)\b`, Severity: model.AlertSeverityHigh, Enabled: true},
		})

		mock.ExpectBegin()
		mock.ExpectQuery(`INSERT INTO "command_alerts"`).WillReturnError(sql.ErrConnDone)
		mock.ExpectRollback()

		assert.NotPanics(t, func() { m.MatchAndStore(cmds, "ssh") })
	})
}
