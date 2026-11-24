package audit

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 產生點的 savepoint 在 PostgreSQL 上的行為（TEST_PG_DSN gated）：內容列 INSERT 以語句錯誤失敗時，
// 交易不得進入 aborted 狀態，業務資料照常提交。觸發器讓 INSERT 在資料庫層失敗（不是 GORM 層的注入）。

func failNotificationInsertsPG(t *testing.T, db *gorm.DB) {
	t.Helper()
	for _, s := range []string{
		`CREATE OR REPLACE FUNCTION fail_notification_msg() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'injected'; END $$ LANGUAGE plpgsql`,
		`CREATE TRIGGER fail_notification_msg BEFORE INSERT ON notification_messages FOR EACH ROW EXECUTE FUNCTION fail_notification_msg()`,
	} {
		if err := db.Exec(s).Error; err != nil {
			t.Fatal(err)
		}
	}
}

func TestSourceIPAlertSavepointPG(t *testing.T) {
	e := newNDLEnvPG(t)
	useSingletonNotifier(t, e.n)
	if err := e.db.Exec(`CREATE TABLE user_source_ips (user_id BIGINT NOT NULL, client_ip TEXT NOT NULL,
		first_seen_at TIMESTAMPTZ, last_seen_at TIMESTAMPTZ, first_session_at TIMESTAMPTZ, first_session_id BIGINT,
		PRIMARY KEY (user_id, client_ip))`).Error; err != nil {
		t.Fatal(err)
	}
	b := NewSourceIPBaseline(e.db, NewAlertRecorder(e.db), NewTxSink())

	// 業務交易回滾時內容列不存在
	b.afterAlertWrite = func() error { return errors.New("injected rollback") }
	if _, err := b.ObserveSession(context.Background(), 1, "203.0.113.9", 21, nil, e.clock.now()); err == nil {
		t.Fatal("應回錯")
	}
	if n := len(e.messages()); n != 0 {
		t.Fatalf("回滾後內容列應為 0，得 %d", n)
	}
	b.afterAlertWrite = nil

	// 內容列 INSERT 在資料庫層失敗：savepoint 讓交易仍可提交，基準與告警列都在
	failNotificationInsertsPG(t, e.db)
	winner, err := b.ObserveSession(context.Background(), 1, "203.0.113.7", 22, nil, e.clock.now())
	if err != nil || !winner {
		t.Fatalf("建線觀察應成功並取得勝者: winner=%v err=%v", winner, err)
	}
	var base, alerts int64
	e.db.Table("user_source_ips").Where("client_ip = ?", "203.0.113.7").Count(&base)
	e.db.Model(&model.CommandAlert{}).Where("kind = ?", model.AlertKindNewSourceIP).Count(&alerts)
	if base != 1 || alerts != 1 || len(e.messages()) != 0 {
		t.Fatalf("基準 %d 告警 %d（應各 1）內容 %d（應 0）", base, alerts, len(e.messages()))
	}
}

func TestAgentBreakerSavepointPG(t *testing.T) {
	db, _ := purgeSchemaDB(t, fmt.Sprintf("ndl_c_breaker_%d", time.Now().UnixNano()))
	if err := db.Exec("DROP TABLE command_alerts").Error; err != nil {
		t.Fatal(err)
	}
	s := probeFixture(t, db)
	setupAgentNoticeDB(t, db)
	s.deps.Notify = NotifyAgentOwner
	failNotificationInsertsPG(t, db)
	var last ProbeBreakerResult
	for _, a := range []uint{1, 2, 3} {
		r, err := s.RecordDenied(context.Background(), 2, 7, a, "GET /assets/:id")
		if err != nil {
			t.Fatalf("通知寫不進去不得讓熔斷交易失敗: %v", err)
		}
		last = r
	}
	if !last.Tripped {
		t.Fatal("第三次應熔斷")
	}
	var probes, alerts int64
	db.Model(&model.AgentProbeEvent{}).Count(&probes)
	db.Model(&model.CommandAlert{}).Where("kind = ?", model.AlertKindAgentBreaker).Count(&alerts)
	var u model.User
	db.First(&u, 2)
	if probes != 3 || alerts != 1 || u.BreakerPendingAt == nil {
		t.Fatalf("探測 %d（應 3）告警 %d（應 1）熔斷狀態 %v", probes, alerts, u.BreakerPendingAt)
	}
}
