package database

import (
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/testgate"
	"gorm.io/gorm"
)

// 來源位址追查 migration 的 pg-gated 實測：回填語義與含資料的 Down／Up。
//
// 跑法（compose 內）：
//
//	TEST_PG_DSN="host=postgres user=postgres password=postgres dbname=postgres port=5432 sslmode=disable" \
//	REQUIRE_INTEGRATION=1 go test ./internal/database -run SourceIPForensicsPG -v

// sipCount 單一整數查詢
func sipCount(t *testing.T, db *gorm.DB, sql string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := db.Raw(sql, args...).Scan(&n).Error; err != nil {
		t.Fatalf("查詢失敗（%s）: %v", sql, err)
	}
	return n
}

// sipKindCheckDef 讀 command_alerts_kind_check 的定義文字
func sipKindCheckDef(t *testing.T, db *gorm.DB, pgSchema string) string {
	t.Helper()
	var def string
	if err := db.Raw(`
		SELECT pg_get_constraintdef(con.oid)
		FROM pg_constraint con
		JOIN pg_class rel ON rel.oid = con.conrelid
		JOIN pg_namespace n ON n.oid = con.connamespace
		WHERE n.nspname = ? AND rel.relname = 'command_alerts' AND con.conname = 'command_alerts_kind_check'`,
		pgSchema).Scan(&def).Error; err != nil {
		t.Fatalf("讀 CHECK 定義失敗: %v", err)
	}
	return def
}

// TestSourceIPForensicsPGBackfillMergesSessionsAndLogins 回填：sessions 全史帶首次建線
// 會話 id；audit_logs 登入成功列只補見到時刻；空位址跳過；兩來源同鍵合併取最早／最晚。
func TestSourceIPForensicsPGBackfillMergesSessionsAndLogins(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	const pgSchema = "sip_backfill_test"
	db := freshSchema(t, dsn, pgSchema)
	if err := applyBaseline(db); err != nil {
		t.Fatalf("baseline 失敗: %v", err)
	}
	if err := applyAuditExportJobs(db); err != nil {
		t.Fatalf("audit_export_jobs 失敗: %v", err)
	}

	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	mustExec := func(sql string, args ...any) {
		t.Helper()
		if err := db.Exec(sql, args...).Error; err != nil {
			t.Fatalf("種子失敗（%.60s）: %v", sql, err)
		}
	}
	// sessions FK 指向 users／assets
	mustExec(`INSERT INTO users (id, username, password, active, created_at, updated_at) VALUES
		(1, 'alice', 'x', true, now(), now()), (2, 'bob', 'x', true, now(), now())`)
	mustExec(`INSERT INTO assets (id, name, host, port, protocol, created_by, created_at, updated_at) VALUES
		(1, 'a1', 'h', 22, 'ssh', 1, now(), now())`)
	// alice 自 203.0.113.5 三場（最早 id=11，start 08-02）；自 10.1.2.3 一場；一場空位址（跳過）；一場軟刪（跳過）
	mustExec(`INSERT INTO sessions (id, session_id, status, protocol, user_id, asset_id, client_ip, start_time, auth_epoch) VALUES
		(11, 's11', 'closed', 'ssh', 1, 1, '203.0.113.5', ?, 0),
		(12, 's12', 'closed', 'ssh', 1, 1, '203.0.113.5', ?, 0),
		(13, 's13', 'closed', 'ssh', 1, 1, '203.0.113.5', ?, 0),
		(14, 's14', 'closed', 'ssh', 1, 1, '10.1.2.3', ?, 0),
		(15, 's15', 'closed', 'ssh', 1, 1, '', ?, 0)`,
		base.Add(24*time.Hour), base.Add(48*time.Hour), base.Add(72*time.Hour), base.Add(96*time.Hour), base.Add(120*time.Hour))
	mustExec(`INSERT INTO sessions (id, session_id, status, protocol, user_id, asset_id, client_ip, start_time, auth_epoch, deleted_at) VALUES
		(16, 's16', 'closed', 'ssh', 1, 1, '198.51.100.9', ?, 0, now())`, base)
	// 登入列：alice 自 203.0.113.5 更早登入（07-31，應成為 first_seen）、bob 只登入過（無會話）；
	// 失敗列與非 login 列不計
	mustExec(`INSERT INTO audit_logs (user_id, username, action, resource, status, client_ip, created_at, idempotency_uuid) VALUES
		(1, 'alice', 'login', 'auth', 'success', '203.0.113.5', ?, 'u1'),
		(2, 'bob', 'login', 'auth', 'success', '192.0.2.7', ?, 'u2'),
		(2, 'bob', 'login', 'auth', 'failure', '192.0.2.8', ?, 'u3'),
		(2, 'bob', 'update', 'user', 'success', '192.0.2.9', ?, 'u4')`,
		base.Add(-24*time.Hour), base, base, base)

	if err := applySourceIPForensics(db); err != nil {
		t.Fatalf("migration Up 失敗: %v", err)
	}

	if n := sipCount(t, db, `SELECT count(*) FROM user_source_ips`); n != 3 {
		t.Fatalf("基準列數 = %d, want 3（alice×2 位址 ＋ bob×1）", n)
	}
	var alice struct {
		FirstSeenAt    time.Time
		LastSeenAt     time.Time
		FirstSessionAt *time.Time
		FirstSessionID *int64
	}
	if err := db.Raw(`SELECT first_seen_at, last_seen_at, first_session_at, first_session_id
		FROM user_source_ips WHERE user_id = 1 AND client_ip = '203.0.113.5'`).Scan(&alice).Error; err != nil {
		t.Fatalf("讀 alice 列失敗: %v", err)
	}
	if !alice.FirstSeenAt.Equal(base.Add(-24 * time.Hour)) {
		t.Errorf("first_seen_at 應取登入列（更早）%v，實得 %v", base.Add(-24*time.Hour), alice.FirstSeenAt)
	}
	if !alice.LastSeenAt.Equal(base.Add(72 * time.Hour)) {
		t.Errorf("last_seen_at 應取最晚會話 %v，實得 %v", base.Add(72*time.Hour), alice.LastSeenAt)
	}
	if alice.FirstSessionAt == nil || !alice.FirstSessionAt.Equal(base.Add(24*time.Hour)) {
		t.Errorf("first_session_at 應為最早會話 %v，實得 %v", base.Add(24*time.Hour), alice.FirstSessionAt)
	}
	if alice.FirstSessionID == nil || *alice.FirstSessionID != 11 {
		t.Errorf("first_session_id 應為最早會話 id 11，實得 %v", alice.FirstSessionID)
	}
	if n := sipCount(t, db, `SELECT count(*) FROM user_source_ips WHERE user_id = 2 AND client_ip = '192.0.2.7' AND first_session_at IS NULL AND first_session_id IS NULL`); n != 1 {
		t.Errorf("bob 只登入過：應有列且首次建線兩欄為 NULL，實得 %d 列", n)
	}
	if n := sipCount(t, db, `SELECT count(*) FROM user_source_ips WHERE client_ip IN ('', '198.51.100.9', '192.0.2.8', '192.0.2.9')`); n != 0 {
		t.Errorf("空位址、軟刪會話、失敗登入與非登入列不得進基準，實得 %d 列", n)
	}
}

// TestSourceIPForensicsPGDownDestroysDataThenUpStartsEmpty 含資料的 Down／Up 實測：
// Down 成功（先刪 new_source_ip 告警列才還原得了 CHECK）、再 Up 成功，之後清單全空、
// 基準零列、告警表無該 kind、CHECK 含新值。這就是「Down 銷毀資料」的機器證據，
// 營運文件據此只能寫「回退＝還原備份」。
func TestSourceIPForensicsPGDownDestroysDataThenUpStartsEmpty(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	const pgSchema = "sip_down_up_test"
	db := freshSchema(t, dsn, pgSchema)
	if err := applyBaseline(db); err != nil {
		t.Fatalf("baseline 失敗: %v", err)
	}
	if err := applyMigrationsAfterBaseline(db); err != nil {
		t.Fatalf("增量 migration 失敗: %v", err)
	}
	mustExec := func(sql string, args ...any) {
		t.Helper()
		if err := db.Exec(sql, args...).Error; err != nil {
			t.Fatalf("種子失敗（%.60s）: %v", sql, err)
		}
	}
	// 3 位使用者的 CIDR、基準 5 列、1 筆 new_source_ip 告警
	mustExec(`INSERT INTO users (id, username, password, active, allowed_cidrs, created_at, updated_at) VALUES
		(1, 'u1', 'x', true, '10.0.0.0/8', now(), now()),
		(2, 'u2', 'x', true, '10.0.0.0/8,2001:db8::/32', now(), now()),
		(3, 'u3', 'x', true, '203.0.113.5/32', now(), now())`)
	mustExec(`INSERT INTO assets (id, name, host, port, protocol, created_by, created_at, updated_at) VALUES
		(1, 'a1', 'h', 22, 'ssh', 1, now(), now())`)
	mustExec(`INSERT INTO sessions (id, session_id, status, protocol, user_id, asset_id, client_ip, start_time, auth_epoch) VALUES
		(1, 's1', 'closed', 'ssh', 1, 1, '10.1.1.1', now(), 0)`)
	mustExec(`INSERT INTO user_source_ips (user_id, client_ip, first_seen_at, last_seen_at, first_session_at, first_session_id) VALUES
		(1, '10.1.1.1', now(), now(), now(), 1), (1, '10.1.1.2', now(), now(), NULL, NULL),
		(2, '10.1.1.3', now(), now(), NULL, NULL), (2, '2001:db8::1', now(), now(), NULL, NULL),
		(3, '203.0.113.5', now(), now(), NULL, NULL)`)
	mustExec(`INSERT INTO command_alerts (rule_id, rule_name, kind, reason_code, session_id, user_id, asset_id, command, severity, triggered_at, disposition, note) VALUES
		(NULL, 'new_source_ip', 'new_source_ip', 'new_source_ip_session', 1, 1, 1, '', 'medium', now(), 'pending', '')`)
	mustExec(`INSERT INTO command_alerts (rule_id, rule_name, kind, reason_code, session_id, user_id, asset_id, command, severity, triggered_at, disposition, note) VALUES
		(NULL, 'audit_degraded_span', 'audit_degraded', 'audit_degraded_span', 1, 1, 1, '', 'medium', now(), 'pending', '')`)

	if n := sipCount(t, db, `SELECT count(*) FROM user_source_ips`); n != 5 {
		t.Fatalf("前置：基準應 5 列，實得 %d", n)
	}
	if !strings.Contains(sipKindCheckDef(t, db, pgSchema), "'new_source_ip'") {
		t.Fatalf("前置：Up 後 CHECK 應含 new_source_ip")
	}

	// Down：走 RollbackMigration 同一條「Down 成功才刪版本列」的路徑——直接呼叫 Down 函式
	if err := db.Transaction(func(tx *gorm.DB) error { return rollbackSourceIPForensics(tx) }); err != nil {
		t.Fatalf("Down 失敗（含資料的庫上 Down 必須成功，否則開發庫無從回退）: %v", err)
	}
	if strings.Contains(sipKindCheckDef(t, db, pgSchema), "'new_source_ip'") {
		t.Errorf("Down 後 CHECK 仍含 new_source_ip")
	}
	if n := sipCount(t, db, `SELECT count(*) FROM command_alerts WHERE kind = 'new_source_ip'`); n != 0 {
		t.Errorf("Down 後告警表仍有 new_source_ip 列 %d 筆", n)
	}
	if n := sipCount(t, db, `SELECT count(*) FROM command_alerts`); n != 1 {
		t.Errorf("Down 只刪 new_source_ip 列，其他 kind 應保留：實得 %d 列，want 1", n)
	}
	if n := sipCount(t, db, `SELECT count(*) FROM information_schema.tables WHERE table_schema = ? AND table_name = 'user_source_ips'`, pgSchema); n != 0 {
		t.Errorf("Down 後 user_source_ips 仍存在")
	}
	if n := sipCount(t, db, `SELECT count(*) FROM information_schema.columns WHERE table_schema = ? AND table_name = 'users' AND column_name = 'allowed_cidrs'`, pgSchema); n != 0 {
		t.Errorf("Down 後 users.allowed_cidrs 仍存在")
	}

	// 再 Up：結構回來、資料沒回來
	if err := db.Transaction(func(tx *gorm.DB) error { return applySourceIPForensics(tx) }); err != nil {
		t.Fatalf("Down 後再 Up 失敗: %v", err)
	}
	if n := sipCount(t, db, `SELECT count(*) FROM users WHERE allowed_cidrs <> ''`); n != 0 {
		t.Errorf("再 Up 後清單應全空（限制靜默消失），實得 %d 位使用者仍有清單", n)
	}
	// 回填會自 sessions 重建 s1 那一列：基準只剩回填得到的，原本 5 列中登入型的 4 列不回來
	if n := sipCount(t, db, `SELECT count(*) FROM user_source_ips`); n != 1 {
		t.Errorf("再 Up 後基準應只剩回填自 sessions 的 1 列，實得 %d", n)
	}
	if n := sipCount(t, db, `SELECT count(*) FROM command_alerts WHERE kind = 'new_source_ip'`); n != 0 {
		t.Errorf("再 Up 後告警表不應有 new_source_ip 列，實得 %d", n)
	}
	if !strings.Contains(sipKindCheckDef(t, db, pgSchema), "'new_source_ip'") {
		t.Errorf("再 Up 後 CHECK 應含 new_source_ip")
	}
}
