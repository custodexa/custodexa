package audit

import (
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/testgate"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 第 6 組的 postgres 整合驗證。
//
// **為何 sqlite 單測不夠**：本組的核心主張是「刪除與 tombstone 同一交易、
// 中斷必回滾」。sqlite `:memory:` 連線池被釘成單連線（既有教訓 ff51836），
// 量不到「交易外的另一條連線看得到什麼」；而「行程被殺」在 Go 內只能以
// panic 近似。postgres 兩者都測得到：另開連線觀察可見性、以
// pg_terminate_backend 真的殺掉交易所在的 session。
//
// 跑法（compose 內）：
//
//	docker compose exec -T backend sh -c 'TEST_PG_DSN="host=postgres user=postgres \
//	  password=postgres dbname=custodexa port=5432 sslmode=disable" \
//	  go test ./internal/modules/audit -run "Postgres" -v -count=1 -timeout 20m'

// purgeSchemaDB 於獨立 schema 建立第 6 組所需的完整最小 schema
func purgeSchemaDB(t *testing.T, schema string) (*gorm.DB, string) {
	t.Helper()
	dsn := testgate.Value(t, testgate.EnvPGDSN)

	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("postgres 連線失敗: %v", err)
	}
	drop := "DROP SCHEMA IF EXISTS " + schema + " CASCADE"
	if err := admin.Exec(drop).Error; err != nil {
		t.Fatalf("清理舊 schema: %v", err)
	}
	if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		t.Fatalf("建立 schema: %v", err)
	}
	t.Cleanup(func() {
		_ = admin.Exec(drop)
		if s, err := admin.DB(); err == nil {
			_ = s.Close()
		}
	})

	scoped := dsn + " search_path=" + schema
	db, err := gorm.Open(postgres.Open(scoped), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("scoped 連線: %v", err)
	}
	t.Cleanup(func() {
		if s, err := db.DB(); err == nil {
			_ = s.Close()
		}
	})
	if err := db.AutoMigrate(&model.AuditLog{}, &model.SecurityPolicy{},
		&model.AuditCheckpoint{}, &model.AuditCheckpointTrim{}, &model.IntegrityBaseline{}); err != nil {
		t.Fatalf("AutoMigrate: %v", err)
	}
	for _, stmt := range []string{
		"CREATE TABLE session_commands (id BIGSERIAL PRIMARY KEY, executed_at TIMESTAMPTZ NOT NULL)",
		"CREATE TABLE command_alerts (id BIGSERIAL PRIMARY KEY, triggered_at TIMESTAMPTZ NOT NULL)",
	} {
		if err := db.Exec(stmt).Error; err != nil {
			t.Fatalf("建表: %v", err)
		}
	}
	if err := db.Create(&model.IntegrityBaseline{
		ID: 1, BaselineAt: time.Now().Add(-500 * 24 * time.Hour), MaxLogID: 0,
	}).Error; err != nil {
		t.Fatalf("seed baseline: %v", err)
	}
	return db, scoped
}

// pgFixture 接線好的封章器／清除器／retention
func pgFixture(t *testing.T, db *gorm.DB) *purgeFixture {
	t.Helper()
	seal, signer := newCheckpointService(t, db, nil, nil)
	if err := seal.EnsureGenesis(); err != nil {
		t.Fatalf("genesis: %v", err)
	}
	purger := NewCheckpointPurger(db, signer)
	auditLog := &fakeAuditLogger{}
	svc := NewRetentionService(db, policy.NewSecurityPolicyService(db), nil, auditLog)
	svc.UseCheckpointIntervals(purger)
	return &purgeFixture{db: db, seal: seal, purger: purger, svc: svc, audit: auditLog, signer: signer}
}

// seedAged 以單句 generate_series 灌 n 筆指定時齡的列
func seedAged(t *testing.T, db *gorm.DB, n int, age time.Duration) {
	t.Helper()
	stmt := `INSERT INTO audit_logs (created_at, updated_at, action, resource, status,
		user_id, username, integrity_hmac, key_version)
		SELECT ?::timestamptz, now(), 'execute', 'audit_log', 'success', 0, 'seed',
		md5(g::text), 1 FROM generate_series(1, ?) g`
	if err := db.Exec(stmt, time.Now().Add(-age), n).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// ── 6.5／6.12 交易原子性與真實中斷 ──────────────────────────────────────

// TestPurgeIntervalAtomicityPostgres 交易外的另一條連線看不到半清狀態。
//
// 這是「同一交易」主張的**直接**證據：sqlite 單連線量不到，只有真的另開
// 一條連線在交易進行中觀察才算數
func TestPurgeIntervalAtomicityPostgres(t *testing.T) {
	db, scoped := purgeSchemaDB(t, "cpchain_purge_atomicity")
	f := pgFixture(t, db)
	seedAged(t, db, 200, 400*24*time.Hour)
	cp, err := f.seal.SealNow()
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	cutoff := time.Now().Add(-365 * 24 * time.Hour)

	// 觀察者：完全獨立的第二條連線
	observer, err := gorm.Open(postgres.Open(scoped), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("observer 連線: %v", err)
	}
	defer func() {
		if s, err := observer.DB(); err == nil {
			_ = s.Close()
		}
	}()
	observe := func() int64 {
		var n int64
		if err := observer.Raw("SELECT COUNT(*) FROM audit_logs WHERE id >= ? AND id <= ?",
			cp.IDFrom, cp.IDTo).Scan(&n).Error; err != nil {
			t.Fatalf("observe: %v", err)
		}
		return n
	}
	var afterDeleteSeen, beforeTombstoneSeen int64 = -1, -1
	f.purger.faults.afterDelete = func() error {
		afterDeleteSeen = observe() // 刪除之後、簽章之前
		return nil
	}
	// **這個觀察點才是「同一交易」的判別式**：它落在簽章之後、tombstone 寫入
	// 之前。若刪除已先行提交（tombstone 另起一次交易），外部連線在此刻就會
	// 看到 0 列——那正是「列沒了但 tombstone 尚未寫」的可觀測窗口。
	// 只觀察 afterDelete 不足以偵測該突變（本測第一版即漏掉，突變存活）
	f.purger.faults.beforeTombstoneWrite = func() error {
		beforeTombstoneSeen = observe()
		return nil
	}
	deleted, err := f.purger.PurgeInterval(cp, 365, cutoff)
	f.purger.faults.afterDelete = nil
	f.purger.faults.beforeTombstoneWrite = nil
	if err != nil {
		t.Fatalf("PurgeInterval: %v", err)
	}
	if f.purger.faults.fired < 2 {
		t.Fatalf("兩個觀察點未都被觸發（fired=%d）：本測退化為零觸發假綠", f.purger.faults.fired)
	}
	midTx := afterDeleteSeen
	if afterDeleteSeen != 200 {
		t.Fatalf("刪除後尚未提交，外部連線應仍看到 200 列，實得 %d", afterDeleteSeen)
	}
	if beforeTombstoneSeen != 200 {
		t.Fatalf("tombstone 寫入前外部連線只看到 %d 列：刪除已先行提交，"+
			"存在「列沒了但無 tombstone」的可觀測窗口", beforeTombstoneSeen)
	}
	if after := observe(); after != 0 {
		t.Fatalf("提交後外部連線應看到 0 列，實得 %d", after)
	}
	t.Logf("[6.5] 交易中外部可見列數=%d、提交後=%d、刪除=%d", midTx, observe(), deleted)

	var got model.AuditCheckpoint
	if err := observer.Where("seq = ?", cp.Seq).First(&got).Error; err != nil {
		t.Fatalf("讀 tombstone: %v", err)
	}
	if got.PurgedAt == nil {
		t.Fatal("提交後 tombstone 必須可見")
	}
}

// TestPurgeIntervalSessionKilledPostgres 清除窗口內 session 被殺（＝行程被 kill）。
//
// 以 pg_terminate_backend 殺掉正在跑清除交易的 backend session：這是比
// panic 更接近「docker compose kill backend」的重現，且由 DB 側強制 abort
func TestPurgeIntervalSessionKilledPostgres(t *testing.T) {
	db, scoped := purgeSchemaDB(t, "cpchain_purge_killed")
	f := pgFixture(t, db)
	seedAged(t, db, 150, 400*24*time.Hour)
	cp, err := f.seal.SealNow()
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	cutoff := time.Now().Add(-365 * 24 * time.Hour)

	killer, err := gorm.Open(postgres.Open(scoped), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("killer 連線: %v", err)
	}
	defer func() {
		if s, err := killer.DB(); err == nil {
			_ = s.Close()
		}
	}()

	var killed int64
	f.purger.faults.afterDelete = func() error {
		// 殺掉「正在本 schema 內執行 DELETE audit_logs 的那條 idle in transaction session」
		if err := killer.Raw(`SELECT COUNT(*) FROM (
			SELECT pg_terminate_backend(pid) FROM pg_stat_activity
			WHERE pid <> pg_backend_pid() AND state = 'idle in transaction'
			  AND query ILIKE '%DELETE FROM audit_logs%') s`).Scan(&killed).Error; err != nil {
			return fmt.Errorf("terminate: %w", err)
		}
		return nil
	}
	_, purgeErr := f.purger.PurgeInterval(cp, 365, cutoff)
	f.purger.faults.afterDelete = nil
	if killed == 0 {
		t.Fatal("未實際殺掉任何 session：本測退化為零觸發假綠")
	}
	if purgeErr == nil {
		t.Fatal("session 被殺後 PurgeInterval 必須回錯")
	}
	t.Logf("[6.12] 已終止 %d 條清除中的 session，PurgeInterval 回錯: %v", killed, purgeErr)

	// 重連後檢查：列完整存在且無 tombstone（spec 二選一狀態的其中一態）
	fresh, err := gorm.Open(postgres.Open(scoped), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("重連: %v", err)
	}
	defer func() {
		if s, err := fresh.DB(); err == nil {
			_ = s.Close()
		}
	}()
	var remain int64
	if err := fresh.Raw("SELECT COUNT(*) FROM audit_logs WHERE id >= ? AND id <= ?",
		cp.IDFrom, cp.IDTo).Scan(&remain).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	var got model.AuditCheckpoint
	if err := fresh.Where("seq = ?", cp.Seq).First(&got).Error; err != nil {
		t.Fatalf("讀檢查點: %v", err)
	}
	t.Logf("[6.12] 重啟後：殘列=%d、purged_at=%v", remain, got.PurgedAt)
	if remain != 150 || got.PurgedAt != nil {
		t.Fatalf("中斷必回滾：殘列=%d（want 150）purged_at=%v（want nil）", remain, got.PurgedAt)
	}

	// 交叉查詢：帶 tombstone 的檢查點殘列必為 0（此處無任何 tombstone）
	var half int64
	if err := fresh.Raw(`SELECT COUNT(*) FROM (SELECT c.seq,
		(SELECT COUNT(*) FROM audit_logs l WHERE l.id BETWEEN c.id_from AND c.id_to) AS remain
		FROM audit_checkpoints c WHERE c.purged_at IS NOT NULL) x WHERE x.remain <> 0`).
		Scan(&half).Error; err != nil {
		t.Fatalf("交叉查詢: %v", err)
	}
	if half != 0 {
		t.Fatalf("存在 %d 個半清區間", half)
	}
	// 驗證端不得回報 purged_invalid
	purger := NewCheckpointPurger(fresh, f.signer)
	res, err := purger.VerifyIntervalContent(&got, 365, f.verifyDeps())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	t.Logf("[6.12] 中斷後內容層狀態 = %s", res.Status)
	if res.Status != IntervalStatusPassed {
		t.Fatalf("中斷後狀態 = %s，want %s（不得產生假告警）", res.Status, IntervalStatusPassed)
	}
}

// ── 6.7 效能對照：legacy 逐列 vs 區間清除 ───────────────────────────────

// TestRetentionIntervalPerformancePostgres 切換前後的清除耗時對照。
//
// **量測設計沿 4.8 的訂正**：樸素 A／B 的執行序位效應在本專案實測達 ±16%，
// 超過判準本身。故採「暖機丟棄 ＋ 三對交錯 ＋ 取中位數」
func TestRetentionIntervalPerformancePostgres(t *testing.T) {
	db, _ := purgeSchemaDB(t, "cpchain_purge_perf")
	const rows, intervalRows = 20000, 5000

	// build 造出等量資料；interval=true 時另封成 4 個檢查點區間
	build := func(interval bool) *purgeFixture {
		if err := db.Exec("TRUNCATE audit_logs, audit_checkpoints, audit_checkpoint_trims RESTART IDENTITY").
			Error; err != nil {
			t.Fatalf("truncate: %v", err)
		}
		f := pgFixture(t, db)
		if !interval {
			f.svc.auditLogMode = auditLogPurgeLegacy
			seedAged(t, db, rows, 400*24*time.Hour)
		} else {
			for i := 0; i < rows/intervalRows; i++ {
				seedAged(t, db, intervalRows, 400*24*time.Hour)
				if _, err := f.seal.SealNow(); err != nil {
					t.Fatalf("seal: %v", err)
				}
			}
		}
		setPolicyDays(t, f.svc, policy.PolicyRetentionAuditLogDays, 365)
		return f
	}
	run := func(interval bool) (time.Duration, int64) {
		f := build(interval)
		start := time.Now()
		res := auditLogResult(t, f.svc.PurgeAll())
		return time.Since(start), res.Deleted
	}

	// 暖機：首輪含冷啟成本，丟棄（4.8 實測首輪最慢）
	run(false)
	run(true)

	var legacy, chain []time.Duration
	for i := 0; i < 3; i++ {
		d, n := run(false)
		if n != rows {
			t.Fatalf("legacy 第 %d 對刪除 %d 筆（want %d）", i+1, n, rows)
		}
		legacy = append(legacy, d)
		d2, n2 := run(true)
		if n2 != rows {
			t.Fatalf("interval 第 %d 對刪除 %d 筆（want %d）", i+1, n2, rows)
		}
		chain = append(chain, d2)
		t.Logf("第 %d 對：legacy %v / interval %v", i+1, d, d2)
	}
	median := func(ds []time.Duration) time.Duration {
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		return ds[len(ds)/2]
	}
	ml, mc := median(legacy), median(chain)
	delta := (float64(mc) - float64(ml)) / float64(ml) * 100
	t.Logf("[6.7 效能] 中位數 legacy=%v interval=%v，差異 %+.1f%%（%d 列 / %d 個區間）",
		ml, mc, delta, rows, rows/intervalRows)
	// 判準寬鬆（本量測的雜訊底與 4.8 同級）：只擋「數量級劣化」
	if mc > ml*3 {
		t.Fatalf("區間清除耗時 %v 超過 legacy %v 的三倍：顯著劣化", mc, ml)
	}
}

// TestRetentionIntervalBaselineComparePostgres 6.7 的行為差異對照：
// 與 design 附錄 1.2 的基準情境同形，明列哪些列因區間語義暫留
func TestRetentionIntervalBaselineComparePostgres(t *testing.T) {
	db, _ := purgeSchemaDB(t, "cpchain_purge_compare")
	f := pgFixture(t, db)

	// 三個整段過期的區間（各 5000 列）＋一個混合區間（4000 過期 + 500 未過期）
	for i := 0; i < 3; i++ {
		seedAged(t, db, 5000, 400*24*time.Hour)
		if _, err := f.seal.SealNow(); err != nil {
			t.Fatalf("seal: %v", err)
		}
	}
	seedAged(t, db, 4000, 400*24*time.Hour)
	seedAged(t, db, 500, 10*24*time.Hour)
	mixed, err := f.seal.SealNow()
	if err != nil {
		t.Fatalf("seal mixed: %v", err)
	}
	setPolicyDays(t, f.svc, policy.PolicyRetentionAuditLogDays, 365)

	start := time.Now()
	res := auditLogResult(t, f.svc.PurgeAll())
	elapsed := time.Since(start)

	var remain int64
	if err := db.Raw("SELECT COUNT(*) FROM audit_logs").Scan(&remain).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	t.Logf("[6.7 對照] 刪除=%d partial=%v 區間=%+v 耗時=%v 殘留=%d",
		res.Deleted, res.Partial, res.Intervals, elapsed, remain)
	// 基準（1.2）在同資料上會刪 19000（含混合區間的 4000 過期列）；
	// 區間語義下只刪 15000，差額 4000 全數可由「所屬區間尚有未過期列」解釋
	if res.Deleted != 15000 {
		t.Fatalf("應刪 15000（三個整段過期區間），實得 %d", res.Deleted)
	}
	if remain != 4500 {
		t.Fatalf("混合區間應整段暫留 4500 列，實得 %d", remain)
	}
	t.Logf("[6.7 對照] 與逐列基準的差額 = 4000 列（seq=%d 區間內已過期但因該區間"+
		"尚有 500 列未過期而暫留）", mixed.Seq)
	if got := f.reload(t, mixed.Seq); got.PurgedAt != nil {
		t.Fatal("混合區間不得有 tombstone")
	}
}
