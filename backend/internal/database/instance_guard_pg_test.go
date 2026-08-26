package database

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/testgate"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 單實例守衛的 postgres 真路徑整合測試（pg-gated）。
//
// 「兩個 *gorm.DB 連線池＝兩個實例」（沿 aad_session_lock_test.go 的 dbA／dbB 形態）。
// watchdog 週期設極長，一律以 CheckNow 驅動；確定性失鎖與競爭以第三條 DBA 連線
// `pg_terminate_backend` 製造，不靠時序競賽。
//
// gating：未設 TEST_PG_DSN 即 t.Skip；REQUIRE_INTEGRATION=1 時 skip 轉 fail。
// **DSN 應指向 postgres 維護庫、不得指向 dev backend 的 custodexa 庫**：advisory lock
// 命名空間是每 database，指向同庫會與執行中的後端互搶同一把鍵（key_manager_pg_lock_test.go）。
// 跑法（compose 內）：
//
//	docker compose exec -T backend sh -c \
//	  'TEST_PG_DSN="host=postgres user=postgres password=postgres dbname=postgres port=5432 sslmode=disable" \
//	   REQUIRE_INTEGRATION=1 go test ./internal/database -run InstanceGuardPG -count=1 -v'

func openGuardPGDB(t *testing.T, dsn string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("postgres 連線失敗（TEST_PG_DSN 是否正確？）: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

func pgGuardOpts(ack string) InstanceGuardOptions {
	return InstanceGuardOptions{
		Ack:           ack,
		WatchPeriod:   time.Hour, // 一律以 CheckNow 驅動
		QueryTimeout:  5 * time.Second,
		RetryInterval: 50 * time.Millisecond,
		RetryAttempts: 2,
	}
}

// grantedGuardLocks 目前 database 內本鍵的已授予 advisory lock 數（pg_locks 是叢集級，須過濾 database）。
func grantedGuardLocks(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	err := db.Raw(`SELECT count(*) FROM pg_locks
		WHERE locktype = 'advisory' AND classid::bigint = ? AND objid::bigint = ? AND objsubid = 1 AND granted
		  AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`,
		instanceGuardLockClassID, instanceGuardLockObjID).Scan(&n).Error
	if err != nil {
		t.Fatalf("查 pg_locks 失敗: %v", err)
	}
	return n
}

// terminateSession 以 DBA 連線終止指定工作階段（測試端的確定性失鎖注入；產品碼不做此事）。
func terminateSession(t *testing.T, dba *gorm.DB, pid int) {
	t.Helper()
	var ok bool
	if err := dba.Raw("SELECT pg_terminate_backend(?)", pid).Scan(&ok).Error; err != nil || !ok {
		t.Fatalf("pg_terminate_backend(%d) = %v, err=%v", pid, ok, err)
	}
}

// checkUntil 以 CheckNow 驅動至狀態符合（上限 20 輪），回傳最終狀態。
func checkUntil(g *InstanceGuard, want GuardState) GuardState {
	var st GuardState
	for i := 0; i < 20; i++ {
		st = g.CheckNow(context.Background())
		if st == want {
			return st
		}
		time.Sleep(50 * time.Millisecond)
	}
	return st
}

func TestInstanceGuardPGTwoInstancesAckAndPeers(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	dbA, dbB, dba := openGuardPGDB(t, dsn), openGuardPGDB(t, dsn), openGuardPGDB(t, dsn)
	if n := grantedGuardLocks(t, dba); n != 0 {
		t.Fatalf("前置條件：本 database 已有 %d 把守衛鎖（DSN 是否指向 dev backend 的庫？）", n)
	}

	a := NewInstanceGuard(dbA, pgGuardOpts(""))
	if err := a.Acquire(context.Background()); err != nil {
		t.Fatalf("A 取鎖失敗: %v", err)
	}
	t.Cleanup(a.Stop)
	snapA := a.Snapshot()
	if snapA.State != GuardStateHeld || snapA.DBSessionPID == 0 {
		t.Fatalf("A 狀態 %s / db_session_pid %d", snapA.State, snapA.DBSessionPID)
	}
	if n := grantedGuardLocks(t, dba); n != 1 {
		t.Fatalf("A 取鎖後 pg_locks 應恰一把，實得 %d", n)
	}

	// B 無 ack：於重試上限內被攔，訊息含 A 的指紋（application_name／pid 與 A 的工作階段一致）
	b0 := NewInstanceGuard(dbB, pgGuardOpts(""))
	start := time.Now()
	err := b0.Acquire(context.Background())
	if !errors.Is(err, ErrInstanceGuardBlocked) {
		t.Fatalf("B 無 ack MUST 被攔，實得 %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("攔下耗時 %s，超過重試上限", time.Since(start))
	}
	msg := err.Error()
	for _, want := range []string{
		"application_name=" + InstanceGuardApplicationName,
		fmt.Sprintf("pid=%d", snapA.DBSessionPID),
		"backend_start=20",
		"code=",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("攔下訊息缺 A 的指紋成分 %q\n%s", want, msg)
		}
	}
	for _, banned := range []string{"password=", "host=", "dbname=", "client_addr"} {
		if strings.Contains(msg, banned) {
			t.Errorf("攔下訊息不得含 %q", banned)
		}
	}
	m := codePattern.FindStringSubmatch(msg)
	if len(m) != 2 {
		t.Fatalf("訊息無 12 碼確認碼：%s", msg)
	}
	code := m[1]
	if n := grantedGuardLocks(t, dba); n != 1 {
		t.Fatalf("被攔下的 B 不得留下鎖，pg_locks 實得 %d", n)
	}

	// B 以該 code 重試 → overridden；持鎖者指紋指向 A 的工作階段
	b := NewInstanceGuard(dbB, pgGuardOpts(code))
	rec := &eventRecorder{}
	b.SetEventSink(rec.sink)
	if err := b.Acquire(context.Background()); err != nil {
		t.Fatalf("B 以相符 ack 啟動失敗: %v", err)
	}
	t.Cleanup(b.Stop)
	snapB := b.Snapshot()
	if snapB.State != GuardStateOverridden || snapB.Holder == nil || snapB.Holder.PID != int64(snapA.DBSessionPID) ||
		snapB.Holder.Code != code || snapB.Holder.Source != FingerprintSourcePGStatActivity {
		t.Fatalf("B 快照不符：%+v", snapB)
	}
	if names := rec.names(); len(names) != 1 || names[0] != GuardEventOverridden {
		t.Fatalf("B 應發 overridden 事件，實得 %v", names)
	}

	// A 的對等偵測：B 的釘選連線帶守衛 application_name → peers == 1
	if st := a.CheckNow(context.Background()); st != GuardStateHeld {
		t.Fatalf("A 狀態 = %s，want held", st)
	}
	if p := a.Snapshot().Peers; p != 1 {
		t.Fatalf("A.peers = %d，want 1", p)
	}

	// A 優雅關閉 → 無殘留；B 下一輪重取成功 → held ＋ regained{ack_startup}
	a.Stop()
	if n := grantedGuardLocks(t, dba); n != 0 {
		t.Fatalf("A 優雅關閉後 pg_locks 仍有 %d 把", n)
	}
	if st := checkUntil(b, GuardStateHeld); st != GuardStateHeld {
		t.Fatalf("A 釋放後 B 重取應成功，狀態 = %s", st)
	}
	evs := rec.all()
	if len(evs) != 2 || evs[1].Event != GuardEventRegained || evs[1].Reason != GuardReasonAckStartup || evs[1].UnheldForMS < 0 {
		t.Fatalf("B 應發 regained{ack_startup}，實得 %+v", evs)
	}
	if n := grantedGuardLocks(t, dba); n != 1 {
		t.Fatalf("B 持鎖後 pg_locks 應恰一把，實得 %d", n)
	}
	// B 的對等偵測：A 已離開 → 0
	b.CheckNow(context.Background())
	if p := b.Snapshot().Peers; p != 0 {
		t.Fatalf("B.peers = %d，want 0", p)
	}

	// 優雅關閉後無殘留
	b.Stop()
	if n := grantedGuardLocks(t, dba); n != 0 {
		t.Fatalf("B 優雅關閉後 pg_locks 仍有 %d 把", n)
	}
}

func TestInstanceGuardPGDeterministicLossAndRegain(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	dbA, dba := openGuardPGDB(t, dsn), openGuardPGDB(t, dsn)
	if n := grantedGuardLocks(t, dba); n != 0 {
		t.Fatalf("前置條件：本 database 已有 %d 把守衛鎖", n)
	}

	a := NewInstanceGuard(dbA, pgGuardOpts(""))
	rec := &eventRecorder{}
	a.SetEventSink(rec.sink)
	if err := a.Acquire(context.Background()); err != nil {
		t.Fatalf("A 取鎖失敗: %v", err)
	}
	t.Cleanup(a.Stop)
	pid := a.Snapshot().DBSessionPID

	// 確定性失鎖：DBA 終止 A 的工作階段（鎖隨工作階段消失）
	terminateSession(t, dba, pid)
	if st := checkUntil(a, GuardStateLost); st != GuardStateLost {
		t.Fatalf("工作階段被終止後 A 應轉 lost，狀態 = %s", st)
	}
	snap := a.Snapshot()
	if snap.LostTotal != 1 || snap.Reason == GuardReasonNone {
		t.Fatalf("lost 快照不符：%+v", snap)
	}
	if names := rec.names(); len(names) != 1 || names[0] != GuardEventLost {
		t.Fatalf("應發 lost 事件，實得 %v", names)
	}
	// 失鎖判定當下已重釘一條新工作階段
	if a.Snapshot().DBSessionPID == 0 || a.Snapshot().DBSessionPID == pid {
		t.Fatalf("失鎖後應重釘新連線（舊 pid %d，現 %d）", pid, a.Snapshot().DBSessionPID)
	}

	// 下一輪重取成功 → held、lost_total=1、regained（gauge 1→0→1 由狀態序列承載）
	if st := checkUntil(a, GuardStateHeld); st != GuardStateHeld {
		t.Fatalf("重取應成功，狀態 = %s", st)
	}
	snap = a.Snapshot()
	if snap.LostTotal != 1 || snap.Reason != GuardReasonNone {
		t.Fatalf("重取後快照不符：%+v", snap)
	}
	if names := rec.names(); len(names) != 2 || names[1] != GuardEventRegained {
		t.Fatalf("應發 regained 事件，實得 %v", names)
	}
	if n := grantedGuardLocks(t, dba); n != 1 {
		t.Fatalf("重取後 pg_locks 應恰一把，實得 %d", n)
	}
	a.Stop()
	if n := grantedGuardLocks(t, dba); n != 0 {
		t.Fatalf("關閉後 pg_locks 仍有 %d 把", n)
	}
}

func TestInstanceGuardPGDeterministicContention(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	dbA, dbB, dba := openGuardPGDB(t, dsn), openGuardPGDB(t, dsn), openGuardPGDB(t, dsn)
	if n := grantedGuardLocks(t, dba); n != 0 {
		t.Fatalf("前置條件：本 database 已有 %d 把守衛鎖", n)
	}

	a := NewInstanceGuard(dbA, pgGuardOpts(""))
	recA := &eventRecorder{}
	a.SetEventSink(recA.sink)
	if err := a.Acquire(context.Background()); err != nil {
		t.Fatalf("A 取鎖失敗: %v", err)
	}
	t.Cleanup(a.Stop)

	// 終止 A 的工作階段 → B 取得鎖（無 ack、正常啟動）→ A 下一輪判定 lost{contention} 且指認 B
	terminateSession(t, dba, a.Snapshot().DBSessionPID)
	b := NewInstanceGuard(dbB, pgGuardOpts(""))
	if err := b.Acquire(context.Background()); err != nil {
		t.Fatalf("A 的工作階段已終止，B 應能取鎖: %v", err)
	}
	t.Cleanup(b.Stop)
	if b.State() != GuardStateHeld {
		t.Fatalf("B 狀態 = %s", b.State())
	}

	if st := checkUntil(a, GuardStateLost); st != GuardStateLost {
		t.Fatalf("A 應轉 lost，狀態 = %s", st)
	}
	snap := a.Snapshot()
	if snap.Reason != GuardReasonContention || snap.Holder == nil ||
		snap.Holder.PID != int64(b.Snapshot().DBSessionPID) || snap.Holder.ApplicationName != InstanceGuardApplicationName {
		t.Fatalf("A 應以 contention 指認 B 的工作階段（B pid %d）：%+v", b.Snapshot().DBSessionPID, snap)
	}
	evs := recA.all()
	if len(evs) != 1 || evs[0].Reason != GuardReasonContention || evs[0].Holder == nil || evs[0].Holder.Code != snap.Holder.Code {
		t.Fatalf("lost 事件應含 contention 與持鎖者指紋：%+v", evs)
	}
	// A 可持續 CheckNow 而不退出、狀態維持 lost、不重複發事件
	for i := 0; i < 3; i++ {
		if st := a.CheckNow(context.Background()); st != GuardStateLost {
			t.Fatalf("第 %d 輪：A 狀態 = %s，want lost", i+1, st)
		}
	}
	if len(recA.all()) != 1 {
		t.Fatal("競爭期間不得重複發 lost 事件")
	}
	// B 的對等偵測看得到 A（A 重釘的連線帶守衛 application_name）
	b.CheckNow(context.Background())
	if p := b.Snapshot().Peers; p != 1 {
		t.Fatalf("B.peers = %d，want 1", p)
	}

	// B 離開 → A 重取成功
	b.Stop()
	if st := checkUntil(a, GuardStateHeld); st != GuardStateHeld {
		t.Fatalf("B 離開後 A 應重取成功，狀態 = %s", st)
	}
	if names := recA.names(); len(names) != 2 || names[1] != GuardEventRegained || recA.all()[1].Reason != GuardReasonContention {
		t.Fatalf("A 應發 regained{reason=contention}，實得 %+v", recA.all())
	}
	a.Stop()
	if n := grantedGuardLocks(t, dba); n != 0 {
		t.Fatalf("全部關閉後 pg_locks 仍有 %d 把", n)
	}
}

// waitGuardLocksDrained 等待本鍵在目前 database 的已授予鎖歸零（postgres 處理連線 EOF 有毫秒級延遲）。
func waitGuardLocksDrained(t *testing.T, db *gorm.DB, stage string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		n := grantedGuardLocks(t, db)
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s：pg_locks 仍有 %d 把守衛鎖（連線被歸池而非丟棄＝永久鎖洩漏）", stage, n)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestInstanceGuardPGTryLockResponseFailureLeavesNoLock spec「取鎖回應失敗不留殘鎖」的整合格：
// **鎖已在 DB 端授予、取鎖回應卻在客戶端失敗**。
//
// 真 postgres 上無法用一般手段觸發，故沿 keyvault TestPGSessionLockAcquireResponseFailureLeavesNoLock
// 的形態覆寫 pgGuardTryLockSQL 為「多回一欄使 Scan 失敗」的變體——`pg_try_advisory_lock` 已在
// 伺服端執行完畢（鎖確實被授予），錯誤純發生在回應解析。注入點走到的證據＝錯誤訊息含
// database/sql 的「expected 2 destination arguments」（表示查詢真的回了兩欄）。
func TestInstanceGuardPGTryLockResponseFailureLeavesNoLock(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	dbA, dbB, dba := openGuardPGDB(t, dsn), openGuardPGDB(t, dsn), openGuardPGDB(t, dsn)
	if n := grantedGuardLocks(t, dba); n != 0 {
		t.Fatalf("前置條件：本 database 已有 %d 把守衛鎖", n)
	}

	orig := pgGuardTryLockSQL
	pgGuardTryLockSQL = "SELECT pg_try_advisory_lock($1), 1"
	t.Cleanup(func() { pgGuardTryLockSQL = orig })

	a := NewInstanceGuard(dbA, pgGuardOpts(""))
	err := a.Acquire(context.Background())
	if err == nil {
		a.Stop()
		t.Fatal("測試前提不成立：取鎖回應應失敗")
	}
	if errors.Is(err, ErrInstanceGuardBlocked) {
		t.Fatalf("回應失敗 SHALL NOT 折疊為攔下（兩者處置不同）: %v", err)
	}
	if !strings.Contains(err.Error(), "expected 2 destination arguments") {
		t.Fatalf("注入點未走到：錯誤應來自兩欄回應的 Scan 失敗，實得 %v", err)
	}
	if !strings.Contains(err.Error(), "已丟棄該連線") {
		t.Fatalf("錯誤應說明連線已丟棄（不歸池）: %v", err)
	}
	if st := a.State(); st == GuardStateHeld || st == GuardStateOverridden {
		t.Fatalf("回應失敗後狀態不得為 %s", st)
	}

	// 核心斷言：鎖已被 DB 端授予，但持鎖連線被丟棄而非歸池，故鎖隨連線結束釋放
	waitGuardLocksDrained(t, dba, "取鎖回應失敗後")

	// 還原 SQL 後，另一個連線池（＝另一實例）能取得鎖：沒有任何池內連線帶著鎖
	pgGuardTryLockSQL = orig
	b := NewInstanceGuard(dbB, pgGuardOpts(""))
	if err := b.Acquire(context.Background()); err != nil {
		t.Fatalf("回應失敗後另一實例 MUST 可正常取鎖，實得 %v", err)
	}
	t.Cleanup(b.Stop)
	if b.State() != GuardStateHeld {
		t.Fatalf("B 狀態 = %s，want held", b.State())
	}
	if n := grantedGuardLocks(t, dba); n != 1 {
		t.Fatalf("B 持鎖後 pg_locks 應恰一把，實得 %d", n)
	}
	b.Stop()
	waitGuardLocksDrained(t, dba, "B 優雅關閉後")

	// 同一個池（A 的池）亦未被毒化：可再取鎖
	a2 := NewInstanceGuard(dbA, pgGuardOpts(""))
	if err := a2.Acquire(context.Background()); err != nil {
		t.Fatalf("A 的連線池在丟棄後 MUST 仍可取鎖，實得 %v", err)
	}
	a2.Stop()
	waitGuardLocksDrained(t, dba, "A2 優雅關閉後")
}

// guardRestrictedRole 指紋查詢受限角色（僅本測試建立／刪除）。
const (
	guardRestrictedRole     = "custodexa_ig_restricted_test"
	guardRestrictedPassword = "ig-restricted-test-only"
)

// setupRestrictedStatActivityRole 建一個能連線、能取 advisory lock、但對 pg_stat_activity
// 無 SELECT 的角色，回傳以該角色連線的 DSN。
//
// pg_stat_activity 的 SELECT 預設授予 PUBLIC，對特定角色 REVOKE 無效（PUBLIC 的授權被所有角色
// 繼承），只能自 PUBLIC 收回、測後還原。ACL 範圍＝目前 database（catalog view 的權限是每
// database），DSN 指向維護庫 postgres；dev backend 在 custodexa 庫且為 superuser，不受影響。
// 若測試中途被殺而未還原：只影響該維護庫內的非 superuser 角色（本機無），手動
// `GRANT SELECT ON pg_catalog.pg_stat_activity TO PUBLIC` 即復原。
func setupRestrictedStatActivityRole(t *testing.T, dba *gorm.DB, baseDSN string) string {
	t.Helper()
	_ = dba.Exec("DROP ROLE IF EXISTS " + guardRestrictedRole).Error // 上次中斷的殘留
	if err := dba.Exec("CREATE ROLE " + guardRestrictedRole + " LOGIN PASSWORD '" + guardRestrictedPassword + "'").Error; err != nil {
		// DSN 角色無 CREATE ROLE 權限：本整合格無法成立。REQUIRE_INTEGRATION=1 時不得靜默 skip。
		if testgate.RequireIntegration() {
			t.Fatalf("CREATE ROLE 失敗（TEST_PG_DSN 角色需 CREATEROLE 權限）: %v", err)
		}
		t.Skipf("CREATE ROLE 失敗，跳過受限角色整合格（TEST_PG_DSN 角色需 CREATEROLE 權限）: %v", err)
	}
	t.Cleanup(func() {
		if err := dba.Exec("DROP ROLE IF EXISTS " + guardRestrictedRole).Error; err != nil {
			t.Errorf("測試角色清理失敗（請手動 DROP ROLE %s）: %v", guardRestrictedRole, err)
		}
	})
	if err := dba.Exec("REVOKE SELECT ON pg_catalog.pg_stat_activity FROM PUBLIC").Error; err != nil {
		t.Fatalf("REVOKE pg_stat_activity 失敗: %v", err)
	}
	t.Cleanup(func() {
		if err := dba.Exec("GRANT SELECT ON pg_catalog.pg_stat_activity TO PUBLIC").Error; err != nil {
			t.Errorf("pg_stat_activity 權限還原失敗（請手動 GRANT SELECT ON pg_catalog.pg_stat_activity TO PUBLIC）: %v", err)
		}
	})
	return dsnWithCredentials(t, baseDSN, guardRestrictedRole, guardRestrictedPassword)
}

// dsnWithCredentials 把 DSN 的 user／password 換成指定角色（支援 key=value 與 URL 兩種形式）。
func dsnWithCredentials(t *testing.T, dsn, user, password string) string {
	t.Helper()
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatalf("解析 URL 形式 DSN 失敗: %v", err)
		}
		u.User = url.UserPassword(user, password)
		return u.String()
	}
	var out []string
	seenUser, seenPW := false, false
	for _, tok := range strings.Fields(dsn) {
		switch {
		case strings.HasPrefix(tok, "user="):
			out = append(out, "user="+user)
			seenUser = true
		case strings.HasPrefix(tok, "password="):
			out = append(out, "password="+password)
			seenPW = true
		default:
			out = append(out, tok)
		}
	}
	if !seenUser {
		out = append(out, "user="+user)
	}
	if !seenPW {
		out = append(out, "password="+password)
	}
	return strings.Join(out, " ")
}

// TestInstanceGuardPGDegradedFingerprintWhenStatActivityDenied spec「指紋查詢不可用時仍有救援路徑」
// 的整合格：持鎖者查詢因權限失敗 → 訊息明說細節不可得、給降級確認碼；
// 以該碼重啟 → overridden，事件的指紋來源標 unavailable；之後仍可對等被偵測、重取成功。
func TestInstanceGuardPGDegradedFingerprintWhenStatActivityDenied(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	dbA, dba := openGuardPGDB(t, dsn), openGuardPGDB(t, dsn)
	if n := grantedGuardLocks(t, dba); n != 0 {
		t.Fatalf("前置條件：本 database 已有 %d 把守衛鎖", n)
	}
	restrictedDSN := setupRestrictedStatActivityRole(t, dba, dsn)
	dbB := openGuardPGDB(t, restrictedDSN)

	a := NewInstanceGuard(dbA, pgGuardOpts(""))
	if err := a.Acquire(context.Background()); err != nil {
		t.Fatalf("A 取鎖失敗: %v", err)
	}
	t.Cleanup(a.Stop)
	snapA := a.Snapshot()

	// B（受限角色）無 ack：被攔，指紋查詢因 42501 失敗 → 降級碼＝unavailable|permanent
	logBuf := captureLog(t)
	b0 := NewInstanceGuard(dbB, pgGuardOpts(""))
	err := b0.Acquire(context.Background())
	if !errors.Is(err, ErrInstanceGuardBlocked) {
		t.Fatalf("B 無 ack MUST 被攔，實得 %v", err)
	}
	msg := err.Error()
	for _, want := range []string{"無法取得持鎖者細節", "INSTANCE_GUARD_ACK=", "本版不支援多實例"} {
		if !strings.Contains(msg, want) {
			t.Errorf("降級攔下訊息缺 %q\n%s", want, msg)
		}
	}
	if strings.Contains(msg, fmt.Sprintf("pid=%d", snapA.DBSessionPID)) {
		t.Errorf("指紋查詢失敗時訊息不應含持鎖者 pid（查不到就是查不到）\n%s", msg)
	}
	if !strings.Contains(logBuf.String(), "42501") {
		t.Fatalf("注入點未走到：日誌應含指紋查詢的 SQLSTATE 42501（permission denied），實得:\n%s", logBuf.String())
	}
	m := codePattern.FindStringSubmatch(msg)
	if len(m) != 2 {
		t.Fatalf("訊息無 12 碼確認碼：%s", msg)
	}
	code := m[1]
	if want := degradedFingerprint(string(guardErrPermanent)).Code; code != want {
		t.Fatalf("降級碼應為 unavailable|permanent 的碼 %s（42501 歸永久類），實得 %s", want, code)
	}
	if n := grantedGuardLocks(t, dba); n != 1 {
		t.Fatalf("被攔下的 B 不得留下鎖，pg_locks 實得 %d", n)
	}

	// 以降級碼重啟 → overridden；事件與快照的指紋來源標 unavailable
	b := NewInstanceGuard(dbB, pgGuardOpts(code))
	rec := &eventRecorder{}
	b.SetEventSink(rec.sink)
	if err := b.Acquire(context.Background()); err != nil {
		t.Fatalf("B 以降級碼啟動失敗: %v", err)
	}
	t.Cleanup(b.Stop)
	snapB := b.Snapshot()
	if snapB.State != GuardStateOverridden || snapB.Holder == nil ||
		snapB.Holder.Source != FingerprintSourceUnavailable || snapB.Holder.Code != code {
		t.Fatalf("B 快照不符（應 overridden、holder.source=unavailable）：%+v", snapB)
	}
	evs := rec.all()
	if len(evs) != 1 || evs[0].Event != GuardEventOverridden || evs[0].Ack != code ||
		evs[0].Holder == nil || evs[0].Holder.Source != FingerprintSourceUnavailable {
		t.Fatalf("overridden 事件應標 fingerprint_source=unavailable，實得 %+v", evs)
	}

	// B 的 watchdog 一輪：仍 overridden（指紋查詢持續失敗不影響重取路徑）、不重複發事件
	if st := b.CheckNow(context.Background()); st != GuardStateOverridden {
		t.Fatalf("B CheckNow 後狀態 = %s，want overridden", st)
	}
	if len(rec.all()) != 1 {
		t.Fatal("overridden 期間不得重複發事件")
	}
	// A（superuser）看得到 B 的守衛連線：受限角色的 set_config('application_name') 仍生效
	a.CheckNow(context.Background())
	if p := a.Snapshot().Peers; p != 1 {
		t.Fatalf("A.peers = %d，want 1", p)
	}

	// A 釋放 → B 重取成功 → held ＋ regained{ack_startup}
	a.Stop()
	if st := checkUntil(b, GuardStateHeld); st != GuardStateHeld {
		t.Fatalf("A 釋放後 B 重取應成功，狀態 = %s", st)
	}
	evs = rec.all()
	if len(evs) != 2 || evs[1].Event != GuardEventRegained || evs[1].Reason != GuardReasonAckStartup {
		t.Fatalf("B 應發 regained{ack_startup}，實得 %+v", evs)
	}
	b.Stop()
	waitGuardLocksDrained(t, dba, "全部關閉後")
}
