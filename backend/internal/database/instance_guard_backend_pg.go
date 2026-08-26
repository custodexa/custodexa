package database

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"gorm.io/gorm"
)

// pgLockBackend postgres 真鎖後端：照 keyvault.withKeyOpSessionLock 的釘選形態。
//
//   - sqlDB.Conn(ctx) 釘一條連線，**終生不歸池**（關閉時一律以 driver.ErrBadConn 語義丟棄）。
//   - 同連線 set_config('application_name')（best-effort：失敗只記 log，不升級為取鎖失敗）。
//   - 同連線 pg_try_advisory_lock；回應失敗即丟棄連線（鎖可能已在 DB 端授予）。
//   - 鎖狀態驗證直接查 pg_locks（不以 ping 代替）。
type pgLockBackend struct {
	db           *gorm.DB
	appName      string
	queryTimeout time.Duration

	mu   sync.Mutex
	conn *sql.Conn
	pid  int
}

// 鎖鍵在 pg_locks 的形狀：classid = 高 32 位、objid = 低 32 位（以 bigint 比對，避免 oid 參數型別問題）。
const (
	instanceGuardLockClassID int64 = (InstanceGuardLockKey >> 32) & 0xFFFF_FFFF // 1869900645
	instanceGuardLockObjID   int64 = InstanceGuardLockKey & 0xFFFF_FFFF         // 1795162116
)

// pgGuardTryLockSQL 取鎖 SQL。**`var` 而非 `const` 的唯一理由是測試**（沿
// keyvault.pgSessionLockAcquireSQL 的先例）：「鎖已在 DB 端授予、
// 取鎖回應卻在客戶端失敗」這條路徑在真 postgres 上無法用一般手段觸發，pg-gated 測試以
// 「多回一欄使 Scan 失敗」的變體覆寫本變數，驗證該連線被丟棄而非歸池、pg_locks 無殘留
// （spec「取鎖回應失敗不留殘鎖」）。生產路徑不改寫本變數；改寫者僅限 _test.go。
var pgGuardTryLockSQL = "SELECT pg_try_advisory_lock($1)"

const (
	pgGuardUnlockSQL = "SELECT pg_advisory_unlock($1)"
	pgGuardIsHeldSQL = `SELECT EXISTS (
		SELECT 1 FROM pg_locks
		WHERE locktype = 'advisory' AND pid = pg_backend_pid()
		  AND classid::bigint = $1 AND objid::bigint = $2 AND objsubid = 1 AND granted
		  AND database = (SELECT oid FROM pg_database WHERE datname = current_database()))`
	// **pg_locks 是叢集級視圖**而 advisory lock 的命名空間是每 database：同一把鍵可在
	// 不同 database 各有持鎖者。不加 database 過濾，指紋會撈到別的 database 的工作階段
	//（2026-08-25 於 compose 內實測：在維護庫 postgres 查到 custodexa 庫的持鎖者）。
	pgGuardHolderSQL = `SELECT a.application_name, a.pid, a.backend_start
		FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
		WHERE l.locktype = 'advisory' AND l.classid::bigint = $1 AND l.objid::bigint = $2
		  AND l.objsubid = 1 AND l.granted
		  AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database())
		LIMIT 1`
	pgGuardPeersSQL = `SELECT count(*) FROM pg_stat_activity
		WHERE datname = current_database() AND application_name = $1 AND pid <> pg_backend_pid()`
)

func (b *pgLockBackend) current() *sql.Conn {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.conn
}

// discard 丟棄目前連線（不歸池）。
func (b *pgLockBackend) discard() {
	b.mu.Lock()
	old := b.conn
	b.conn = nil
	b.pid = 0
	b.mu.Unlock()
	if old != nil {
		discardGuardConn(old)
	}
}

// discardGuardConn 以 driver.ErrBadConn 語義標記後關閉：database/sql 於此情形實體關閉
// 連線而非歸還池；postgres 隨連線結束釋放其 session 級 advisory lock。
func discardGuardConn(conn *sql.Conn) {
	_ = conn.Raw(func(any) error { return driver.ErrBadConn })
	_ = conn.Close()
}

func (b *pgLockBackend) reconnect(ctx context.Context) error {
	b.discard()
	sqlDB, err := b.db.DB()
	if err != nil {
		return fmt.Errorf("取得底層連線池失敗: %w", err)
	}
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "SELECT set_config('application_name', $1, false)", b.appName); err != nil {
		log.Printf("[InstanceGuard] 設定釘選連線 application_name 失敗（best-effort，本實例在其他實例眼中將看不出是守衛）: %v", err)
	}
	var pid int
	if err := conn.QueryRowContext(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		discardGuardConn(conn)
		return err
	}
	b.mu.Lock()
	b.conn = conn
	b.pid = pid
	b.mu.Unlock()
	return nil
}

func (b *pgLockBackend) tryLock(ctx context.Context) (bool, error) {
	conn := b.current()
	if conn == nil {
		return false, errGuardNotConnected
	}
	var got bool
	if err := conn.QueryRowContext(ctx, pgGuardTryLockSQL, InstanceGuardLockKey).Scan(&got); err != nil {
		// 鎖可能已在 DB 端授予：SHALL NOT 歸池
		b.discard()
		return false, err
	}
	return got, nil
}

func (b *pgLockBackend) isHeld(ctx context.Context) (bool, error) {
	conn := b.current()
	if conn == nil {
		return false, errGuardNotConnected
	}
	var held bool
	if err := conn.QueryRowContext(ctx, pgGuardIsHeldSQL, instanceGuardLockClassID, instanceGuardLockObjID).Scan(&held); err != nil {
		return false, err
	}
	return held, nil
}

func (b *pgLockBackend) holderFingerprint(ctx context.Context) (HolderFingerprint, bool) {
	conn := b.current()
	if conn == nil {
		return degradedFingerprint(string(guardErrRetryable)), false
	}
	var (
		appName sql.NullString
		pid     sql.NullInt64
		start   sql.NullTime
	)
	err := conn.QueryRowContext(ctx, pgGuardHolderSQL, instanceGuardLockClassID, instanceGuardLockObjID).Scan(&appName, &pid, &start)
	if errors.Is(err, sql.ErrNoRows) {
		return degradedFingerprint("no_holder"), false
	}
	if err != nil {
		log.Printf("[InstanceGuard] 持鎖者指紋查詢失敗，改用降級確認碼: %v", err)
		return degradedFingerprint(string(classifyGuardError(err))), false
	}
	var (
		appPtr   *string
		pidPtr   *int64
		startPtr *time.Time
	)
	if appName.Valid {
		appPtr = &appName.String
	}
	if pid.Valid {
		pidPtr = &pid.Int64
	}
	if start.Valid {
		startPtr = &start.Time
	}
	return fingerprintOf(appPtr, pidPtr, startPtr), true
}

func (b *pgLockBackend) countPeers(ctx context.Context) (int, error) {
	conn := b.current()
	if conn == nil {
		return 0, errGuardNotConnected
	}
	var n int
	if err := conn.QueryRowContext(ctx, pgGuardPeersSQL, b.appName).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func (b *pgLockBackend) sessionPID() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pid
}

func (b *pgLockBackend) connected() bool { return b.current() != nil }

func (b *pgLockBackend) runsWatchdog() bool { return true }

// close 釋放釘選連線：持鎖時 best-effort 解鎖後丟棄；否則直接丟棄。
// **一律丟棄、不歸池**：帶著守衛 application_name 的連線若回到池中，會在其他實例的
// 對等計數中被誤認為存活的守衛。
func (b *pgLockBackend) close(ctx context.Context, unlock bool) {
	conn := b.current()
	if conn == nil {
		return
	}
	if unlock {
		var released bool
		if err := conn.QueryRowContext(ctx, pgGuardUnlockSQL, InstanceGuardLockKey).Scan(&released); err != nil || !released {
			log.Printf("[InstanceGuard] 單實例鎖解鎖未確認（err=%v, released=%v）：丟棄該連線以強制釋放", err, released)
		}
	}
	b.discard()
}
