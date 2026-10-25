package main

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// 嚴格等待證明（各交錯案例共通規則，「確認等待」一律指此定義）。
//
// 觀測連線輪詢 pg_locks，(甲)(乙) 同一次觀測都成立才算確認：
//   - (甲) 後行交易的 pid 有一列 NOT granted、且依共用資源限定的鎖：
//     advisory 限定同一 database、classid、objid、objsubid=2；
//     transactionid 要與先行 pid 已 granted 的同一個 transactionid 值配對（可以是先行交易的子交易編號，
//     所以不拿 pg_current_xact_id() 比對）；tuple 限定同一 database 與該表的 relation OID，
//     並與持有方 granted 的同一個 (relation, page, tuple) 配對。
//   - (乙) 先行 pid 在 pg_blocking_pids(後行 pid) 之內；advisory 另要求同一 database 與 key 上
//     先行 pid granted 恰 1 列。
//
// 每次觀測都是一條聚合查詢、回一列、寫進新宣告的變數（GORM Scan 零列不覆寫目的變數，
// 前後兩次觀測共用變數會讀到舊值）。輪詢有上限，不以逾時、「送出第一個語句」或
// 「第一筆寫入未發生」代替。

// pwloUserCredentialLockClass 使用者憑證鎖的 advisory classid（identity 未匯出的 userCredentialLockClass，
// `identity/user_credential_lock.go:37`）。值寫錯時 (甲) 的 classid 限定配不到、等待證明不成立，不會假綠。
const pwloUserCredentialLockClass int32 = 0x6F74_6B03

const (
	pwloProofBound    = 5 * time.Second
	pwloProofInterval = 20 * time.Millisecond
)

// pwloTarget 等待證明要求的共用資源。
type pwloTarget struct {
	kind     string // advisory | transactionid | tuple
	class    int32  // advisory
	objid    int64  // advisory（使用者編號折成 int4 後的 oid 值；拓撲鎖為 1）
	relation string // tuple：表名（以觀測連線的 search_path 解析成 regclass）
}

func pwloAdvisory(class int32, objid int64) pwloTarget {
	return pwloTarget{kind: "advisory", class: class, objid: objid}
}

func pwloUserLock(userID uint) pwloTarget {
	return pwloAdvisory(pwloUserCredentialLockClass, int64(uint32(userID)))
}

func pwloRowLock() pwloTarget { return pwloTarget{kind: "transactionid"} }

func pwloTupleLock(relation string) pwloTarget { return pwloTarget{kind: "tuple", relation: relation} }

// pwloProof 一筆成立的等待證明。
type pwloProof struct {
	kind string
	key  string
}

func (p pwloProof) String() string { return p.kind + "(" + p.key + ")" }

// pwloRun 一個在背景執行的交易入口：done 關閉後 err 才可讀。觀測端以非消耗的方式查它是否已結束。
type pwloRun struct {
	done chan struct{}
	err  error
}

func pwloGo(fn func() error) *pwloRun {
	r := &pwloRun{done: make(chan struct{})}
	go func() {
		defer close(r.done)
		r.err = fn()
	}()
	return r
}

func (r *pwloRun) finished() bool {
	if r == nil {
		return false
	}
	select {
	case <-r.done:
		return true
	default:
		return false
	}
}

func (r *pwloRun) wait(t *testing.T, what string) error {
	t.Helper()
	select {
	case <-r.done:
		return r.err
	case <-time.After(pwloDeadline):
		t.Fatalf("%s 在 %s 內未返回", what, pwloDeadline)
		return nil
	}
}

// pwloProveWait 在 bound 內輪詢，直到 (甲)(乙) 在同一次觀測中成立；回傳證明、是否成立與未成立的原因。
// waiter 在被證明之前就結束（waiterRun 已 done），表示它沒有被 holder 擋住，立即回未成立。
func pwloProveWait(t *testing.T, obs *gorm.DB, waiter, holder int64, tg pwloTarget, bound time.Duration, waiterRun *pwloRun) (pwloProof, bool, string) {
	t.Helper()
	require.NotZero(t, waiter, "waiter pid 未取得")
	require.NotZero(t, holder, "holder pid 未取得")
	require.NotEqual(t, waiter, holder, "waiter 與 holder 是同一個 pid")
	if bound > pwloProofBound {
		bound = pwloProofBound
	}
	ticker := time.NewTicker(pwloProofInterval)
	defer ticker.Stop()
	timeout := time.NewTimer(bound)
	defer timeout.Stop()
	last := "尚未觀測"
	for {
		proof, ok, why := pwloObserveWait(t, obs, waiter, holder, tg)
		if ok {
			return proof, true, ""
		}
		last = why
		if waiterRun.finished() {
			return pwloProof{}, false, fmt.Sprintf("waiter pid %d 在被證明等待 pid %d 之前就已結束（err=%v）；最後觀測：%s", waiter, holder, waiterRun.err, last)
		}
		select {
		case <-ticker.C:
		case <-timeout.C:
			return pwloProof{}, false, fmt.Sprintf("%s 內未證明 pid %d 正在等 pid %d 持有的 %s；最後觀測：%s", bound, waiter, holder, tg.kind, last)
		}
	}
}

// pwloObserveWait 一次觀測：(甲)(乙) 同一條查詢內求值。
func pwloObserveWait(t *testing.T, obs *gorm.DB, waiter, holder int64, tg pwloTarget) (pwloProof, bool, string) {
	t.Helper()
	switch tg.kind {
	case "advisory":
		var row struct {
			Waiting int64
			Held    int64
			Blocked bool
		}
		require.NoError(t, obs.Raw(`SELECT
 (SELECT count(*) FROM pg_locks WHERE pid = ? AND NOT granted AND locktype = 'advisory'
    AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
    AND classid::bigint = ? AND objid::bigint = ? AND objsubid = 2) AS waiting,
 (SELECT count(*) FROM pg_locks WHERE pid = ? AND granted AND locktype = 'advisory'
    AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
    AND classid::bigint = ? AND objid::bigint = ? AND objsubid = 2) AS held,
 (?::int = ANY(pg_blocking_pids(?::int))) AS blocked`,
			waiter, int64(tg.class), tg.objid, holder, int64(tg.class), tg.objid, holder, waiter).Scan(&row).Error)
		if row.Waiting == 1 && row.Held == 1 && row.Blocked {
			return pwloProof{kind: "advisory", key: fmt.Sprintf("class=%d,objid=%d,objsubid=2", tg.class, tg.objid)}, true, ""
		}
		return pwloProof{}, false, fmt.Sprintf("advisory waiting=%d held=%d blocked=%v", row.Waiting, row.Held, row.Blocked)
	case "transactionid":
		var row struct {
			Paired  int64
			Xid     string
			Blocked bool
			SameDB  int64
		}
		require.NoError(t, obs.Raw(`SELECT count(*) AS paired, coalesce(max(w.transactionid::text), '') AS xid,
 (?::int = ANY(pg_blocking_pids(?::int))) AS blocked,
 (SELECT count(*) FROM pg_stat_activity WHERE pid IN (?, ?) AND datname = current_database()) AS same_db
 FROM pg_locks w JOIN pg_locks h
   ON h.locktype = 'transactionid' AND h.granted AND h.pid = ? AND h.transactionid = w.transactionid
 WHERE w.pid = ? AND w.locktype = 'transactionid' AND NOT w.granted`,
			holder, waiter, waiter, holder, holder, waiter).Scan(&row).Error)
		if row.Paired == 1 && row.Blocked && row.SameDB == 2 {
			return pwloProof{kind: "transactionid", key: "xid=" + row.Xid}, true, ""
		}
		return pwloProof{}, false, fmt.Sprintf("transactionid paired=%d blocked=%v same_db=%d", row.Paired, row.Blocked, row.SameDB)
	case "tuple":
		var row struct {
			Paired  int64
			Blocked bool
		}
		require.NoError(t, obs.Raw(`SELECT count(*) AS paired, (?::int = ANY(pg_blocking_pids(?::int))) AS blocked
 FROM pg_locks w JOIN pg_locks h
   ON h.locktype = 'tuple' AND h.granted AND h.pid = ? AND h.database = w.database
  AND h.relation = w.relation AND h.page = w.page AND h.tuple = w.tuple
 WHERE w.pid = ? AND w.locktype = 'tuple' AND NOT w.granted
   AND w.database = (SELECT oid FROM pg_database WHERE datname = current_database())
   AND w.relation = ?::regclass`,
			holder, waiter, holder, waiter, tg.relation).Scan(&row).Error)
		if row.Paired == 1 && row.Blocked {
			return pwloProof{kind: "tuple", key: "relation=" + tg.relation}, true, ""
		}
		return pwloProof{}, false, fmt.Sprintf("tuple paired=%d blocked=%v", row.Paired, row.Blocked)
	default:
		t.Fatalf("未知的等待證明種類 %q", tg.kind)
		return pwloProof{}, false, ""
	}
}

// pwloAdvisoryHeld 某 pid 在本 database 上 granted 持有指定 advisory 鍵的列數（單列 count）。
func pwloAdvisoryHeld(t *testing.T, obs *gorm.DB, pid int64, class int32, objid int64) int64 {
	t.Helper()
	var n int64
	require.NoError(t, obs.Raw(`SELECT count(*) FROM pg_locks WHERE pid = ? AND granted AND locktype = 'advisory'
 AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
 AND classid::bigint = ? AND objid::bigint = ? AND objsubid = 2`, pid, int64(class), objid).Scan(&n).Error)
	return n
}

// pwloSelfCheckConn 一條釘住的連線，手動開交易，pid 在交易開始時取得。
type pwloSelfCheckConn struct {
	conn *sql.Conn
	pid  int64
}

func pwloBeginConn(t *testing.T, db *sql.DB) *pwloSelfCheckConn {
	t.Helper()
	ctx := context.Background()
	c, err := db.Conn(ctx)
	require.NoError(t, err)
	_, err = c.ExecContext(ctx, "BEGIN")
	require.NoError(t, err)
	var pid int64
	require.NoError(t, c.QueryRowContext(ctx, "SELECT pg_backend_pid()").Scan(&pid))
	return &pwloSelfCheckConn{conn: c, pid: pid}
}

// pwloReleaseConns 依建立順序回滾並關閉（先放持有者，等待者才結束得了；中途失敗時清理也不會互等）。
func pwloReleaseConns(t *testing.T, conns ...*pwloSelfCheckConn) {
	t.Cleanup(func() {
		for _, c := range conns {
			_, _ = c.conn.ExecContext(context.Background(), "ROLLBACK")
		}
		for _, c := range conns {
			_ = c.conn.Close()
		}
	})
}

func (c *pwloSelfCheckConn) exec(t *testing.T, sqlText string, args ...any) {
	t.Helper()
	_, err := c.conn.ExecContext(context.Background(), sqlText, args...)
	require.NoError(t, err, sqlText)
}

func (c *pwloSelfCheckConn) goExec(sqlText string, args ...any) *pwloRun {
	return pwloGo(func() error {
		_, err := c.conn.ExecContext(context.Background(), sqlText, args...)
		return err
	})
}

// runStrictWaitProofSelfCheck 等待證明 helper 的正負向自測：正向控制必須成立；
// 錯鍵、錯 class、錯持有者、只送出語句而未等待、持有者不持該 xid／tuple 都必須不成立。
// 把 helper 改成「送出第一個語句即算等待」會讓「只送出語句」那一案轉紅。
func runStrictWaitProofSelfCheck(t *testing.T, e *pwloEnv) {
	const negBound = 400 * time.Millisecond
	const probeClass int32 = 0x7077_6C01 // 本自測專用，不與產品 class 相撞
	expectOK := func(name string, waiter, holder int64, tg pwloTarget, run *pwloRun) pwloProof {
		t.Helper()
		p, ok, why := pwloProveWait(t, e.obs, waiter, holder, tg, pwloProofBound, run)
		require.True(t, ok, "正向控制 %s 應成立：%s", name, why)
		t.Logf("self-check %s: confirmed %s", name, p)
		return p
	}
	expectNo := func(name string, waiter, holder int64, tg pwloTarget, run *pwloRun) {
		t.Helper()
		p, ok, why := pwloProveWait(t, e.obs, waiter, holder, tg, negBound, run)
		require.False(t, ok, "負向 %s 不得成立（helper 回報 %s）", name, p)
		t.Logf("self-check %s: rejected (%s)", name, why)
	}
	pool := e.selfCheckPool(t)

	// advisory：c1 持鍵 (probeClass, 1)，c2 等同一鍵，c3 只送出一個語句後停在交易中
	c1, c2, c3 := pwloBeginConn(t, pool), pwloBeginConn(t, pool), pwloBeginConn(t, pool)
	pwloReleaseConns(t, c1, c2, c3)
	e.notePIDs("self_check", c1.pid, c2.pid, c3.pid)
	c1.exec(t, "SELECT pg_advisory_xact_lock($1, $2)", probeClass, int32(1))
	adv2 := c2.goExec("SELECT pg_advisory_xact_lock($1, $2)", probeClass, int32(1))
	c3.exec(t, "SELECT 1")
	expectOK("advisory_positive", c2.pid, c1.pid, pwloAdvisory(probeClass, 1), adv2)
	expectNo("advisory_wrong_objid", c2.pid, c1.pid, pwloAdvisory(probeClass, 2), adv2)
	expectNo("advisory_wrong_class", c2.pid, c1.pid, pwloAdvisory(probeClass+1, 1), adv2)
	expectNo("advisory_wrong_holder", c2.pid, c3.pid, pwloAdvisory(probeClass, 1), adv2)
	expectNo("statement_sent_not_waiting", c3.pid, c1.pid, pwloAdvisory(probeClass, 1), nil)
	expectNo("row_kind_on_advisory_wait", c2.pid, c1.pid, pwloRowLock(), adv2)
	c1.exec(t, "ROLLBACK")
	require.NoError(t, adv2.wait(t, "advisory 等待者"))
	c2.exec(t, "ROLLBACK")
	c3.exec(t, "ROLLBACK")

	// 列鎖：r1 先寫一列取得最外層 xid，再開 SAVEPOINT 寫目標列（子交易 xid）；r2 等子交易 xid，r3 等 r2 持有的 tuple 鎖
	require.NoError(t, e.fix.Exec("CREATE TABLE IF NOT EXISTS pwlo_probe (id int PRIMARY KEY, v int NOT NULL)").Error)
	require.NoError(t, e.fix.Exec("CREATE TABLE IF NOT EXISTS pwlo_probe_other (id int PRIMARY KEY)").Error)
	require.NoError(t, e.fix.Exec("INSERT INTO pwlo_probe (id, v) VALUES (1, 0), (2, 0) ON CONFLICT (id) DO NOTHING").Error)
	r1, r2, r3 := pwloBeginConn(t, pool), pwloBeginConn(t, pool), pwloBeginConn(t, pool)
	pwloReleaseConns(t, r1, r2, r3)
	e.notePIDs("self_check", r1.pid, r2.pid, r3.pid)
	r1.exec(t, "UPDATE pwlo_probe SET v = v + 1 WHERE id = 2")
	var top string
	require.NoError(t, r1.conn.QueryRowContext(context.Background(), "SELECT pg_current_xact_id()::text").Scan(&top))
	r1.exec(t, "SAVEPOINT pwlo_sp")
	r1.exec(t, "UPDATE pwlo_probe SET v = v + 1 WHERE id = 1")
	row2 := r2.goExec("UPDATE pwlo_probe SET v = v + 10 WHERE id = 1")
	p := expectOK("transactionid_subxact_positive", r2.pid, r1.pid, pwloRowLock(), row2)
	require.NotEqual(t, "xid="+top, p.key, "等待方等的應是子交易編號，不是最外層編號 %s", top)
	expectNo("transactionid_wrong_holder", r2.pid, r3.pid, pwloRowLock(), row2)
	expectNo("advisory_kind_on_row_wait", r2.pid, r1.pid, pwloAdvisory(probeClass, 1), row2)
	row3 := r3.goExec("UPDATE pwlo_probe SET v = v + 100 WHERE id = 1")
	expectOK("tuple_positive", r3.pid, r2.pid, pwloTupleLock("pwlo_probe"), row3)
	expectNo("tuple_wrong_holder", r3.pid, r1.pid, pwloTupleLock("pwlo_probe"), row3)
	expectNo("tuple_wrong_relation", r3.pid, r2.pid, pwloTupleLock("pwlo_probe_other"), row3)
	r1.exec(t, "ROLLBACK")
	require.NoError(t, row2.wait(t, "列鎖等待者 r2"))
	r2.exec(t, "ROLLBACK")
	require.NoError(t, row3.wait(t, "列鎖等待者 r3"))
	r3.exec(t, "ROLLBACK")
}
