package dbconsole

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"
)

// 以 stub driver 注入結果與錯誤，使「錯誤發生在第幾個結果集之後」這類只在真實
// 目標端上偶發的形態成為可重現的斷言。
//
// **不是替代整合測試**：真實方言的錯誤碼、取消語義與型別名要對三種靶機實跑
// （見 integration_test.go）。stub 驗的是我方的判定邏輯——那一部分與目標端無關，
// 卻是狀態被記錯時唯一的成因。

// stubConfig 模擬 driver 的設定物件，只保留我方會清零的那一欄
type stubConfig struct {
	Password string
}

// stubScript 一次 QueryContext 的腳本
type stubScript struct {
	// sets 逐結果集的資料（每個結果集：欄名 + 列）
	sets []stubSet
	// queryErr QueryContext 當場回的錯誤（＝連本地都沒送出去／立刻被拒）
	queryErr error
	// afterSets 讀完第 N 個結果集之後回的錯誤（N＝len(sets) 時為讀到底才錯）
	afterSets int
	afterErr  error
}

type stubSet struct {
	columns []string
	rows    [][]driver.Value
}

type stubDriver struct{}

func (stubDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("stub: 不支援 DSN 開啟")
}

type stubConnector struct {
	cfg      *stubConfig
	scripts  map[string]stubScript
	fallback stubScript
	// probeRow 探詢語句的回應（當前庫、交易態、影響列數）
	probeRow []driver.Value
	// passwordAtConnect 首次 Connect 當下我方設定物件裡的密碼快照。
	// 清零測試要能區分「連的時候就是空的」（那 driver 根本拿不到密碼）
	// 與「連完才清零」——只斷言最終為空無法分辨這兩者
	passwordAtConnect string
	connected         int
}

func (c *stubConnector) Connect(context.Context) (driver.Conn, error) {
	c.connected++
	c.passwordAtConnect = c.cfg.Password
	return &stubConn{owner: c}, nil
}

func (c *stubConnector) Driver() driver.Driver { return stubDriver{} }

type stubConn struct {
	owner  *stubConnector
	closed bool
}

func (c *stubConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("stub: 不支援 prepare")
}
func (c *stubConn) Close() error              { c.closed = true; return nil }
func (c *stubConn) Begin() (driver.Tx, error) { return nil, errors.New("stub: 不支援交易") }

func (c *stubConn) QueryContext(ctx context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "DATABASE()") || strings.Contains(query, "DB_NAME()") {
		return &stubRows{
			script: stubScript{sets: []stubSet{{
				columns: []string{"db", "tx", "aff"},
				rows:    [][]driver.Value{c.owner.probeRow},
			}}},
		}, nil
	}
	script, ok := c.owner.scripts[query]
	if !ok {
		script = c.owner.fallback
	}
	if script.queryErr != nil {
		return nil, script.queryErr
	}
	return &stubRows{script: script}, nil
}

func (c *stubConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return driver.RowsAffected(0), nil
}

type stubRows struct {
	script  stubScript
	setIdx  int
	rowIdx  int
	drained bool
}

func (r *stubRows) Columns() []string {
	if r.setIdx >= len(r.script.sets) {
		return nil
	}
	return r.script.sets[r.setIdx].columns
}

func (r *stubRows) Close() error { return nil }

func (r *stubRows) Next(dest []driver.Value) error {
	if r.setIdx >= len(r.script.sets) {
		return io.EOF
	}
	set := r.script.sets[r.setIdx]
	if r.rowIdx >= len(set.rows) {
		return io.EOF
	}
	copy(dest, set.rows[r.rowIdx])
	r.rowIdx++
	return nil
}

func (r *stubRows) HasNextResultSet() bool {
	// 尚有結果集，或還欠一個「讀完第 N 個之後才發生」的錯誤要交出去
	return r.setIdx+1 < len(r.script.sets) ||
		(r.script.afterErr != nil && r.setIdx+1 == r.script.afterSets)
}

func (r *stubRows) NextResultSet() error {
	r.setIdx++
	r.rowIdx = 0
	if r.script.afterErr != nil && r.setIdx == r.script.afterSets {
		return r.script.afterErr
	}
	if r.setIdx >= len(r.script.sets) {
		return io.EOF
	}
	return nil
}

// newStubDialect 以 stub connector 組出一個 sqlDialect，走的是與產品路徑
// 完全相同的裝配（一次性 connector → sql.OpenDB → 釘選單連線）。
//
// 走同一條裝配路徑才有意義：若測試自己 new 一個 sqlDialect，
// 「釘選少設了一個參數」這類缺陷就永遠不會被這些測試碰到。
func newStubDialect(t *testing.T, proto Protocol, connector *stubConnector, ourCopy []byte) (*sqlDialect, *oneShotConnector) {
	t.Helper()
	oneShot := newOneShotConnector(connector, func() {
		connector.cfg.Password = ""
		zeroBytes(ourCopy)
	})
	db := sql.OpenDB(oneShot)
	conn, err := pinSingleConnection(context.Background(), db)
	if err != nil {
		t.Fatalf("釘選單連線失敗: %v", err)
	}
	d := &sqlDialect{
		proto: proto, db: db, conn: conn, connector: oneShot,
		currentDB: "app",
		meta: dialectMeta{
			probeSQL: "SELECT DATABASE(), 'unknown', ROW_COUNT()",
			useSQL:   "USE %s",
		},
	}
	t.Cleanup(func() { _ = d.Close() })
	return d, oneShot
}

func strPtr(s string) *string { return &s }
