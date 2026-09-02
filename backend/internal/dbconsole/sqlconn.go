package dbconsole

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
)

// ErrNoStatementInFlight 沒有進行中的執行單位可取消
var ErrNoStatementInFlight = errors.New("dbconsole: 沒有進行中的執行單位")

// ErrBusy 已有進行中的執行單位（每會話同時只允許一個）
var ErrBusy = errors.New("dbconsole: 已有進行中的執行單位")

// sqlDialect MySQL 與 MSSQL 共用的實作骨架。
//
// 兩者的差異只在四處：探詢語句、切庫語句、識別字引用、目錄查詢。
// 共用的部分——單連線的釘選、進行中單位的互斥與取消、結果讀取與上限——
// 抄兩份的話，「取消後狀態怎麼判」這種只在某一個方言上被改對的事就會發生。
//
// PostgreSQL 不走這裡：它用 pgx 的簡單查詢協議直取文字格式結果，
// 且切庫是重新連線而不是一句控制語句。
type sqlDialect struct {
	proto     Protocol
	db        *sql.DB
	conn      *sql.Conn
	connector *oneShotConnector
	meta      dialectMeta

	mu        sync.Mutex
	currentDB string
	inflight  *inflightUnit
}

// dialectMeta 方言之間唯一的差異面
type dialectMeta struct {
	// probeSQL 一次往返取回「當前庫、交易態、上一句的影響列數」三件事。
	// 合成一句的理由不只是省往返：分開問會拿到三個時點的答案，
	// 而影響列數是**會被下一句語句重設**的計數器
	probeSQL string
	// useSQL 切庫語句的格式（%s 為已引用的識別字）
	useSQL string
	// listDatabasesSQL 目錄查詢：回 (name, connectable)
	listDatabasesSQL string
	// listTablesSQL 當前庫的表與檢視：回 (schema, name, kind)
	listTablesSQL string
	// listColumnsSQL 欄位：回 (name, type_name, nullable)，參數為 (schema, table)
	listColumnsSQL string
}

// inflightUnit 進行中的執行單位。
//
// 它存在的唯一理由是 Cancel：取消一定發生在另一個 goroutine（訊息迴圈）上，
// 而「目標端有沒有確認取消」這個事實只有跑 Exec 的那一邊看得到。
type inflightUnit struct {
	cancel    context.CancelFunc
	done      chan struct{}
	confirmed bool
}

func (d *sqlDialect) CurrentDatabase() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.currentDB
}

func (d *sqlDialect) Close() error {
	// 先關釘選連線再關池：釘選連線不在池的管理之下，反序會讓它成為孤兒
	var firstErr error
	if d.conn != nil {
		if err := d.conn.Close(); err != nil {
			firstErr = err
		}
	}
	if d.db != nil {
		if err := d.db.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ConnectAttempts 一次性 connector 的撥號次數。
// 測試以它證明「目標連線關閉後零重撥」——只斷言沒有錯誤的話，
// 重撥成功與根本沒重撥是同一個結果
func (d *sqlDialect) ConnectAttempts() int64 { return d.connector.ConnectAttempts() }

func (d *sqlDialect) Switch(ctx context.Context, name string) error {
	stmt := fmt.Sprintf(d.meta.useSQL, QuoteIdentifier(d.proto, name))
	if _, err := d.conn.ExecContext(ctx, stmt); err != nil {
		return err
	}
	d.mu.Lock()
	d.currentDB = name
	d.mu.Unlock()
	return nil
}

func (d *sqlDialect) ProbeState(ctx context.Context) (State, error) {
	st, _, err := d.probe(ctx)
	return st, err
}

// probe 一次往返取回當前庫、交易態與上一句的影響列數。
//
// 探詢失敗**不使執行單位失敗**：交易態是脈絡不是結果，取不到就記 unknown。
// 讓一個附帶的探詢把一次已經成功的執行判成失敗，是把次要資訊升格成主要事實。
func (d *sqlDialect) probe(ctx context.Context) (State, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()

	var (
		dbName  sql.NullString
		txState sql.NullString
		affRaw  sql.NullInt64
	)
	row := d.conn.QueryRowContext(ctx, d.meta.probeSQL)
	if err := row.Scan(&dbName, &txState, &affRaw); err != nil {
		return State{Database: d.CurrentDatabase(), TxState: TxStateUnknown}, 0, err
	}

	st := State{Database: dbName.String, TxState: TxStateUnknown}
	if txState.Valid {
		st.TxState = txState.String
	}
	if st.Database != "" {
		d.mu.Lock()
		d.currentDB = st.Database
		d.mu.Unlock()
	}
	return st, affRaw.Int64, nil
}

func (d *sqlDialect) Cancel(ctx context.Context) (bool, error) {
	d.mu.Lock()
	unit := d.inflight
	d.mu.Unlock()
	if unit == nil {
		return false, ErrNoStatementInFlight
	}

	unit.cancel()
	select {
	case <-unit.done:
		return unit.confirmed, nil
	case <-ctx.Done():
		// 等不到單位收束就回未確認：**這是誠實的答案**——
		// 我們確實不知道目標端怎麼處理了那次取消
		return false, ctx.Err()
	}
}

// beginUnit 登記一個進行中的執行單位。回傳的 ctx 已綁上語句逾時。
func (d *sqlDialect) beginUnit(parent context.Context) (context.Context, *inflightUnit, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.inflight != nil {
		return nil, nil, ErrBusy
	}
	ctx, cancel := context.WithTimeout(parent, StatementTimeout)
	unit := &inflightUnit{cancel: cancel, done: make(chan struct{})}
	d.inflight = unit
	return ctx, unit, nil
}

func (d *sqlDialect) endUnit(unit *inflightUnit, confirmed bool) {
	d.mu.Lock()
	unit.confirmed = confirmed
	d.inflight = nil
	d.mu.Unlock()
	unit.cancel()
	close(unit.done)
}

// Exec 送出一個執行單位並讀回結果。
//
// # 順序
//
// 送出 → 逐結果集讀到上限 → 探詢（當前庫、交易態、影響列數）→ 分類。
// 探詢在讀完結果之後：影響列數是會被下一句重設的計數器，而讀取結果本身
// 不算一句語句，故這個順序取得到的是本單位的值。
func (d *sqlDialect) Exec(parent context.Context, statement string) (*ExecOutcome, error) {
	ctx, unit, err := d.beginUnit(parent)
	if err != nil {
		return nil, err
	}

	builder := newResultBuilder(MaxBytesPerSubmission)
	out, confirmed := d.execUnit(ctx, statement, builder)
	d.endUnit(unit, confirmed)
	return out, nil
}

// ExecWithBudget 同 Exec，但共用呼叫端給的位元組額度（MSSQL 多批次用）。
func (d *sqlDialect) ExecWithBudget(parent context.Context, statement string, builder *resultBuilder) (*ExecOutcome, error) {
	ctx, unit, err := d.beginUnit(parent)
	if err != nil {
		return nil, err
	}
	builder.resetUnit()
	out, confirmed := d.execUnit(ctx, statement, builder)
	d.endUnit(unit, confirmed)
	return out, nil
}

func (d *sqlDialect) execUnit(ctx context.Context, statement string, builder *resultBuilder) (*ExecOutcome, bool) {
	out := &ExecOutcome{Status: StatusOK}

	// 探詢即使在錯誤路徑上也要做：交易態在錯誤之後才是最有價值的
	// （PostgreSQL 的失敗交易態、MSSQL 的不可提交態都是錯誤造成的）。
	// **每一條返回路徑都必須經過它**——漏掉哪一條，那條路徑上的單位就會帶著
	// 空字串的交易態進審計，而空字串在這個欄位上的既有語義是「命令列的列」
	// takeAffected 為假＝語句連送都沒送成功，此時的 ROW_COUNT() 是上一個語句留下的，
	// 抄過來就是把別人的影響列數記到這一筆上
	probeNow := func(takeAffected bool) {
		st, affected, probeErr := d.probe(context.WithoutCancel(ctx))
		if probeErr != nil {
			out.TxState = TxStateUnknown
			// 探詢是我方在同一條連線上的一次往返，它撞上連線層錯誤就是
			// 「這條連線已經不能再用」的直接證據。**這條路才問得出取消之後的死活**：
			// driver 的取消實作若是關閉連線，語句本身回的是取消而不是連線錯誤，
			// 死活因此不在那個錯誤裡。判定放在這裡也不多花一次往返——
			// 每一條返回路徑本來就都經過這次探詢
			if IsConnectionLost(probeErr) {
				out.ConnectionLost = true
			}
			return
		}
		out.TxState = st.TxState
		if takeAffected {
			out.RowsAffected = affected
		}
	}

	rows, err := d.conn.QueryContext(ctx, statement)
	if err != nil {
		probeNow(false)
		return d.classifyUnitError(ctx, out, err, false), out.CancelConfirmed
	}
	readErr := d.collectSets(rows, builder, out)
	_ = rows.Close()

	probeNow(true)

	out.Truncated = builder.truncated
	if readErr != nil {
		hadResults := len(out.Sets) > 0
		return d.classifyUnitError(ctx, out, readErr, hadResults), out.CancelConfirmed
	}
	if builder.truncated && builder.reason == "cell" {
		out.Reason = ReasonCellTruncated
	}
	return out, false
}

// classifyUnitError 把 driver 錯誤翻成八值狀態之一。
//
// 判定順序即語義優先序：
//
//  1. **連線斷了 → effect_unknown**。語句送出去了，目標端沒回報結果也沒確認取消，
//     我們確知自己不知道。這一條要排在取消之前——MySQL 的取消實作就是關閉連線，
//     若先判取消，一次未獲確認的取消會被記成「確認未生效」。
//  2. 使用者要求取消或逾時 → 依目標端**有沒有確認**分成兩組狀態。
//  3. 錯誤前已有完成的結果 → partial。它記的是「目標端回報過完成」這個事實，
//     已完成部分是否已提交取決於方言與使用者寫的交易結構，我們不推斷。
//  4. 其餘 → error（帶目標端錯誤碼與原文；這是使用者自己語句撞到的錯）。
func (d *sqlDialect) classifyUnitError(ctx context.Context, out *ExecOutcome, err error, hadResults bool) *ExecOutcome {
	timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded)
	cancelled := errors.Is(ctx.Err(), context.Canceled)
	confirmed := IsCancelConfirmed(d.proto, err)

	switch {
	case IsConnectionLost(err):
		out.Status = StatusEffectUnknown
		out.ConnectionLost = true
		switch {
		case timedOut:
			out.Reason = ReasonTimeoutUnconfirmed
		case cancelled:
			out.Reason = ReasonCancelUnconfirmed
		default:
			out.Reason = ReasonConnectionLost
		}
		out.DBError = DBErrorOf(d.proto, err, false)
	case timedOut:
		if confirmed {
			out.Status = StatusTimeout
			out.Reason = ReasonTimeoutConfirmed
			out.CancelConfirmed = true
		} else {
			out.Status = StatusEffectUnknown
			out.Reason = ReasonTimeoutUnconfirmed
		}
	case cancelled:
		if confirmed {
			out.Status = StatusCancelled
			out.Reason = ReasonCancelConfirmed
			out.CancelConfirmed = true
		} else {
			out.Status = StatusEffectUnknown
			out.Reason = ReasonCancelUnconfirmed
		}
	case hadResults:
		out.Status = StatusPartial
		out.Reason = ReasonErrorAfterResults
		out.DBError = DBErrorOf(d.proto, err, true)
	default:
		out.Status = StatusError
		out.DBError = DBErrorOf(d.proto, err, true)
	}
	if out.DBError == nil && out.Status == StatusError {
		// 沒有可辨識的目標端錯誤碼：仍要有東西可回報，
		// 否則畫面上會是一個沒有任何說明的錯誤態
		out.DBError = &DBError{Code: "", Message: err.Error()}
	}
	return out
}

// collectSets 逐結果集讀到上限。
//
// 回傳的錯誤是**讀取途中**的錯誤——它與「一開始就送不出去」在狀態分類上不同：
// 前者可能已有結果集完成（partial），後者不可能。
func (d *sqlDialect) collectSets(rows *sql.Rows, builder *resultBuilder, out *ExecOutcome) error {
	setIndex := 0
	for {
		set, err := d.collectOneSet(rows, builder, setIndex)
		if err != nil {
			return err
		}
		if set != nil {
			out.Sets = append(out.Sets, *set)
			setIndex++
		}
		if !rows.NextResultSet() {
			return rows.Err()
		}
	}
}

func (d *sqlDialect) collectOneSet(rows *sql.Rows, builder *resultBuilder, index int) (*ResultSet, error) {
	colTypes, err := rows.ColumnTypes()
	if err != nil {
		return nil, err
	}
	if len(colTypes) == 0 {
		// 無欄位＝非查詢語句（DML／DDL）。它不是一個結果集，
		// 影響列數由探詢取得——回 nil 使 set_index 不因它而跳號
		return nil, nil
	}

	set := &ResultSet{SetIndex: index, Columns: make([]ColumnMeta, 0, len(colTypes))}
	for _, ct := range colTypes {
		set.Columns = append(set.Columns, ColumnMeta{
			Name:     ct.Name(),
			TypeName: ct.DatabaseTypeName(),
			Kind:     KindOf(ct.DatabaseTypeName()),
		})
	}

	holders := make([]any, len(colTypes))
	ptrs := make([]any, len(colTypes))
	for i := range holders {
		ptrs[i] = &holders[i]
	}

	for rows.Next() {
		if builder.exhausted() {
			// 額度在上一列剛好用盡：這一列存在但不搬回來，
			// **列層與單位層都要標記**——只標其一的話，畫面上會有一個沒有橫幅的截斷結果
			builder.markTruncated("row_limit")
			set.Truncated = true
			break
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make([]*string, len(holders))
		for i := range holders {
			cell, cut := textifyCounted(holders[i], set.Columns[i].Kind)
			if cut {
				builder.markTruncated("cell")
			}
			row[i] = cell
		}
		if !builder.consumeRow(approxRowSize(row)) {
			set.Truncated = true
			break
		}
		set.Rows = append(set.Rows, row)
	}
	set.RowCount = len(set.Rows)
	if err := rows.Err(); err != nil {
		// 已讀到的部分照樣回報：它是目標端確實回報過的事實
		return set, err
	}
	return set, nil
}

// pinSingleConnection 把 *sql.DB 釘成單連線並取出那一條連線持有整場。
//
// 三個設定缺一不可：MaxOpen 限制併發、MaxIdle 讓那條連線不被回收後重建、
// ConnMaxLifetime 為零使它不因年齡被換掉。少任何一個，池都可能在會話中途
// 換一條連線——而換連線意味著 `SET`、暫存表與交易全部悄悄消失。
func pinSingleConnection(ctx context.Context, db *sql.DB) (*sql.Conn, error) {
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	db.SetConnMaxIdleTime(0)

	ctx, cancel := context.WithTimeout(ctx, ConnectTimeout)
	defer cancel()
	return db.Conn(ctx)
}

// ExecWithin 同 Exec，但與同一次送出的其他單位共用位元組額度。
//
// 只有 MySQL／MSSQL 這一族實作它：PostgreSQL 的一次送出恆為一個單位
// （簡單查詢協議把整段文字當一個單位送），沒有跨單位共用額度的問題
func (d *sqlDialect) ExecWithin(parent context.Context, statement string, s *Submission) (*ExecOutcome, error) {
	if s == nil || s.builder == nil {
		return d.Exec(parent, statement)
	}
	return d.ExecWithBudget(parent, statement, s.builder)
}
