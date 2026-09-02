package dbconsole

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgconn/ctxwatch"
)

// PostgreSQL 方言。
//
// # 為什麼不走 database/sql
//
// 執行單位以**簡單查詢協議**（`PgConn().Exec`）送出，理由有二：延伸協議禁止
// 一次送多個語句，而執行單位就是使用者送出的文字原文；簡單查詢協議的結果一律
// 是**文字格式**，正是我方要傳輸的形態——不必經過一次「二進位→Go 型別→文字」
// 的轉換，也就沒有轉換過程中失真的可能。
//
// # 切庫＝重新連線
//
// PostgreSQL 的連線綁定資料庫，沒有 `USE`。切庫因此是關閉舊連線、重新撥號——
// 未提交的交易與暫存態隨之消失（介面於動作前明示），而重新撥號要重新解封憑證，
// 故必須重跑閘序。**這不是自動重連**：它由使用者的動作觸發，且每次都重新過閘。
// 本套件只提供 Reconnect 這個動作，閘序與解封由呼叫端負責。
//
// # 取消保留連線
//
// 以 `CancelRequestContextWatcherHandler` 取代 pgx 的預設處置——預設是對底層
// net.Conn 設 deadline（等於把連線關掉），那會讓每一次取消都變成「未獲確認」。
// 換成送 CancelRequest 之後，目標端會回 SQLSTATE 57014，我們才有依據說
// 「這句確認沒有生效」。

// pgDialect PostgreSQL 的連線適配器
type pgDialect struct {
	conn *pgx.Conn

	mu        sync.Mutex
	currentDB string
	inflight  *inflightUnit
}

// pgxConfigFromFields 逐欄位組裝 pgx 設定。
//
// # 為什麼這裡出現 ParseConfig（唯一的例外）
//
// pgx 的 `pgconn.Config` 帶一個未匯出的 `createdByParseConfig` 旗標，
// `ConnectConfig` 在它為假時**直接 panic**（pgconn/pgconn.go:144）。
// 也就是說「自己造一個設定物件再連」在 pgx v5 上不是風格選擇，是做不到。
//
// 折衷是：以**空字串**呼叫 `ParseConfig` 取得一個帶旗標的預設設定，
// 其後每一個連線欄位都由我方覆寫。空字串裡沒有任何憑證，故
// 「程序內不存在 DSN 字串」這個不變式仍然成立——靜態守衛因此不是取消，
// 而是收窄成「ParseConfig 只能以空字串字面呼叫，且全套件僅此一處」。
//
// 另外清空 `Fallbacks`：`ParseConfig("")` 會讀 libpq 的環境變數，
// 而 `PGHOST` 帶多個主機時會生出備援目標。留著它，一次連線可能落到
// 我們沒有指定、也沒有過閘的主機上。
func pgxConfigFromFields(cfg Config, tlsSet tlsSettings) (*pgx.ConnConfig, error) {
	connCfg, err := pgx.ParseConfig("")
	if err != nil {
		return nil, fmt.Errorf("dbconsole: 取得 pgx 預設設定失敗: %w", err)
	}

	connCfg.Host = cfg.Host
	connCfg.Port = uint16(cfg.Port)
	connCfg.User = cfg.Username
	connCfg.Password = string(cfg.Password)
	connCfg.Database = cfg.Database
	connCfg.ConnectTimeout = ConnectTimeout
	connCfg.Fallbacks = nil
	connCfg.TLSConfig = nil
	if !tlsSet.isDefaultMode(cfg.TLSMode) && tlsSet.enabled {
		connCfg.TLSConfig = tlsSet.stdConfig(cfg.Host)
	}
	// 取消走 PostgreSQL 的帶外取消請求，而不是 pgx 的預設處置（直接對 socket 設
	// 期限，等同拉斷連線）。差別落在審計上：帶外取消會讓目標端回 SQLSTATE 57014，
	// 我方據此把結果記成 `cancelled`；拉斷連線則什麼也問不到，只能記
	// `effect_unknown`——而那兩者對稽核是完全不同的事實。
	//
	// **兩個 delay 必須顯式給值**：零值會讓 `HandleCancel` 立刻把 net.Conn 的期限
	// 設成「現在」，取消請求還沒送到伺服器連線就死了，於是每一次取消都退化成
	// `effect_unknown`。DeadlineDelay 是最後的保命索——伺服器對取消請求毫無反應時，
	// 它讓我方不會無限期地掛在一個永遠不返回的讀取上。
	connCfg.BuildContextWatcherHandler = func(pgConn *pgconn.PgConn) ctxwatch.Handler {
		return &pgconn.CancelRequestContextWatcherHandler{
			Conn:               pgConn,
			CancelRequestDelay: pgCancelRequestDelay,
			DeadlineDelay:      pgCancelDeadlineDelay,
		}
	}
	// 不用 statement cache：本路徑不走延伸協議，快取只是一個沒有讀者的結構
	connCfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	return connCfg, nil
}

func openPostgres(ctx context.Context, cfg Config) (Dialect, error) {
	tlsSet, err := resolveTLS(cfg.TLSMode, cfg.CACert)
	if err != nil {
		return nil, err
	}
	connCfg, err := pgxConfigFromFields(cfg, tlsSet)
	if err != nil {
		zeroBytes(cfg.Password)
		return nil, err
	}

	dialCtx, cancel := context.WithTimeout(ctx, ConnectTimeout)
	defer cancel()
	conn, err := pgx.ConnectConfig(dialCtx, connCfg)

	// 清零在 ConnectConfig 返回之後、無論成敗：我方持有的明文自此不再需要。
	// **driver 內部另有一份**（*pgx.Conn 保留一個 ConnConfig 直到 Close），
	// 那是我方清不掉的誠實邊界——我方不呼叫 Conn.Config()、不傳遞該指標
	connCfg.Password = ""
	zeroBytes(cfg.Password)

	if err != nil {
		return nil, err
	}

	d := &pgDialect{conn: conn, currentDB: cfg.Database}
	if d.currentDB == "" {
		// 資產沒填資料庫名時，實際連上的是伺服端的預設庫（通常同帳號名），
		// 而那個名字**只有目標端知道**：本路徑的設定物件是以空字串起手再逐欄
		// 覆寫的，Database 欄從頭到尾都是我方寫進去的值，不會被回填。
		// 問不到就留空——留空是「我們不知道當前庫」，猜一個名字進審計列
		// 則是一句可能是錯的話
		probeCtx, probeCancel := context.WithTimeout(ctx, ProbeTimeout)
		var name string
		if qErr := conn.QueryRow(probeCtx, "SELECT current_database()").Scan(&name); qErr == nil {
			d.currentDB = name
		}
		probeCancel()
	}
	return d, nil
}

func (d *pgDialect) CurrentDatabase() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.currentDB
}

func (d *pgDialect) Close() error {
	return d.conn.Close(context.Background())
}

// Switch PostgreSQL 沒有 `USE`：連線綁定資料庫。
//
// 本套件**不自行重撥**——重撥要重新解封憑證，而解封只能發生在呼叫端的閘序之後。
// 故本方法一律回 ErrSwitchRequiresReconnect，由呼叫端負責關閉本連線、重跑閘序、
// 以新的資料庫名再開一條。
func (d *pgDialect) Switch(_ context.Context, _ string) error {
	return ErrSwitchRequiresReconnect
}

// ErrSwitchRequiresReconnect PostgreSQL 的切庫必須由呼叫端重跑閘序後重新連線
var ErrSwitchRequiresReconnect = errors.New("dbconsole: PostgreSQL 切庫需要重新連線（重跑閘序後由呼叫端重開）")

func (d *pgDialect) ProbeState(ctx context.Context) (State, error) {
	st := State{Database: d.CurrentDatabase(), TxState: TxStateUnknown}
	// 交易態取自**協議層**而不是一句查詢：`PgConn().TxStatus()` 是伺服器在每一次
	// 回應尾端回報的狀態位元組，不必額外往返，也不會因為「查詢本身開了一個交易」
	// 而失真
	switch d.conn.PgConn().TxStatus() {
	case 'I':
		st.TxState = TxStateNone
	case 'T':
		st.TxState = TxStateActive
	case 'E':
		st.TxState = TxStateFailed
	}
	if ctx.Err() != nil {
		return st, ctx.Err()
	}
	return st, nil
}

func (d *pgDialect) Cancel(ctx context.Context) (bool, error) {
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
		return false, ctx.Err()
	}
}

func (d *pgDialect) beginUnit(parent context.Context) (context.Context, *inflightUnit, error) {
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

func (d *pgDialect) endUnit(unit *inflightUnit, confirmed bool) {
	d.mu.Lock()
	unit.confirmed = confirmed
	d.inflight = nil
	d.mu.Unlock()
	unit.cancel()
	close(unit.done)
}

func (d *pgDialect) Exec(parent context.Context, statement string) (*ExecOutcome, error) {
	ctx, unit, err := d.beginUnit(parent)
	if err != nil {
		return nil, err
	}
	out := d.execUnit(ctx, statement, newResultBuilder(MaxBytesPerSubmission))
	d.endUnit(unit, out.CancelConfirmed)
	return out, nil
}

func (d *pgDialect) execUnit(ctx context.Context, statement string, builder *resultBuilder) *ExecOutcome {
	out := &ExecOutcome{Status: StatusOK}
	pgConn := d.conn.PgConn()
	typeMap := d.conn.TypeMap()

	mrr := pgConn.Exec(ctx, statement)
	setIndex := 0
	// completed 目標端**回報過完成**的結果數（含無欄位的 DML）。
	// partial 的判定用它而不是「已讀到的列數」：讀到一半的列不代表目標端
	// 回報過那個語句完成，而 partial 記的正是「回報過完成」這個事實
	completed := 0
	var readErr error

	for mrr.NextResult() {
		rr := mrr.ResultReader()
		fields := rr.FieldDescriptions()

		var set *ResultSet
		if len(fields) > 0 {
			set = &ResultSet{SetIndex: setIndex, Columns: make([]ColumnMeta, 0, len(fields))}
			for _, f := range fields {
				typeName := strconv.FormatUint(uint64(f.DataTypeOID), 10)
				if t, ok := typeMap.TypeForOID(f.DataTypeOID); ok {
					typeName = t.Name
				}
				set.Columns = append(set.Columns, ColumnMeta{
					Name: f.Name, TypeName: typeName, Kind: KindOf(typeName),
				})
			}
		}

		for rr.NextRow() {
			if set == nil {
				continue
			}
			if builder.exhausted() {
				// 額度在上一列剛好用盡：這一列存在但不搬回來，
				// **列層與單位層都要標記**——只標其一的話，畫面上會有一個沒有橫幅的截斷結果
				builder.markTruncated("row_limit")
				set.Truncated = true
				break
			}
			raw := rr.Values()
			row := make([]*string, len(raw))
			for i := range raw {
				if raw[i] == nil {
					continue // SQL NULL
				}
				kind := KindOther
				if i < len(set.Columns) {
					kind = set.Columns[i].Kind
				}
				cell, cut := textifyCounted(raw[i], kind)
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

		tag, err := rr.Close()
		if err != nil {
			readErr = err
			if set != nil {
				set.RowCount = len(set.Rows)
				out.Sets = append(out.Sets, *set)
			}
			break
		}
		out.RowsAffected += tag.RowsAffected()
		completed++
		if set != nil {
			set.RowCount = len(set.Rows)
			out.Sets = append(out.Sets, *set)
			setIndex++
		}
	}
	if err := mrr.Close(); err != nil && readErr == nil {
		readErr = err
	}

	out.Truncated = builder.truncated
	st, probeErr := d.ProbeState(context.WithoutCancel(ctx))
	out.TxState = st.TxState
	// 探詢是我方在同一條連線上的一次往返：撞上連線層錯誤即「這條連線不能再用」。
	// 交易態取不到本身不使單位失敗（那是脈絡不是結果），但連線的死活要帶回去，
	// 否則呼叫端得等下一個單位撞上才知道
	if IsConnectionLost(probeErr) {
		out.ConnectionLost = true
	}
	if readErr != nil {
		return classifyPGError(ctx, out, readErr, completed > 0)
	}
	if builder.truncated && builder.reason == "cell" {
		out.Reason = ReasonCellTruncated
	}
	return out
}

// classifyPGError 與 sqlDialect.classifyUnitError 同一套判定序，
// 但取消確認的依據是 PostgreSQL 的 SQLSTATE 57014。
//
// **兩份實作不合併**：合併要把 pgx 與 database/sql 兩種錯誤形態塞進同一個函式，
// 而判定序本身（連線斷 → 取消／逾時 → partial → error）是共用的語義，
// 已由本檔與 sqlconn.go 的註解各自說明。分歧的風險由表驅動測試逐方言逐碼承接。
func classifyPGError(ctx context.Context, out *ExecOutcome, err error, hadResults bool) *ExecOutcome {
	timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded)
	cancelled := errors.Is(ctx.Err(), context.Canceled)
	confirmed := IsCancelConfirmed(ProtocolPostgres, err)

	switch {
	case timedOut && confirmed:
		out.Status = StatusTimeout
		out.Reason = ReasonTimeoutConfirmed
		out.CancelConfirmed = true
	case cancelled && confirmed:
		out.Status = StatusCancelled
		out.Reason = ReasonCancelConfirmed
		out.CancelConfirmed = true
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
	case timedOut:
		out.Status = StatusEffectUnknown
		out.Reason = ReasonTimeoutUnconfirmed
	case cancelled:
		out.Status = StatusEffectUnknown
		out.Reason = ReasonCancelUnconfirmed
	case hadResults:
		out.Status = StatusPartial
		out.Reason = ReasonErrorAfterResults
		out.DBError = DBErrorOf(ProtocolPostgres, err, true)
	default:
		out.Status = StatusError
		out.DBError = DBErrorOf(ProtocolPostgres, err, true)
	}
	if out.DBError == nil && out.Status == StatusError {
		out.DBError = &DBError{Message: err.Error()}
	}
	return out
}

// pgListDatabasesSQL 目錄查詢。
//
// `pg_database` 列出**全部**非樣板資料庫（含此帳號連不上的）；可連線旗標由
// `datallowconn` 與 `has_database_privilege` 判定——這正是「看得到但連不上」
// 要呈現的事實。旗標是預檢不是保證：主機端規則與連線數上限都在撥號時才會擋。
const pgListDatabasesSQL = `SELECT datname,
	(datallowconn AND has_database_privilege(current_user, datname, 'CONNECT')) AS connectable
	FROM pg_database WHERE NOT datistemplate ORDER BY datname`

const pgListTablesSQL = `SELECT table_schema, table_name,
	CASE WHEN table_type = 'VIEW' THEN 'view' ELSE 'table' END
	FROM information_schema.tables
	WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
	ORDER BY table_schema, table_name`

const pgListColumnsSQL = `SELECT column_name, data_type, is_nullable = 'YES'
	FROM information_schema.columns
	WHERE table_schema = $1 AND table_name = $2
	ORDER BY ordinal_position`

func (d *pgDialect) ListDatabases(ctx context.Context) ([]DatabaseInfo, error) {
	rows, err := d.conn.Query(ctx, pgListDatabasesSQL)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]DatabaseInfo, 0, 16)
	for rows.Next() {
		if len(out) >= MaxTreeNodesPerLevel {
			break
		}
		var info DatabaseInfo
		if err := rows.Scan(&info.Name, &info.Connectable); err != nil {
			return nil, err
		}
		out = append(out, info)
	}
	return out, rows.Err()
}

func (d *pgDialect) ListTables(ctx context.Context, schema string) ([]TableInfo, error) {
	rows, err := d.conn.Query(ctx, pgListTablesSQL)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]TableInfo, 0, 64)
	for rows.Next() {
		if len(out) >= MaxTreeNodesPerLevel {
			break
		}
		var t TableInfo
		if err := rows.Scan(&t.Schema, &t.Name, &t.Kind); err != nil {
			return nil, err
		}
		if schema != "" && t.Schema != schema {
			continue
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (d *pgDialect) ListColumns(ctx context.Context, schema, table string) ([]ColumnInfo, error) {
	rows, err := d.conn.Query(ctx, pgListColumnsSQL, schema, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]ColumnInfo, 0, 32)
	for rows.Next() {
		if len(out) >= MaxTreeNodesPerLevel {
			break
		}
		var c ColumnInfo
		if err := rows.Scan(&c.Name, &c.TypeName, &c.Nullable); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
