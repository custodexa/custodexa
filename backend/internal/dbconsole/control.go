package dbconsole

import (
	"context"
	"database/sql"
	"fmt"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	mssql "github.com/microsoft/go-mssqldb"
)

// ControlAppName 改密控制連線在目標端顯示的連線識別名（SQL Server 的應用程式名稱、
// PostgreSQL 的 application_name、MySQL 連線屬性 program_name）。與主控台不同名，
// 讓目標端分得出改密連線與查詢主控台。
const ControlAppName = "custodexa-credential-rotation"

// ControlConn 改密用的窄連線：只有單列查詢、單句執行與關閉。
//
// 與主控台的 Dialect 刻意分開：主控台要多語句、結果分類與取消語義，改密只要一句
// 一句送、讀一列字串。MySQL 關閉多語句，送進來的整段文字只能是一句。
type ControlConn interface {
	// QueryRow 執行查詢並以文字形式回傳第一列各欄（NULL 為空字串）；沒有列時回錯誤。
	QueryRow(ctx context.Context, query string, args ...any) ([]string, error)
	// Exec 執行一句不回結果集的語句。args 只有 SQL Server 走具名參數（RPC）使用。
	Exec(ctx context.Context, query string, args ...any) error
	Close() error
}

// ErrControlNoRows 單列查詢沒有回任何列
var ErrControlNoRows = fmt.Errorf("dbconsole: 控制連線查詢沒有回傳列")

// OpenControl 建立一條改密控制連線。
//
// 密碼所有權與 Open 相同：`cfg.Password` 在本函式返回時已被覆寫為零，呼叫端須交副本。
// 原始 driver 錯誤原樣回傳，分類由呼叫端以 ClassifyConnect／IsConnectionLost 做。
func OpenControl(ctx context.Context, cfg Config) (ControlConn, error) {
	if !cfg.Protocol.Supported() {
		zeroBytes(cfg.Password)
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedProtocol, cfg.Protocol)
	}
	tlsSet, err := resolveTLS(cfg.TLSMode, cfg.CACert)
	if err != nil {
		zeroBytes(cfg.Password)
		return nil, err
	}
	switch cfg.Protocol {
	case ProtocolMySQL:
		return openMySQLControl(ctx, cfg, tlsSet)
	case ProtocolMSSQL:
		return openMSSQLControl(ctx, cfg, tlsSet)
	default:
		return openPostgresControl(ctx, cfg, tlsSet)
	}
}

// mysqlControlConfig 主控台設定收窄成改密用：關多語句、關客戶端插值、標連線識別名。
func mysqlControlConfig(cfg Config, tlsSet tlsSettings) *mysqldriver.Config {
	driverCfg := mysqlDriverConfig(cfg, tlsSet)
	driverCfg.MultiStatements = false
	driverCfg.InterpolateParams = false
	driverCfg.ConnectionAttributes = "program_name:" + ControlAppName
	return driverCfg
}

// pgxControlConfig 主控台設定加上連線識別名。改密語句的密碼位置不能綁定參數，
// 一律以簡單查詢協議送整句。
func pgxControlConfig(cfg Config, tlsSet tlsSettings) (*pgx.ConnConfig, error) {
	connCfg, err := pgxConfigFromFields(cfg, tlsSet)
	if err != nil {
		return nil, err
	}
	if connCfg.RuntimeParams == nil {
		connCfg.RuntimeParams = map[string]string{}
	}
	connCfg.RuntimeParams["application_name"] = ControlAppName
	return connCfg, nil
}

func openMySQLControl(ctx context.Context, cfg Config, tlsSet tlsSettings) (ControlConn, error) {
	driverCfg := mysqlControlConfig(cfg, tlsSet)
	connector, err := mysqldriver.NewConnector(driverCfg)
	if err != nil {
		zeroConfig(&driverCfg.Passwd, cfg.Password)
		return nil, fmt.Errorf("dbconsole: 組裝 mysql 控制連線失敗: %w", err)
	}
	oneShot := newOneShotConnector(connector, func() { zeroConfig(&driverCfg.Passwd, cfg.Password) })
	return pinControl(ctx, sql.OpenDB(oneShot), func() { zeroConfig(&driverCfg.Passwd, cfg.Password) })
}

func openMSSQLControl(ctx context.Context, cfg Config, tlsSet tlsSettings) (ControlConn, error) {
	driverCfg, err := mssqlDriverConfig(cfg, tlsSet, ControlAppName)
	if err != nil {
		zeroConfig(&driverCfg.Password, cfg.Password)
		return nil, err
	}
	connector := mssql.NewConnectorConfig(driverCfg)
	oneShot := newOneShotConnector(connector, func() { zeroConfig(&driverCfg.Password, cfg.Password) })
	return pinControl(ctx, sql.OpenDB(oneShot), func() { zeroConfig(&driverCfg.Password, cfg.Password) })
}

func pinControl(ctx context.Context, db *sql.DB, zero func()) (ControlConn, error) {
	conn, err := pinSingleConnection(ctx, db)
	// 成功時一次性 connector 已清零；失敗時也要清，不留任何一條路徑帶著明文
	zero()
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &sqlControl{db: db, conn: conn}, nil
}

func openPostgresControl(ctx context.Context, cfg Config, tlsSet tlsSettings) (ControlConn, error) {
	connCfg, err := pgxControlConfig(cfg, tlsSet)
	if err != nil {
		zeroBytes(cfg.Password)
		return nil, err
	}
	dialCtx, cancel := context.WithTimeout(ctx, ConnectTimeout)
	defer cancel()
	conn, err := pgx.ConnectConfig(dialCtx, connCfg)
	connCfg.Password = ""
	zeroBytes(cfg.Password)
	if err != nil {
		return nil, err
	}
	return &pgControl{conn: conn}, nil
}

// sqlControl MySQL 與 SQL Server 的控制連線（database/sql 單一釘選連線）。
type sqlControl struct {
	db   *sql.DB
	conn *sql.Conn
}

func (c *sqlControl) QueryRow(ctx context.Context, query string, args ...any) ([]string, error) {
	rows, err := c.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return nil, ErrControlNoRows
	}
	vals := make([]sql.NullString, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	if err := rows.Scan(ptrs...); err != nil {
		return nil, err
	}
	out := make([]string, len(cols))
	for i, v := range vals {
		out[i] = v.String
	}
	return out, rows.Err()
}

func (c *sqlControl) Exec(ctx context.Context, query string, args ...any) error {
	_, err := c.conn.ExecContext(ctx, query, args...)
	return err
}

func (c *sqlControl) Close() error {
	cerr := c.conn.Close()
	if err := c.db.Close(); err != nil {
		return err
	}
	return cerr
}

// pgControl PostgreSQL 的控制連線（簡單查詢協議，見 pgxConfigFromFields）。
type pgControl struct {
	conn *pgx.Conn
}

func (c *pgControl) QueryRow(ctx context.Context, query string, args ...any) ([]string, error) {
	rows, err := c.conn.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return nil, ErrControlNoRows
	}
	raw := rows.RawValues()
	out := make([]string, len(raw))
	for i, v := range raw {
		out[i] = string(v)
	}
	return out, rows.Err()
}

func (c *pgControl) Exec(ctx context.Context, query string, args ...any) error {
	_, err := c.conn.Exec(ctx, query, args...)
	return err
}

func (c *pgControl) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), ConnectTimeout)
	defer cancel()
	return c.conn.Close(ctx)
}
