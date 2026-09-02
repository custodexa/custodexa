package dbconsole

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strconv"

	mysqldriver "github.com/go-sql-driver/mysql"
)

// MySQL 方言。
//
// # 設定物件逐欄位組裝
//
// `mysql.NewConfig()` 給預設值，其餘欄位逐一指派——**不呼叫 ParseDSN，也不以
// 字串組出 `user:pass@tcp(host)/db`**。DSN 一旦成形就會被複製、被記錄、被印進
// 錯誤訊息，而它整條都是憑證。
//
// # 取消即斷線（誠實邊界）
//
// go-sql-driver 的 ctx 取消實作是**關閉連線**，沒有辦法在保留連線的前提下中止
// 一句進行中的語句。故 MySQL 的取消一律「未獲確認」，該單位記 effect_unknown，
// 而本會話的目標連線就此終止（不重撥）。
// 替代方案是另開一條連線送 `KILL QUERY`——那需要 PROCESS 權限，
// 且等於替使用者執行一條他沒有下的語句。

func openMySQL(ctx context.Context, cfg Config) (Dialect, error) {
	tlsSet, err := resolveTLS(cfg.TLSMode, cfg.CACert)
	if err != nil {
		return nil, err
	}

	driverCfg := mysqldriver.NewConfig()
	driverCfg.Net = "tcp"
	driverCfg.Addr = net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	driverCfg.User = cfg.Username
	driverCfg.Passwd = string(cfg.Password)
	driverCfg.DBName = cfg.Database
	driverCfg.Timeout = ConnectTimeout
	driverCfg.AllowNativePasswords = true
	driverCfg.CheckConnLiveness = true
	// 一次送出可含多個語句：這是主控台的執行單位語義（送出的文字原文逐位元組送出，
	// 我方不切分）。**同時也是 partial 狀態存在的理由**——多語句單位裡前面幾句
	// 成功、後面某句失敗，是一個真實且必須誠實記錄的結果
	driverCfg.MultiStatements = true
	// 時間值不轉成 time.Time：轉了就要決定時區與精度，而那兩個決定會讓同一筆資料
	// 在主控台與命令列上長得不一樣。保持 driver 的文字原文
	driverCfg.ParseTime = false
	// 不做客戶端參數插值：本路徑沒有參數化查詢，開著只是多一條字串組裝路徑
	driverCfg.InterpolateParams = false
	if !tlsSet.isDefaultMode(cfg.TLSMode) {
		// TLS 設定直接掛在 Config.TLS 上，**不走 driver 的具名全域註冊表**：
		// 全域註冊表要有人負責取消註冊，而取消註冊失敗的路徑是行程崩潰時
		driverCfg.TLS = tlsSet.stdConfig(cfg.Host)
	}

	connector, err := mysqldriver.NewConnector(driverCfg)
	if err != nil {
		zeroConfig(&driverCfg.Passwd, cfg.Password)
		return nil, fmt.Errorf("dbconsole: 組裝 mysql connector 失敗: %w", err)
	}

	oneShot := newOneShotConnector(connector, func() {
		zeroConfig(&driverCfg.Passwd, cfg.Password)
	})
	db := sql.OpenDB(oneShot)

	conn, err := pinSingleConnection(ctx, db)
	if err != nil {
		zeroConfig(&driverCfg.Passwd, cfg.Password)
		_ = db.Close()
		return nil, err
	}

	d := &sqlDialect{
		proto:     ProtocolMySQL,
		db:        db,
		conn:      conn,
		connector: oneShot,
		currentDB: cfg.Database,
		meta: dialectMeta{
			// 三件事一次問完。交易態恆為 unknown——MySQL 沒有失敗交易態，
			// 而探詢「有沒有進行中的交易」要讀 innodb_trx，那需要 PROCESS 權限
			probeSQL: "SELECT DATABASE(), 'unknown', ROW_COUNT()",
			useSQL:   "USE %s",
			listTablesSQL: `SELECT TABLE_SCHEMA, TABLE_NAME,
				CASE WHEN TABLE_TYPE = 'VIEW' THEN 'view' ELSE 'table' END
				FROM information_schema.TABLES
				WHERE TABLE_SCHEMA = DATABASE()
				ORDER BY TABLE_NAME`,
			listColumnsSQL: `SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE = 'YES'
				FROM information_schema.COLUMNS
				WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?
				ORDER BY ORDINAL_POSITION`,
		},
	}
	// 起始庫可能來自伺服器預設（cfg.Database 為空）：問一次才知道自己在哪
	if st, _, probeErr := d.probe(ctx); probeErr == nil && st.Database != "" {
		d.currentDB = st.Database
	}
	return d, nil
}

// zeroConfig 清除我方持有的全部明文副本。
//
// `driverCfg.Passwd` 是字串、無法就地清零，只能丟棄引用（driver 內部另有一份
// 拷貝，存活至 Close——那是誠實邊界，不是我方可以清的東西）；
// `cfg.Password` 是我方的 []byte，就地覆寫為零。
func zeroConfig(passwd *string, raw []byte) {
	*passwd = ""
	zeroBytes(raw)
}

// mysqlListDatabases MySQL 的目錄查詢。
//
// **可連線旗標恆為真**：`SHOW DATABASES` 已由伺服器依權限過濾，
// 列出來的就是這個帳號看得到的。MySQL 沒有第二層資訊可以回答「看得到但連不上」，
// 硬造一個旗標只會是憑空的斷言。
func mysqlListDatabases(ctx context.Context, conn *sql.Conn) ([]DatabaseInfo, error) {
	rows, err := conn.QueryContext(ctx, "SHOW DATABASES")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := make([]DatabaseInfo, 0, 16)
	for rows.Next() {
		if len(out) >= MaxTreeNodesPerLevel {
			break
		}
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, DatabaseInfo{Name: name, Connectable: true})
	}
	return out, rows.Err()
}
