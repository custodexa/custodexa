package dbconsole

import (
	"context"
	"database/sql"
	"fmt"

	mssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"
)

// MSSQL 方言。
//
// # 設定物件逐欄位組裝
//
// `msdsn.Config` 的每一欄逐一指派——**不呼叫 msdsn.Parse，也不組任何
// `sqlserver://` 或 ODBC 形態的連線字串**。
//
// # 取消保留連線
//
// go-mssqldb 的 ctx 取消送 Attention 封包，目標端確認後連線仍在。故 MSSQL 的
// 取消**可能**獲得確認（狀態 cancelled），與 MySQL 相反。
//
// # 執行單位＝批次
//
// T-SQL 的執行單位是批次，以獨立一行的 `GO` 送出（切分見 batch.go）。
// 一次送出可含多個批次，每個批次各有事件 ID 與審計列；第一個失敗即停止後續，
// 未送出的批次記為 cancelled／batch_stopped。

func openMSSQL(ctx context.Context, cfg Config) (Dialect, error) {
	tlsSet, err := resolveTLS(cfg.TLSMode, cfg.CACert)
	if err != nil {
		return nil, err
	}

	driverCfg := msdsn.Config{
		Host:     cfg.Host,
		Port:     uint64(cfg.Port),
		User:     cfg.Username,
		Password: string(cfg.Password),
		Database: cfg.Database,
		// 只走 TCP：其餘協議（named pipe、shared memory）在容器化的目標上
		// 不可達，留著只是多一條會拖長連線失敗時間的嘗試
		Protocols:   []string{"tcp"},
		DialTimeout: ConnectTimeout,
		// 關閉 database/sql 在壞連線上的自動重試：那正是「不重撥」要擋的東西。
		// 開著的話，一次因連線中斷而失敗的執行會被 database/sql 悄悄重跑一次，
		// 而重跑一條 DML 是使用者沒有要求的第二次生效
		DisableRetry: true,
		AppName:      "custodexa-db-console",
	}

	switch {
	case cfg.TLSMode == TLSModeDefault:
		// 沿 driver 預設：加密登入封包、其後依伺服器協商，**且信任伺服器憑證**。
		//
		// 這一段必須顯式做，不能靠留白：driver 的那份預設是連線字串解析路徑
		// 給的（未指定加密參數時即信任伺服器憑證），而本路徑逐欄位組裝、
		// 從不解析連線字串，留白的結果是連線時退回一套帶完整主機名核對的設定
		// ——比 driver 自己的預設嚴。自簽憑證是這個目標端的出廠狀態，
		// 於是同一台資產在命令列連得上、在主控台連不上，而使用者什麼也沒改。
		// 要更嚴的傳輸保證有專屬檔位（require／verify-ca／verify-full）
		stdCfg, tlsErr := msdsn.SetupTLS("", "", true, cfg.Host, "")
		if tlsErr != nil {
			return nil, fmt.Errorf("dbconsole: mssql 預設 TLS 設定失敗: %w", tlsErr)
		}
		driverCfg.TLSConfig = stdCfg
	case !tlsSet.enabled:
		driverCfg.Encryption = msdsn.EncryptionDisabled
	default:
		driverCfg.Encryption = msdsn.EncryptionRequired
		driverCfg.TLSConfig = tlsSet.stdConfig(cfg.Host)
	}

	connector := mssql.NewConnectorConfig(driverCfg)
	oneShot := newOneShotConnector(connector, func() {
		zeroConfig(&driverCfg.Password, cfg.Password)
	})
	db := sql.OpenDB(oneShot)

	conn, err := pinSingleConnection(ctx, db)
	if err != nil {
		zeroConfig(&driverCfg.Password, cfg.Password)
		_ = db.Close()
		return nil, fmt.Errorf("dbconsole: 連線 mssql 失敗: %w", err)
	}

	d := &sqlDialect{
		proto:     ProtocolMSSQL,
		db:        db,
		conn:      conn,
		connector: oneShot,
		currentDB: cfg.Database,
		meta: dialectMeta{
			// 當前庫、交易態、影響列數三件事一次問完。
			// `@@ROWCOUNT` 回報的是上一句語句的列數，故本句必須緊接在單位之後。
			//
			// **有沒有交易以 `@@TRANCOUNT` 判**：探詢是獨立的一次往返，
			// 而 `XACT_STATE()` 在該脈絡下實測恆回 1（連 `@@TRANCOUNT` 為 0 時
			// 也是），拿它判「有交易」會讓每一場會話的每一列都標成交易進行中，
			// 連帶每場都生出一筆「結束時交易還開著」的假事件。
			// `XACT_STATE()` 只留著認 -1 的不可提交態——它是這個值域裡
			// `@@TRANCOUNT` 答不出來的那一格。
			// 實測記載：不可提交態在本路徑上觀察不到，目標端在**批次結束時**
			// 就把不可提交的交易回滾掉（並回報 3998），而探詢是下一次往返，
			// 看到的因此是回滾之後的狀態。這一格留著是為了它一旦浮出來時
			// 有正確的落點，不是宣稱它到得了
			probeSQL: `SELECT DB_NAME(),
				CASE WHEN XACT_STATE() = -1 THEN 'failed'
					WHEN @@TRANCOUNT > 0 THEN 'active' ELSE 'none' END,
				@@ROWCOUNT`,
			useSQL: "USE %s",
			listTablesSQL: `SELECT TABLE_SCHEMA, TABLE_NAME,
				CASE WHEN TABLE_TYPE = 'VIEW' THEN 'view' ELSE 'table' END
				FROM INFORMATION_SCHEMA.TABLES
				ORDER BY TABLE_SCHEMA, TABLE_NAME`,
			listColumnsSQL: `SELECT COLUMN_NAME, DATA_TYPE,
				CASE WHEN IS_NULLABLE = 'YES' THEN 1 ELSE 0 END
				FROM INFORMATION_SCHEMA.COLUMNS
				WHERE TABLE_SCHEMA = @p1 AND TABLE_NAME = @p2
				ORDER BY ORDINAL_POSITION`,
		},
	}
	if st, _, probeErr := d.probe(ctx); probeErr == nil && st.Database != "" {
		d.currentDB = st.Database
	}
	return d, nil
}

// mssqlListDatabases MSSQL 的目錄查詢。
//
// `sys.databases` 列出**全部**資料庫（含此帳號連不上的），可連線旗標另由
// `state_desc = 'ONLINE'` 與 `HAS_DBACCESS` 判定——這正是「看得到但連不上」
// 要呈現的事實。`HAS_DBACCESS` 對離線的庫回 NULL，故套 ISNULL 收成 0。
//
// 旗標是**預檢不是保證**：真的連下去仍可能因連線數上限或剛剛才離線而失敗。
const mssqlListDatabasesSQL = `SELECT name,
	CASE WHEN state_desc = 'ONLINE' AND ISNULL(HAS_DBACCESS(name), 0) = 1 THEN 1 ELSE 0 END
	FROM sys.databases ORDER BY name`

// scanDatabaseInfos 讀 (name, connectable) 兩欄的目錄查詢
func scanDatabaseInfos(ctx context.Context, conn *sql.Conn, query string) ([]DatabaseInfo, error) {
	rows, err := conn.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

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
