package dbconsole

import "context"

// MySQL 與 MSSQL 的目錄查詢（PostgreSQL 走 pgx，實作在 postgres.go）。
//
// 每一層都在 MaxTreeNodesPerLevel 處截斷：一個有數萬張表的目標端能把樹的一次
// 展開變成幾十 MB 的訊息，而使用者在畫面上根本捲不到第兩千筆。
// 截斷是回傳上限——目錄本身沒有變少，介面明示即可。

func (d *sqlDialect) ListDatabases(ctx context.Context) ([]DatabaseInfo, error) {
	switch d.proto {
	case ProtocolMySQL:
		return mysqlListDatabases(ctx, d.conn)
	case ProtocolMSSQL:
		return scanDatabaseInfos(ctx, d.conn, mssqlListDatabasesSQL)
	}
	return nil, nil
}

func (d *sqlDialect) ListTables(ctx context.Context, schema string) ([]TableInfo, error) {
	rows, err := d.conn.QueryContext(ctx, d.meta.listTablesSQL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := make([]TableInfo, 0, 64)
	for rows.Next() {
		if len(out) >= MaxTreeNodesPerLevel {
			break
		}
		var t TableInfo
		if err := rows.Scan(&t.Schema, &t.Name, &t.Kind); err != nil {
			return nil, err
		}
		// schema 過濾在我方而非查詢內：MySQL 的 schema 就是資料庫本身
		// （查詢已用 DATABASE() 綁住），多帶一個參數只會讓兩個方言的查詢形狀分岔
		if schema != "" && t.Schema != schema {
			continue
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (d *sqlDialect) ListColumns(ctx context.Context, schema, table string) ([]ColumnInfo, error) {
	args := []any{table}
	if d.proto == ProtocolMSSQL {
		// MSSQL 的表名在 schema 之下才唯一（dbo.users 與 app.users 是兩張表），
		// 故必須兩個鍵一起帶；MySQL 的「schema」就是當前資料庫，查詢已綁住
		args = []any{schema, table}
	}
	rows, err := d.conn.QueryContext(ctx, d.meta.listColumnsSQL, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

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
