package dbconsole

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/testgate"
)

// 對真實目標端的整合測試。
//
// 單元測試以 stub driver 證明的是**我方的判定邏輯**：狀態怎麼分類、額度怎麼扣、
// 錯誤怎麼歸類。它證明不了的是另一半——目標端到底回什麼。三個方言的取消語義、
// 交易態表達、多結果集的邊界、目錄查詢的欄位，全部是目標端的行為，
// 只有連上去才會知道我方的假設是不是還成立（driver 升版、伺服器換版本皆可能改變）。
//
// gating：三個座標變數各自獨立，未設即 skip；`REQUIRE_INTEGRATION=1` 時 skip 轉 fail。
//
// 跑法（compose 內，靶機須先 up）：
//
//	docker compose exec -T backend sh -c '
//	  TEST_DBCONSOLE_MYSQL="mysql-test|3306|root|testpass123|testdb" \
//	  TEST_DBCONSOLE_POSTGRES="postgres|5432|postgres|postgres|postgres" \
//	  TEST_DBCONSOLE_MSSQL="mssql-test|1433|sa|Testpass123!|master" \
//	  REQUIRE_INTEGRATION=1 go test ./internal/dbconsole -run Integration -v'

// targetSpec 五段式座標。刻意逐欄位拆開後才交給 Config——
// 測試與產品走同一條「不存在連線字串」的路
func targetSpec(t *testing.T, proto Protocol, env string) Config {
	t.Helper()
	raw := testgate.Value(t, env)
	parts := strings.Split(raw, "|")
	if len(parts) != 5 {
		t.Fatalf("%s 的值需為 host|port|user|password|database 五段，實得 %d 段", env, len(parts))
	}
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		t.Fatalf("%s 的埠 %q 非數字: %v", env, parts[1], err)
	}
	return Config{
		Protocol: proto,
		Host:     parts[0],
		Port:     port,
		Username: parts[2],
		Password: []byte(parts[3]),
		Database: parts[4],
	}
}

func openTarget(t *testing.T, proto Protocol, env string) Dialect {
	t.Helper()
	cfg := targetSpec(t, proto, env)
	ctx, cancel := context.WithTimeout(context.Background(), ConnectTimeout)
	defer cancel()
	d, err := Open(ctx, cfg)
	if err != nil {
		t.Fatalf("連線 %s 靶機失敗: %v", proto, err)
	}
	t.Cleanup(func() { _ = d.Close() })
	// 密碼所有權已移交：Open 返回後我方那份必須是零
	for i, b := range cfg.Password {
		if b != 0 {
			t.Fatalf("Open 返回後 cfg.Password[%d] = %d，明文未清零", i, b)
		}
	}
	return d
}

func execOK(t *testing.T, d Dialect, sql string) *ExecOutcome {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), StatementTimeout)
	defer cancel()
	out, err := d.Exec(ctx, sql)
	if err != nil {
		t.Fatalf("送出失敗（連本地都沒送出去）: %v", err)
	}
	if out.Status != StatusOK {
		t.Fatalf("狀態 = %s/%s，want ok；錯誤 = %+v", out.Status, out.Reason, out.DBError)
	}
	return out
}

// --- 逐方言的共同面 -------------------------------------------------------

// dialectCase 三個方言各自的語法差異。共同的斷言只寫一次——
// 三份複製貼上的測試會在某一份被改壞時靜默失去對照
type dialectCase struct {
	name        string
	proto       Protocol
	env         string
	syntaxError string
	// bigRows 產生 2000 列的查詢（用來撞 MaxRowsPerUnit＝1000）
	bigRows string
	// wideCell 產生一個超過 MaxCellBytes 的單欄值
	wideCell string
	// beginTx 開一個交易；failTx 在交易內製造錯誤
	beginTx string
	failTx  string
	// 目錄查詢是否帶「看得到但連不上」的第二層資訊
	hasConnectableFlag bool
}

func dialectCases() []dialectCase {
	return []dialectCase{
		{
			name:  "mysql",
			proto: ProtocolMySQL,
			env:   testgate.EnvDBConsoleMySQL,
			// 語法錯誤的原文須原樣回到使用者手上——那是他自己的產品內容
			syntaxError: "SELEKT 1",
			// 不用遞迴 CTE：MySQL 的 cte_max_recursion_depth 預設 1000，
			// 剛好在本測試要撞的上限之下，測到的會是伺服器設定而不是我方的額度
			bigRows:            "SELECT ROW_NUMBER() OVER () AS n FROM information_schema.COLUMNS LIMIT 2000",
			wideCell:           "SELECT REPEAT('x', 70000) AS wide",
			beginTx:            "BEGIN",
			failTx:             "SELECT * FROM no_such_table_here",
			hasConnectableFlag: false,
		},
		{
			name:               "postgres",
			proto:              ProtocolPostgres,
			env:                testgate.EnvDBConsolePostgres,
			syntaxError:        "SELEKT 1",
			bigRows:            "SELECT g FROM generate_series(1, 2000) AS g",
			wideCell:           "SELECT repeat('x', 70000) AS wide",
			beginTx:            "BEGIN",
			failTx:             "SELECT * FROM no_such_table_here",
			hasConnectableFlag: true,
		},
		{
			name:               "mssql",
			proto:              ProtocolMSSQL,
			env:                testgate.EnvDBConsoleMSSQL,
			syntaxError:        "SELEKT 1",
			bigRows:            "SELECT TOP 2000 ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS n FROM sys.all_objects a CROSS JOIN sys.all_objects b",
			wideCell:           "SELECT REPLICATE(CAST('x' AS varchar(max)), 70000) AS wide",
			beginTx:            "BEGIN TRANSACTION",
			failTx:             "SELECT * FROM no_such_table_here",
			hasConnectableFlag: true,
		},
	}
}

// TestIntegrationCatalogListing 目錄三層與可連線旗標
func TestIntegrationCatalogListing(t *testing.T) {
	for _, tc := range dialectCases() {
		t.Run(tc.name, func(t *testing.T) {
			d := openTarget(t, tc.proto, tc.env)
			ctx := context.Background()

			dbs, err := d.ListDatabases(ctx)
			if err != nil {
				t.Fatalf("列庫失敗: %v", err)
			}
			if len(dbs) == 0 {
				t.Fatal("列庫回空：帳號至少看得到自己所在的庫")
			}
			if !tc.hasConnectableFlag {
				// MySQL 沒有第二層資訊，旗標恆真——若哪天變成有假值，
				// 代表有人憑空造了一個斷言
				for _, db := range dbs {
					if !db.Connectable {
						t.Errorf("%s 的 %s 回報不可連線，但本方言沒有第二層資訊可據", tc.name, db.Name)
					}
				}
			}

			if _, err := d.ListTables(ctx, ""); err != nil {
				t.Fatalf("列表失敗: %v", err)
			}
			t.Logf("%s：%d 個資料庫", tc.name, len(dbs))
		})
	}
}

// TestIntegrationSwitchDatabase 切庫後當前庫確實改變（PG 走重連、其餘走 USE）
func TestIntegrationSwitchDatabase(t *testing.T) {
	for _, tc := range dialectCases() {
		t.Run(tc.name, func(t *testing.T) {
			d := openTarget(t, tc.proto, tc.env)
			ctx := context.Background()

			dbs, err := d.ListDatabases(ctx)
			if err != nil {
				t.Fatalf("列庫失敗: %v", err)
			}
			current := d.CurrentDatabase()
			var target string
			for _, db := range dbs {
				if db.Connectable && db.Name != current {
					target = db.Name
					break
				}
			}
			if target == "" {
				t.Skipf("%s 靶機上沒有第二個可連線的庫，無從切", tc.name)
			}

			// PostgreSQL 的連線綁定資料庫，沒有 USE。本套件不自行重撥
			//（重撥要重新解封憑證，而解封只能發生在呼叫端的閘序之後），
			// 故它的正確行為就是回這支哨兵錯誤，而不是切成功
			if tc.proto == ProtocolPostgres {
				if !errors.Is(d.Switch(ctx, target), ErrSwitchRequiresReconnect) {
					t.Error("PostgreSQL 的 Switch 未回 ErrSwitchRequiresReconnect：" +
						"呼叫端會以為切庫已完成，而連線其實還在原本的庫上")
				}
				if got := d.CurrentDatabase(); got != current {
					t.Errorf("切庫被拒後當前庫變成 %q, want 維持 %q", got, current)
				}
				return
			}

			if err := d.Switch(ctx, target); err != nil {
				t.Fatalf("切到 %s 失敗: %v", target, err)
			}
			if got := d.CurrentDatabase(); got != target {
				t.Errorf("我方記錄的當前庫 = %q, want %q", got, target)
			}
			// 我方記錄的與目標端認定的必須一致——不一致時，其後每一筆審計列的
			// 目標庫都是錯的，而那個錯誤沒有任何症狀
			st, err := d.ProbeState(ctx)
			if err != nil {
				t.Fatalf("探詢失敗: %v", err)
			}
			if st.Database != target {
				t.Errorf("目標端回報的當前庫 = %q, want %q", st.Database, target)
			}
		})
	}
}

// TestIntegrationRowLimitTruncates 列上限對真實結果集成立
func TestIntegrationRowLimitTruncates(t *testing.T) {
	for _, tc := range dialectCases() {
		t.Run(tc.name, func(t *testing.T) {
			d := openTarget(t, tc.proto, tc.env)
			out := execOK(t, d, tc.bigRows)
			if len(out.Sets) != 1 {
				t.Fatalf("結果集數 = %d, want 1", len(out.Sets))
			}
			set := out.Sets[0]
			if set.RowCount != MaxRowsPerUnit {
				t.Errorf("回傳列數 = %d, want %d", set.RowCount, MaxRowsPerUnit)
			}
			if !set.Truncated || !out.Truncated {
				t.Error("列數達上限但未標記截斷：畫面會把「這是全部」說成事實")
			}
		})
	}
}

// TestIntegrationCellTruncation 單欄上限與其原因碼
func TestIntegrationCellTruncation(t *testing.T) {
	for _, tc := range dialectCases() {
		t.Run(tc.name, func(t *testing.T) {
			d := openTarget(t, tc.proto, tc.env)
			out := execOK(t, d, tc.wideCell)
			if len(out.Sets) != 1 || len(out.Sets[0].Rows) != 1 {
				t.Fatalf("結果形狀不符：%d 個結果集", len(out.Sets))
			}
			cell := out.Sets[0].Rows[0][0]
			if cell == nil {
				t.Fatal("單欄值為 NULL，want 截斷後的文字")
			}
			if len(*cell) > MaxCellBytes+64 {
				t.Errorf("單欄長度 = %d，超過上限 %d 甚多：截斷未生效", len(*cell), MaxCellBytes)
			}
			if !out.Truncated {
				t.Error("單欄被截斷但 outcome 未標記截斷")
			}
		})
	}
}

// TestIntegrationSyntaxErrorKeepsOriginalMessage 語法錯誤的原文與碼都要回到使用者手上
func TestIntegrationSyntaxErrorKeepsOriginalMessage(t *testing.T) {
	for _, tc := range dialectCases() {
		t.Run(tc.name, func(t *testing.T) {
			d := openTarget(t, tc.proto, tc.env)
			ctx, cancel := context.WithTimeout(context.Background(), StatementTimeout)
			defer cancel()

			out, err := d.Exec(ctx, tc.syntaxError)
			if err != nil {
				t.Fatalf("送出失敗: %v", err)
			}
			if out.Status != StatusError {
				t.Fatalf("狀態 = %s, want error", out.Status)
			}
			if out.DBError == nil {
				t.Fatal("錯誤結果沒有 DBError：使用者拿不到目標端說了什麼")
			}
			if out.DBError.Code == "" {
				t.Error("DBError.Code 為空")
			}
			if out.DBError.Message == "" {
				t.Error("已建連線上的 SQL 層錯誤必須帶原文訊息")
			}
			// 語句寫錯不使連線失效。判成失效的代價是會話被收線，
			// 而使用者看到的只是「打錯一個字就斷線」
			if out.ConnectionLost {
				t.Errorf("%s 語法錯誤被判定為連線已失", tc.name)
			}
			t.Logf("%s 語法錯誤：code=%s message=%s", tc.name, out.DBError.Code, out.DBError.Message)
		})
	}
}

// TestIntegrationTxStateAfterUnit 交易態探詢。
//
// MySQL 恆 unknown（沒有可讀的交易態），PG／MSSQL 則要看得到 active 與 failed 兩態——
// failed 那一格是稽核判讀「這筆 ok 落在一個注定回滾的交易裡」的唯一依據
func TestIntegrationTxStateAfterUnit(t *testing.T) {
	for _, tc := range dialectCases() {
		t.Run(tc.name, func(t *testing.T) {
			d := openTarget(t, tc.proto, tc.env)

			// 交易開始之前：沒有交易就是沒有交易。標成進行中的代價不只是顯示不準，
			// 每一場會話都會在結束時多出一筆「交易還開著」的事實陳述，
			// 而該事件的價值全在於它罕見
			idle := execOK(t, d, "SELECT 1")
			switch tc.proto {
			case ProtocolMySQL:
				if idle.TxState != TxStateUnknown {
					t.Errorf("MySQL 交易態 = %q, want unknown", idle.TxState)
				}
			default:
				if idle.TxState != TxStateNone {
					t.Errorf("%s 未開交易時交易態 = %q, want none", tc.name, idle.TxState)
				}
			}

			begun := execOK(t, d, tc.beginTx)
			if tc.proto == ProtocolMySQL {
				if begun.TxState != TxStateUnknown {
					t.Errorf("MySQL 交易態 = %q, want unknown", begun.TxState)
				}
			} else if begun.TxState != TxStateActive {
				t.Errorf("BEGIN 後交易態 = %q, want active", begun.TxState)
			}

			ctx, cancel := context.WithTimeout(context.Background(), StatementTimeout)
			defer cancel()
			failed, err := d.Exec(ctx, tc.failTx)
			if err != nil {
				t.Fatalf("送出失敗: %v", err)
			}
			if failed.Status != StatusError {
				t.Fatalf("狀態 = %s, want error", failed.Status)
			}
			switch tc.proto {
			case ProtocolMySQL:
				if failed.TxState != TxStateUnknown {
					t.Errorf("MySQL 交易態 = %q, want unknown", failed.TxState)
				}
			case ProtocolPostgres:
				if failed.TxState != TxStateFailed {
					t.Errorf("PG 交易內失敗後交易態 = %q, want failed", failed.TxState)
				}
			}
			t.Logf("%s：BEGIN 後 %q、失敗後 %q", tc.name, begun.TxState, failed.TxState)

			// 回滾之後回到 none：交易態要跟得上交易的結束，否則會話結束時
			// 那筆「交易還開著」的事件對每一場都成立
			rolled := execOK(t, d, "ROLLBACK")
			switch tc.proto {
			case ProtocolMySQL:
				if rolled.TxState != TxStateUnknown {
					t.Errorf("MySQL 交易態 = %q, want unknown", rolled.TxState)
				}
			default:
				if rolled.TxState != TxStateNone {
					t.Errorf("%s 回滾後交易態 = %q, want none", tc.name, rolled.TxState)
				}
			}
		})
	}
}

// TestIntegrationCancelSemantics 取消的兩種語義。
//
// PG 與 MSSQL 有帶外取消（目標端會確認），MySQL 的 driver 取消實作是關連線——
// 後者的結果**必然是未知**，因為語句可能已經在目標端跑完。
// 這個差別不是缺陷而是事實，測試把它釘住是為了不讓人把 MySQL 的 effect_unknown
// 「修」成 cancelled
func TestIntegrationCancelSemantics(t *testing.T) {
	sleepSQL := map[Protocol]string{
		ProtocolMySQL:    "SELECT SLEEP(20)",
		ProtocolPostgres: "SELECT pg_sleep(20)",
		ProtocolMSSQL:    "WAITFOR DELAY '00:00:20'",
	}
	for _, tc := range dialectCases() {
		t.Run(tc.name, func(t *testing.T) {
			d := openTarget(t, tc.proto, tc.env)

			done := make(chan *ExecOutcome, 1)
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), StatementTimeout)
				defer cancel()
				out, err := d.Exec(ctx, sleepSQL[tc.proto])
				if err != nil {
					done <- &ExecOutcome{Status: "送出失敗:" + err.Error()}
					return
				}
				done <- out
			}()

			// 讓語句真的進到目標端再取消——取消一個還沒送出的語句什麼也證明不了
			deadline := time.Now().Add(5 * time.Second)
			var confirmed bool
			for {
				ctx, cancel := context.WithTimeout(context.Background(), ProbeTimeout)
				c, err := d.Cancel(ctx)
				cancel()
				if err == nil {
					confirmed = c
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("五秒內取不到進行中的單位: %v", err)
				}
				time.Sleep(100 * time.Millisecond)
			}

			var out *ExecOutcome
			select {
			case out = <-done:
			case <-time.After(StatementTimeout + 5*time.Second):
				t.Fatal("取消後語句未在期限內返回")
			}

			switch tc.proto {
			case ProtocolMySQL:
				if !confirmed && out.Status != StatusEffectUnknown {
					t.Errorf("MySQL 取消結果 = %s/%s, want effect_unknown", out.Status, out.Reason)
				}
				// 取消即關連線，而這個事實被原因碼蓋掉了（碼要先講取消）。
				// 不隨結果一起帶回去，呼叫端就得等下一個單位撞上死連線才知道
				// 會話已經不能用——那個單位一個位元組都沒送出，卻會先留下一列紀錄
				if out.Reason == ReasonCancelUnconfirmed && !out.ConnectionLost {
					t.Errorf("MySQL 取消後 ConnectionLost = false，"+
						"期望 true（狀態 = %s/%s）", out.Status, out.Reason)
				}
			default:
				if confirmed && out.Status != StatusCancelled {
					t.Errorf("%s 取消獲確認但狀態 = %s/%s, want cancelled",
						tc.name, out.Status, out.Reason)
				}
				// 帶外取消不動連線：確認得了取消，就代表連線還在回話。
				// 這裡若判成連線已失，會話會被無故收線
				if confirmed && out.ConnectionLost {
					t.Errorf("%s 取消獲確認卻判定連線已失——連線並未關閉", tc.name)
				}
			}
			t.Logf("%s：confirmed=%v status=%s reason=%s", tc.name, confirmed, out.Status, out.Reason)
		})
	}
}

// TestIntegrationTextRoundTrip 文字化對真實型別成立。
//
// 單元測試以 stub 證明的是我方的格式化；這裡證明的是**目標端的型別經過 driver
// 之後仍然是同一個值**。2^63-1 與 30 位 decimal 是兩個典型的失真點
func TestIntegrationTextRoundTrip(t *testing.T) {
	queries := map[Protocol]string{
		ProtocolMySQL:    "SELECT 9223372036854775807 AS big, CAST('123456789012345678901234567890' AS DECIMAL(30,0)) AS dec30",
		ProtocolPostgres: "SELECT 9223372036854775807::bigint AS big, 123456789012345678901234567890::numeric(30,0) AS dec30",
		ProtocolMSSQL:    "SELECT CAST(9223372036854775807 AS bigint) AS big, CAST('123456789012345678901234567890' AS decimal(30,0)) AS dec30",
	}
	for _, tc := range dialectCases() {
		t.Run(tc.name, func(t *testing.T) {
			d := openTarget(t, tc.proto, tc.env)
			out := execOK(t, d, queries[tc.proto])
			if len(out.Sets) != 1 || len(out.Sets[0].Rows) != 1 {
				t.Fatalf("結果形狀不符")
			}
			row := out.Sets[0].Rows[0]
			want := []string{"9223372036854775807", "123456789012345678901234567890"}
			for i, w := range want {
				if row[i] == nil {
					t.Fatalf("第 %d 欄為 NULL", i)
				}
				if *row[i] != w {
					t.Errorf("第 %d 欄 = %q, want %q", i, *row[i], w)
				}
			}
		})
	}
}

// TestIntegrationMultipleResultSets 一個執行單位回多個結果集時，索引不得錯位——
// 匯出端點是以 (event_id, set_index) 定位的，錯位即匯出到另一份資料
func TestIntegrationMultipleResultSets(t *testing.T) {
	// PG 的 simple protocol 一次送出多語句只回最後一個結果集，不在此測
	multi := map[Protocol]string{
		ProtocolMySQL: "SELECT 1 AS a; SELECT 2 AS b; SELECT 3 AS c",
		ProtocolMSSQL: "SELECT 1 AS a; SELECT 2 AS b; SELECT 3 AS c",
	}
	for _, tc := range dialectCases() {
		sql, ok := multi[tc.proto]
		if !ok {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			d := openTarget(t, tc.proto, tc.env)
			out := execOK(t, d, sql)
			if len(out.Sets) != 3 {
				t.Fatalf("結果集數 = %d, want 3", len(out.Sets))
			}
			for i, set := range out.Sets {
				if set.SetIndex != i {
					t.Errorf("第 %d 個結果集的 SetIndex = %d, want %d", i, set.SetIndex, i)
				}
				if len(set.Rows) != 1 || set.Rows[0][0] == nil {
					t.Fatalf("第 %d 個結果集形狀不符", i)
				}
				if got, want := *set.Rows[0][0], fmt.Sprint(i+1); got != want {
					t.Errorf("第 %d 個結果集的值 = %q, want %q", i, got, want)
				}
			}
		})
	}
}

// TestIntegrationCurrentDatabaseWithoutConfiguredName 資產沒填資料庫名時，
// 當前庫仍須是目標端實際連上的那一個。
//
// PostgreSQL 的連線一定落在某一個庫上（沒填就是伺服端的預設庫），而那個名字
// 只有目標端知道——我方的設定物件裡永遠只有自己寫進去的空字串。當前庫留空的
// 後果有兩面：審計列說不出語句打在哪個庫，以及允許清單把一個明明在清單內的庫
// 判成「不在清單內」
func TestIntegrationCurrentDatabaseWithoutConfiguredName(t *testing.T) {
	cfg := targetSpec(t, ProtocolPostgres, testgate.EnvDBConsolePostgres)
	cfg.Database = ""

	ctx, cancel := context.WithTimeout(context.Background(), ConnectTimeout)
	defer cancel()
	d, err := Open(ctx, cfg)
	if err != nil {
		t.Fatalf("連線 postgres 靶機失敗: %v", err)
	}
	defer func() { _ = d.Close() }()

	got := d.CurrentDatabase()
	if got == "" {
		t.Fatal("未設資料庫名時當前庫為空：審計列將指不出目標庫，允許清單也會誤鎖")
	}
	st, err := d.ProbeState(context.Background())
	if err != nil {
		t.Fatalf("探詢失敗: %v", err)
	}
	if st.Database != got {
		t.Errorf("我方記錄的當前庫 = %q，目標端回報 = %q", got, st.Database)
	}
	out := execOK(t, d, "SELECT current_database()")
	if len(out.Sets) != 1 || len(out.Sets[0].Rows) != 1 || out.Sets[0].Rows[0][0] == nil {
		t.Fatal("current_database() 的結果形狀不符")
	}
	if actual := *out.Sets[0].Rows[0][0]; actual != got {
		t.Errorf("當前庫 = %q，目標端 current_database() = %q", got, actual)
	}
}
