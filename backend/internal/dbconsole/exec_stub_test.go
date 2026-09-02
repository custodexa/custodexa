package dbconsole

import (
	"context"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
)

// 以 stub driver 注入的執行路徑判定：partial、effect_unknown、截斷、文字化。

func mkStubDialect(t *testing.T, proto Protocol, script stubScript, affected int64) *sqlDialect {
	t.Helper()
	ourCopy := []byte("pw")
	connector := &stubConnector{
		cfg:      &stubConfig{Password: "pw"},
		probeRow: probeRowValues("app", "unknown", affected),
		fallback: script,
	}
	d, _ := newStubDialect(t, proto, connector, ourCopy)
	return d
}

// TestExecPartialWhenErrorFollowsCompletedSet 錯誤前已有結果集完成＝partial。
//
// partial 記的是「目標端回報過完成」這個事實。把它記成 error，稽核員讀到的是
// 「這句沒有生效」——而多語句單位的前半可能已經改了資料。
func TestExecPartialWhenErrorFollowsCompletedSet(t *testing.T) {
	boom := &mysqldriver.MySQLError{Number: 1064, Message: "You have an error in your SQL syntax"}
	d := mkStubDialect(t, ProtocolMySQL, stubScript{
		sets: []stubSet{{
			columns: []string{"id"},
			rows:    [][]driver.Value{{[]byte("1")}, {[]byte("2")}},
		}},
		afterSets: 1,
		afterErr:  boom,
	}, 0)

	out, err := d.Exec(context.Background(), "SELECT id FROM t; SELECT bad")
	if err != nil {
		t.Fatalf("Exec 回錯: %v", err)
	}
	if out.Status != StatusPartial {
		t.Errorf("狀態 = %q, want %q", out.Status, StatusPartial)
	}
	if out.Reason != ReasonErrorAfterResults {
		t.Errorf("原因碼 = %q, want %q", out.Reason, ReasonErrorAfterResults)
	}
	if len(out.Sets) != 1 || out.Sets[0].RowCount != 2 {
		t.Errorf("已完成的結果未被保留：%+v——partial 的價值正在於它記得已完成的部分", out.Sets)
	}
	if out.DBError == nil || out.DBError.Code != "1064" {
		t.Errorf("目標端錯誤碼 = %+v, want 1064", out.DBError)
	}
	if out.DBError != nil && out.DBError.Message == "" {
		t.Error("使用者自己語句的 SQL 層錯誤應帶訊息原文")
	}
}

// TestExecErrorWithoutAnyResult 沒有任何結果就回錯＝error（不是 partial）。
func TestExecErrorWithoutAnyResult(t *testing.T) {
	boom := &mysqldriver.MySQLError{Number: 1146, Message: "Table 'app.nope' doesn't exist"}
	d := mkStubDialect(t, ProtocolMySQL, stubScript{queryErr: boom}, 0)

	out, err := d.Exec(context.Background(), "SELECT * FROM nope")
	if err != nil {
		t.Fatalf("Exec 回錯: %v", err)
	}
	if out.Status != StatusError {
		t.Errorf("狀態 = %q, want %q", out.Status, StatusError)
	}
	if out.Reason != "" {
		t.Errorf("原因碼 = %q, want 空（error 不帶原因碼）", out.Reason)
	}
}

// TestExecEffectUnknownOnConnectionLost 送出後連線斷掉＝effect_unknown。
//
// **不是 error**：語句已經出去了，目標端沒回報結果也沒確認取消。
// 記成 error 等於斷言它沒生效，而我們沒有那個依據。
func TestExecEffectUnknownOnConnectionLost(t *testing.T) {
	d := mkStubDialect(t, ProtocolMySQL, stubScript{
		queryErr: mysqldriver.ErrInvalidConn,
	}, 0)

	out, err := d.Exec(context.Background(), "UPDATE t SET x = 1")
	if err != nil {
		t.Fatalf("Exec 回錯: %v", err)
	}
	if out.Status != StatusEffectUnknown {
		t.Errorf("狀態 = %q, want %q", out.Status, StatusEffectUnknown)
	}
	if out.Reason != ReasonConnectionLost {
		t.Errorf("原因碼 = %q, want %q", out.Reason, ReasonConnectionLost)
	}
	if out.DBError != nil && out.DBError.Message != "" {
		t.Error("連線中斷屬連線階段，回應不得帶訊息原文")
	}
}

// TestExecRowLimitTruncates 列數上限。
func TestExecRowLimitTruncates(t *testing.T) {
	rows := make([][]driver.Value, MaxRowsPerUnit+50)
	for i := range rows {
		rows[i] = []driver.Value{[]byte("x")}
	}
	d := mkStubDialect(t, ProtocolMySQL, stubScript{
		sets: []stubSet{{columns: []string{"c"}, rows: rows}},
	}, 0)

	out, err := d.Exec(context.Background(), "SELECT c FROM big")
	if err != nil {
		t.Fatalf("Exec 回錯: %v", err)
	}
	if out.Status != StatusOK {
		t.Fatalf("狀態 = %q, want ok", out.Status)
	}
	if !out.Truncated || !out.Sets[0].Truncated {
		t.Error("達列數上限時 Truncated 未標記——使用者會拿一份被截斷的結果去做決定")
	}
	if got := out.Sets[0].RowCount; got != MaxRowsPerUnit {
		t.Errorf("回傳列數 = %d, want %d", got, MaxRowsPerUnit)
	}
}

// TestExecCellTruncationMarksReason 單欄上限：值被截斷、標記進值裡、原因碼落地。
func TestExecCellTruncationMarksReason(t *testing.T) {
	big := strings.Repeat("A", MaxCellBytes+1234)
	d := mkStubDialect(t, ProtocolMySQL, stubScript{
		sets: []stubSet{{columns: []string{"blob_text"}, rows: [][]driver.Value{{[]byte(big)}}}},
	}, 0)

	out, err := d.Exec(context.Background(), "SELECT blob_text FROM t")
	if err != nil {
		t.Fatalf("Exec 回錯: %v", err)
	}
	if !out.Truncated {
		t.Fatal("單欄截斷未使單位標記為 truncated")
	}
	if out.Reason != ReasonCellTruncated {
		t.Errorf("原因碼 = %q, want %q", out.Reason, ReasonCellTruncated)
	}
	cell := out.Sets[0].Rows[0][0]
	if cell == nil {
		t.Fatal("截斷後的值不得為 NULL")
	}
	if !strings.HasSuffix(*cell, "bytes]") {
		t.Errorf("截斷標記未附在值上：%.60s…——只有列層旗標的話，使用者分不出是哪一欄被砍了", *cell)
	}
	if len(*cell) <= MaxCellBytes {
		// 標記本身會讓長度略超過上限，這是刻意的
		t.Errorf("截斷後長度 = %d，期望為上限加上標記", len(*cell))
	}
}

// TestExecTextRoundTrip 值一律以文字傳輸，且逐字元原樣。
//
// 這一組值是專門挑的：`9223372036854775807` 超過 JS 的安全整數、30 位 decimal
// 的尾數會在雙精度下消失、微秒時戳會被截、`NaN` 在 JSON number 裡不存在。
// 四者共同的失效形態是**沒有症狀**——畫面上看起來就是一個正常的值。
func TestExecTextRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		raw  driver.Value
		kind string
		want string
	}{
		{"最大 int64", []byte("9223372036854775807"), "BIGINT", "9223372036854775807"},
		{"30 位 decimal", []byte("123456789012345678901234567.890"), "DECIMAL(30,3)", "123456789012345678901234567.890"},
		{"微秒時戳", []byte("2026-09-02 13:45:06.123456"), "DATETIME(6)", "2026-09-02 13:45:06.123456"},
		{"NaN 字面", []byte("NaN"), "DOUBLE", "NaN"},
		{"負數", []byte("-5"), "INT", "-5"},
		{"空字串", []byte(""), "VARCHAR(10)", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := mkStubDialect(t, ProtocolMySQL, stubScript{
				sets: []stubSet{{columns: []string{"v"}, rows: [][]driver.Value{{tc.raw}}}},
			}, 0)
			out, err := d.Exec(context.Background(), "SELECT v")
			if err != nil {
				t.Fatalf("Exec 回錯: %v", err)
			}
			cell := out.Sets[0].Rows[0][0]
			if cell == nil {
				t.Fatal("值不得為 NULL")
			}
			if *cell != tc.want {
				t.Errorf("值 = %q, want %q（逐字元相同）", *cell, tc.want)
			}
		})
	}
}

// TestExecNullIsDistinctFromEmptyString NULL 與空字串不可合流。
func TestExecNullIsDistinctFromEmptyString(t *testing.T) {
	d := mkStubDialect(t, ProtocolMySQL, stubScript{
		sets: []stubSet{{
			columns: []string{"a", "b"},
			rows:    [][]driver.Value{{nil, []byte("")}},
		}},
	}, 0)

	out, err := d.Exec(context.Background(), "SELECT a, b")
	if err != nil {
		t.Fatalf("Exec 回錯: %v", err)
	}
	row := out.Sets[0].Rows[0]
	if row[0] != nil {
		t.Errorf("SQL NULL 應為 nil，實得 %q", *row[0])
	}
	if row[1] == nil || *row[1] != "" {
		t.Error("空字串應為空字串而非 NULL——兩者在畫面與 CSV 上是不同的東西")
	}
}

// TestExecMultipleResultSetsIndexed 多結果集逐一編號。
func TestExecMultipleResultSetsIndexed(t *testing.T) {
	d := mkStubDialect(t, ProtocolMySQL, stubScript{
		sets: []stubSet{
			{columns: []string{"a"}, rows: [][]driver.Value{{[]byte("1")}}},
			{columns: []string{"b"}, rows: [][]driver.Value{{[]byte("2")}, {[]byte("3")}}},
		},
	}, 0)

	out, err := d.Exec(context.Background(), "SELECT a; SELECT b")
	if err != nil {
		t.Fatalf("Exec 回錯: %v", err)
	}
	if len(out.Sets) != 2 {
		t.Fatalf("結果集數 = %d, want 2", len(out.Sets))
	}
	for i, set := range out.Sets {
		if set.SetIndex != i {
			t.Errorf("第 %d 個結果集的 set_index = %d——匯出 URL 與畫面分頁都以它定址", i, set.SetIndex)
		}
	}
}

// TestExecRejectsSecondConcurrentUnit 每會話同時只允許一個進行中的送出。
func TestExecRejectsSecondConcurrentUnit(t *testing.T) {
	d := mkStubDialect(t, ProtocolMySQL, stubScript{}, 0)

	ctx, unit, err := d.beginUnit(context.Background())
	if err != nil {
		t.Fatalf("登記第一個單位失敗: %v", err)
	}
	defer d.endUnit(unit, false)
	_ = ctx

	if _, err := d.Exec(context.Background(), "SELECT 1"); !errors.Is(err, ErrBusy) {
		t.Errorf("第二個單位的錯誤 = %v, want ErrBusy", err)
	}
}

// TestCancelWithoutInFlightUnit 沒有進行中的單位時取消要說得出來。
func TestCancelWithoutInFlightUnit(t *testing.T) {
	d := mkStubDialect(t, ProtocolMySQL, stubScript{}, 0)
	if _, err := d.Cancel(context.Background()); !errors.Is(err, ErrNoStatementInFlight) {
		t.Errorf("錯誤 = %v, want ErrNoStatementInFlight", err)
	}
}

// TestProbeFillsRowsAffectedAndTxState 探詢把影響列數與交易態填進結果。
func TestProbeFillsRowsAffectedAndTxState(t *testing.T) {
	d := mkStubDialect(t, ProtocolMySQL, stubScript{}, 42)
	out, err := d.Exec(context.Background(), "UPDATE t SET x = 1")
	if err != nil {
		t.Fatalf("Exec 回錯: %v", err)
	}
	if out.RowsAffected != 42 {
		t.Errorf("影響列數 = %d, want 42", out.RowsAffected)
	}
	if out.TxState != TxStateUnknown {
		t.Errorf("MySQL 的交易態 = %q, want %q（該方言取不到，恆為未知）", out.TxState, TxStateUnknown)
	}
	if len(out.Sets) != 0 {
		t.Errorf("非查詢語句不得產生結果集（實得 %d 個）——空結果集會讓畫面多出一個沒有內容的分頁", len(out.Sets))
	}
}

// TestExecEffectUnknownAfterConnectionClosed 連線已經死掉之後的下一個單位。
//
// 取消（MySQL 的取消實作就是關連線）或逾時打死連線後，database/sql 對後續每一次
// 送出回的是 `sql.ErrConnDone` 而不是 driver 的原始錯誤。把它歸成 error 有兩個
// 後果：稽核讀到「這句沒生效」，以及 database/sql 的內部字串被當成目標端的錯誤
// 原文送到使用者面前。
func TestExecEffectUnknownAfterConnectionClosed(t *testing.T) {
	d := mkStubDialect(t, ProtocolMySQL, stubScript{}, 0)
	if err := d.conn.Close(); err != nil {
		t.Fatalf("關閉連線失敗: %v", err)
	}

	out, err := d.Exec(context.Background(), "UPDATE t SET x = 1")
	if err != nil {
		t.Fatalf("Exec 回錯: %v", err)
	}
	if out.Status != StatusEffectUnknown || out.Reason != ReasonConnectionLost {
		t.Errorf("狀態 = %q/%q, want %q/%q", out.Status, out.Reason,
			StatusEffectUnknown, ReasonConnectionLost)
	}
	if out.DBError != nil && out.DBError.Message != "" {
		t.Errorf("回應帶了 driver 原文 %q——連線階段的錯誤一律只回碼", out.DBError.Message)
	}
}
