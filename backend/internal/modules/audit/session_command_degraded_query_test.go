package audit

import (
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
)

// 降級列的查詢面守衛（command-audit-altscreen-bypass tasks 2.7 的後端側）。
//
// 這裡釘的是**一個語義決定**，不是欄位有沒有接上：
// `degraded_total` 刻意不套 keyword、也不套 degraded 過濾。
// 降級列的 command 恆為空字串，`command ILIKE '%rm -rf%'` 永遠不會命中它們——
// 若這一筆計數跟著 keyword 走，稽核員搜 `rm -rf` 得到 0 筆時它也是 0，
// 於是「這個區間有 N 輪根本沒有文字可搜」仍然無從得知，而那正是它存在的理由。
//
// sqlmock 而非 sqlite：`ILIKE` 是 PostgreSQL 語法，sqlite 跑不了；
// 且本測試要斷言的正是「第二個 COUNT 的 WHERE 裡沒有 ILIKE」。

func TestSessionCommandSearchDegradedTotalIgnoresKeywordAndFilter(t *testing.T) {
	mock, gormDB := setupMatcherMockDB(t)
	svc := NewSessionCommandService(gormDB)

	onlyText := false
	from := time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)
	filter := &SessionCommandFilter{
		Keyword:   "rm -rf",
		Degraded:  &onlyText,
		StartTime: &from,
		Page:      1,
		PageSize:  20,
	}

	// 列表計數：套範圍 ＋ keyword ＋ degraded
	mock.ExpectQuery(`SELECT count\(\*\) FROM "session_commands" WHERE executed_at >= \$1 AND command ILIKE \$2 AND degraded = \$3`).
		WithArgs(from, "%rm -rf%", false).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// 降級計數：**只套範圍**。正則以 $ 收尾，keyword 或 degraded 條件一旦被帶進來即不匹配
	mock.ExpectQuery(`SELECT count\(\*\) FROM "session_commands" WHERE executed_at >= \$1 AND degraded = \$2$`).
		WithArgs(from, true).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(7))

	mock.ExpectQuery(`SELECT session_commands\.\*`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "session_id", "user_id", "command", "seq", "executed_at", "degraded", "degrade_reason"}))

	res, err := svc.Search(filter)

	assert.NoError(t, err)
	assert.Equal(t, int64(0), res.Total, "keyword 搜不到東西是預期的")
	assert.Equal(t, int64(7), res.DegradedTotal,
		"degraded_total 被 keyword／degraded 條件歸零了——誠實橫幅會因此永遠說 0 輪")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestSessionCommandSearchDegradedFilterIsOptional 未指定 degraded 時 SHALL NOT 過濾。
//
// **指標型的理由就在這裡**：值型 bool 的零值是 false，會把「沒指定」靜默變成
// 「只要有文字的列」——降級列整批消失，而查詢看起來完全正常。
func TestSessionCommandSearchDegradedFilterIsOptional(t *testing.T) {
	mock, gormDB := setupMatcherMockDB(t)
	svc := NewSessionCommandService(gormDB)

	// 列表計數不得含 degraded 條件（正則以 $ 收尾）
	mock.ExpectQuery(`SELECT count\(\*\) FROM "session_commands"$`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(12))
	mock.ExpectQuery(`SELECT count\(\*\) FROM "session_commands" WHERE degraded = \$1$`).
		WithArgs(true).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(4))
	mock.ExpectQuery(`SELECT session_commands\.\*`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	res, err := svc.Search(&SessionCommandFilter{Page: 1, PageSize: 20})

	assert.NoError(t, err)
	assert.Equal(t, int64(12), res.Total)
	assert.Equal(t, int64(4), res.DegradedTotal)
	assert.NoError(t, mock.ExpectationsWereMet())
}
