package audit

import (
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/assert"
)

// 結果事實篩選的查詢面。
//
// 兩件事：條件落在正確的欄（來源面以結果狀態是否為空判別，那也是 partial 索引的
// 述詞），以及**降級輪數不受這些條件影響**——`degraded_total` 回答的是「這個範圍內
// 有幾輪沒有文字可搜」，跟著 `source=console` 走就會恆為 0，而那個事實與主控台無關。
//
// sqlmock 而非 sqlite：本檔要斷言的正是產生出來的 WHERE 子句本身。

func TestSessionCommandSearchResultFactFilters(t *testing.T) {
	mock, gormDB := setupMatcherMockDB(t)
	svc := NewSessionCommandService(gormDB)

	filter := &SessionCommandFilter{
		Source:         SourceConsole,
		TargetDatabase: "payments",
		ResultStatuses: []string{model.ResultStatusPartial, model.ResultStatusEffectUnknown},
		ErrorCode:      "42601",
		Page:           1,
		PageSize:       20,
	}

	mock.ExpectQuery(`SELECT count\(\*\) FROM "session_commands" WHERE result_status <> \$1 `+
		`AND target_database = \$2 AND result_status IN \(\$3,\$4\) AND error_code = \$5$`).
		WithArgs("", "payments", model.ResultStatusPartial, model.ResultStatusEffectUnknown, "42601").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	// 降級計數只套範圍條件；結果事實條件一旦被帶進來即不匹配（正則以 $ 收尾）
	mock.ExpectQuery(`SELECT count\(\*\) FROM "session_commands" WHERE degraded = \$1$`).
		WithArgs(true).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))

	mock.ExpectQuery(`SELECT session_commands\.\*`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "session_id", "user_id", "command", "seq", "executed_at"}))

	res, err := svc.Search(filter)

	assert.NoError(t, err)
	assert.Equal(t, int64(2), res.Total)
	assert.Equal(t, int64(5), res.DegradedTotal,
		"降級輪數被結果事實條件影響了——誠實橫幅會因此在主控台篩選下說 0 輪")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestSessionCommandSearchSourceCLI 命令列那一側取結果狀態為空的列
func TestSessionCommandSearchSourceCLI(t *testing.T) {
	mock, gormDB := setupMatcherMockDB(t)
	svc := NewSessionCommandService(gormDB)

	mock.ExpectQuery(`SELECT count\(\*\) FROM "session_commands" WHERE result_status = \$1$`).
		WithArgs("").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(9))
	mock.ExpectQuery(`SELECT count\(\*\) FROM "session_commands" WHERE degraded = \$1$`).
		WithArgs(true).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery(`SELECT session_commands\.\*`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "session_id", "user_id", "command", "seq", "executed_at"}))

	res, err := svc.Search(&SessionCommandFilter{Source: SourceCLI, Page: 1, PageSize: 20})

	assert.NoError(t, err)
	assert.Equal(t, int64(9), res.Total)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestSessionCommandSearchWithoutResultFactFiltersIsUnchanged 未帶結果條件時
// SHALL NOT 多出任何 WHERE——既有查詢面不因新欄位而收窄
func TestSessionCommandSearchWithoutResultFactFiltersIsUnchanged(t *testing.T) {
	mock, gormDB := setupMatcherMockDB(t)
	svc := NewSessionCommandService(gormDB)

	mock.ExpectQuery(`SELECT count\(\*\) FROM "session_commands"$`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(12))
	mock.ExpectQuery(`SELECT count\(\*\) FROM "session_commands" WHERE degraded = \$1$`).
		WithArgs(true).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))
	mock.ExpectQuery(`SELECT session_commands\.\*`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "session_id", "user_id", "command", "seq", "executed_at"}))

	res, err := svc.Search(&SessionCommandFilter{Page: 1, PageSize: 20})

	assert.NoError(t, err)
	assert.Equal(t, int64(12), res.Total)
	assert.NoError(t, mock.ExpectationsWereMet())
}
