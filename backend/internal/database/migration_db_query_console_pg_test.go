package database

import (
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/testgate"
	"gorm.io/gorm"
)

// 查詢主控台增量的**值域約束實測**（PG-gated；未設 TEST_PG_DSN 即 skip，
// REQUIRE_INTEGRATION=1 時 skip 轉 fail）。
//
// 與 baseline_parity_pg_test.go 的具名清單不重疊：那一條問「約束在不在、掛對表沒」，
// 本檔問「它到底擋不擋得住」。CHECK 的定義文字看起來對、實際射程不對（值域少列一個、
// 條件寫反）是無症狀缺陷——寫得進去的那一刻沒有任何東西會紅，症狀要等到有人去讀
// 稽核報表、看到一個無人認得的狀態字串為止。

// insertSessionCommand 以原生 SQL 插一列，回傳 DB 的錯誤（nil＝寫入成功）。
//
// 走原生 SQL 而不經 model：本檔要驗的是**資料庫層**擋不擋得住，
// 經過應用層的驗證會讓「DB 沒擋、應用層擋了」與「DB 擋了」不可分辨。
func insertSessionCommand(db *gorm.DB, cols map[string]interface{}) error {
	base := map[string]interface{}{
		"session_id":  1,
		"user_id":     1,
		"command":     "SELECT 1",
		"seq":         1,
		"executed_at": "2026-09-02T00:00:00Z",
	}
	for k, v := range cols {
		base[k] = v
	}
	names := make([]string, 0, len(base))
	holders := make([]string, 0, len(base))
	args := make([]interface{}, 0, len(base))
	for k, v := range base {
		names = append(names, k)
		holders = append(holders, "?")
		args = append(args, v)
	}
	sql := "INSERT INTO session_commands (" + strings.Join(names, ", ") +
		") VALUES (" + strings.Join(holders, ", ") + ")"
	return db.Exec(sql, args...).Error
}

func TestDBQueryConsoleConstraintsRejectOutOfDomainPostgres(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	const pgSchema = "db_console_domain_test"
	db := freshSchema(t, dsn, pgSchema)
	if err := applyBaseline(db); err != nil {
		t.Fatalf("baseline 失敗: %v", err)
	}
	if err := applyMigrationsAfterBaseline(db); err != nil {
		t.Fatalf("增量 migration 失敗: %v", err)
	}

	// ── 正向對照：合法值必須寫得進去 ──
	//
	// 沒有這一組，「全部被拒」與「CHECK 太嚴」不可分辨，而後者的症狀是
	// 主控台每一筆審計列都寫不進去，fail-close 之下等於整個功能無法使用。
	accepted := []struct {
		name string
		cols map[string]interface{}
	}{
		{"命令列列（全部留預設值）", map[string]interface{}{}},
		{"主控台 running 列", map[string]interface{}{
			"event_id": "01JBQ0000000000000000000AA", "result_status": "running",
			"target_database": "app", "tx_state_after": "none",
		}},
		{"主控台終態列", map[string]interface{}{
			"event_id": "01JBQ0000000000000000000AB", "result_status": "effect_unknown",
			"result_reason": "connection_lost", "tx_state_after": "unknown",
		}},
	}
	for _, tc := range accepted {
		if err := insertSessionCommand(db, tc.cols); err != nil {
			t.Errorf("%s 應可寫入，卻被拒：%v", tc.name, err)
		}
	}

	// ── 反向：值域外的值必須被 DB 擋下 ──
	rejected := []struct {
		name       string
		constraint string
		cols       map[string]interface{}
	}{
		{"結果狀態集合外值", "session_commands_result_status_domain",
			map[string]interface{}{"result_status": "succeeded"}},
		{"結果狀態大小寫不符", "session_commands_result_status_domain",
			map[string]interface{}{"result_status": "OK"}},
		{"交易態集合外值", "session_commands_tx_state_domain",
			map[string]interface{}{"tx_state_after": "open"}},
		{"事件 ID 長度非 26", "session_commands_event_id_shape",
			map[string]interface{}{"event_id": "01JBQ0"}},
	}
	for _, tc := range rejected {
		err := insertSessionCommand(db, tc.cols)
		if err == nil {
			t.Errorf("%s 應被 %s 拒絕，卻寫入成功", tc.name, tc.constraint)
			continue
		}
		if !strings.Contains(err.Error(), tc.constraint) {
			t.Errorf("%s 被拒，但錯誤訊息未指名 %s：%v\n"+
				"  錯誤來源可能是別的約束，這一格因此沒有真的驗到", tc.name, tc.constraint, err)
		}
	}

	// ── 事件 ID 唯一性：partial 條件的兩側各驗一次 ──
	//
	// 空 ID 側必須放行（命令列列每筆都是空 ID，擋住即整個指令審計停擺）；
	// 非空側必須擋住（匯出、轉錄、詳情錨點全部以它定址，重複即定址失效）。
	if err := insertSessionCommand(db, map[string]interface{}{}); err != nil {
		t.Errorf("第二筆空事件 ID 的列應可寫入（partial 條件把 CLI 列排除在唯一性之外），卻被拒：%v", err)
	}
	dup := map[string]interface{}{"event_id": "01JBQ0000000000000000000AA", "result_status": "ok"}
	if err := insertSessionCommand(db, dup); err == nil {
		t.Error("重複的非空事件 ID 應被 idx_session_commands_event_id 拒絕，卻寫入成功")
	}
}
