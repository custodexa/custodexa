package audit

import (
	"bytes"
	"encoding/csv"
	"testing"
	"time"
)

// 證據包 commands.csv 的結果事實欄。
//
// 稽核拿這份 CSV 判讀的是「這句語句到底生效了沒有」，而該判讀完全靠狀態與原因碼
// ——`partial` 與 `effect_unknown` 兩列若退化成看起來像成功或看起來像沒發生，
// 讀的人會做出相反的結論。本檔釘住表頭順序與這三種列的欄值。

// consoleCSVHeader 表頭的權威順序（前六欄為既有欄，後十欄為結果事實）
var consoleCSVHeader = []string{
	"session_id", "user_id", "asset_id", "seq", "command", "executed_at",
	"event_id", "target_database", "result_status", "result_reason",
	"result_rows", "rows_affected", "result_sets", "error_code",
	"duration_ms", "result_truncated", "tx_state_after",
}

// exportCommandsCSV 跑一次證據包匯出並解出 commands.csv
func exportCommandsCSV(t *testing.T, userID uint) [][]string {
	t.Helper()
	svc := exportEnvWithConsoleRows(t)
	var buf bytes.Buffer
	uid := userID
	if _, err := svc.Export(&buf, &ExportFilter{UserID: &uid}, 9, "auditor1"); err != nil {
		t.Fatalf("Export: %v", err)
	}
	files := unzip(t, buf.Bytes())
	raw, ok := files["commands.csv"]
	if !ok {
		t.Fatalf("匯出包缺 commands.csv")
	}
	recs, err := csv.NewReader(bytes.NewReader(raw)).ReadAll()
	if err != nil {
		t.Fatalf("解析 commands.csv: %v", err)
	}
	return recs
}

// exportEnvWithConsoleRows 種四列：一列命令列、三列主控台（阻斷／部分／未知）
func exportEnvWithConsoleRows(t *testing.T) *AuditExportService {
	t.Helper()
	svc, db := setupExportEnv(t)
	now := time.Now()
	// 命令列那一側：結果事實欄一律留在預設值
	db.Exec(`INSERT INTO session_commands (session_id, user_id, asset_id, command, seq, executed_at)
		VALUES (1, 1, NULL, 'ls -la', 1, ?)`, now)
	// 阻斷：未送出目標端，故無耗時、無結果集
	db.Exec(`INSERT INTO session_commands
		(session_id, user_id, asset_id, command, seq, executed_at,
		 event_id, target_database, result_status, result_reason, error_code, result_truncated)
		VALUES (2, 1, NULL, 'DROP TABLE t', 1, ?, '01J0BLOCKED0000000000000AA', 'app',
		        'blocked', 'matcher_hit', '', 0)`, now)
	// 部分：回錯前已有語句完成——已完成的部分落在使用者仍未提交的交易內
	db.Exec(`INSERT INTO session_commands
		(session_id, user_id, asset_id, command, seq, executed_at,
		 event_id, target_database, result_status, result_reason,
		 result_rows, rows_affected, result_sets, error_code, duration_ms, result_truncated, tx_state_after)
		VALUES (2, 1, NULL, 'UPDATE a; UPDATE b', 2, ?, '01J0PARTIAL0000000000000BB', 'app',
		        'partial', 'error_after_results', 3, 2, 1, '23505', 120, 0, 'active')`, now)
	// 未知：已送出、目標端既未回報完成也未確認取消——連線已斷，交易態探詢不可得
	db.Exec(`INSERT INTO session_commands
		(session_id, user_id, asset_id, command, seq, executed_at,
		 event_id, target_database, result_status, result_reason,
		 error_code, duration_ms, result_truncated, tx_state_after)
		VALUES (2, 1, NULL, 'DELETE FROM big', 3, ?, '01J0UNKNOWN0000000000000CC', 'app',
		        'effect_unknown', 'connection_lost', '', 60000, 0, 'unknown')`, now)
	return svc
}

// TestExportCommandsCSVHeaderCarriesResultFacts 表頭逐欄逐序
func TestExportCommandsCSVHeaderCarriesResultFacts(t *testing.T) {
	recs := exportCommandsCSV(t, 1)
	if len(recs) == 0 {
		t.Fatalf("commands.csv 無任何列")
	}
	got := recs[0]
	if len(got) != len(consoleCSVHeader) {
		t.Fatalf("表頭欄數 = %d, want %d：%v", len(got), len(consoleCSVHeader), got)
	}
	for i, want := range consoleCSVHeader {
		if got[i] != want {
			t.Errorf("表頭第 %d 欄 = %q, want %q", i+1, got[i], want)
		}
	}
}

// TestExportCommandsCSVConsoleRowValues 三種主控台列的狀態值，
// 以及命令列那一側的十欄留空
func TestExportCommandsCSVConsoleRowValues(t *testing.T) {
	recs := exportCommandsCSV(t, 1)
	idx := map[string]int{}
	for i, name := range recs[0] {
		idx[name] = i
	}
	byCommand := map[string][]string{}
	for _, r := range recs[1:] {
		byCommand[r[idx["command"]]] = r
	}

	cli, ok := byCommand["ls -la"]
	if !ok {
		t.Fatalf("找不到命令列那一列：%v", byCommand)
	}
	for _, col := range consoleCSVHeader[6:] {
		if cli[idx[col]] != "" {
			t.Errorf("命令列的列在 %s 欄應留空，實得 %q", col, cli[idx[col]])
		}
	}

	cases := []struct {
		command string
		want    map[string]string
	}{
		{"DROP TABLE t", map[string]string{
			"event_id": "01J0BLOCKED0000000000000AA", "target_database": "app",
			"result_status": "blocked", "result_reason": "matcher_hit",
			// 未送出＝沒有耗時與結果集可言，留空而非 0；交易態探詢同理未曾發生
			"result_rows": "", "rows_affected": "", "result_sets": "",
			"duration_ms": "", "result_truncated": "false", "tx_state_after": "",
		}},
		{"UPDATE a; UPDATE b", map[string]string{
			"result_status": "partial", "result_reason": "error_after_results",
			"result_rows": "3", "rows_affected": "2", "result_sets": "1",
			"error_code": "23505", "duration_ms": "120", "tx_state_after": "active",
		}},
		{"DELETE FROM big", map[string]string{
			"result_status": "effect_unknown", "result_reason": "connection_lost",
			"result_rows": "", "rows_affected": "", "duration_ms": "60000",
			"tx_state_after": "unknown",
		}},
	}
	for _, c := range cases {
		row, ok := byCommand[c.command]
		if !ok {
			t.Errorf("找不到 %q 的列", c.command)
			continue
		}
		for col, want := range c.want {
			if got := row[idx[col]]; got != want {
				t.Errorf("[%s] %s = %q, want %q", c.command, col, got, want)
			}
		}
	}
}
