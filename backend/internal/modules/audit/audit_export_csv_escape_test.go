package audit

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 匯出 CSV 的公式注入轉義（spec「匯出 CSV 的公式注入轉義」三條 scenario）。
//
// 轉義規則本身在 internal/csvsafe 驗；這裡驗的是**兩個匯出點確實接上了**——
// 規則存在與每條路徑有沒有接上它是兩件事。

func cellOf(t *testing.T, rows [][]string, col string, matchCol, matchVal string) string {
	t.Helper()
	ci, mi := indexOf(rows[0], col), indexOf(rows[0], matchCol)
	if ci < 0 || mi < 0 {
		t.Fatalf("表頭缺 %q 或 %q：%v", col, matchCol, rows[0])
	}
	for _, r := range rows[1:] {
		if r[mi] == matchVal {
			return r[ci]
		}
	}
	t.Fatalf("找不到 %s=%q 的列：%v", matchCol, matchVal, rows[1:])
	return ""
}

// quotedCells 整份 CSV 內以單引號起頭的儲存格數。
// 「其餘欄位逐字不變」不能只抽一欄驗——轉義若誤傷別的欄，只有全表計數看得見
func quotedCells(rows [][]string) int {
	n := 0
	for _, r := range rows {
		for _, c := range r {
			if strings.HasPrefix(c, "'") {
				n++
			}
		}
	}
	return n
}

// TestReportCSVCellsEscaped 事件報告：指令欄與規則名被轉義、其餘欄逐字不變、揭露碼在
func TestReportCSVCellsEscaped(t *testing.T) {
	svc, db := setupReportEnv(t)
	from, to, at := reportWindow()
	assetID := uint(7)
	if err := db.Create(&model.Session{
		SessionID: "sess-esc", Status: model.SessionStatusClosed, Protocol: model.ProtocolSSH,
		UserID: 1, AssetID: &assetID, StartTime: at, AccountUsername: "root", ClientIP: "10.0.0.9",
	}).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}
	for i, cmd := range []string{`=HYPERLINK("http://x")`, `-rf /tmp`, `plain`} {
		if err := db.Exec(`INSERT INTO session_commands (id, session_id, user_id, asset_id, command, seq, executed_at)
			VALUES (?, 1, 1, 7, ?, ?, ?)`, i+1, cmd, i+1, at).Error; err != nil {
			t.Fatalf("seed command: %v", err)
		}
	}
	if err := db.Exec(`INSERT INTO command_alerts (id, rule_id, rule_name, session_id, user_id, asset_id,
		command, severity, triggered_at, disposition, note, blocked)
		VALUES (1, 2, '@sum', 1, 1, 7, '=HYPERLINK("http://x")', 'high', ?, 'pending', '', 1)`, at).Error; err != nil {
		t.Fatalf("seed alert: %v", err)
	}

	uid := uint(1)
	m, files := exportReport(t, svc, &ExportFilter{
		Subject: SubjectUser, UserID: &uid, StartTime: &from, EndTime: &to,
	})

	cmds := csvRows(t, files["commands.csv"])
	for seq, want := range map[string]string{
		"1": `'=HYPERLINK("http://x")`,
		"2": `'-rf /tmp`,
		"3": `plain`,
	} {
		if got := cellOf(t, cmds, "command", "command_seq", seq); got != want {
			t.Errorf("commands.csv seq %s command = %q, want %q", seq, got, want)
		}
	}
	// 其餘欄逐字不變：record_ref 是回系統查對原文的鍵，不得被改寫
	if got := cellOf(t, cmds, "record_ref", "command_seq", "1"); got != "command:1" {
		t.Errorf("record_ref = %q, want command:1（非轉義欄不得改寫）", got)
	}
	if n := quotedCells(cmds); n != 2 {
		t.Errorf("commands.csv 被改寫的儲存格數 = %d, want 2（只有兩個公式起始的指令欄）", n)
	}
	alerts := csvRows(t, files["alerts.csv"])
	if got := cellOf(t, alerts, "rule_name", "record_ref", "alert:1"); got != "'@sum" {
		t.Errorf("alerts.csv rule_name = %q, want '@sum", got)
	}
	if got := cellOf(t, alerts, "command", "record_ref", "alert:1"); got != `'=HYPERLINK("http://x")` {
		t.Errorf("alerts.csv command = %q, want 轉義後原文", got)
	}
	if n := quotedCells(alerts); n != 2 {
		t.Errorf("alerts.csv 被改寫的儲存格數 = %d, want 2（規則名與指令）", n)
	}
	if !hasDisclosure(m, DisclosureCSVFormulaEscape) {
		t.Errorf("事件報告 manifest 缺揭露碼 %s：%+v", DisclosureCSVFormulaEscape, m.Disclosures)
	}
	// 揭露碼在 limit 命名空間，且 manifest 本身不被轉義（它是 JSON）
	if !strings.HasPrefix(DisclosureCSVFormulaEscape, "export.limit.") {
		t.Errorf("揭露碼 %q 不在 export.limit. 命名空間", DisclosureCSVFormulaEscape)
	}
	if bytes.Contains(files["manifest.json"], []byte(`'=`)) {
		t.Errorf("manifest.json 不該套 CSV 轉義")
	}
}

// TestBundleCSVCellsEscapedNumericExempt 證據包：指令欄被轉義、負數值欄豁免、JSON 不套規則、揭露碼在
func TestBundleCSVCellsEscapedNumericExempt(t *testing.T) {
	svc, db := setupExportEnv(t)
	now := time.Now()
	if err := db.Exec(`INSERT INTO session_commands (session_id, user_id, asset_id, command, seq, executed_at)
		VALUES (1, 1, NULL, '+x', 1, ?)`, now).Error; err != nil {
		t.Fatalf("seed cli command: %v", err)
	}
	if err := db.Exec(`INSERT INTO session_commands
		(session_id, user_id, asset_id, command, seq, executed_at,
		 event_id, target_database, result_status, result_reason,
		 result_rows, rows_affected, result_sets, error_code, duration_ms, result_truncated, tx_state_after)
		VALUES (2, 1, NULL, 'UPDATE a', 2, ?, '01J0PARTIAL0000000000000BB', 'app',
		        'partial', 'error_after_results', 0, -1, 1, '', 5, 0, 'active')`, now).Error; err != nil {
		t.Fatalf("seed console command: %v", err)
	}
	if err := db.Create(&model.AuditLog{
		CreatedAt: now, UserID: 1, Username: "=eq", Action: model.ActionUpdate,
		Resource: model.ResourceAsset, Status: model.StatusSuccess, Method: "PUT", Path: "/api/v1/assets/7",
	}).Error; err != nil {
		t.Fatalf("seed audit log: %v", err)
	}

	uid := uint(1)
	var buf bytes.Buffer
	m, err := svc.Export(&buf, &ExportFilter{UserID: &uid}, 9, "auditor1")
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	files := unzip(t, buf.Bytes())

	cmds := csvRows(t, files["commands.csv"])
	if got := cellOf(t, cmds, "command", "seq", "1"); got != "'+x" {
		t.Errorf("commands.csv command = %q, want '+x", got)
	}
	if got := cellOf(t, cmds, "rows_affected", "seq", "2"); got != "-1" {
		t.Errorf("rows_affected = %q, want -1（純數值字面豁免）", got)
	}
	if n := quotedCells(cmds); n != 1 {
		t.Errorf("commands.csv 被改寫的儲存格數 = %d, want 1", n)
	}
	// JSON 段不套 CSV 規則：帳號名原樣
	if raw := files["audit_logs.json"]; !bytes.Contains(raw, []byte(`"=eq"`)) || bytes.Contains(raw, []byte(`'=eq`)) {
		t.Errorf("audit_logs.json 不該套 CSV 轉義：%s", raw)
	}
	if !hasDisclosure(m, DisclosureCSVFormulaEscape) {
		t.Errorf("證據包 manifest 缺揭露碼 %s：%+v", DisclosureCSVFormulaEscape, m.Disclosures)
	}
}
