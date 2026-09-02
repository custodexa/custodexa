package sshproxy

import (
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/dbconsole"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
)

// 語句審計的順序不變式與八值狀態回填。
//
// # 為什麼斷言的是順序而不是結果
//
// 「列 INSERT 早於任何目標端效果」「回應晚於阻斷證據持久化」「INSERT 失敗即不執行」
// 三條之中，任何一條被調換之後，**最終狀態看起來仍然完全正確**：列在、結果對、
// 回應也送出去了。只有把兩邊的呼叫記進同一份序列，才看得出中間曾經存在一個
// 「已對目標生效但沒有留痕」的窗口。故本檔的 stub 方言與 stub 語句紀錄共用
// 同一份 callLog。

func okOutcome(rows int) *dbconsole.ExecOutcome {
	set := dbconsole.ResultSet{SetIndex: 0, RowCount: rows,
		Columns: []dbconsole.ColumnMeta{{Name: "c", TypeName: "int", Kind: dbconsole.KindInteger}}}
	for i := 0; i < rows; i++ {
		v := "1"
		set.Rows = append(set.Rows, []*string{&v})
	}
	return &dbconsole.ExecOutcome{Status: dbconsole.StatusOK,
		Sets: []dbconsole.ResultSet{set}, TxState: dbconsole.TxStateNone}
}

// TestConsoleInsertPrecedesExec 先寫後執行：紀錄列必須早於任何目標端效果
func TestConsoleInsertPrecedesExec(t *testing.T) {
	d := &stubDialect{currentDB: "app", execOutcomes: []*dbconsole.ExecOutcome{okOutcome(2)}}
	f := newConsoleFixture(t, d)

	f.runQuery("SELECT 1")

	calls := d.callLog()
	iInsert, iExec := indexOfPrefix(calls, "insert:"), indexOfPrefix(calls, "exec:")
	if iInsert < 0 || iExec < 0 {
		t.Fatalf("呼叫序列缺 insert 或 exec：%v", calls)
	}
	if iInsert > iExec {
		t.Fatalf("紀錄列寫在執行之後（序列 %v）——那是一個「已對目標生效但沒有留痕」的窗口", calls)
	}
	if indexOfPrefix(calls, "match_block") > iInsert {
		t.Errorf("阻斷比對晚於紀錄列：%v（比對必須在配發事件識別之後、寫列之前）", calls)
	}
}

// TestConsoleInsertFailureDoesNotExecute 留痕失敗即不執行。
//
// 這是主控台比命令列嚴的那一條：命令列的指令入庫是盡力而為（位元組流不能為了
// 審計而凍住終端，且錄影是獨立真相），主控台的執行者是伺服器自己
func TestConsoleInsertFailureDoesNotExecute(t *testing.T) {
	d := &stubDialect{currentDB: "app", execOutcomes: []*dbconsole.ExecOutcome{okOutcome(1)}}
	f := newConsoleFixture(t, d)
	f.recorder.insertErrAt = 1

	f.runQuery("DELETE FROM t")

	if i := indexOfPrefix(d.callLog(), "exec:"); i >= 0 {
		t.Fatalf("紀錄寫入失敗後仍送出語句（序列 %v）", d.callLog())
	}
	if code := lastErrorCode(f.drain()); code != string(apierror.CodeDBConsoleAuditUnavailable) {
		t.Errorf("回應碼 = %q, want %q", code, apierror.CodeDBConsoleAuditUnavailable)
	}
}

// TestConsoleMatcherUnavailableFailsClose 比對器不可用即不執行，
// 且列為 blocked／matcher_unavailable
func TestConsoleMatcherUnavailableFailsClose(t *testing.T) {
	d := &stubDialect{currentDB: "app", execOutcomes: []*dbconsole.ExecOutcome{okOutcome(1)}}
	f := newConsoleFixture(t, d)
	f.matcher.health = errNotAvailable{}

	f.runQuery("SELECT 1")

	if i := indexOfPrefix(d.callLog(), "exec:"); i >= 0 {
		t.Fatalf("比對器不可用時仍送出語句（序列 %v）——刪掉規則就等於關掉阻斷", d.callLog())
	}
	rows, _ := f.recorder.snapshot()
	if len(rows) != 1 || rows[0].ResultStatus != model.ResultStatusBlocked ||
		rows[0].ResultReason != model.ReasonMatcherUnavailable {
		t.Fatalf("列 = %+v, want blocked/matcher_unavailable", rows)
	}
	if code := lastErrorCode(f.drain()); code != string(apierror.CodeDBConsoleBlockerUnavailable) {
		t.Errorf("回應碼 = %q, want %q", code, apierror.CodeDBConsoleBlockerUnavailable)
	}
}

// TestConsoleBlockedRowPersistsBeforeResponse 阻斷證據持久化後才回應；
// 且阻斷列寫入失敗時回的是 AUDIT_UNAVAILABLE 而不是 BLOCKED——
// 後者會宣稱一件沒有紀錄的事
func TestConsoleBlockedRowPersistsBeforeResponse(t *testing.T) {
	d := &stubDialect{currentDB: "app"}
	f := newConsoleFixture(t, d)
	f.matcher.hit = true
	f.matcher.rule = &model.AlertRule{Name: "禁止全表刪除"}

	f.runQuery("DELETE FROM t")

	rows, _ := f.recorder.snapshot()
	if len(rows) != 1 || rows[0].ResultStatus != model.ResultStatusBlocked ||
		rows[0].ResultReason != model.ReasonMatcherHit {
		t.Fatalf("列 = %+v, want blocked/matcher_hit", rows)
	}
	msgs := f.drain()
	if code := lastErrorCode(msgs); code != string(apierror.CodeDBConsoleStatementBlocked) {
		t.Fatalf("回應碼 = %q, want %q", code, apierror.CodeDBConsoleStatementBlocked)
	}
	if i := indexOfPrefix(d.callLog(), "exec:"); i >= 0 {
		t.Errorf("命中阻斷規則仍送出語句：%v", d.callLog())
	}

	// 阻斷列寫不進去時：不得回 BLOCKED
	d2 := &stubDialect{currentDB: "app"}
	f2 := newConsoleFixture(t, d2)
	f2.matcher.hit = true
	f2.matcher.rule = &model.AlertRule{Name: "禁止全表刪除"}
	f2.recorder.insertErrAt = 1
	f2.runQuery("DELETE FROM t")
	if code := lastErrorCode(f2.drain()); code != string(apierror.CodeDBConsoleAuditUnavailable) {
		t.Errorf("阻斷列寫入失敗時回應碼 = %q, want %q（宣稱被擋卻沒有證據，等於說了一件沒有紀錄的事）",
			code, apierror.CodeDBConsoleAuditUnavailable)
	}
}

// TestConsoleMultiStatementBlockedAsWhole 多語句單位整體命中整體不執行
func TestConsoleMultiStatementBlockedAsWhole(t *testing.T) {
	d := &stubDialect{currentDB: "app"}
	f := newConsoleFixture(t, d)
	f.matcher.hit = true
	f.matcher.rule = &model.AlertRule{Name: "危險語句"}

	f.runQuery("SELECT 1; DELETE FROM t; SELECT 2")

	rows, _ := f.recorder.snapshot()
	if len(rows) != 1 {
		t.Fatalf("列數 = %d, want 1（一次送出＝一個執行單位）", len(rows))
	}
	if !strings.Contains(rows[0].Command, "DELETE") || !strings.Contains(rows[0].Command, "SELECT 1") {
		t.Errorf("列的原文未保留整段送出內容：%q", rows[0].Command)
	}
	if i := indexOfPrefix(d.callLog(), "exec:"); i >= 0 {
		t.Errorf("整體命中卻仍送出：%v", d.callLog())
	}
}

// TestConsoleAlertMatchingUsesSameEntry 未命中阻斷時，列仍走與命令列同一個
// 告警比對入口
func TestConsoleAlertMatchingUsesSameEntry(t *testing.T) {
	d := &stubDialect{currentDB: "app", execOutcomes: []*dbconsole.ExecOutcome{okOutcome(1)}}
	f := newConsoleFixture(t, d)

	f.runQuery("SELECT 1")

	if len(f.matcher.matched) != 1 || f.matcher.matched[0].Command != "SELECT 1" {
		t.Fatalf("告警比對收到的批次 = %+v, want 一筆 SELECT 1", f.matcher.matched)
	}
}

// TestConsoleBackfillStatuses 八值狀態的回填：partial、三種 effect_unknown、
// 交易態一併寫入
func TestConsoleBackfillStatuses(t *testing.T) {
	cases := []struct {
		name    string
		outcome *dbconsole.ExecOutcome
		status  string
		reason  string
		txState string
	}{
		{"部分生效", &dbconsole.ExecOutcome{Status: dbconsole.StatusPartial,
			Reason: dbconsole.ReasonErrorAfterResults, Sets: okOutcome(3).Sets,
			DBError: &dbconsole.DBError{Code: "1054", Message: "Unknown column"},
			TxState: dbconsole.TxStateUnknown},
			model.ResultStatusPartial, model.ReasonErrorAfterResults, model.TxStateUnknown},
		{"取消未獲確認", &dbconsole.ExecOutcome{Status: dbconsole.StatusEffectUnknown,
			Reason: dbconsole.ReasonCancelUnconfirmed, TxState: dbconsole.TxStateUnknown},
			model.ResultStatusEffectUnknown, model.ReasonCancelUnconfirmed, model.TxStateUnknown},
		{"逾時未獲確認", &dbconsole.ExecOutcome{Status: dbconsole.StatusEffectUnknown,
			Reason: dbconsole.ReasonTimeoutUnconfirmed, TxState: dbconsole.TxStateUnknown},
			model.ResultStatusEffectUnknown, model.ReasonTimeoutUnconfirmed, model.TxStateUnknown},
		{"送出後連線中斷", &dbconsole.ExecOutcome{Status: dbconsole.StatusEffectUnknown,
			Reason: dbconsole.ReasonConnectionLost, TxState: dbconsole.TxStateUnknown},
			model.ResultStatusEffectUnknown, model.ReasonConnectionLost, model.TxStateUnknown},
		{"交易進行中", &dbconsole.ExecOutcome{Status: dbconsole.StatusOK,
			TxState: dbconsole.TxStateActive},
			model.ResultStatusOK, "", model.TxStateActive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &stubDialect{currentDB: "app", execOutcomes: []*dbconsole.ExecOutcome{tc.outcome}}
			f := newConsoleFixture(t, d)
			f.runQuery("BEGIN; UPDATE t SET a=1")

			rows, backfill := f.recorder.snapshot()
			if len(rows) != 1 {
				t.Fatalf("列數 = %d, want 1", len(rows))
			}
			facts, ok := backfill[rows[0].ID]
			if !ok {
				t.Fatalf("列 %d 未回填", rows[0].ID)
			}
			if facts.Status != tc.status || facts.Reason != tc.reason {
				t.Errorf("回填 = %s/%s, want %s/%s", facts.Status, facts.Reason, tc.status, tc.reason)
			}
			if facts.TxState != tc.txState {
				t.Errorf("tx_state_after = %q, want %q", facts.TxState, tc.txState)
			}
			if facts.TxState == "" {
				t.Errorf("tx_state_after 為空字串——空字串在這個欄位上的語義是「命令列的列」")
			}
		})
	}
}

// TestConsoleTerminalStateNotUpdatableAgain 狀態只能自 running 單向轉入終態：
// 回填條件帶 `result_status='running'`，故對已是終態的列再回填零列受影響
func TestConsoleTerminalStateNotUpdatableAgain(t *testing.T) {
	env := setupConsoleEnv(t, "mysql")
	store := newConsoleCommandStore(env.db)
	row := consoleCommandRow(1, 1, nil, 1, "01J000000000000000000000AA", "app", "SELECT 1")
	row.ResultStatus = model.ResultStatusRunning
	row.TxStateAfter = model.TxStateUnknown
	if err := store.Insert(row); err != nil {
		t.Fatalf("insert: %v", err)
	}
	rows64 := int64(3)
	if err := store.Backfill(row.ID, consoleResultFacts{Status: model.ResultStatusOK,
		ResultRows: &rows64, TxState: model.TxStateNone}); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	// 第二次回填（模擬遲到的另一條路徑）：不得改動已終結的事實
	if err := store.Backfill(row.ID, consoleResultFacts{Status: model.ResultStatusError,
		TxState: model.TxStateFailed}); err != nil {
		t.Fatalf("second backfill: %v", err)
	}
	var got struct {
		ResultStatus string
		TxStateAfter string
	}
	if err := env.db.Model(&model.SessionCommand{}).
		Select("result_status", "tx_state_after").Where("id = ?", row.ID).
		Scan(&got).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.ResultStatus != model.ResultStatusOK {
		t.Fatalf("result_status = %q, want ok（終態被改寫即審計不可信）", got.ResultStatus)
	}
	if got.TxStateAfter != model.TxStateNone {
		t.Errorf("tx_state_after = %q, want none", got.TxStateAfter)
	}
}

// TestConsoleAllowedListNarrowingDeniesNextUnit 管理者縮限清單後，
// 既有會話的下一個單位即被拒（每次動作重讀，不快照）
func TestConsoleAllowedListNarrowingDeniesNextUnit(t *testing.T) {
	d := &stubDialect{currentDB: "app", execOutcomes: []*dbconsole.ExecOutcome{okOutcome(1)}}
	f := newConsoleFixture(t, d)

	f.runQuery("SELECT 1")
	if n := len(f.recorder.rows); n != 1 {
		t.Fatalf("縮限前應照常執行，列數 = %d", n)
	}
	f.env.setAllowedDatabases(t, model.StringList{"other"})
	f.drain()

	f.runQuery("SELECT 2")

	if n := len(f.recorder.rows); n != 1 {
		t.Fatalf("縮限後仍寫了新列（列數 = %d）——被拒的執行不產生執行單位", n)
	}
	if code := lastErrorCode(f.drain()); code != string(apierror.CodeDBConsoleDatabaseNotAllowed) {
		t.Errorf("回應碼 = %q, want %q", code, apierror.CodeDBConsoleDatabaseNotAllowed)
	}
	if !hasAuditKind(f.env.auditRows(t), consoleKindTargetDenied) {
		t.Errorf("目標受限拒絕未留痕")
	}
}

// TestConsoleAllowedListRereadPerUnit 重讀粒度是**執行單位**而不是送出。
//
// 一次送出可含多個批次，而每個批次各有一份完整的語句逾時額度——
// 只在送出前讀一次，那段窗口內管理者的縮限就對後面的批次不生效。
// 本測試把縮限放在第一個批次的執行當下，第二個批次必須在送出前被拒
func TestConsoleAllowedListRereadPerUnit(t *testing.T) {
	d := &stubDialect{currentDB: "app", execOutcomes: []*dbconsole.ExecOutcome{okOutcome(1)}}
	f := newConsoleFixture(t, d)
	f.s.protocol = dbconsole.ProtocolMSSQL
	f.env.setAllowedDatabases(t, model.StringList{"app"})

	// 管理者於第一個批次執行期間縮限清單
	d.execHook = func() { f.env.setAllowedDatabases(t, model.StringList{"other"}) }

	units, err := dbconsole.SplitUnits(dbconsole.ProtocolMSSQL, "SELECT 1\nGO\nSELECT 2")
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if len(units) != 2 {
		t.Fatalf("批次數 = %d, want 2", len(units))
	}
	f.s.runSubmission(units)

	if n := countPrefix(d.callLog(), "exec:"); n != 1 {
		t.Errorf("送出次數 = %d, want 1（第二個批次應在送出前即被拒）", n)
	}
	rows, _ := f.recorder.snapshot()
	if len(rows) != 2 {
		t.Fatalf("列數 = %d, want 2（每個批次一列，含未送出者）", len(rows))
	}
	if rows[1].ResultStatus != model.ResultStatusCancelled ||
		rows[1].ResultReason != model.ReasonBatchStopped {
		t.Errorf("第二個批次的列 = %s/%s, want cancelled/batch_stopped",
			rows[1].ResultStatus, rows[1].ResultReason)
	}
	if code := lastErrorCode(f.drain()); code != string(apierror.CodeDBConsoleDatabaseNotAllowed) {
		t.Errorf("回應碼 = %q, want %q", code, apierror.CodeDBConsoleDatabaseNotAllowed)
	}
	if !hasAuditKind(f.env.auditRows(t), consoleKindTargetDenied) {
		t.Errorf("單位粒度的目標受限拒絕未留痕")
	}
	if !f.s.isRestricted() {
		t.Errorf("縮限後未進入目標受限態")
	}
}

// TestConsoleDriftEntersRestrictedWithoutRedial 漂移進受限態且不重建連線
func TestConsoleDriftEntersRestrictedWithoutRedial(t *testing.T) {
	d := &stubDialect{currentDB: "app", execOutcomes: []*dbconsole.ExecOutcome{okOutcome(0)}}
	// 執行後目標端的當前庫變了（單位內含 USE）
	d.execHook = func() {
		d.mu.Lock()
		d.currentDB = "mysql"
		d.mu.Unlock()
	}
	f := newConsoleFixture(t, d)
	f.env.setAllowedDatabases(t, model.StringList{"app"})

	f.runQuery("USE mysql")

	if !f.s.isRestricted() {
		t.Fatalf("漂移到清單外的庫之後未進入目標受限態")
	}
	if d.dialCount != 0 {
		t.Errorf("漂移後重撥次數 = %d, want 0（重撥要重新解封憑證，那是一次沒有票的連線建立）", d.dialCount)
	}
	if !hasAuditKind(f.env.auditRows(t), consoleKindTargetDenied) {
		t.Errorf("漂移拒絕未留痕")
	}

	// 受限態下的下一個單位一律被拒
	before := len(f.recorder.rows)
	f.runQuery("SELECT 1")
	if len(f.recorder.rows) != before {
		t.Errorf("受限態下仍執行了新單位")
	}
}

// TestConsoleBatchStoppedRowsAreRecorded MSSQL 的批次序列：第一個失敗即停，
// 未送出的批次各留一列 cancelled/batch_stopped
func TestConsoleBatchStoppedRowsAreRecorded(t *testing.T) {
	d := &stubDialect{currentDB: "app", execOutcomes: []*dbconsole.ExecOutcome{
		{Status: dbconsole.StatusError, TxState: dbconsole.TxStateNone,
			DBError: &dbconsole.DBError{Code: "207", Message: "Invalid column name"}},
	}}
	f := newConsoleFixture(t, d)
	f.s.protocol = dbconsole.ProtocolMSSQL

	units, err := dbconsole.SplitUnits(dbconsole.ProtocolMSSQL, "SELECT bad\nGO\nSELECT 1\nGO\nSELECT 2")
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if len(units) != 3 {
		t.Fatalf("批次數 = %d, want 3", len(units))
	}
	f.s.runSubmission(units)

	rows, _ := f.recorder.snapshot()
	if len(rows) != 3 {
		t.Fatalf("列數 = %d, want 3（每個批次一列，含未送出者）", len(rows))
	}
	for _, r := range rows[1:] {
		if r.ResultStatus != model.ResultStatusCancelled || r.ResultReason != model.ReasonBatchStopped {
			t.Errorf("未送出批次的列 = %s/%s, want cancelled/batch_stopped", r.ResultStatus, r.ResultReason)
		}
	}
	if n := countPrefix(d.callLog(), "exec:"); n != 1 {
		t.Errorf("送出次數 = %d, want 1（第一個失敗即停）", n)
	}
}

// TestConsoleSessionEndWithOpenTransaction 會話結束時交易仍未提交即留一筆事實
func TestConsoleSessionEndWithOpenTransaction(t *testing.T) {
	d := &stubDialect{currentDB: "app", execOutcomes: []*dbconsole.ExecOutcome{
		{Status: dbconsole.StatusOK, TxState: dbconsole.TxStateActive}}}
	f := newConsoleFixture(t, d)

	f.runQuery("BEGIN; DELETE FROM t")
	f.s.auditSessionEndTransaction()

	rows := f.env.auditRows(t)
	if !hasAuditKind(rows, consoleKindSessionEndTxOpn) {
		t.Fatalf("交易未提交而結束卻無事件留痕（列：%d）", len(rows))
	}
	var found bool
	for _, r := range rows {
		if strings.Contains(r.RequestBody, consoleKindSessionEndTxOpn) {
			found = strings.Contains(r.RequestBody, `"tx_state":"`+model.TxStateActive+`"`)
		}
	}
	if !found {
		t.Errorf("事件未記下結束當下的交易態")
	}
}

// TestConsoleTranscriptCarriesEventID 轉錄的每一行都帶得回同一個事件識別
func TestConsoleTranscriptCarriesEventID(t *testing.T) {
	d := &stubDialect{currentDB: "app", execOutcomes: []*dbconsole.ExecOutcome{okOutcome(2)}}
	f := newConsoleFixture(t, d)

	f.runQuery("SELECT 1")

	rows, _ := f.recorder.snapshot()
	if len(rows) != 1 {
		t.Fatalf("列數 = %d", len(rows))
	}
	text := f.sink.String()
	lines := strings.Split(strings.TrimSpace(text), "\r\n")
	if len(lines) != 2 {
		t.Fatalf("轉錄行數 = %d, want 2（語句行＋結果行）：%q", len(lines), text)
	}
	for _, ln := range lines {
		if !strings.Contains(ln, rows[0].EventID) {
			t.Errorf("轉錄行 %q 不含事件識別 %s——沒有它，轉錄與紀錄就對不回去", ln, rows[0].EventID)
		}
	}
	if strings.Contains(text, "\"c\"") || strings.Contains(text, "row_count") {
		t.Errorf("轉錄含結果資料：%q", text)
	}
}

// ---------------------------------------------------------------------------

type errNotAvailable struct{}

func (errNotAvailable) Error() string { return "規則快取載入失敗" }

func indexOfPrefix(calls []string, prefix string) int {
	for i, c := range calls {
		if strings.HasPrefix(c, prefix) {
			return i
		}
	}
	return -1
}

func countPrefix(calls []string, prefix string) int {
	n := 0
	for _, c := range calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func lastErrorCode(msgs []map[string]any) string {
	code := ""
	for _, m := range msgs {
		if m["type"] == consoleMsgError {
			if s, ok := m["code"].(string); ok {
				code = s
			}
		}
	}
	return code
}

func hasAuditKind(rows []model.AuditLog, kind string) bool {
	for _, r := range rows {
		if strings.Contains(r.RequestBody, `"kind":"`+kind+`"`) {
			return true
		}
	}
	return false
}

// TestConsoleRealMatcherFailsCloseWhenRulesUnavailable 正式組裝下的 fail-close。
//
// 本測試刻意用**產品的比對器本體**而非測試替身：可用性的判定若只有替身答得出來，
// 那條 fail-close 分支在真實組裝下就永遠走不到，而它要防的正是規則來源讀不到
// 這件事——規則載入失敗時比對器帶著空快取留在原位，比對結果與「沒有規則要擋」
// 完全同形，於是每一句語句都會被放行。
//
// 兩半都驗：規則來源不可用時 fail-close，來源恢復後同一個比對器自行復原。
func TestConsoleRealMatcherFailsCloseWhenRulesUnavailable(t *testing.T) {
	d := &stubDialect{currentDB: "app", execOutcomes: []*dbconsole.ExecOutcome{okOutcome(1)}}
	f := newConsoleFixture(t, d)

	// 失效通報的落地面（不初始化的話通報無處可寫，看不出它有沒有發生）
	if err := f.env.db.AutoMigrate(&model.AuditFailureEvent{}); err != nil {
		t.Fatalf("migrate audit_failure_events: %v", err)
	}
	audit.InitAuditFailure(f.env.db, policy.NewSecurityPolicyService(f.env.db))
	t.Cleanup(audit.ResetAuditFailureSingleton)

	// 規則讀不到＝規則載入失敗。比對器本體照常建構、照常註冊——
	// 這正是啟動時規則載入失敗後留下的狀態
	if err := f.env.db.Migrator().DropTable(&model.AlertRule{}); err != nil {
		t.Fatalf("移除規則表: %v", err)
	}
	real := audit.NewAlertMatcher(f.env.db, audit.NewAlertRecorder(f.env.db))
	f.s.matcher = consoleMatcherOf(real)

	f.runQuery("SELECT 1")

	if i := indexOfPrefix(d.callLog(), "exec:"); i >= 0 {
		t.Fatalf("規則載入失敗時仍送出語句（序列 %v）——刪掉規則就等於關掉阻斷", d.callLog())
	}
	rows, _ := f.recorder.snapshot()
	if len(rows) != 1 || rows[0].ResultStatus != model.ResultStatusBlocked ||
		rows[0].ResultReason != model.ReasonMatcherUnavailable {
		t.Fatalf("列 = %+v, want blocked/matcher_unavailable", rows)
	}
	if code := lastErrorCode(f.drain()); code != string(apierror.CodeDBConsoleBlockerUnavailable) {
		t.Errorf("回應碼 = %q, want %q", code, apierror.CodeDBConsoleBlockerUnavailable)
	}
	var failures int64
	if err := f.env.db.Model(&model.AuditFailureEvent{}).
		Where("mechanism = ?", model.MechanismCommandBlocking).Count(&failures).Error; err != nil {
		t.Fatalf("查失效事件: %v", err)
	}
	if failures != 1 {
		t.Errorf("失效事件 = %d 筆, want 1——阻斷失效只留一行啟動日誌是看不見的", failures)
	}

	// 規則來源恢復：同一個比對器不必等人去改規則就該復原，且行為與規則正常時無異
	if err := f.env.db.AutoMigrate(&model.AlertRule{}); err != nil {
		t.Fatalf("migrate alert_rules: %v", err)
	}
	f.runQuery("SELECT 1")

	if i := indexOfPrefix(d.callLog(), "exec:"); i < 0 {
		t.Fatalf("規則來源恢復後仍不送出語句（序列 %v）", d.callLog())
	}
	rows, _ = f.recorder.snapshot()
	if len(rows) != 2 || rows[1].ResultStatus != model.ResultStatusRunning {
		t.Fatalf("第二列 = %+v, want 一列自 running 起算的正常執行", rows)
	}
}

// TestConsoleSwitchDeniedRecordsSwitchTrigger 切庫被清單擋下時的觸發點。
//
// 觸發點答的是「這筆拒絕是哪個動作引起的」。切庫當下沒有任何執行單位，
// 記成執行會讓稽核以為使用者送了一句語句——而那一句不存在。
func TestConsoleSwitchDeniedRecordsSwitchTrigger(t *testing.T) {
	d := &stubDialect{currentDB: "app"}
	f := newConsoleFixture(t, d)
	f.env.setAllowedDatabases(t, model.StringList{"app"})

	f.s.handleSwitch("mysql")

	if code := lastErrorCode(f.drain()); code != string(apierror.CodeDBConsoleDatabaseNotAllowed) {
		t.Fatalf("回應碼 = %q, want %q", code, apierror.CodeDBConsoleDatabaseNotAllowed)
	}
	rows := f.env.auditRows(t)
	if !hasAuditKind(rows, consoleKindTargetDenied) {
		t.Fatalf("切庫被拒未留受限拒絕的痕跡")
	}
	for _, r := range rows {
		if !strings.Contains(r.RequestBody, `"kind":"`+consoleKindTargetDenied+`"`) {
			continue
		}
		if !strings.Contains(r.RequestBody, `"trigger":"`+consoleTriggerSwitch+`"`) {
			t.Errorf("切庫拒絕列的觸發點不是切庫：%s", r.RequestBody)
		}
		if strings.Contains(r.RequestBody, `"trigger":"`+consoleTriggerExecute+`"`) {
			t.Errorf("切庫拒絕列標成執行，但當下沒有任何執行單位：%s", r.RequestBody)
		}
	}
	if len(f.recorder.rows) != 0 {
		t.Errorf("被拒的切庫寫了 %d 列語句紀錄——切庫不是執行單位", len(f.recorder.rows))
	}
}
