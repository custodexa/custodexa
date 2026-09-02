package sshproxy

import (
	"context"
	"errors"
	"log"
	"strconv"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/dbconsole"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// handleQuery 一次送出。
//
// 訊息層的三道檢查（大小、互斥、目標範圍）**不產生語句紀錄列**：它們攔下的
// 不是一個執行單位，而是一個畸形或越界的請求。真正的執行單位自
// runSubmission 起算，那裡的每一個單位都會先有一列
func (s *consoleSession) handleQuery(text string) {
	if len(text) > dbconsole.MaxStatementBytes {
		s.sendError("", apierror.CodeDBConsoleStatementTooLarge, nil, nil)
		return
	}
	units, err := dbconsole.SplitUnits(s.protocol, text)
	if errors.Is(err, dbconsole.ErrGoCountUnsupported) {
		s.sendError("", apierror.CodeDBConsoleGoCountUnsupported, nil, nil)
		return
	}
	if err != nil {
		s.sendError("", apierror.CodeBadRequestFormat, nil, nil)
		return
	}
	if len(units) == 0 {
		return
	}
	if !s.acquire() {
		s.sendError("", apierror.CodeDBConsoleBusy, nil, nil)
		return
	}

	// 執行不在讀取迴圈上：迴圈要繼續收 `cancel`，否則取消永遠送不進來。
	// 而語句的 ctx **不綁 WebSocket**——客戶端走了，語句照樣跑完並回填真相
	s.inWork.Add(1)
	go func() {
		defer s.inWork.Done()
		defer s.release()
		s.runSubmission(units)
	}()
}

// runSubmission 逐單位執行。第一個失敗即停止後續批次（MSSQL 的 GO 序列），
// 未送出的批次各留一列——那些列記的是「從未送出」，不是「執行失敗」
func (s *consoleSession) runSubmission(units []string) {
	allowed, current, ok := s.resolveTarget()
	if !ok {
		return
	}

	// 快取範圍＝最近一次送出：新的送出即清空舊的
	s.cache.reset()

	var budget *dbconsole.Submission
	if _, budgeted := s.currentDialect().(dbconsole.BudgetedDialect); budgeted && len(units) > 1 {
		budget = dbconsole.NewSubmission()
	}

	stopped := false
	for i, unit := range units {
		// 允許清單於**每個執行單位執行前**重讀，而不是每次送出前讀一次。
		// 一次送出可能含多個批次，前一個批次的執行期間（每個批次各有一份
		// 完整的語句逾時額度）足夠管理者縮限清單——讀一次就等於在那段窗口內
		// 沿用一份過期的授權
		if !stopped && i > 0 {
			var ok bool
			allowed, current, ok = s.resolveTarget()
			if !ok {
				stopped = true
			}
		}
		if stopped {
			s.recordNotSent(unit, current, i, len(units))
			continue
		}
		if !s.runUnit(unit, current, allowed, i, len(units), budget) {
			stopped = true
		}
	}
}

// resolveTarget 目標範圍檢查（每個執行單位執行前重讀，不快照）。
//
// **重讀失敗即拒絕**：空清單的語義是「不限制」，把讀取失敗當成空清單，
// 會讓資料庫的一次短暫故障變成一次靜默的範圍放寬。
//
// 被拒時仍回當前資料庫名——呼叫端要用它為未送出的單位留列
func (s *consoleSession) resolveTarget() (model.StringList, string, bool) {
	current := s.currentDialect().CurrentDatabase()
	allowed, err := s.allowedDatabases()
	if err != nil {
		log.Printf("[DBConsole] 允許清單重讀失敗，拒絕執行 (SessionID=%d): %v", s.sessionID(), err)
		s.auditCtx.auditTargetDenied(current, current, consoleTriggerExecute)
		s.sendError("", apierror.CodeDBConsoleDatabaseNotAllowed, nil, nil)
		return nil, current, false
	}
	if s.isRestricted() || !databaseAllowed(allowed, current) {
		s.setRestricted(true)
		s.auditCtx.auditTargetDenied(current, current, consoleTriggerExecute)
		s.sendError("", apierror.CodeDBConsoleDatabaseNotAllowed, nil, nil)
		return nil, current, false
	}
	return allowed, current, true
}

// recordNotSent 前一個批次失敗後未送出的批次。
//
// 直接以終態寫入而不經 running：它從來沒有被送出，中間態不存在。
// `cancelled` 的語義正是「確認未生效」，這是它成立得最徹底的一種情形
func (s *consoleSession) recordNotSent(unit, database string, index, total int) {
	eventID, err := dbconsole.NewEventID()
	if err != nil {
		log.Printf("[DBConsole] 事件識別產生失敗: %v", err)
		return
	}
	row := consoleCommandRow(s.sessionID(), s.userID, s.assetRef(), s.nextSeq(), eventID, database, unit)
	row.ResultStatus = model.ResultStatusCancelled
	row.ResultReason = model.ReasonBatchStopped
	row.TxStateAfter = s.txStateOrUnknown()
	if err := s.recorder.Insert(row); err != nil {
		s.reportAuditFailure(err)
		return
	}
	s.transcript.Terminal(eventID, model.ResultStatusCancelled, model.ReasonBatchStopped)
	s.send(consoleResultMessage{Type: consoleMsgResult, EventID: eventID, Seq: row.Seq,
		Status: model.ResultStatusCancelled, ResultReason: model.ReasonBatchStopped,
		Sets: []dbconsole.ResultSet{}, TxState: s.txStateOrUnknown()})
	_ = index
	_ = total
}

// runUnit 一個執行單位的完整順序。回傳「後續批次可否繼續」。
//
// 順序是安全紅線，不是實作偏好：
//   - 列 INSERT 早於任何目標端效果；
//   - 回應晚於阻斷證據持久化；
//   - INSERT 失敗即不執行。
//
// 三者任一被調換，都會產生「對目標生效但沒有留痕」或「說了被擋但證據沒落地」
// 的窗口，而這條路徑沒有第二個真相來源可以事後補
func (s *consoleSession) runUnit(unit, database string, allowed model.StringList,
	index, total int, budget *dbconsole.Submission) bool {
	eventID, err := dbconsole.NewEventID()
	if err != nil {
		log.Printf("[DBConsole] 事件識別產生失敗: %v", err)
		s.sendError("", apierror.CodeDBConsoleAuditUnavailable, nil, nil)
		return false
	}
	seq := s.nextSeq()
	row := consoleCommandRow(s.sessionID(), s.userID, s.assetRef(), seq, eventID, database, unit)

	// 步驟 3：阻斷比對。比對器不可用與規則命中都不送目標端，
	// 差別在原因碼——前者是我們的故障，後者是規則生效
	rule, hit, available := s.matchBlock(unit)
	if !available {
		row.ResultStatus = model.ResultStatusBlocked
		row.ResultReason = model.ReasonMatcherUnavailable
		row.TxStateAfter = s.txStateOrUnknown()
		if insErr := s.recorder.Insert(row); insErr != nil {
			s.reportAuditFailure(insErr)
			s.sendError(eventID, apierror.CodeDBConsoleAuditUnavailable, nil, nil)
			return false
		}
		s.reportBlockerFailure()
		s.transcript.BlockerUnavailable(eventID)
		s.sendError(eventID, apierror.CodeDBConsoleBlockerUnavailable, nil, nil)
		return false
	}
	if hit {
		row.ResultStatus = model.ResultStatusBlocked
		row.ResultReason = model.ReasonMatcherHit
		row.TxStateAfter = s.txStateOrUnknown()
		if insErr := s.recorder.Insert(row); insErr != nil {
			// 阻斷證據沒落地就先回應，等於宣稱了一件沒有紀錄的事
			s.reportAuditFailure(insErr)
			s.sendError(eventID, apierror.CodeDBConsoleAuditUnavailable, nil, nil)
			return false
		}
		s.recordBlockedAlert(rule, unit)
		s.transcript.Blocked(eventID, ruleName(rule))
		s.sendError(eventID, apierror.CodeDBConsoleStatementBlocked,
			map[string]any{"rule": ruleName(rule)}, nil)
		return false
	}

	// 步驟 5：先寫後執行。寫不進去就不執行——這條路徑的執行者是伺服器自己，
	// 拒絕的代價只是一則錯誤訊息
	row.ResultStatus = model.ResultStatusRunning
	row.TxStateAfter = s.txStateOrUnknown()
	if insErr := s.recorder.Insert(row); insErr != nil {
		s.reportAuditFailure(insErr)
		s.sendError(eventID, apierror.CodeDBConsoleAuditUnavailable, nil, nil)
		return false
	}

	// 步驟 6：告警比對走與命令列同一個入口（失敗只記 log——列已經存在）
	if s.matcher != nil {
		s.matcher.MatchAndStore([]model.SessionCommand{*row}, string(s.protocol))
	}

	// 步驟 7：轉錄語句原文
	s.noteEvent(eventID)
	s.transcript.Statement(database, eventID, unit)
	s.send(consoleUnitStartedMessage{Type: consoleMsgUnitStarted, EventID: eventID,
		Seq: seq, BatchIndex: index, BatchCount: total})

	// 步驟 8：送出。ctx 只綁逾時與明確取消
	started := time.Now()
	outcome, execErr := s.execUnit(unit, budget)
	elapsed := time.Since(started)

	if execErr != nil {
		// 連送都沒送出去，而我們無法證明目標端沒收到——誠實的答案是「不知道」
		outcome = &dbconsole.ExecOutcome{
			Status:         dbconsole.StatusEffectUnknown,
			Reason:         dbconsole.ReasonConnectionLost,
			ConnectionLost: true,
		}
	}

	// 步驟 9：回填。條件更新使狀態只能自 running 單向轉入終態
	facts := consoleFactsFrom(outcome, elapsed, s.txStateOrUnknown())
	if upErr := s.recorder.Backfill(row.ID, facts); upErr != nil {
		log.Printf("[DBConsole] 結果回填失敗（列停在 running）: eventID=%s err=%v", eventID, upErr)
		s.reportAuditFailure(upErr)
	}
	s.setTxState(facts.TxState)

	// 步驟 10：轉錄結果行、快取、回應
	s.writeOutcomeTranscript(eventID, outcome, facts, elapsed)
	if len(outcome.Sets) > 0 {
		s.cache.put(&consoleCachedUnit{EventID: eventID, Seq: seq,
			Database: database, Sets: outcome.Sets})
	}
	s.sendOutcome(eventID, seq, outcome, facts, elapsed)

	s.detectDrift(database, allowed)

	// 步驟 11：目標連線是否還能用。**判準是方言層帶回來的事實，不是原因碼**——
	// 取消與逾時的原因碼講的是使用者問的問題（那一句到底生效了沒），
	// 連線本身的死活被它蓋掉。改以原因碼判斷的話，會話會一路撐到下一個單位
	// 才發現連線早就沒了，而那個單位一個位元組都沒送到目標端就先留下一列紀錄
	if outcome.ConnectionLost {
		s.targetConnectionLost()
		return false
	}
	return outcome.Status == dbconsole.StatusOK
}

// execUnit 送出一個單位。多批次送出共用同一份位元組額度——
// 每個批次各給一份完整額度，等於那條上限對多批次形同不存在
func (s *consoleSession) execUnit(unit string, budget *dbconsole.Submission) (*dbconsole.ExecOutcome, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbconsole.StatementTimeout)
	defer cancel()

	d := s.currentDialect()
	if budget != nil {
		if bd, ok := d.(dbconsole.BudgetedDialect); ok {
			return bd.ExecWithin(ctx, unit, budget)
		}
	}
	return d.Exec(ctx, unit)
}

// consoleFactsFrom 把方言層分類完的結果翻成審計列的欄位。
//
// 分類已經在方言層完成，這裡**不再判讀 driver 錯誤**——判讀散在兩處就會漂移，
// 而漂移的方向不會有人注意到，因為兩邊各自看起來都對
func consoleFactsFrom(o *dbconsole.ExecOutcome, elapsed time.Duration, fallbackTx string) consoleResultFacts {
	var rows int64
	for _, set := range o.Sets {
		rows += int64(set.RowCount)
	}
	sets := int32(len(o.Sets))
	ms := int32(elapsed.Milliseconds())
	affected := o.RowsAffected

	facts := consoleResultFacts{
		Status:       o.Status,
		Reason:       o.Reason,
		ResultRows:   &rows,
		RowsAffected: &affected,
		ResultSets:   &sets,
		DurationMS:   &ms,
		Truncated:    o.Truncated,
		TxState:      o.TxState,
	}
	if facts.TxState == "" {
		facts.TxState = fallbackTx
	}
	if o.DBError != nil {
		facts.ErrorCode = o.DBError.Code
	}
	return facts
}

func (s *consoleSession) writeOutcomeTranscript(eventID string, o *dbconsole.ExecOutcome,
	f consoleResultFacts, elapsed time.Duration) {
	ms := elapsed.Milliseconds()
	rows := int64(0)
	if f.ResultRows != nil {
		rows = *f.ResultRows
	}
	switch o.Status {
	case dbconsole.StatusOK:
		s.transcript.OK(eventID, rows, o.RowsAffected, len(o.Sets), ms)
	case dbconsole.StatusPartial:
		s.transcript.Partial(eventID, rows, o.RowsAffected, len(o.Sets), ms)
		s.transcript.Error(eventID, f.ErrorCode, dbErrorMessage(o.DBError))
	case dbconsole.StatusError:
		s.transcript.Error(eventID, f.ErrorCode, dbErrorMessage(o.DBError))
	default:
		s.transcript.Terminal(eventID, o.Status, o.Reason)
	}
}

func dbErrorMessage(e *dbconsole.DBError) string {
	if e == nil {
		return ""
	}
	return e.Message
}

// sendOutcome 即時回應。**訊息與審計列同源**：兩者由同一個 outcome 生出
func (s *consoleSession) sendOutcome(eventID string, seq int, o *dbconsole.ExecOutcome,
	f consoleResultFacts, elapsed time.Duration) {
	sets := o.Sets
	if sets == nil {
		sets = []dbconsole.ResultSet{}
	}
	s.send(consoleResultMessage{
		Type: consoleMsgResult, EventID: eventID, Seq: seq,
		Status: o.Status, ResultReason: o.Reason, Sets: sets,
		RowsAffected: o.RowsAffected, DurationMS: int32(elapsed.Milliseconds()),
		Truncated: o.Truncated, TxState: f.TxState, DBError: o.DBError,
	})
}

// detectDrift 單位執行後的目標漂移偵測（MySQL／MSSQL 的 `USE`）。
//
// **不重建連線**：重建要重新解封憑證，那是一次沒有票、沒有閘序的連線建立。
// 改為使會話進入目標受限態，後續執行一律拒絕並留痕，直到使用者切回清單內
func (s *consoleSession) detectDrift(before string, allowed model.StringList) {
	after := s.currentDialect().CurrentDatabase()
	if after == "" || after == before {
		return
	}
	if !databaseAllowed(allowed, after) {
		s.setRestricted(true)
		s.auditCtx.auditTargetDenied(after, before, consoleTriggerDrift)
		s.sendNotice(consoleNoticeDatabaseDriftDenied,
			map[string]any{"database": after, "previous": before})
		return
	}
	// 清單為空（不限制）時只同步介面顯示的當前庫
	s.sendNotice(consoleNoticeDatabaseSwitched, map[string]any{"database": after})
}

// ---------------------------------------------------------------------------
// 比對器與失效通報
// ---------------------------------------------------------------------------

// matchBlock 回傳（命中的規則、是否命中、比對器是否可用）。
//
// **比對器缺席即不可用**：命令列那一側的 nil 比對器是直通，理由是位元組流不能
// 為了審計而凍住終端；主控台沒有這個理由——它的執行者是伺服器自己
func (s *consoleSession) matchBlock(unit string) (*model.AlertRule, bool, bool) {
	if s.matcher == nil {
		return nil, false, false
	}
	if err := s.matcher.BlockerHealth(); err != nil {
		log.Printf("[DBConsole] 阻斷比對器不可用: %v", err)
		return nil, false, false
	}
	rule, hit := s.matcher.MatchBlock(unit, string(s.protocol))
	return rule, hit, true
}

func ruleName(rule *model.AlertRule) string {
	if rule == nil {
		return ""
	}
	return rule.Name
}

// recordBlockedAlert 阻斷告警經與命令列同一個落地面（入庫＋通知＋離機轉發）。
// 失敗只記 log：語句**已經**沒有送出，沒有可回滾的東西，
// 而把告警系統故障升級成使用者被踢線並不會讓任何人更安全
func (s *consoleSession) recordBlockedAlert(rule *model.AlertRule, command string) {
	if rule == nil {
		return
	}
	ruleID := rule.ID
	alert := gatewayapi.CommandAlert{
		Kind:        model.AlertKindRule,
		RuleID:      &ruleID,
		RuleName:    rule.Name,
		Level:       rule.Severity,
		Command:     command,
		OccurredAt:  time.Now(),
		SessionID:   s.sessionID(),
		Actor:       gatewayapi.Actor{UserID: s.userID},
		AssetID:     s.assetRef(),
		Disposition: model.AlertDispositionPending,
		Blocked:     true,
	}
	if err := gatewayapi.RecordAlert(context.Background(), s.alerts, alert); err != nil {
		log.Printf("[DBConsole] 阻斷告警落地失敗（語句已阻斷，紀錄未留存）: %v", err)
	}
}

// reportAuditFailure 語句紀錄寫入失敗的失效通報。
// 這條路徑上「寫不進去」等於「這場會話的證據鏈斷了」，不得只記 log
func (s *consoleSession) reportAuditFailure(err error) {
	if failure := audit.GetAuditFailure(); failure != nil {
		failure.Report(model.MechanismAuditWrite, model.CauseCommandAuditWriteRefused,
			map[string]string{
				"session_id":           strconv.FormatUint(uint64(s.sessionID()), 10),
				model.CauseParamDetail: err.Error(),
			})
	}
}

// reportBlockerFailure 比對器不可用的失效通報
func (s *consoleSession) reportBlockerFailure() {
	if failure := audit.GetAuditFailure(); failure != nil {
		failure.Report(model.MechanismCommandBlocking, model.CauseCommandBlockerUnavailable,
			map[string]string{
				"session_id": strconv.FormatUint(uint64(s.sessionID()), 10),
			})
	}
}

func (s *consoleSession) assetRef() *uint {
	if s.assetID == 0 {
		return nil
	}
	id := s.assetID
	return &id
}

// txStateOrUnknown 尚未探詢過時的交易態。
//
// **不得留空字串**：空字串在這個欄位上的既有語義是「命令列的列」，
// 主控台的列帶著它進審計就是一筆說謊的證據
func (s *consoleSession) txStateOrUnknown() string {
	if v := s.currentTxState(); v != "" {
		return v
	}
	return model.TxStateUnknown
}
