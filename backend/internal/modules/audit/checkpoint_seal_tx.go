package audit

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/custodexa/backend/internal/model"
	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
)

// 封章的單一交易：帳本區間、權限附證（含首次啟用）、簽章與落庫在同一個交易內提交。
//
// 啟用事件與它的第一個帶附證檢查點同交易提交，資料庫裡不會出現「有啟用事件、沒有檢查點」
// 的狀態；首次封章失敗整筆回滾，下一輪重來仍是起點，沒有另一條重試分支。
//
// 順序（PG）：
//  1. LOCK agent_tool_calls IN SHARE MODE（等在途帳本 INSERT 落地），隔離 REPEATABLE READ。
//     表鎖在第一個 SELECT 之前取得，快照在第一個 SELECT 才凍結。
//  2. 帳本上界與聚合。
//  3. 讀起點判定所需的事實（permissionLineage）；讀取失敗本輪不封章。
//  4. 起點旗標＝clean()。
//  5. 讀權限狀態（savepoint 內）；首次啟用路徑對 authz_state 單列取列鎖；寫啟用事件或取鏈頭。
//  6. 填附證欄；對帳結果由交易內對帳決定（起點沒有前一個基準可比，固定 null）。
//  7. 一次簽章（載荷含 perm），INSERT。
//  8. 提交。
//
// 首次啟用與合法權限寫入的交界：所有合法權限寫入都在自己的交易內 UPDATE authz_state 單列
// （authz.AdvanceVersion），封章在啟用路徑經 authz 注入的交界鎖（SetPermissionActivationLock）對同一列取 FOR UPDATE。快照凍結後若有權限寫入已提交，
// PG 回 40001，本輪整筆回滾並立即重試一次（新快照看得到那筆寫入）；之後才開始的寫入等封章提交，
// 再以啟用事件為鏈頭寫下自己的變更事件。三種交錯都自動相符。已啟用時不取這把鎖。

// sealFaults 封章交易內的同步點與故障注入（測試專用，生產路徑恆為零值）。
type sealFaults struct {
	// beforeActivationLock 讀完權限狀態之後、取 authz_state 列鎖之前呼叫（僅啟用路徑）
	beforeActivationLock func()
	// afterActivationLock 取得 authz_state 列鎖之後、寫啟用事件之前呼叫（僅啟用路徑）
	afterActivationLock func()
}

// permSealOutcome 交易結束之後才做的留痕與結案（不在持鎖交易內向 s.db 要連線）。
type permSealOutcome struct {
	readFailure error // 可延後啟用分支：讀權限狀態失敗、已封出 perm 為 null 的點
	attested    bool  // 本點帶附證
}

// sealInTx 單一封章交易（見檔頭）。40001 時立即重試一次，再失敗回錯（下一輪 Tick 重來）。
func (s *CheckpointService) sealInTx(last *model.AuditCheckpoint, cp *model.AuditCheckpoint) error {
	var outcome permSealOutcome
	attempt := func() error {
		outcome = permSealOutcome{}
		cp.ID = 0
		clearCheckpointPerm(cp)
		return s.db.Transaction(func(tx *gorm.DB) error {
			if err := sealLedgerInterval(tx, last, cp); err != nil {
				return err
			}
			if err := s.attachPermission(tx, cp, &outcome); err != nil {
				return err
			}
			return s.signAndPersistDB(tx, cp)
		}, repeatableRead(s.db)...)
	}
	err := attempt()
	if isSerializationFailure(err) {
		log.Printf("[Checkpoint] 封章與同時進行的權限寫入衝突，讓位後立即重試一次")
		err = attempt()
	}
	if err != nil {
		return err
	}
	switch {
	case outcome.readFailure != nil:
		// 不擋封章，但失敗不可無痕：經既有失效事件通道留痕並告警（交易已結束）
		s.roleState.ReportPermissionReadFailure(outcome.readFailure)
	case outcome.attested:
		// 讀取恢復並完成啟用／附證：結案先前的讀取失敗
		s.roleState.ResolvePermissionReadFailure()
	}
	return nil
}

func clearCheckpointPerm(cp *model.AuditCheckpoint) {
	cp.PermStateSnapshot, cp.PermFormat, cp.PermEventSeq, cp.PermEventHead, cp.PermReconciled, cp.PermOrigin = nil, nil, nil, nil, nil, nil
}

// isSerializationFailure PG 的序列化衝突（REPEATABLE READ 下對快照後被更新的列取鎖）。
func isSerializationFailure(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40001"
}

// sealLedgerInterval 步驟 1–2：帳本表鎖、上界與聚合。
//
// SHARE waits for in-flight ledger INSERT transactions before capturing the upper
// bound and prevents late commits below that bound. Results may change after sealing.
func sealLedgerInterval(tx *gorm.DB, last *model.AuditCheckpoint, cp *model.AuditCheckpoint) error {
	if !checkpointHasLedger(cp.AggScheme) {
		return nil
	}
	if tx.Dialector.Name() == "postgres" {
		if err := tx.Exec("LOCK TABLE agent_tool_calls IN SHARE MODE").Error; err != nil {
			return err
		}
	}
	var to uint
	if err := tx.Model(&model.AgentToolCall{}).Select("COALESCE(MAX(id),0)").Scan(&to).Error; err != nil {
		return fmt.Errorf("ledger upper bound: %w", err)
	}
	from := uint(1)
	if last == nil {
		to = 0 // Genesis starts ledger coverage at the first row, without claiming pre-existing rows yet.
	} else if checkpointHasLedger(last.AggScheme) && last.ToolCallIDTo != nil {
		from = *last.ToolCallIDTo + 1
		if to < *last.ToolCallIDTo {
			to = *last.ToolCallIDTo
		}
	}
	hash, count, err := aggregateToolCalls(tx, from, to)
	if err != nil {
		return err
	}
	cp.ToolCallIDFrom, cp.ToolCallIDTo, cp.ToolCallRowCount, cp.ToolCallAggHash = &from, &to, &count, &hash
	return nil
}

// attachPermission 步驟 3–6：起點判定、讀權限狀態、首次啟用、填附證欄。
// 來源未注入（單元測試夾具）或載荷版本在第四版之前時不產生附證。
func (s *CheckpointService) attachPermission(tx *gorm.DB, cp *model.AuditCheckpoint, out *permSealOutcome) error {
	if !PermissionSourcesWired() || cp.AggScheme != model.AggSchemeV4 {
		return nil
	}
	ctx := context.Background()
	lin, err := readPermissionLineage(tx, s.signer)
	if err != nil {
		// 讀不到起點判定的事實就證明不了 clean()：本輪不封章，沒有 null 點分支
		return fmt.Errorf("封章前讀取權限附證事實失敗（本輪不封章）: %w", err)
	}
	origin := lin.clean()

	// 5a：只有這一讀包在 savepoint 內。PG 上讀取的 SQL 錯誤使交易進入 aborted 狀態，
	// 回到 savepoint 才能繼續封出 perm 為 null 的點。
	if err := tx.SavePoint("perm_read").Error; err != nil {
		return err
	}
	state, rerr := ReadPermissionState(ctx, tx)
	if rerr != nil {
		if !origin {
			// 有痕跡或事件卻讀不到權限狀態：不得藉讀取失敗退回尚未涵蓋
			return fmt.Errorf("封章前取權限狀態失敗（本輪不封章）: %w", rerr)
		}
		if err := tx.RollbackTo("perm_read").Error; err != nil {
			return fmt.Errorf("讀取權限狀態失敗後回到 savepoint 失敗（本輪不封章）: %w", err)
		}
		log.Printf("[Checkpoint] 權限附證尚未啟用，且讀取權限狀態失敗，啟用延後（本點不帶附證）: %v", rerr)
		out.readFailure = rerr
		return nil
	}

	// 5b：首次啟用路徑的交界鎖
	activating := !lin.eventsExist
	if activating {
		if hook := s.faults.beforeActivationLock; hook != nil {
			hook()
		}
		if err := lockPermissionActivation(ctx, tx); err != nil {
			return err
		}
		if hook := s.faults.afterActivationLock; hook != nil {
			hook()
		}
	}

	// 5c：寫啟用事件或取鏈頭
	head, err := EnsurePermissionActivation(ctx, tx, state, int64(cp.Seq))
	if err != nil {
		return err
	}
	body, err := state.Encode()
	if err != nil {
		return err
	}
	// 鏈頭摘要取現算值（不取摘要欄）：欄位被改成任意字串時，封章不因它而停擺；
	// 現算值與欄位不符時，之後自本點起算的錨定檢查照樣判無法判定。
	snap, format, headDigest := string(body), PermissionStateFormatVersion, permissionEventDigest(head)
	cp.PermStateSnapshot, cp.PermFormat = &snap, &format
	cp.PermEventSeq, cp.PermEventHead = &head.Seq, &headDigest
	cp.PermOrigin = &origin
	// 6：無法判定或尚未涵蓋時留空；留空的附證保留當下現況作證據，但永遠不成為對帳基準
	// （起點例外，起點以簽章內的旗標辨識）。本交易寫下啟用事件時沒有前一個基準可比。
	cp.PermReconciled = nil
	if !activating && s.signer != nil {
		switch rep := ReconcilePermissionState(ctx, tx, s.signer); rep.State {
		case "match":
			t := true
			cp.PermReconciled = &t
		case "mismatch":
			f := false
			cp.PermReconciled = &f
		}
	}
	out.attested = true
	return nil
}
