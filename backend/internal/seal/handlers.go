package seal

import (
	"context"
	"errors"
	"fmt"
)

// 本檔為 12 格中各終局處置的實作。所有轉態一律經 attempt.casCell → 單一
// CompareAndSwap(observed, new)；柵欄因此涵蓋段 2 的全部終局副作用——發佈、
// faulted 轉態、逾時回退、全域冷卻更新、cleanup 標記的設定與清除——而非僅發佈。
//
// 「標記」走 CAS，「釋放動作」本身不走：釋放必須真的發生，只有其已完成的標記
// 可因非當代而被丟棄。

// abortUnsettled 是 defer 安全網的分派：依所處階段選擇 3b／4b／6。
func (a *attempt) abortUnsettled(cause error) error {
	switch a.phase {
	case phasePrePrepare:
		return a.abortPrePrepare(CodeAborted, cause)
	case phasePostPrepare:
		return a.abortPostPrepare(cause)
	default:
		return a.initFailed(cause, nil)
	}
}

// abortPrePrepare 為格 3b：received 落地前的任何終止——請求取消／panic／
// 寫入 I/O 失敗／寫入逾時。回 sourceState，且不計入材料失敗計數
// （此類中止未觸及任何材料，計入會讓網路抖動把正當管理員推進冷卻）。
func (a *attempt) abortPrePrepare(code string, cause error) error {
	a.settled = true
	a.casCell(EventPrePrepareAbort, nil)
	return newError(code, cellPreAbort, a.gen, cause)
}

// abortPostPrepare 為格 4b：received 已落地後、驗證前／中的取消或 panic。
//
// SHALL 先寫 outcome=aborted 並確認 durable，成功後才 CAS 回 sourceState
// ——反序會把一次明確的主動中止永久留成「有 received 無 outcome ＝結果未知」。
// 補寫失敗則走 journal I/O 故障處置，且仍回 sourceState
// （不得為了記錄而滯留於 unsealing）。同樣不計入材料失敗計數。
func (a *attempt) abortPostPrepare(cause error) error {
	a.settled = true
	werr := a.writeOutcome(OutcomeAborted)
	a.casCell(EventPostPrepareAbort, nil)
	if werr != nil {
		return newError(CodeJournalIOFailure, cellPostAbort, a.gen, werr)
	}
	return newError(CodeAborted, cellPostAbort, a.gen, cause)
}

// materialFailure 為格 4：材料驗證失敗 → 回 sourceState，失敗計數 +1。
// 達全域門檻時，冷卻到期時間由同一道 CAS 寫入 sealNode（柵欄涵蓋全域冷卻）。
func (a *attempt) materialFailure(cause error) error {
	a.settled = true
	_ = a.writeOutcome(OutcomeMaterialFailure)

	cooldownUntil, armed := a.m.limiter.RecordMaterialFailure(a.sourceKey, a.m.now())
	a.casCell(EventMaterialFailure, func(n *sealNode) {
		if armed {
			n.cooldownUntil = cooldownUntil
		}
	})
	return newError(CodeMaterialInvalid, cellMaterialBad, a.gen, cause)
}

// timedOut 為格 7：段 2 逾時（僅逾時）→ 回 sourceState 並設 cleanup。
//
// 自 sealed-faulted 進入者保留 faulted 與原故障機器碼——逾時不新增故障資訊，
// 亦不得抹除既有故障事實。逾時 SHALL NOT 計入材料失敗計數，另計逾時次數。
func (a *attempt) timedOut() error {
	a.settled = true
	_ = a.writeOutcome(OutcomeTimeout)
	a.m.limiter.RecordTimeout()
	a.casCell(EventStage2Timeout, nil)
	return newError(CodeStage2Timeout, cellTimeout, a.gen, nil)
}

// initFailed 為格 6：段 2 逾時以外的一切失敗（含段 2 期間的取消／panic）
// → sealed-faulted 並設 cleanup。
func (a *attempt) initFailed(cause error, graph ServiceGraph) error {
	a.settled = true
	_ = a.writeOutcome(OutcomeInitFailed)
	a.casCell(EventStage2Failure, func(n *sealNode) { n.faultCode = CodeInitFailed })
	// 標記已由上一行的 CAS 寫入，釋放動作本身不走 CAS；完成後才以 CAS 清 cleanup。
	a.m.go_(func() { a.releaseAndClear(graph) })
	return newError(CodeInitFailed, cellInitFailed, a.gen, cause)
}

// publish 為格 5：段 2 完成 → 寫 SUCCESS ＋同步 → 成功才 publish（CAS）→ 回應。
//
// SUCCESS 寫在 publish 之前，使「已放行後要收回」的整類問題不存在：寫入失敗時
// 服務從未放行（格 5b）。SHALL NOT 採 publish-then-write。
func (a *attempt) publish(graph ServiceGraph) (Result, error) {
	a.settled = true

	if err := a.writeOutcome(OutcomeSuccess); err != nil {
		return Result{}, a.unpublished(err, graph)
	}
	if !a.casCell(EventStage2Published, func(n *sealNode) { n.services = graph }) {
		return Result{}, a.unpublished(errUnpublishedCAS, graph)
	}

	// publish 成功後另寫 published（同 generation）。此寫入與 publish CAS 之間
	// 依然存在窗口——那是「每兩個原子操作之間都有窗口」的必然，本設計選擇使其
	// 可被辨識並據實標示（回灌時判為「已驗證通過但未確認發佈」），而非宣稱已消除。
	pctx, cancel := context.WithTimeout(context.WithoutCancel(a.baseCtx), a.m.journalTimeout)
	defer cancel()
	_ = a.m.journal.WritePublished(pctx, a.gen, a.seq)

	a.m.limiter.RecordSuccess(a.sourceKey)
	return Result{Generation: a.gen, State: StateUnsealed, Services: graph}, nil
}

var errUnpublishedCAS = errors.New("seal: publish CAS 未成功（較新世代搶先或已被逾時回退取代）")

// unpublished 為格 5b：段 2 完成但服務從未放行。兩成因同一處置。
//
// 成因一：SUCCESS 未 durable。成因二：SUCCESS 已 durable 而 publish CAS 未成功。
// 處置＝丟棄服務圖、清除已解封 KEK、回 sourceState。
// 本格不設 cleanup：持有者就在本地且已返回，資源就地同步釋放即可，
// 不需要以「待收束」擋住下一次解封（與格 6／7 的持有者可能仍在跑不同）。
func (a *attempt) unpublished(cause error, graph ServiceGraph) error {
	a.releaseGraph(graph)
	a.casCell(EventStage2Unpublished, nil)
	return newError(CodePublishUnconfirmed, cellUnpublished, a.gen, cause)
}

// releaseGraph 釋放（可能是半建構的）服務圖，並吞下 panic：
// 收束途中放棄會讓剩餘資源永久洩漏而使 cleanup 永不完成。
func (a *attempt) releaseGraph(graph ServiceGraph) {
	if graph == nil {
		return
	}
	base := a.baseCtx
	if base == nil {
		base = context.Background()
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(base), a.m.cleanupTimeout)
	defer cancel()
	defer func() {
		if r := recover(); r != nil {
			_ = fmt.Errorf("seal: 釋放服務圖 panic: %v", r)
		}
	}()
	_ = graph.Release(ctx)
}

// releaseAndClear 釋放資源後以 CAS 清除 cleanup（格 8）；此後才可再取得持有權。
func (a *attempt) releaseAndClear(graph ServiceGraph) {
	a.releaseGraph(graph)
	a.m.CompleteCleanup(a.gen)
}
