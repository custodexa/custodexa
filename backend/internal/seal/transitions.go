package seal

import "time"

// Event 為遷移表的事件維度（D6.2.2，12 格）。
type Event string

const (
	// EventBoot B 模式行程啟動（格 1）
	EventBoot Event = "boot"
	// EventUnsealRequest 收到解封請求（格 2／3；以 HolderAcquired 區分）
	EventUnsealRequest Event = "unseal_request"
	// EventPrePrepareAbort received 落地前的任何終止：請求取消／panic／
	// 寫入 I/O 失敗／寫入逾時（格 3b）
	EventPrePrepareAbort Event = "pre_prepare_abort"
	// EventMaterialFailure 材料驗證失敗——格式／解包／初始化憑證（格 4）
	EventMaterialFailure Event = "material_failure"
	// EventPostPrepareAbort received 已落地後、驗證前／中的取消或 panic（格 4b）
	EventPostPrepareAbort Event = "post_prepare_abort"
	// EventStage2Published 段 2 完成、SUCCESS 已 durable 且 publish CAS 成功（格 5）
	EventStage2Published Event = "stage2_published"
	// EventStage2Unpublished 段 2 完成但 SUCCESS 未 durable，或 SUCCESS 已 durable
	// 而 publish CAS 未成功（格 5b，兩成因同一處置）
	EventStage2Unpublished Event = "stage2_unpublished"
	// EventStage2Failure 段 2 失敗——逾時以外的一切失敗，含段 2 期間的取消／panic（格 6）
	EventStage2Failure Event = "stage2_failure"
	// EventStage2Timeout 段 2 逾時，且僅逾時（格 7）
	EventStage2Timeout Event = "stage2_timeout"
	// EventCleanupDone 前代持有者收束完成（格 8）
	EventCleanupDone Event = "cleanup_done"
	// EventProcessExit 行程結束（格 9；無持久化，下次啟動回 sealed）
	EventProcessExit Event = "process_exit"
)

// 目標態的兩個 sentinel。不使用 SealState 的真值，避免與四態混淆。
const (
	// targetSource 表示「回 sourceState」（格 3b／4／4b／5b／7）
	targetSource SealState = "@source"
	// targetUnchanged 表示「態不變」（格 3／8）
	targetUnchanged SealState = "@unchanged"
)

// 遷移格號常數（供 Error.Cell 與測試對照）。
const (
	cellBoot        = "1"
	cellAcquire     = "2"
	cellRejected    = "3"
	cellPreAbort    = "3b"
	cellMaterialBad = "4"
	cellPostAbort   = "4b"
	cellPublished   = "5"
	cellUnpublished = "5b"
	cellInitFailed  = "6"
	cellTimeout     = "7"
	cellCleanupDone = "8"
	cellProcessExit = "9"
)

// Situation 是遷移判準所需的全部可觀察輸入。
//
// 12 格的 (From, Event) 判準 SHALL 兩兩互斥：任一 Situation 至多命中一格。
// 互斥性由 TestCellsPairwiseExclusive 以窮舉笛卡兒積驗證，非靠人工推論。
type Situation struct {
	// From 為觀察到的來源態；格 1 使用 stateBoot 偽態
	From SealState
	// Event 為事件
	Event Event
	// HasCleanup 為來源節點的 cleanup != nil
	HasCleanup bool
	// HolderAcquired 為本次請求是否取得持有權（CAS 成功）
	HolderAcquired bool
}

// Cell 為遷移表的一格。
//
// 本表是狀態機的唯一判準來源：Machine 的每一次轉態都經 Resolve 取得本格並
// 依 Target 計算目標態，故表寫錯會直接使行為測試變紅——它不是平行維護的裝飾。
type Cell struct {
	// ID 為格號（"1"、"2"、"3b"…）
	ID string
	// Event 為本格對應的事件
	Event Event
	// Target 為目標態，可為四態之一或 targetSource／targetUnchanged
	Target SealState
	// SetsCleanup 表示本格的那一次 CAS SHALL 同時寫入 cleanup = token(該 generation)
	SetsCleanup bool
	// CleanupReason 為 cleanup token 的成因機器碼
	CleanupReason string
	// ClearsCleanup 表示本格 SHALL 以 CAS 清除 cleanup
	ClearsCleanup bool
	// CountsMaterialFailure 表示本格 SHALL 計入材料失敗計數
	CountsMaterialFailure bool
	// Outcome 為本格流程 SHALL 寫入的 journal 結果碼（空字串＝本格不寫）
	Outcome string

	match func(Situation) bool
}

// cells 為 12 格定稿表（D6.2.2）。順序即表列順序。
var cells = []Cell{
	{
		ID: cellBoot, Event: EventBoot, Target: StateSealed,
		// 格 1：B 模式啟動即 sealed，不讀 data_keys
		match: func(s Situation) bool {
			return s.From == stateBoot && s.Event == EventBoot
		},
	},
	{
		ID: cellAcquire, Event: EventUnsealRequest, Target: StateUnsealing,
		// 格 2：來源態集合為 {sealed, sealed-faulted}，且結構性前置 cleanup == nil。
		// 驗證尚未開始——CAS 進入 unsealing 發生在任何驗證之前（D6.2.1）。
		match: func(s Situation) bool {
			return s.Event == EventUnsealRequest && s.HolderAcquired &&
				!s.HasCleanup && (s.From == StateSealed || s.From == StateSealedFaulted)
		},
	},
	{
		ID: cellRejected, Event: EventUnsealRequest, Target: targetUnchanged,
		// 格 3：唯一的「未取得持有權」出口。態不變，成因以機器碼區分
		// （進行中／待收束／已解封），不進行任何驗證。
		match: func(s Situation) bool {
			return s.Event == EventUnsealRequest && !s.HolderAcquired
		},
	},
	{
		ID: cellPreAbort, Event: EventPrePrepareAbort, Target: targetSource,
		// 格 3b：received 落地前的任何終止。不計入材料失敗計數。
		match: func(s Situation) bool {
			return s.From == StateUnsealing && s.Event == EventPrePrepareAbort
		},
	},
	{
		ID: cellMaterialBad, Event: EventMaterialFailure, Target: targetSource,
		CountsMaterialFailure: true, Outcome: OutcomeMaterialFailure,
		// 格 4：材料驗證失敗 → 回來源態，失敗計數 +1
		match: func(s Situation) bool {
			return s.From == StateUnsealing && s.Event == EventMaterialFailure
		},
	},
	{
		ID: cellPostAbort, Event: EventPostPrepareAbort, Target: targetSource,
		Outcome: OutcomeAborted,
		// 格 4b：received 已落地後的主動中止。SHALL 先寫 aborted 並確認 durable，
		// 成功後才 CAS 回 sourceState——反序會把已知中止留成「結果未知」。
		match: func(s Situation) bool {
			return s.From == StateUnsealing && s.Event == EventPostPrepareAbort
		},
	},
	{
		ID: cellPublished, Event: EventStage2Published, Target: StateUnsealed,
		Outcome: OutcomeSuccess,
		// 格 5：段 2 完成、SUCCESS 已 durable 且 publish CAS 成功。
		// 單一 CAS 原子發佈；隨後另寫 published（同 generation）。
		match: func(s Situation) bool {
			return s.From == StateUnsealing && s.Event == EventStage2Published
		},
	},
	{
		ID: cellUnpublished, Event: EventStage2Unpublished, Target: targetSource,
		// 格 5b：兩成因同一處置——丟棄服務圖、清除 KEK、回 sourceState，服務從未放行。
		// Outcome 留空：成因一是 SUCCESS 寫入失敗，成因二的 SUCCESS 已於同一流程寫過。
		match: func(s Situation) bool {
			return s.From == StateUnsealing && s.Event == EventStage2Unpublished
		},
	},
	{
		ID: cellInitFailed, Event: EventStage2Failure, Target: StateSealedFaulted,
		SetsCleanup: true, CleanupReason: CodeInitFailed, Outcome: OutcomeInitFailed,
		// 格 6：段 2 逾時以外的一切失敗（含取消／panic）→ sealed-faulted，設 cleanup
		match: func(s Situation) bool {
			return s.From == StateUnsealing && s.Event == EventStage2Failure
		},
	},
	{
		ID: cellTimeout, Event: EventStage2Timeout, Target: targetSource,
		SetsCleanup: true, CleanupReason: CodeStage2Timeout, Outcome: OutcomeTimeout,
		// 格 7：僅逾時 → 回 sourceState（自 sealed-faulted 進入者保留 faulted 與
		// 原故障機器碼），設 cleanup。逾時不新增故障資訊，亦不得抹除既有故障事實。
		match: func(s Situation) bool {
			return s.From == StateUnsealing && s.Event == EventStage2Timeout
		},
	},
	{
		ID: cellCleanupDone, Event: EventCleanupDone, Target: targetUnchanged,
		ClearsCleanup: true,
		// 格 8：前代持有者收束完成，由收束方以 CAS 清除 cleanup；此後才可再取得持有權
		match: func(s Situation) bool {
			return s.Event == EventCleanupDone && s.HasCleanup &&
				(s.From == StateSealed || s.From == StateSealedFaulted)
		},
	},
	{
		ID: cellProcessExit, Event: EventProcessExit, Target: StateSealed,
		// 格 9：行程結束，無持久化，下次啟動回 sealed
		match: func(s Situation) bool {
			return s.Event == EventProcessExit
		},
	},
}

// Cells 回傳 12 格定稿表的複本（測試與稽核用）。
func Cells() []Cell {
	out := make([]Cell, len(cells))
	copy(out, cells)
	return out
}

// AllStates 回傳全部狀態值（含格 1 的 stateBoot 偽態），供窮舉測試。
func AllStates() []SealState {
	return []SealState{stateBoot, StateSealed, StateUnsealing, StateUnsealed, StateSealedFaulted}
}

// AllEvents 回傳全部事件值，供窮舉測試。
func AllEvents() []Event {
	return []Event{
		EventBoot, EventUnsealRequest, EventPrePrepareAbort, EventMaterialFailure,
		EventPostPrepareAbort, EventStage2Published, EventStage2Unpublished,
		EventStage2Failure, EventStage2Timeout, EventCleanupDone, EventProcessExit,
	}
}

// Resolve 依 Situation 判定所屬遷移格。
// 無任何格命中即為非法遷移，回 ok=false——狀態機 SHALL 拒絕而非靜默改態。
func Resolve(s Situation) (Cell, bool) {
	for i := range cells {
		if cells[i].match(s) {
			return cells[i], true
		}
	}
	return Cell{}, false
}

// resolveAll 回傳全部命中的格，供互斥性測試使用。
func resolveAll(s Situation) []string {
	var ids []string
	for i := range cells {
		if cells[i].match(s) {
			ids = append(ids, cells[i].ID)
		}
	}
	return ids
}

// applyCell 依遷移格計算目標節點。observed 為呼叫方進入時讀到的節點指標。
// mut 用於補上該格特有的欄位（服務圖、故障碼、全域冷卻）。
func applyCell(observed *sealNode, cell Cell, now time.Time, mut func(*sealNode)) *sealNode {
	next := observed.clone()
	switch cell.Target {
	case targetUnchanged:
		// 態不變
	case targetSource:
		next.state = observed.sourceState
		next.sourceState = ""
		next.services = nil
		if next.state != StateSealedFaulted {
			// 回到 sealed 時不得殘留故障碼；回到 sealed-faulted 則保留原碼（格 7）
			next.faultCode = ""
		}
	case StateUnsealing:
		// 格 2：generation 每次進入 unsealing +1（兩個來源態皆然），並記住來源態
		next.generation = observed.generation + 1
		next.state = StateUnsealing
		next.sourceState = observed.state
		next.services = nil
	default:
		next.state = cell.Target
		next.sourceState = ""
		next.services = nil
		if next.state != StateSealedFaulted {
			next.faultCode = ""
		}
	}
	if cell.ClearsCleanup {
		next.cleanup = nil
	}
	if cell.SetsCleanup {
		next.cleanup = &cleanupToken{
			generation: observed.generation,
			reason:     cell.CleanupReason,
			startedAt:  now,
		}
	}
	if mut != nil {
		mut(next)
	}
	return next
}
