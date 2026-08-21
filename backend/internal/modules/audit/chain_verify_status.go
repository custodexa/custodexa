package audit

import (
	"errors"
	"fmt"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 自動驗證狀態的揭露面（audit-chain-scheduled-verification D8／tasks 5.1-5.2）。
//
// **為什麼要揭露**：偵測控制若在畫面上看不見，稽核只能假設它沒在跑——而排程器
// 靜默停擺時不會有任何告警（沒跑就沒有異常可報，這是所有 watchdog 的共同盲點）。
// 兩層各自的最近執行時點是唯一能讓人看出「它其實沒在運作」的訊號。
//
// **它不是完整性證明，讀取端必須明說**：本狀態存於單列表，不在鏈的覆蓋範圍內
// （鏈只覆蓋 audit_logs），可由資料庫直寫改成「最近驗過、全數通過」。此風險已落在
// 既有邊界 R0 之內，不新增風險面；但驗證頁 SHALL 明示此區塊為營運狀態而非證明，
// 否則我們就是在頁面上製造一個看起來像證據的東西。
//
// **不新增路由**：本狀態掛在既有結構層報告（GET /audit-checkpoints/verify）上，
// 避免動 TestAPIIndex／TestRoutesMatchGolden 兩份機器產物。

// ChainAutoVerifyStatus 兩層自動驗證的營運狀態快照。
//
// **對外只帶計數，不帶失敗區間的序號清單**：與告警出站同一條紅線
// （D5 去識別）——「哪一段被發現了」對已在系統內的攻擊者有直接情報價值，
// 而計數足以驅動「有人得去看」這個唯一必要的行為。要逐段查是誰，
// 走既有的失效事件與逐筆紀錄驗證，兩者都有各自的授權面
type ChainAutoVerifyStatus struct {
	// ── 近期層（封存完成觸發）──
	RecentLastRunAt  *time.Time `json:"recent_last_run_at,omitempty"`
	RecentLastStatus string     `json:"recent_last_status"`
	// RecentWindowDaysEffective 最近一次近期層**實際生效**的窗口天數
	// （政策值經審計紀錄保留天數 clamp 後）。顯示生效值而非設定值：
	// 承諾驗證保留期以外的範圍是空頭支票，畫面上得看得出真正驗了幾天
	RecentWindowDaysEffective int `json:"recent_window_days_effective"`

	// ── 全鏈層（排程週期觸發）──
	FullLastRunAt  *time.Time `json:"full_last_run_at,omitempty"`
	FullLastStatus string     `json:"full_last_status"`
	// FullIntervalSeconds 現行的全鏈層驗證間隔（現讀政策，非啟動時快照）
	FullIntervalSeconds int64 `json:"full_interval_seconds"`
	// ContentCursorSeq 逐筆重驗已推進到的檢查點序號（0＝尚未開始推進）
	ContentCursorSeq uint `json:"content_cursor_seq"`
	// LastFullCycleAt 最近一次繞完全部歷史區間的時點；nil＝尚未繞完過一輪
	LastFullCycleAt *time.Time `json:"last_full_cycle_at,omitempty"`

	// OpenFailedIntervals 尚未重驗轉綠的失敗區間**數量**（不含序號清單）
	OpenFailedIntervals int `json:"open_failed_intervals"`
	// StructureFailedCount 最近一次結構層全鏈驗證的失敗點數
	StructureFailedCount int `json:"structure_failed_count"`

	// RowsPerHour 現行掃描速率（列/小時，經消費端上下界收束後的生效值）
	RowsPerHour int64 `json:"rows_per_hour"`
	// CycleEstimateHours 依現行速率與現有鏈長預估「繞行全歷史一輪」所需小時數。
	//
	// **這個數字必須誠實顯示**：逐筆重驗是十億列級的掃描，任何宣稱「持續全量
	// 驗證」的設計都是在說謊或在拖垮生產庫。可調的是速率與間隔，不可調的是
	// 「一定有在滾、最新區間每輪必驗、已知失敗區間每輪必重驗」
	CycleEstimateHours float64 `json:"cycle_estimate_hours"`
}

// Status 讀出自動驗證的營運狀態，供驗證頁揭露。
//
// **唯讀，且不建立狀態列**（與 LoadState 的差別）：本方法掛在驗證端點上，
// 而 spec 明文「驗證 SHALL 為唯讀」。狀態列尚未建立時回一份零值快照——
// 那正是「排程從未跑過」的真實樣貌，不是錯誤，更不該由一個 GET 去補建
func (s *ChainVerifyService) Status() (*ChainAutoVerifyStatus, error) {
	var st model.AuditChainVerifyState
	err := s.db.First(&st, model.AuditChainVerifyStateID).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("讀取鏈驗證狀態失敗: %w", err)
	}

	rate := s.effectiveRowsPerHour()
	out := &ChainAutoVerifyStatus{
		RecentLastRunAt:           st.RecentLastRunAt,
		RecentLastStatus:          st.RecentLastStatus,
		RecentWindowDaysEffective: st.RecentWindowDaysEffective,
		FullLastRunAt:             st.FullLastRunAt,
		FullLastStatus:            st.FullLastStatus,
		FullIntervalSeconds:       int64(s.fullInterval() / time.Second),
		ContentCursorSeq:          st.ContentCursorSeq,
		LastFullCycleAt:           st.LastFullCycleAt,
		OpenFailedIntervals:       len(decodeSeqSet(st.OpenFailedSeqs)),
		StructureFailedCount:      st.StructureFailedCount,
		RowsPerHour:               rate,
	}

	hours, err := s.cycleEstimateHours(rate)
	if err != nil {
		return nil, err
	}
	out.CycleEstimateHours = hours
	return out, nil
}

// cycleEstimateHours 依現行速率預估繞行全歷史一輪的小時數。
//
// 分母取**已封區間所記的列數總和**（與滾動窗的預算會計同一個量），
// 故估的是同一件事而非另一套換算。鏈為空時回 0＝沒有歷史要繞
func (s *ChainVerifyService) cycleEstimateHours(rate int64) (float64, error) {
	var total int64
	if err := s.db.Model(&model.AuditCheckpoint{}).
		Select("COALESCE(SUM(row_count), 0)").Scan(&total).Error; err != nil {
		return 0, fmt.Errorf("統計鏈上紀錄總數失敗: %w", err)
	}
	if total <= 0 || rate <= 0 {
		return 0, nil
	}
	return float64(total) / float64(rate), nil
}
