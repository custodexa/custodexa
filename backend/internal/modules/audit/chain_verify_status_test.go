package audit

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 自動驗證狀態揭露面的行為釘子。
//
// 三件事各自都會讓揭露面失真而畫面上看不出來：
//   - 讀狀態順手把列建起來 → 驗證端點不再唯讀，且「從未跑過」被抹成「跑過但沒結果」；
//   - 顯示設定值而非生效值 → 頁面上的速率與實際掃描速度長期不一致；
//   - 把失敗區間的序號一起帶出去 → 與告警出站同一條去識別紅線被繞過。

// TestChainVerifyStatusReadOnlyOnMissingState 狀態列不存在時回零值快照且不建列。
//
// 驗證端點是唯讀面（spec 明文）。一個 GET 若順手補建狀態列，
// 「排程從未啟動」這件事就再也無法從資料層分辨——那正是本區塊要讓人看見的東西
func TestChainVerifyStatusReadOnlyOnMissingState(t *testing.T) {
	f := setupChainVerifyFixture(t)

	var before int64
	if err := f.db.Model(&model.AuditChainVerifyState{}).Count(&before).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if before != 0 {
		t.Fatalf("前置條件失效：狀態列已存在 %d 列", before)
	}

	st, err := f.svc.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.RecentLastRunAt != nil || st.FullLastRunAt != nil {
		t.Errorf("從未執行時不得有最近執行時點：recent=%v full=%v",
			st.RecentLastRunAt, st.FullLastRunAt)
	}
	if st.RecentLastStatus != "" || st.FullLastStatus != "" {
		t.Errorf("從未執行時不得有結果：recent=%q full=%q", st.RecentLastStatus, st.FullLastStatus)
	}

	var after int64
	if err := f.db.Model(&model.AuditChainVerifyState{}).Count(&after).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if after != 0 {
		t.Fatalf("讀取狀態建立了 %d 列：驗證面必須唯讀", after)
	}
	t.Logf("零值快照：速率=%d 列/小時、間隔=%d 秒、未結案失敗區間=%d",
		st.RowsPerHour, st.FullIntervalSeconds, st.OpenFailedIntervals)
}

// TestChainVerifyStatusExposesBothLayersAndOpenFailures 兩層各自的時點與結果、
// 生效窗口天數、滾動位置、未結案失敗區間數都要出得來
func TestChainVerifyStatusExposesBothLayersAndOpenFailures(t *testing.T) {
	f := setupChainVerifyFixture(t)
	seqs := f.sealIntervals(t, 3, 4)
	// 抽走中段區間的一列：內容層必然失敗，該區間即進入未結案集合
	victim := f.rowIn(t, seqs[1], 1)
	f.mustExec(t, "DELETE FROM audit_logs WHERE id = ?", victim.ID)

	if err := f.svc.RunFullNow(context.Background()); err != nil {
		t.Fatalf("全鏈層: %v", err)
	}
	if err := f.svc.RunRecentNow(context.Background()); err != nil {
		t.Fatalf("近期層: %v", err)
	}

	st, err := f.svc.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.FullLastRunAt == nil || st.RecentLastRunAt == nil {
		t.Fatalf("兩層各自的最近執行時點缺一：recent=%v full=%v",
			st.RecentLastRunAt, st.FullLastRunAt)
	}
	if st.FullLastStatus != ChainVerifyStatusFailed || st.RecentLastStatus != ChainVerifyStatusFailed {
		t.Errorf("抽列後兩層結果應為失敗：recent=%q full=%q",
			st.RecentLastStatus, st.FullLastStatus)
	}
	if st.RecentWindowDaysEffective <= 0 {
		t.Errorf("近期層生效窗口天數 = %d，應為正數", st.RecentWindowDaysEffective)
	}
	if st.OpenFailedIntervals != 1 {
		t.Errorf("未結案失敗區間數 = %d, want 1", st.OpenFailedIntervals)
	}
	t.Logf("兩層狀態：近期 %s（窗口 %d 天）／全鏈 %s（已重驗至序號 %d）、未結案 %d 段",
		st.RecentLastStatus, st.RecentWindowDaysEffective, st.FullLastStatus,
		st.ContentCursorSeq, st.OpenFailedIntervals)
}

// TestChainVerifyStatusWindowClampedByRetention 顯示的是生效值不是設定值。
//
// 承諾驗證保留期以外的範圍是空頭支票；畫面上得看得出真正驗了幾天
func TestChainVerifyStatusWindowClampedByRetention(t *testing.T) {
	f := setupChainVerifyFixture(t)
	f.sealIntervals(t, 1, 2)
	f.tuning.days = 30
	f.pol.vals["retention_audit_log_days"] = 3

	if err := f.svc.RunRecentNow(context.Background()); err != nil {
		t.Fatalf("近期層: %v", err)
	}
	st, err := f.svc.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.RecentWindowDaysEffective != 3 {
		t.Errorf("生效窗口 = %d 天, want 3（設定 30 天但保留政策只留 3 天）",
			st.RecentWindowDaysEffective)
	}
}

// TestChainVerifyStatusCycleEstimateFollowsRate 繞行一輪的預估隨速率縮放，
// 且與間隔無關（速率語義：間隔改變不改變繞行週期）
func TestChainVerifyStatusCycleEstimateFollowsRate(t *testing.T) {
	f := setupChainVerifyFixture(t)
	f.sealIntervals(t, 4, 5000) // 共 2 萬列

	f.tuning.rows = 10000 // 1 萬列/小時 → 2 小時繞完
	f.tuning.interval = time.Hour
	st, err := f.svc.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if math.Abs(st.CycleEstimateHours-2) > 0.01 {
		t.Errorf("繞行預估 = %.3f 小時, want 2（2 萬列 ÷ 1 萬列/小時）", st.CycleEstimateHours)
	}

	// 間隔加倍：每輪預算等比放大，繞行週期不變
	f.tuning.interval = 2 * time.Hour
	st2, err := f.svc.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if math.Abs(st2.CycleEstimateHours-st.CycleEstimateHours) > 0.01 {
		t.Errorf("間隔加倍後繞行預估變成 %.3f 小時（原 %.3f）：速率語義已失效",
			st2.CycleEstimateHours, st.CycleEstimateHours)
	}

	// 速率減半：繞行週期加倍
	f.tuning.rows = 5000
	st3, err := f.svc.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	// 5000 低於消費端下界 10000，生效值仍為 10000——顯示的是生效值
	if st3.RowsPerHour != chainVerifyRowsPerHourMin {
		t.Errorf("速率生效值 = %d, want %d（低於下界須收束並如實顯示）",
			st3.RowsPerHour, chainVerifyRowsPerHourMin)
	}
	t.Logf("繞行預估：%.2f 小時（速率 %d 列/小時）", st3.CycleEstimateHours, st3.RowsPerHour)
}
