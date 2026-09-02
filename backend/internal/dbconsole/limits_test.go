package dbconsole

import (
	"testing"
	"time"
)

// 上限值的釘選。
//
// **本檔不是重複宣告，是變更閘**：上限被悄悄調寬（為了讓某個測試過、為了讓某次
// 展示看起來順）在功能上沒有任何症狀，而它們每一項都是單一實例的記憶體防線。
// 要改值就必須同時改這裡，而改這裡會出現在 diff 上被人看見。
func TestLimitsArePinned(t *testing.T) {
	ints := []struct {
		name string
		got  int
		want int
	}{
		{"每人同時會話數", MaxConcurrentSessionsPerUser, 4},
		{"全域同時會話數", MaxConcurrentSessionsGlobal, 64},
		{"語句文字位元組", MaxStatementBytes, 256 * 1024},
		{"單位回傳列數", MaxRowsPerUnit, 1000},
		{"送出序列化位元組", MaxBytesPerSubmission, 8 * 1024 * 1024},
		{"單欄原始值位元組", MaxCellBytes, 64 * 1024},
		{"樹每層節點數", MaxTreeNodesPerLevel, 2000},
		{"外送佇列深度", OutboundQueueDepth, 16},
	}
	for _, tc := range ints {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
		}
	}

	durations := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"語句逾時", StatementTimeout, 60 * time.Second},
		{"連線逾時", ConnectTimeout, 15 * time.Second},
		{"探詢逾時", ProbeTimeout, 5 * time.Second},
		{"單則寫入期限", WriteDeadline, 10 * time.Second},
		// 這一格不是「又一個上限」，是一道回歸閘：兩個 delay 的零值會讓
		// PostgreSQL 的帶外取消退化成拉斷連線，於是每一次取消都被記成
		// effect_unknown 而不是 cancelled。那個退化在功能上沒有症狀
		//（使用者一樣看到語句停了），只有稽核讀那筆列時才會發現事實變了
		{"PG 取消保命期限", pgCancelDeadlineDelay, 5 * time.Second},
	}
	if pgCancelRequestDelay != 0 {
		t.Errorf("PG 取消請求延遲 = %v, want 0（取消一律立刻送出）", time.Duration(pgCancelRequestDelay))
	}
	for _, tc := range durations {
		if tc.got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
}

// TestResultBudgetSemantics 兩個額度的層級不同，這一點是刻意的。
//
// 列數的額度是**單位級**（防單一查詢把整張表拉回來），位元組的額度是**送出級**
// （防整體記憶體佔用）。兩者若同級，MSSQL 的多批次就能靠切批次繞過列數上限。
func TestResultBudgetSemantics(t *testing.T) {
	b := newResultBuilder(MaxBytesPerSubmission)

	for i := 0; i < MaxRowsPerUnit; i++ {
		if !b.consumeRow(10) {
			t.Fatalf("第 %d 列就被拒，列額度小於宣告值", i)
		}
	}
	if b.consumeRow(10) {
		t.Error("第 1001 列應被拒")
	}
	if !b.truncated {
		t.Error("列額度用盡時未標記截斷")
	}

	usedBytes := MaxBytesPerSubmission - b.byteBudget
	b.resetUnit()
	if b.rowBudget != MaxRowsPerUnit {
		t.Errorf("新單位的列額度 = %d, want %d（列額度是單位級）", b.rowBudget, MaxRowsPerUnit)
	}
	if got := MaxBytesPerSubmission - b.byteBudget; got != usedBytes {
		t.Errorf("新單位重設了位元組額度（已用 %d → %d）——"+
			"位元組額度是送出級，重設它等於讓多批次可以無限累積", usedBytes, got)
	}
}
