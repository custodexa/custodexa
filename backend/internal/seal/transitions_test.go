package seal

import (
	"testing"
	"time"
)

// TestCellCountIsTwelve：遷移表為 12 格定稿表，格數本身是驗收條件。
func TestCellCountIsTwelve(t *testing.T) {
	if got := len(Cells()); got != 12 {
		t.Fatalf("預期 12 格，實得 %d", got)
	}
	seen := map[string]bool{}
	for _, c := range Cells() {
		if seen[c.ID] {
			t.Fatalf("格號重複: %s", c.ID)
		}
		seen[c.ID] = true
	}
	for _, want := range []string{"1", "2", "3", "3b", "4", "4b", "5", "5b", "6", "7", "8", "9"} {
		if !seen[want] {
			t.Errorf("缺格 %s", want)
		}
	}
}

// TestCellsPairwiseExclusive：12 格的 (from, event) 判準 SHALL 兩兩互斥。
// 以窮舉笛卡兒積驗證，不得有同一 Situation 落入兩格。
func TestCellsPairwiseExclusive(t *testing.T) {
	total := 0
	for _, from := range AllStates() {
		for _, ev := range AllEvents() {
			for _, hasCleanup := range []bool{false, true} {
				for _, acquired := range []bool{false, true} {
					sit := Situation{From: from, Event: ev, HasCleanup: hasCleanup, HolderAcquired: acquired}
					ids := resolveAll(sit)
					total++
					if len(ids) > 1 {
						t.Errorf("Situation %+v 同時命中多格 %v", sit, ids)
					}
				}
			}
		}
	}
	// 正向案例：窮舉本身要真的跑過足量組合，否則「零命中多格」是空真
	if total != len(AllStates())*len(AllEvents())*4 {
		t.Fatalf("窮舉組合數異常: %d", total)
	}
	if total == 0 {
		t.Fatal("窮舉未執行任何組合")
	}
}

// TestEveryCellHasPositiveSituation：每一格至少要有一個命中的 Situation。
// 缺此正向案例時，一個永遠為 false 的判準也能通過互斥性測試（守衛假綠）。
func TestEveryCellHasPositiveSituation(t *testing.T) {
	hit := map[string]int{}
	for _, from := range AllStates() {
		for _, ev := range AllEvents() {
			for _, hasCleanup := range []bool{false, true} {
				for _, acquired := range []bool{false, true} {
					for _, id := range resolveAll(Situation{From: from, Event: ev, HasCleanup: hasCleanup, HolderAcquired: acquired}) {
						hit[id]++
					}
				}
			}
		}
	}
	for _, c := range Cells() {
		if hit[c.ID] == 0 {
			t.Errorf("格 %s 沒有任何命中的 Situation（判準恆偽）", c.ID)
		}
	}
}

// TestCellsMatchDesignTable：逐格對照遷移表定稿的目標態與副作用欄位。
func TestCellsMatchDesignTable(t *testing.T) {
	want := map[string]Cell{
		"1":  {Target: StateSealed},
		"2":  {Target: StateUnsealing},
		"3":  {Target: targetUnchanged},
		"3b": {Target: targetSource},
		"4":  {Target: targetSource, CountsMaterialFailure: true, Outcome: OutcomeMaterialFailure},
		"4b": {Target: targetSource, Outcome: OutcomeAborted},
		"5":  {Target: StateUnsealed, Outcome: OutcomeSuccess},
		"5b": {Target: targetSource},
		"6":  {Target: StateSealedFaulted, SetsCleanup: true, CleanupReason: CodeInitFailed, Outcome: OutcomeInitFailed},
		"7":  {Target: targetSource, SetsCleanup: true, CleanupReason: CodeStage2Timeout, Outcome: OutcomeTimeout},
		"8":  {Target: targetUnchanged, ClearsCleanup: true},
		"9":  {Target: StateSealed},
	}
	for _, c := range Cells() {
		w, ok := want[c.ID]
		if !ok {
			t.Errorf("格 %s 不在對照表", c.ID)
			continue
		}
		if c.Target != w.Target {
			t.Errorf("格 %s 目標態: 預期 %s 實得 %s", c.ID, w.Target, c.Target)
		}
		if c.SetsCleanup != w.SetsCleanup || c.ClearsCleanup != w.ClearsCleanup {
			t.Errorf("格 %s cleanup 欄位不符: %+v", c.ID, c)
		}
		if c.CleanupReason != w.CleanupReason {
			t.Errorf("格 %s cleanup 成因: 預期 %q 實得 %q", c.ID, w.CleanupReason, c.CleanupReason)
		}
		if c.CountsMaterialFailure != w.CountsMaterialFailure {
			t.Errorf("格 %s 材料失敗計數旗標不符", c.ID)
		}
		if c.Outcome != w.Outcome {
			t.Errorf("格 %s outcome: 預期 %q 實得 %q", c.ID, w.Outcome, c.Outcome)
		}
		if c.Outcome != "" {
			if _, ok := validOutcomes[c.Outcome]; !ok {
				t.Errorf("格 %s 的 outcome %q 不在五類值域內", c.ID, c.Outcome)
			}
		}
	}
}

// TestLegalTransitionsResolveToExpectedCell：逐格的代表性合法 Situation。
func TestLegalTransitionsResolveToExpectedCell(t *testing.T) {
	cases := []struct {
		name string
		sit  Situation
		cell string
	}{
		{"格1 啟動", Situation{From: stateBoot, Event: EventBoot}, "1"},
		{"格2 自 sealed 取得持有權", Situation{From: StateSealed, Event: EventUnsealRequest, HolderAcquired: true}, "2"},
		{"格2 自 faulted 取得持有權", Situation{From: StateSealedFaulted, Event: EventUnsealRequest, HolderAcquired: true}, "2"},
		{"格3 已有持有者", Situation{From: StateUnsealing, Event: EventUnsealRequest}, "3"},
		{"格3 待收束", Situation{From: StateSealed, Event: EventUnsealRequest, HasCleanup: true}, "3"},
		{"格3 已解封", Situation{From: StateUnsealed, Event: EventUnsealRequest}, "3"},
		{"格3b pre-PREPARE abort", Situation{From: StateUnsealing, Event: EventPrePrepareAbort}, "3b"},
		{"格4 材料驗證失敗", Situation{From: StateUnsealing, Event: EventMaterialFailure}, "4"},
		{"格4b post-PREPARE abort", Situation{From: StateUnsealing, Event: EventPostPrepareAbort}, "4b"},
		{"格5 已發佈", Situation{From: StateUnsealing, Event: EventStage2Published}, "5"},
		{"格5b 未發佈", Situation{From: StateUnsealing, Event: EventStage2Unpublished}, "5b"},
		{"格6 段2失敗", Situation{From: StateUnsealing, Event: EventStage2Failure}, "6"},
		{"格7 段2逾時", Situation{From: StateUnsealing, Event: EventStage2Timeout}, "7"},
		{"格8 收束完成", Situation{From: StateSealedFaulted, Event: EventCleanupDone, HasCleanup: true}, "8"},
		{"格9 行程結束", Situation{From: StateUnsealed, Event: EventProcessExit}, "9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, ok := Resolve(tc.sit)
			if !ok {
				t.Fatalf("未命中任何格: %+v", tc.sit)
			}
			if c.ID != tc.cell {
				t.Fatalf("預期格 %s，實得 %s", tc.cell, c.ID)
			}
		})
	}
}

// TestIllegalTransitionsResolveToNothing：非法遷移必須零命中，狀態機才會拒絕
// 而非靜默改態。
func TestIllegalTransitionsResolveToNothing(t *testing.T) {
	cases := []struct {
		name string
		sit  Situation
	}{
		{"sealed 收到段2逾時", Situation{From: StateSealed, Event: EventStage2Timeout}},
		{"sealed 收到段2失敗", Situation{From: StateSealed, Event: EventStage2Failure}},
		{"sealed 收到發佈", Situation{From: StateSealed, Event: EventStage2Published}},
		{"unsealed 收到材料失敗", Situation{From: StateUnsealed, Event: EventMaterialFailure}},
		{"unsealed 收到發佈", Situation{From: StateUnsealed, Event: EventStage2Published}},
		{"faulted 收到 post-PREPARE abort", Situation{From: StateSealedFaulted, Event: EventPostPrepareAbort}},
		{"unsealing 於待收束下取得持有權", Situation{From: StateUnsealing, Event: EventUnsealRequest, HolderAcquired: true}},
		{"sealed 於待收束下取得持有權", Situation{From: StateSealed, Event: EventUnsealRequest, HasCleanup: true, HolderAcquired: true}},
		{"unsealed 取得持有權", Situation{From: StateUnsealed, Event: EventUnsealRequest, HolderAcquired: true}},
		{"unsealing 收束完成", Situation{From: StateUnsealing, Event: EventCleanupDone, HasCleanup: true}},
		{"無待收束時收束完成", Situation{From: StateSealed, Event: EventCleanupDone}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if c, ok := Resolve(tc.sit); ok {
				t.Fatalf("非法遷移竟命中格 %s: %+v", c.ID, tc.sit)
			}
		})
	}
}

// TestApplyCellSourceStateSemantics：回 sourceState 時，自 sealed-faulted 進入者
// SHALL 保留 faulted 與原故障機器碼；自 sealed 進入者不得殘留故障碼。
func TestApplyCellSourceStateSemantics(t *testing.T) {
	now := time.Unix(1000, 0)
	cell, _ := Resolve(Situation{From: StateUnsealing, Event: EventStage2Timeout})

	fromFaulted := &sealNode{generation: 7, state: StateUnsealing, sourceState: StateSealedFaulted, faultCode: CodeInitFailed}
	got := applyCell(fromFaulted, cell, now, nil)
	if got.state != StateSealedFaulted {
		t.Errorf("自 faulted 逾時回退應仍為 sealed-faulted，實得 %s", got.state)
	}
	if got.faultCode != CodeInitFailed {
		t.Errorf("逾時不得抹除既有故障碼，實得 %q", got.faultCode)
	}
	if got.cleanup == nil || got.cleanup.generation != 7 || got.cleanup.reason != CodeStage2Timeout {
		t.Errorf("格 7 應於同一次 CAS 設 cleanup，實得 %+v", got.cleanup)
	}

	fromSealed := &sealNode{generation: 3, state: StateUnsealing, sourceState: StateSealed}
	got = applyCell(fromSealed, cell, now, nil)
	if got.state != StateSealed || got.faultCode != "" {
		t.Errorf("自 sealed 逾時回退應回 sealed 且無故障碼，實得 %s/%q", got.state, got.faultCode)
	}
}

// TestApplyCellAcquireIncrementsGeneration：格 2 於每次進入 unsealing 時 +1，
// 兩個來源態皆然，並記住來源態。
func TestApplyCellAcquireIncrementsGeneration(t *testing.T) {
	cell, _ := Resolve(Situation{From: StateSealed, Event: EventUnsealRequest, HolderAcquired: true})
	for _, from := range []SealState{StateSealed, StateSealedFaulted} {
		n := &sealNode{generation: 41, state: from}
		got := applyCell(n, cell, time.Unix(0, 0), nil)
		if got.generation != 42 {
			t.Errorf("來源態 %s: 預期 generation 42，實得 %d", from, got.generation)
		}
		if got.state != StateUnsealing {
			t.Errorf("來源態 %s: 預期進入 unsealing，實得 %s", from, got.state)
		}
		if got.sourceState != from {
			t.Errorf("來源態 %s: sourceState 未記錄，實得 %s", from, got.sourceState)
		}
	}
}
