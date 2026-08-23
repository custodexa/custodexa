package sshproxy

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// B 層重放的「已知缺口棘輪」。
//
// 語料於 2026-08-16 重錄，每個情境都自「提示符已在螢幕上」的狀態開始
// （錄製起點＝SSH 認證完成後的 Shell()／psql 首個提示符之前，與產線
// CommandParser 在連線建立時即掛上的形態一致）。重錄後 28 個情境的實質指令
// 全數正確，收尾指令原有兩筆無法還原；ctrl-c 那一筆已在本 change 修復並移出，
// 現只剩下面一筆 **psql-meta**。
//
// 它不是語料缺陷，是以「螢幕上出現過什麼」為原理的解析器的能力邊界。
// 把它們列成具名清單而不是放著紅，是為了讓
// CI 上的紅只代表「新的回歸」；但清單必須是**精確集合**而非上限——
// 本專案踩過「棘輪卡在舊基準等同全鬆」的坑，所以
// TestCaptureReplayKnownTeardownGapsAreExact 用集合相等（含結算值逐字相等）把關：
//   - 缺口被修好 → 實際失敗集合縮小 → 紅（強迫把該筆從清單刪掉）
//   - 缺口形態改變（結算值不同）→ 紅
//   - 出現清單外的新失敗 → 紅
//
// 清單只覆蓋「收尾指令」這一個維度。實質指令的比對走
// TestCaptureReplaySSHScenarios／TestCaptureReplayPsqlScenarios，那兩條**未被放寬**，
// 任何實質指令的回歸都會直接轉紅，不經過本清單。

// teardownGap 為一筆已知的收尾指令重建缺口。
type teardownGap struct {
	// gotCommand 是實測的結算值，逐字釘死：形態改變也算回歸。
	gotCommand string
	// reason 為成因（逐位元組追過事件流後的結論，不是推測）。
	reason string
	// designRef 為這一筆所依據的設計原則。
	designRef string
	// removalCondition 說明什麼情況下這一筆應該被刪掉。
	removalCondition string
}

var knownTeardownGaps = map[string]teardownGap{
	// ctrl-c 已於本 change 修復（interruptKeys／abortTyping，command_parser.go）：
	// 中斷鍵在輸入行尚未送出時中止當輪並回到閒置，下一次按鍵因而重新快照原點，
	// 收尾指令自 `ssh-test-server:~$ exit` 回正為 `exit`。
	// 依上面的集合相等規則，它必須從本清單移除，不得留著假裝還沒修。
	// 回歸釘死在 command_parser_interrupt_test.go。
	"psql-meta": {
		gotCommand: "custodexa=#",
		reason: "`\\dt` 的輸出超過一頁而落入 pager，`\\q` 的按鍵被 pager 吃掉、" +
			"**回顯根本不在輸出流裡**（實測事件流：`\\q\\r` 之後的 out 只有 pager 的重繪與重印的提示符，" +
			"沒有任何 `\\q` 字樣）。以螢幕重建為原理的解析器記的是「終端上出現過什麼」，" +
			"不是「使用者按了什麼」，故在原理上無法還原它。",
		designRef:        "誠實邊界：重建不出來的缺口如實列出，不以推測補足。",
		removalCondition: "指令來源改為以輸入方向為事實源（或新增 pager 感知的輸入側記錄）之後，這一筆即應刪除。",
	},
}

// observedTeardownGaps 重放全部語料，回傳實際的收尾指令失敗集合（情境名 → 首個不符的結算值）。
func observedTeardownGaps(t *testing.T) map[string]string {
	t.Helper()
	actual := map[string]string{}
	for _, tc := range []struct {
		file     string
		protocol string
	}{
		{sshCaptureFile, "ssh"},
		{psqlCaptureFile, "postgres"},
	} {
		for _, sc := range loadCapture(t, tc.file) {
			teardown := trailingTeardownInputs(sc)
			if len(teardown) == 0 {
				continue
			}
			emitted := replayScenario(t, sc, tc.protocol)
			if len(emitted) < len(teardown) {
				actual[sc.Name] = fmt.Sprintf("<結算出的指令數 %d 少於收尾按鍵數 %d>", len(emitted), len(teardown))
				continue
			}
			got := emitted[len(emitted)-len(teardown):]
			for i := range teardown {
				if got[i] != teardown[i] {
					actual[sc.Name] = got[i]
					break
				}
			}
		}
	}
	return actual
}

// TestCaptureReplayKnownTeardownGapsAreExact 斷言「實際失敗集合 == 已知缺口清單」。
//
// 精確相等，不是「失敗數 ≤ N」：後者會讓新出現的失敗被靜默吸收，
// 也會讓已修好的缺口繼續掛在清單上假裝還沒修。
func TestCaptureReplayKnownTeardownGapsAreExact(t *testing.T) {
	actual := observedTeardownGaps(t)

	var missing, unexpected, changed []string
	for name, gap := range knownTeardownGaps {
		got, ok := actual[name]
		switch {
		case !ok:
			missing = append(missing, fmt.Sprintf(
				"  %s：清單說它會失敗，實測卻通過了。這是好事——請把這一筆從 knownTeardownGaps 刪掉。\n"+
					"    移除條件（清單自述）：%s", name, gap.removalCondition))
		case got != gap.gotCommand:
			changed = append(changed, fmt.Sprintf(
				"  %s：缺口形態改變\n    清單記載：%q\n    實測結算：%q", name, gap.gotCommand, got))
		}
	}
	for name, got := range actual {
		if _, ok := knownTeardownGaps[name]; !ok {
			unexpected = append(unexpected, fmt.Sprintf(
				"  %s：收尾指令被重組成 %q，且不在已知缺口清單內——這是新的回歸", name, got))
		}
	}
	sort.Strings(missing)
	sort.Strings(unexpected)
	sort.Strings(changed)

	if len(missing)+len(unexpected)+len(changed) > 0 {
		var b strings.Builder
		b.WriteString("已知缺口清單與實際失敗集合不再精確相等：\n")
		for _, group := range [][]string{unexpected, changed, missing} {
			for _, line := range group {
				b.WriteString(line + "\n")
			}
		}
		b.WriteString(fmt.Sprintf("清單共 %d 筆，實測失敗共 %d 筆。", len(knownTeardownGaps), len(actual)))
		t.Fatal(b.String())
	}

	names := make([]string, 0, len(knownTeardownGaps))
	for name := range knownTeardownGaps {
		names = append(names, name)
	}
	sort.Strings(names)
	t.Logf("已知收尾缺口 %d 筆，與實測失敗集合精確相等：%s", len(names), strings.Join(names, ", "))
}

// TestCaptureReplayKnownGapScenariosExist 防止清單指向不存在的情境
// （情境被改名或刪除時，缺口條目會變成沒有射程的死條文）。
func TestCaptureReplayKnownGapScenariosExist(t *testing.T) {
	present := map[string]bool{}
	for _, path := range []string{sshCaptureFile, psqlCaptureFile} {
		for _, sc := range loadCapture(t, path) {
			present[sc.Name] = true
		}
	}
	for name, gap := range knownTeardownGaps {
		if !present[name] {
			t.Errorf("已知缺口清單指向不存在的情境 %s（成因記載：%s）", name, gap.reason)
		}
		if strings.TrimSpace(gap.removalCondition) == "" {
			t.Errorf("已知缺口 %s 沒有寫移除條件：說不出什麼時候該刪，就不該進清單", name)
		}
		if strings.TrimSpace(gap.designRef) == "" {
			t.Errorf("已知缺口 %s 沒有設計依據", name)
		}
	}
}
