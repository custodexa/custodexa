package vtscreen

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// 行為基準守衛（design.md D9 的比對協議）。
//
// 基準的期望值由「只看規格、不看實作」的標註者逐筆訂死，實作則由看不到期望值的人寫成；
// 本檔把兩邊對起來。任何不一致都是有價值的訊號——處置是逐欄依 ECMA-48 推算後判定哪一邊錯，
// **不得為了讓測試轉綠而改 expected_lines**。
//
// 除逐筆比對外另有三條防假綠斷言：
//  1. differs_from_legacy=true 者必須留下 decision_ref 與 reason（杜絕「跑出什麼就寫什麼」）；
//  2. 舊實作會 panic 的樣本，新實作不得 panic；
//  3. 樣本總數不得低於 119（杜絕靠刪樣本轉綠）。

// baselineMinSamples 為基準樣本數下限。
// 抽取當日為 119 組；只增不減，減少即代表有人刪樣本換綠燈。
const baselineMinSamples = 119

// baselineFile 為版控中的行為基準。
const baselineFile = "testdata/behavior-baseline.json"

// baselineSample 對應 design.md D9 的欄位格式。
// legacy_* 三欄是舊實作的既成事實（歷史紀錄，不參與斷言的正確性判準）；
// expected_lines 才是新實作 SHALL 產出的結果。
type baselineSample struct {
	ID                string   `json:"id"`
	Source            string   `json:"source"`
	Desc              string   `json:"desc"`
	InputB64          string   `json:"input_b64"`
	InputEscaped      string   `json:"input_escaped"`
	LegacyOutputLines []string `json:"legacy_output_lines"`
	LegacyPanicked    bool     `json:"legacy_panicked"`
	LegacyUpstreamLog []string `json:"legacy_upstream_log"`
	ExpectedLines     []string `json:"expected_lines"`
	DiffersFromLegacy bool     `json:"differs_from_legacy"`
	DecisionRef       string   `json:"decision_ref"`
	Reason            string   `json:"reason"`
}

type baselineFileContent struct {
	Note    string           `json:"note"`
	Samples []baselineSample `json:"samples"`
}

// loadBaseline 讀取並解碼行為基準。
func loadBaseline(t *testing.T) []baselineSample {
	t.Helper()
	raw, err := os.ReadFile(baselineFile)
	if err != nil {
		t.Fatalf("讀取行為基準失敗：%v", err)
	}
	var content baselineFileContent
	if err := json.Unmarshal(raw, &content); err != nil {
		t.Fatalf("解析行為基準 JSON 失敗：%v", err)
	}
	return content.Samples
}

// decodeInput 解出樣本的原始輸入位元組。
func decodeInput(t *testing.T, s baselineSample) []byte {
	t.Helper()
	input, err := base64.StdEncoding.DecodeString(s.InputB64)
	if err != nil {
		t.Fatalf("樣本 %s 的 input_b64 解碼失敗：%v", s.ID, err)
	}
	return input
}

// linesRecovering 呼叫 Lines 並攔截 panic，使「哪一筆 panic」成為可斷言的事實
// 而非讓整個測試流程中斷。
func linesRecovering(input []byte) (lines []string, panicValue any) {
	defer func() {
		if r := recover(); r != nil {
			panicValue = r
		}
	}()
	return Lines(input), nil
}

// formatLines 把行陣列排成可讀的多行文字，供失敗訊息使用。
func formatLines(lines []string) string {
	if len(lines) == 0 {
		return "    （零行）"
	}
	var b strings.Builder
	for i, line := range lines {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString("    [")
		b.WriteString(itoa(i))
		b.WriteString("] ")
		b.WriteString(quote(line))
	}
	return b.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func quote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return s
	}
	return string(b)
}

// linesEqual 逐行比對；長度不同或任一行不同即為不符。
func linesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestBaselineLinesMatchExpected 對基準的每一組樣本斷言
// vtscreen.Lines(input) 等於標註者訂死的 expected_lines（design.md D9 協議 1）。
func TestBaselineLinesMatchExpected(t *testing.T) {
	samples := loadBaseline(t)
	t.Logf("行為基準樣本數：%d（下限 %d）", len(samples), baselineMinSamples)

	matched, mismatched := 0, 0
	for _, s := range samples {
		s := s
		t.Run(s.ID, func(t *testing.T) {
			input := decodeInput(t, s)
			got, panicValue := linesRecovering(input)
			if panicValue != nil {
				mismatched++
				t.Fatalf("樣本 %s（%s）解析時 panic：%v\n  輸入：%s",
					s.ID, s.Desc, panicValue, s.InputEscaped)
			}
			if linesEqual(got, s.ExpectedLines) {
				matched++
				return
			}
			mismatched++
			t.Errorf("樣本 %s（%s）與基準不符\n"+
				"  輸入      ：%s\n"+
				"  decision_ref：%s\n"+
				"  期望 %d 行：\n%s\n"+
				"  實得 %d 行：\n%s\n"+
				"  首個差異  ：%s",
				s.ID, s.Desc,
				s.InputEscaped,
				refOrNone(s.DecisionRef),
				len(s.ExpectedLines), formatLines(s.ExpectedLines),
				len(got), formatLines(got),
				firstDiff(s.ExpectedLines, got))
		})
	}
	t.Logf("比對結果：共 %d 組，相符 %d 組，不符 %d 組", len(samples), matched, mismatched)
}

func refOrNone(ref string) string {
	if ref == "" {
		return "（無，此筆標註為與舊實作相同）"
	}
	return ref
}

// firstDiff 指出第一個不同的行號與兩邊的值。
func firstDiff(want, got []string) string {
	n := len(want)
	if len(got) < n {
		n = len(got)
	}
	for i := 0; i < n; i++ {
		if want[i] != got[i] {
			return "第 " + itoa(i) + " 行 期望=" + quote(want[i]) + " 實得=" + quote(got[i])
		}
	}
	if len(want) > len(got) {
		return "實得少了第 " + itoa(n) + " 行（期望=" + quote(want[n]) + "）"
	}
	if len(got) > len(want) {
		return "實得多出第 " + itoa(n) + " 行（實得=" + quote(got[n]) + "）"
	}
	return "（行內容相同）"
}

// TestBaselineDifferenceRequiresWrittenReason 斷言每一筆與舊實作有差異的樣本
// 都留下了 decision_ref 與 reason（design.md D9 協議 2）。
//
// 這條守的是流程而非語義：差異一律要有書面理由，否則「跑出什麼就把期望值改成什麼」
// 會讓整份基準退化成實作的鏡子，失去對照價值。
func TestBaselineDifferenceRequiresWrittenReason(t *testing.T) {
	samples := loadBaseline(t)
	differs := 0
	for _, s := range samples {
		if !s.DiffersFromLegacy {
			continue
		}
		differs++
		if strings.TrimSpace(s.DecisionRef) == "" {
			t.Errorf("樣本 %s 標為與舊實作有差異，卻沒有 decision_ref", s.ID)
		}
		if strings.TrimSpace(s.Reason) == "" {
			t.Errorf("樣本 %s 標為與舊實作有差異，卻沒有 reason", s.ID)
		}
	}
	t.Logf("differs_from_legacy=true 的樣本數：%d", differs)
	if differs == 0 {
		t.Fatal("基準內沒有任何 differs_from_legacy=true 的樣本：" +
			"本 change 至少修了十三條缺陷，差異數為零代表基準已被抹平")
	}
}

// TestBaselineLegacyPanicSamplesDoNotPanic 斷言舊實作會 panic 的樣本
// 在新實作下不 panic（design.md D9 協議 3、D5 B5）。
//
// 舊實作對被截斷的 CSI 做負索引切片而 panic；新實作把未完成序列保留在狀態機內，
// 這一整類因而消失。
func TestBaselineLegacyPanicSamplesDoNotPanic(t *testing.T) {
	samples := loadBaseline(t)
	checked := 0
	for _, s := range samples {
		if !s.LegacyPanicked {
			continue
		}
		checked++
		input := decodeInput(t, s)
		if _, panicValue := linesRecovering(input); panicValue != nil {
			t.Errorf("樣本 %s（%s）在新實作下仍 panic：%v\n  輸入：%s",
				s.ID, s.Desc, panicValue, s.InputEscaped)
		}
	}
	t.Logf("legacy_panicked=true 的樣本數：%d", checked)
	if checked == 0 {
		t.Fatal("基準內找不到任何 legacy_panicked=true 的樣本：" +
			"B5 的兩組截斷樣本是這條守衛的射程，消失即代表基準被動過")
	}
}

// TestBaselineSampleCountNotReduced 斷言樣本總數不低於下限（design.md D9 協議 4）。
// 這條擋的是「刪掉不過的樣本讓測試轉綠」。
func TestBaselineSampleCountNotReduced(t *testing.T) {
	samples := loadBaseline(t)
	if len(samples) < baselineMinSamples {
		t.Fatalf("基準樣本數 %d 低於下限 %d：樣本只准增不准減，"+
			"少掉的樣本等於少掉的守衛射程", len(samples), baselineMinSamples)
	}
	seen := make(map[string]bool, len(samples))
	for _, s := range samples {
		if s.ID == "" {
			t.Error("有樣本缺少 id")
			continue
		}
		if seen[s.ID] {
			t.Errorf("樣本 id 重複：%s（重複的 id 會使「總數 119」被灌水）", s.ID)
		}
		seen[s.ID] = true
	}
	t.Logf("樣本總數 %d，唯一 id %d", len(samples), len(seen))
}
