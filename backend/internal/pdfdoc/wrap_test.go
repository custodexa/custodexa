package pdfdoc

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"strings"
	"testing"
	"unicode"
	"unicode/utf16"
)

// wrapSamples 折行測試的樣本：繁中、日文（假名與漢字混排）、英文、中英數混排。
//
// 每段都比版心寬，保證會折行；前面再墊 0..n 個字元，讓折行點滑過句中每一個位置。
var wrapSamples = []string{
	"本報告呈現資料時點下，此政策組涵蓋的安全設定比對結果，並另列由產品承擔、無可調設定值的條文。「符合」表示該項設定值達到條文要求，不代表機構已完成該規範的整體合規認定；程序、人員與其他系統的控制措施不在本報告範圍內。",
	"本レポートは、データ時点において本ポリシーグループが対象とするセキュリティ設定の比較結果を示し、製品が担う調整可能な設定値のない条文を別に掲載します。「適合」は当該設定値が条文の要求を満たすことを示すもので、組織が当該規範の全体的な適合性評価を完了したことを意味しません。",
	"This report shows how the security settings covered by this policy group compared with its clauses at the data-as-of time, and separately lists the clauses carried by the product that have no adjustable setting.",
	"資產 core-db-01 的帳號 svc_backup 於 2026-09-01T12:00:00+08:00 輪替成功，距今 28 天；剩餘天數 A＝適用天數 − 距最後成功改密天數，逾期者列入附錄 B（共 3 筆）。",
}

// wrapShift 每段樣本墊字的最大數量；大於一行可容納的全形字數即可涵蓋所有折行位置。
const wrapShift = 48

// wrapPad 墊在樣本前的字元（全形與半形交錯，讓折行點同時以兩種步幅移動）。
var wrapPad = []rune("甲a乙b丙c丁d戊e己f庚g辛h壬i癸j子k丑l寅m卯n辰o巳p午q未r申s酉t戌u亥v天w地x玄y黃z")

func paddedSample(sample string, k int) string {
	return string(wrapPad[:k]) + sample
}

// TestPdfDocWrapKeepsEveryCharacter 自動折行不得吃掉任何字元。
//
// 折行發生在哪一個字上由字串內容與版心寬度決定，不是呼叫端能控制的——
// 所以逐一滑動折行點，對 Paragraph、KeyValues、NoteBlock 三種會折行的區塊
// 各產出一份 PDF，從內容串流抽回文字，逐字比對（折行處的空白允許省略）。
func TestPdfDocWrapKeepsEveryCharacter(t *testing.T) {
	blocks := []struct {
		name   string
		render func(d *Doc, text string)
		// prefix 區塊自行加在文字前的標記
		prefix string
	}{
		{"Paragraph", func(d *Doc, s string) { d.Paragraph(s) }, ""},
		{"KeyValues", func(d *Doc, s string) { d.KeyValues([]KV{{Key: "", Value: s}}) }, ""},
		{"NoteBlock", func(d *Doc, s string) { d.NoteBlock("", []string{s}) }, "・"},
		{"TableWrap", func(d *Doc, s string) {
			w := d.FitColumns([]float64{1, 3})
			d.Table(Table{Columns: []Column{{Width: w[0]}, {Width: w[1]}}, Rows: [][]string{{"", s}}, Wrap: true})
		}, ""},
	}
	for _, b := range blocks {
		for si, sample := range wrapSamples {
			t.Run(fmt.Sprintf("%s/sample%d", b.name, si), func(t *testing.T) {
				d, err := New(Options{})
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				var want []string
				for k := 0; k <= wrapShift; k++ {
					s := paddedSample(sample, k)
					b.render(d, s)
					want = append(want, b.prefix+s)
				}
				var buf bytes.Buffer
				if err := d.Output(&buf); err != nil {
					t.Fatalf("Output: %v", err)
				}
				lines := extractTextLines(t, buf.Bytes())
				// 防假綠：每段都必須真的折過行，否則這支測試什麼都沒驗到
				if len(lines) < 2*len(want) {
					t.Fatalf("抽回 %d 行、區塊 %d 個：樣本沒有折行，測試前提不成立", len(lines), len(want))
				}
				got := stripSpace(strings.Join(lines, ""))
				exp := stripSpace(strings.Join(want, ""))
				if got != exp {
					t.Errorf("折行後文字與原文不一致：%s", firstDiff(exp, got))
				}
			})
		}
	}
}

func stripSpace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

// firstDiff 指出第一個不一致處與前後文，讓失敗訊息直接看得出掉了哪個字。
func firstDiff(want, got string) string {
	w, g := []rune(want), []rune(got)
	i := 0
	for i < len(w) && i < len(g) && w[i] == g[i] {
		i++
	}
	ctx := func(r []rune) string {
		lo, hi := i-12, i+12
		if lo < 0 {
			lo = 0
		}
		if hi > len(r) {
			hi = len(r)
		}
		if lo > hi {
			lo = hi
		}
		return string(r[lo:hi])
	}
	return fmt.Sprintf("第 %d 字起不同；原文「%s」，成品「%s」（原文 %d 字、成品 %d 字）",
		i, ctx(w), ctx(g), len(w), len(g))
}

// extractTextLines 解壓每個內容串流，依序取出每一個 `(…)Tj` 文字運算元並解回 UTF-8。
//
// 內嵌 UTF-8 字型時文字以 UTF-16BE 寫入、並對 `\`、`(`、`)`、CR 做跳脫；
// 這裡照相反順序還原，得到的就是讀者在頁面上看到的每一行。
func extractTextLines(t *testing.T, pdf []byte) []string {
	t.Helper()
	var lines []string
	const begin, end = "\nstream\n", "\nendstream"
	for i := 0; ; {
		s := bytes.Index(pdf[i:], []byte(begin))
		if s < 0 {
			break
		}
		s += i + len(begin)
		e := bytes.Index(pdf[s:], []byte(end))
		if e < 0 {
			break
		}
		e += s
		i = e
		zr, err := zlib.NewReader(bytes.NewReader(pdf[s:e]))
		if err != nil {
			continue
		}
		plain, rerr := io.ReadAll(zr)
		_ = zr.Close()
		if rerr != nil || !bytes.Contains(plain, []byte("BT ")) {
			continue
		}
		lines = append(lines, textOperands(plain)...)
	}
	return lines
}

// textOperands 從一段已解壓的內容串流取出 `Td (…)Tj` 的字串並解碼。
func textOperands(plain []byte) []string {
	var out []string
	marker := []byte("Td (")
	for p := 0; ; {
		m := bytes.Index(plain[p:], marker)
		if m < 0 {
			return out
		}
		p += m + len(marker)
		var raw []byte
		for p < len(plain) {
			c := plain[p]
			p++
			if c == '\\' && p < len(plain) {
				n := plain[p]
				p++
				if n == 'r' {
					n = '\r'
				}
				raw = append(raw, n)
				continue
			}
			if c == ')' {
				break
			}
			raw = append(raw, c)
		}
		if !bytes.HasPrefix(plain[p:], []byte("Tj")) {
			continue
		}
		u := make([]uint16, 0, len(raw)/2)
		for j := 0; j+1 < len(raw); j += 2 {
			u = append(u, uint16(raw[j])<<8|uint16(raw[j+1]))
		}
		out = append(out, string(utf16.Decode(u)))
	}
}

// TestPdfDocWrapLinesFitWidth 折行結果每一行都放得進版心、拼回去就是原文，
// 且句讀不落在行首。
//
// 保住每個字之外，也不能靠「不折行、讓字溢出版心」來過關。
func TestPdfDocWrapLinesFitWidth(t *testing.T) {
	d, err := New(Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	d.setFont(sizeBody)
	samples := append([]string{
		strings.Repeat("0123456789abcdef", 20), // 無任何可折處的長字串：硬折
		"第一行\n\n第三行（前一行為空）\n",                  // 明示換行保留、段尾換行省略
	}, wrapSamples...)
	for _, width := range []float64{15, 37.5, 90, 182} {
		for si, sample := range samples {
			for k := 0; k <= wrapShift; k += 7 {
				s := paddedSample(sample, k)
				lines := d.wrapLines(s, width)
				for li, ln := range lines {
					if w := d.pdf.GetStringWidth(ln); w > width+widthEpsilon && len([]rune(ln)) > 1 {
						t.Errorf("寬 %.1f 樣本 %d 墊 %d：第 %d 行寬 %.2f 超出「%s」", width, si, k, li, w, ln)
					}
					if li > 0 && ln != "" && strings.ContainsRune("、。，．：；？！）」』】", []rune(ln)[0]) {
						t.Errorf("寬 %.1f 樣本 %d 墊 %d：第 %d 行以句讀起頭「%s」", width, si, k, li, ln)
					}
				}
				want := stripSpace(strings.TrimRight(s, "\n"))
				if got := stripSpace(strings.Join(lines, "")); got != want {
					t.Errorf("寬 %.1f 樣本 %d 墊 %d：%s", width, si, k, firstDiff(want, got))
				}
			}
		}
	}
	if got := d.wrapLines("第一行\n\n第三行\n", 182); len(got) != 3 || got[1] != "" {
		t.Errorf("明示換行應得三行且中間為空行，得到 %q", got)
	}
}
