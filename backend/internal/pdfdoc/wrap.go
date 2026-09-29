package pdfdoc

import (
	"strings"
	"unicode"
)

// 自動折行。
//
// fpdf 的 MultiCell 把 CJK 字元視為折行點，但折行時沿用「跳過分隔字元」的
// 處理——那是為空白設計的，套在 CJK 上就是把折行點上的那個字丟掉。
// 中文與日文段落幾乎每一次折行都會掉一個字，而讀者無從察覺。
// 故折行在這裡自行計算，逐行以 CellFormat 輸出，不經 MultiCell。

// widthEpsilon 寬度比較的容差（公釐），避免浮點誤差把剛好塞滿的一行判成溢出。
const widthEpsilon = 1e-6

// multiLine 在目前位置畫一段自動折行的文字（靠左、無框、無底色）。
//
// 每一行都從同一個 X 起畫，畫完後 X 回到左邊界、Y 停在最後一行之下。
func (d *Doc) multiLine(w, h float64, text string) {
	x := d.pdf.GetX()
	for _, ln := range d.wrapLines(text, w-2*d.pdf.GetCellMargin()) {
		d.pdf.SetX(x)
		d.pdf.CellFormat(w, h, ln, "", 2, "L", false, 0, "")
	}
	d.pdf.SetX(marginLeft)
}

// wrapLines 以目前字型把文字切成每行不超過 width（公釐）的多行。
//
// 保證：除了折行處被省略的空白之外，輸入的每一個字元都依序出現在某一行裡。
// 明示換行（\n）保留，段尾的換行省略。
func (d *Doc) wrapLines(text string, width float64) []string {
	text = strings.ReplaceAll(text, "\r", "")
	text = strings.TrimRight(text, "\n")
	var out []string
	for _, para := range strings.Split(text, "\n") {
		out = append(out, d.wrapParagraph([]rune(para), width)...)
	}
	return out
}

func (d *Doc) wrapParagraph(rs []rune, width float64) []string {
	if len(rs) == 0 {
		return []string{""}
	}
	var out []string
	for start := 0; start < len(rs); {
		end, next := d.fitLine(rs, start, width)
		out = append(out, strings.TrimRight(string(rs[start:end]), " "))
		start = next
	}
	return out
}

// fitLine 從 start 起找出放得進 width 的最長一行。
// 回傳本行結束位置（不含）與下一行起點；兩者之間只可能是被省略的空白。
func (d *Doc) fitLine(rs []rune, start int, width float64) (end, next int) {
	used := 0.0
	brk := -1
	for i := start; i < len(rs); i++ {
		if i > start && canBreakBefore(rs, i) {
			brk = i
		}
		used += d.pdf.GetStringWidth(string(rs[i]))
		if used <= width+widthEpsilon {
			continue
		}
		switch {
		case rs[i] == ' ':
			// 溢出的是空白：就在這裡折，空白不帶到下一行
			return i, skipSpaces(rs, i)
		case brk > start:
			return brk, skipSpaces(rs, brk)
		case i == start:
			// 單一字元就比一行寬：照樣放一個，避免無窮迴圈
			return i + 1, i + 1
		default:
			// 整段沒有可折之處（例如超長的英數字串）：在字元邊界硬折
			return i, i
		}
	}
	return len(rs), len(rs)
}

func skipSpaces(rs []rune, i int) int {
	for i < len(rs) && rs[i] == ' ' {
		i++
	}
	return i
}

// canBreakBefore 可否在 rs[i-1] 與 rs[i] 之間折行。
//
// 空白之後可折；CJK 字元前後可折，但句讀與閉括號不置行首、開括號不置行尾。
func canBreakBefore(rs []rune, i int) bool {
	prev, cur := rs[i-1], rs[i]
	if cur == ' ' {
		return false
	}
	if prev == ' ' {
		return true
	}
	if strings.ContainsRune(noLineStart, cur) || strings.ContainsRune(noLineEnd, prev) {
		return false
	}
	return isWide(prev) || isWide(cur)
}

const (
	// noLineStart 不置於行首的字元
	noLineStart = "、。，．：；？！）」』】〕〉》｝］〙〗ー・,.;:!?)]}"
	// noLineEnd 不置於行尾的字元
	noLineEnd = "（「『【〔〈《｛［〘〖([{"
)

// isWide 是否為可在前後折行的 CJK 字元（漢字、假名、諺文、全形標點與符號）。
func isWide(r rune) bool {
	switch {
	case r >= 0x3000 && r <= 0x30FF, // CJK 標點、平假名、片假名
		r >= 0xFF00 && r <= 0xFFEF: // 全形與半形形式
		return true
	}
	return unicode.In(r, unicode.Han, unicode.Hangul)
}
