package vtscreen

import "github.com/mattn/go-runewidth"

// 行模型與螢幕語義。
//
// 模型刻意不含「螢幕寬度」：不做自動折行（DECAWM）、不做捲動、不做 alternate buffer。
// 理由是指令重組只取還原結果的最後一個非空行，
// 一旦超寬指令被折成多行，審計留下的就只有指令尾段。
//
// 每一列是一串 cell，一個 cell 等於一個顯示欄；寬字元佔兩欄（主位 ＋ 續位）。
// 「行尾的空白」與「沒有內容」在螢幕上不可分辨，故清除觸及行尾時直接截短該列；
// 相對地，被明確寫入的空白是內容，一律保留。

const (
	// maxRows 列數上限。空列本身只佔一個 slice header，可放寬。
	maxRows = 8192
	// maxCols 單列顯示欄上限。
	maxCols = 65536
	// maxCells 全螢幕已配置 cell 總數上限，是記憶體的硬上限
	// （畸形輸入可用 ICH／絕對定位撐大螢幕，此處收口）。
	maxCells = 1 << 18
	// tabWidth 固定 8 欄 tab stop。
	tabWidth = 8
	// maxZeroWidth 單一顯示欄可附著的零寬字元位元組上限。
	maxZeroWidth = 32
)

// contRune 標記寬字元佔用的第二個顯示欄。
const contRune = rune(-1)

// cell 為一個顯示欄。
type cell struct {
	r  rune   // 顯示字元；contRune 代表寬字元續位
	zw string // 附著於本欄的零寬字元（組合附加符號、ZWJ 等）
}

func blankCell() cell { return cell{r: ' '} }

// print 寫入一個可列印字元（覆寫語義）。
func (s *Screen) print(r rune) {
	w := runewidth.RuneWidth(r)
	if w <= 0 {
		s.attachZeroWidth(r)
		return
	}
	if s.cx < 0 {
		s.cx = 0
	}
	if s.cx+w > maxCols {
		s.dropped = true
		return // 超出上限即丟棄；不折行
	}
	// 游標右移超出行尾時，寫入前以空白補齊到游標欄
	row := s.padTo(s.cy, s.cx+w)
	if row == nil {
		s.dropped = true
		return
	}
	s.breakWide(row, s.cx)
	row[s.cx] = cell{r: r}
	if w == 2 {
		s.breakWide(row, s.cx+1)
		row[s.cx+1] = cell{r: contRune}
	}
	s.cx += w
}

// attachZeroWidth 把零寬字元（組合附加符號、ZWJ）附著到左側最近的主位，
// 使其不佔顯示欄、亦不從審計文字中消失。
func (s *Screen) attachZeroWidth(r rune) {
	if s.cy >= len(s.rows) {
		return
	}
	row := s.rows[s.cy]
	col := s.cx - 1
	if col >= len(row) {
		col = len(row) - 1
	}
	if col > 0 && row[col].r == contRune {
		col--
	}
	if col < 0 || col >= len(row) {
		return
	}
	if len(row[col].zw) >= maxZeroWidth {
		return
	}
	row[col].zw += string(r)
}

// execute 處理 C0 控制字元。
func (s *Screen) execute(b byte) {
	switch b {
	case 0x08: // BS：左移一欄，不抹除內容
		if s.cx > 0 {
			s.cx--
		}
	case 0x09: // HT：推進到下一個 tab stop；恰在 tab stop 上時推進到「下一個」
		s.cx = clampCol((s.cx/tabWidth + 1) * tabWidth)
	case 0x0A, 0x0B, 0x0C: // LF／VT／FF：下移一列，欄位不變（xterm ctlseqs：VT、FF 同 LF）
		if s.cy+1 < maxRows {
			s.cy++
			break
		}
		s.dropped = true // 觸及列數上限：換行失效，其後內容會與最後一列相疊
	case 0x0D: // CR
		s.cx = 0
	default:
		// BEL 與其餘 C0：吞掉，不進文字
	}
}

// csiDispatch 分派控制序列。未列名的 final byte 一律吃掉（catch-all），不留殘骸。
func (s *Screen) csiDispatch(final byte, params []int) {
	switch final {
	case '@': // ICH 行內插入
		s.insertChars(paramDef(params, 0, 1))
	case 'A': // CUU
		s.cy = clampRow(s.cy - paramDef(params, 0, 1))
	case 'B': // CUD
		s.cy = clampRow(s.cy + paramDef(params, 0, 1))
	case 'C': // CUF
		s.cx = clampCol(s.cx + paramDef(params, 0, 1))
	case 'D': // CUB
		s.cx = clampCol(s.cx - paramDef(params, 0, 1))
	case 'E': // CNL
		s.cy = clampRow(s.cy + paramDef(params, 0, 1))
		s.cx = 0
	case 'F': // CPL
		s.cy = clampRow(s.cy - paramDef(params, 0, 1))
		s.cx = 0
	case 'G': // CHA：參數 1-based，內部游標 0-based
		s.cx = clampCol(paramDef(params, 0, 1) - 1)
	case 'H', 'f': // CUP／HVP：兩個參數皆 1-based
		s.cy = clampRow(paramDef(params, 0, 1) - 1)
		s.cx = clampCol(paramDef(params, 1, 1) - 1)
		s.redrawn = true // 絕對列定位：行編輯器用不起（見 Redrawn）
	case 'J': // ED
		if ps := paramRaw(params, 0); ps == 2 || ps == 3 {
			s.redrawn = true // 整螢幕清除
		}
		s.eraseDisplay(paramRaw(params, 0))
	case 'K': // EL
		s.eraseLine(paramRaw(params, 0))
	case 'P': // DCH 行內刪除（左移）
		s.deleteChars(paramDef(params, 0, 1))
	case 'X': // ECH 原地清除（不左移）
		s.eraseChars(paramDef(params, 0, 1))
	case 'd': // VPA：參數 1-based
		s.cy = clampRow(paramDef(params, 0, 1) - 1)
		s.redrawn = true // 絕對列定位
	case 'r': // DECSTBM 捲動區：本螢幕不實作捲動，只記錄「這是全螢幕程式」
		s.redrawn = true
	case 'm', 'h', 'l':
		// SGR／SM／RM：明確吃掉不解讀。
		// SGR 不得有任何屬性相關的特殊處理——被取代的實作在此錄製補全提示，
		// 會靜默剪掉該行後續文字。
	default:
		// 其餘 final byte：完整消耗、不留殘骸
	}
}

// escDispatch 處理 ESC 引導的非 CSI 序列（字集指示、ESC 7/8、ESC D/E/M、ESC c、ST）。
// 正確消耗即可，語義可略。
func (s *Screen) escDispatch(byte) {
}

// eraseLine 實作 EL。游標一律不動。
func (s *Screen) eraseLine(ps int) {
	switch ps {
	case 0: // 自游標欄（含）清到行尾
		s.truncateRow(s.cy, s.cx)
	case 1: // 自行首清到游標欄（含）
		s.blankRange(s.cy, 0, s.cx)
	case 2: // 清整列，且不碰其他列
		s.truncateRow(s.cy, 0)
	}
}

// eraseDisplay 實作 ED。列數與游標皆不動，只把內容清空。
func (s *Screen) eraseDisplay(ps int) {
	switch ps {
	case 0: // 自游標處清到畫面尾
		s.truncateRow(s.cy, s.cx)
		for y := s.cy + 1; y < len(s.rows); y++ {
			s.truncateRow(y, 0)
		}
	case 1: // 自畫面首清到游標處（含游標欄）
		for y := 0; y < s.cy && y < len(s.rows); y++ {
			s.truncateRow(y, 0)
		}
		s.blankRange(s.cy, 0, s.cx)
	case 2: // 清整個畫面
		for y := range s.rows {
			s.truncateRow(y, 0)
		}
	default:
		// Ps=3（清捲動歷史）：本實作無捲動歷史，無事可做
	}
}

// insertChars 實作 ICH：於游標處插入空白，其後內容右移。
func (s *Screen) insertChars(n int) {
	if s.cy >= len(s.rows) || n <= 0 {
		return
	}
	row := s.rows[s.cy]
	if s.cx >= len(row) {
		return // 游標在行尾之後：插入空白於螢幕上無變化
	}
	if n > maxCols-len(row) {
		n = maxCols - len(row)
		s.dropped = true // 插入被上限截短：其後內容右移的欄數與真實終端不同
	}
	if n <= 0 || s.cells+n > maxCells {
		s.dropped = true
		return
	}
	s.breakWide(row, s.cx)
	row = append(row, make([]cell, n)...)
	copy(row[s.cx+n:], row[s.cx:])
	for i := s.cx; i < s.cx+n; i++ {
		row[i] = blankCell()
	}
	s.cells += n
	s.rows[s.cy] = row
}

// deleteChars 實作 DCH：刪除游標處起的字元，其後內容左移。
func (s *Screen) deleteChars(n int) {
	if s.cy >= len(s.rows) || n <= 0 {
		return
	}
	row := s.rows[s.cy]
	if s.cx >= len(row) {
		return
	}
	if n > len(row)-s.cx {
		n = len(row) - s.cx
	}
	s.breakWide(row, s.cx)
	s.breakWide(row, s.cx+n-1)
	copy(row[s.cx:], row[s.cx+n:])
	s.cells -= n
	s.rows[s.cy] = row[:len(row)-n]
}

// eraseChars 實作 ECH：原地清成空白，不左移（與 DCH 不同）。
func (s *Screen) eraseChars(n int) {
	if n <= 0 {
		return
	}
	s.blankRange(s.cy, s.cx, s.cx+n-1)
}

// blankRange 把 [from,to]（含端點）清成空白。
// 清除若觸及行尾則直接截短——螢幕上行尾空白與無內容不可分辨。
func (s *Screen) blankRange(y, from, to int) {
	if y < 0 || y >= len(s.rows) || to < from {
		return
	}
	row := s.rows[y]
	if from < 0 {
		from = 0
	}
	if from >= len(row) {
		return
	}
	if to >= len(row)-1 {
		s.truncateRow(y, from)
		return
	}
	s.breakWide(row, from)
	s.breakWide(row, to)
	for i := from; i <= to; i++ {
		row[i] = blankCell()
	}
}

// truncateRow 把某列截短到 n 欄。
func (s *Screen) truncateRow(y, n int) {
	if y < 0 || y >= len(s.rows) {
		return
	}
	row := s.rows[y]
	if n < 0 {
		n = 0
	}
	if n >= len(row) {
		return
	}
	if n > 0 && row[n].r == contRune {
		row[n-1] = blankCell() // 截在寬字元中間：左半成為空白
	}
	s.cells -= len(row) - n
	s.rows[y] = row[:n]
}

// breakWide 處理覆寫寬字元時的殘半：
// col 若為續位，其左側主位改為空白；col 若為寬字元主位，其右側續位改為空白。
func (s *Screen) breakWide(row []cell, col int) {
	if col < 0 || col >= len(row) {
		return
	}
	if row[col].r == contRune {
		if col > 0 {
			row[col-1] = blankCell()
		}
		return
	}
	if col+1 < len(row) && row[col+1].r == contRune {
		row[col+1] = blankCell()
	}
}

// padTo 確保第 y 列存在且至少有 n 欄，不足處以空白補齊。
// 觸及記憶體上限時回傳 nil，呼叫端據此放棄該次寫入。
func (s *Screen) padTo(y, n int) []cell {
	if y < 0 || y >= maxRows {
		return nil
	}
	for len(s.rows) <= y {
		s.rows = append(s.rows, nil)
	}
	row := s.rows[y]
	if len(row) >= n {
		return row
	}
	grow := n - len(row)
	if s.cells+grow > maxCells {
		return nil
	}
	for i := 0; i < grow; i++ {
		row = append(row, blankCell())
	}
	s.cells += grow
	s.rows[y] = row
	return row
}

// renderRow 把一列還原為文字：續位不輸出，零寬字元跟在主位之後。
func renderRow(row []cell) string {
	if len(row) == 0 {
		return ""
	}
	out := make([]rune, 0, len(row))
	for _, c := range row {
		if c.r == contRune {
			continue
		}
		out = append(out, c.r)
		if c.zw != "" {
			out = append(out, []rune(c.zw)...)
		}
	}
	return string(out)
}

// isBlankRow 判斷一列在螢幕上是否完全看不見內容。
func isBlankRow(row []cell) bool {
	for _, c := range row {
		if c.zw != "" {
			return false
		}
		if c.r != ' ' && c.r != contRune {
			return false
		}
	}
	return true
}

func clampRow(y int) int {
	if y < 0 {
		return 0
	}
	if y >= maxRows {
		return maxRows - 1
	}
	return y
}

func clampCol(x int) int {
	if x < 0 {
		return 0
	}
	if x > maxCols {
		return maxCols
	}
	return x
}

// paramRaw 取第 i 個參數；缺省為 0。
func paramRaw(params []int, i int) int {
	if i >= len(params) {
		return 0
	}
	return params[i]
}

// paramDef 取第 i 個參數；缺省或為 0 時皆採預設值（ECMA-48 的參數預設規則）。
func paramDef(params []int, i, def int) int {
	v := paramRaw(params, i)
	if v == 0 {
		return def
	}
	return v
}
