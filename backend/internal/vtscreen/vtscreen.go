// Package vtscreen 以最小虛擬螢幕把終端控制序列串流還原為「螢幕上看得到的文字行」，
// 供指令審計重組使用。
//
// 設計取捨（規範來源：openspec/specs/terminal-screen-parser/spec.md）：
//   - 只還原文字，不保存顏色與屬性；
//   - 不實作自動折行（DECAWM）、捲動、捲動區與 alternate buffer；
//   - 未實作語義的控制序列一律完整消耗，其任何位元組 SHALL NOT 以文字形式流出；
//   - 解析路徑零日誌輸出，且以「不 panic」為設計目標。
//
// 實作依據為 ECMA-48（5th ed.）的控制功能定義與序列結構，
// 以及 xterm ctlseqs 對參數預設值的說明。
package vtscreen

// Screen 為有狀態的虛擬螢幕。
//
// 非併發安全：呼叫端（CommandParser）已在同一把鎖之下使用。
type Screen struct {
	p     parser
	rows  [][]cell
	cx    int // 游標顯示欄（0-based）
	cy    int // 游標列（0-based）
	cells int // 已配置的 cell 總數，供記憶體上限守衛
	// dropped 記錄「曾因記憶體上限丟棄內容」。上限本身是必要的阻斷
	// （防惡意輸出吃爆容器），但靜默丟字是審計產品最不能有的失效形態，
	// 故把它暴露給呼叫端記錄（design.md D14 第 11 條）。
	dropped bool
	// redrawn 記錄「本次寫入曾出現整螢幕層級的定位或清除」。
	// 見 Redrawn 的說明。
	redrawn bool
}

// New 建立一個空螢幕。
func New() *Screen {
	return &Screen{}
}

// Seed 種入原點：以 line 作為第一列的既有內容、cursorX 作為游標的顯示欄。
//
// 這是指令重組的關鍵入口。shell／readline 的欄位算術以「含提示符的整行」為原點，
// 而指令回顯緩衝並不含提示符；不種入原點，重繪就會從錯誤的欄位切開，
// 使審計得到一條使用者從未輸入過的指令。
//
// Seed 會重置整個螢幕狀態，應在 Write 之前呼叫。
// line 內的控制字元一律略過——它的來源是另一個螢幕的還原結果，本就不該含控制位元組。
func (s *Screen) Seed(line string, cursorX int) {
	*s = Screen{}
	for _, r := range line {
		if r < 0x20 || r == 0x7F {
			continue
		}
		s.print(r)
	}
	s.cx = clampCol(cursorX)
	s.cy = 0
}

// Write 餵入原始終端位元組。可重複呼叫：
// 未完成的控制序列與被切開的多位元組字元一律保留在狀態內，下次呼叫時續接，
// 既不 panic，也不會把殘留的位元組吐成文字。
func (s *Screen) Write(p []byte) {
	for _, b := range p {
		s.p.feed(b, s)
	}
}

// Lines 回傳可見文字行，尾端的空白列已去除。
// 列內被寫入的空白是內容，一律保留（例如提示符尾端的那一格空白）。
func (s *Screen) Lines() []string {
	last := -1
	for y := len(s.rows) - 1; y >= 0; y-- {
		if !isBlankRow(s.rows[y]) {
			last = y
			break
		}
	}
	out := make([]string, 0, last+1)
	for y := 0; y <= last; y++ {
		out = append(out, renderRow(s.rows[y]))
	}
	return out
}

// CurrentLine 回傳游標所在列的原文（未 trim）。
func (s *Screen) CurrentLine() string {
	if s.cy < 0 || s.cy >= len(s.rows) {
		return ""
	}
	return renderRow(s.rows[s.cy])
}

// CursorX 回傳游標的顯示欄（0-based）。
func (s *Screen) CursorX() int {
	return s.cx
}

// Dropped 回報本螢幕是否曾因記憶體上限（maxRows／maxCols／maxCells）丟棄內容。
//
// 正常輸入恆為 false：CommandParser 的輸入上限是 tailBufMax 8KB／typingBufMax 64KB，
// 走不到這些上限；為真代表被稽核主機送出了畸形的定位或插入序列，
// 還原出的文字**已經不完整**，呼叫端據此記錄降級事件。
func (s *Screen) Dropped() bool {
	return s.dropped
}

// Redrawn 回報本螢幕是否出現過「整螢幕層級」的游標定位或清除。
//
// 判準的依據不是啟發式而是行編輯器的能力邊界：readline／zle／sqlcmd 這類**行編輯器
// 不知道自己在螢幕的哪一列**，故其重繪只用得起「相對於當前列」的手段——
// CR、BS、CUF/CUB（C/D）、CHA（G，欄絕對）、EL（K）、DCH/ICH。
// 反之，**絕對列定位**（CUP/HVP 的 H/f、VPA 的 d）、**整螢幕清除**（ED 的 Ps=2/3）與
// **捲動區設定**（DECSTBM 的 r）只有全螢幕程式用得起。
//
// 因此本旗標為真，代表這段位元組流不是一次行編輯——把它當成指令行來切，
// 切出來的會是螢幕上某一列的殘留而不是使用者送出的指令。
//
// **刻意不含 CUU/CUD（A/B）**：多列提示符的 zsh 會用它們做行內移動，納入會誤判。
//
// 旗標由 Seed 重置（Seed 會重置整個螢幕），故它描述的恆是「本次 Write 的那段位元組」。
func (s *Screen) Redrawn() bool {
	return s.redrawn
}

// Lines 為便利函式：建立螢幕、寫入 data、回傳可見文字行。
// 供行為基準比對與不需要種入原點的路徑使用。
func Lines(data []byte) []string {
	s := New()
	s.Write(data)
	return s.Lines()
}
