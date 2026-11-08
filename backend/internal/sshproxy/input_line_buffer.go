package sshproxy

import "strings"

// InputLineBuffer 輸入側行緩衝（command-blocking 輪 A）：
// 追蹤使用者正在鍵入的一行，Enter 時供阻斷判定。
// 適用互動 shell 行模式；偵測到 ESC 序列（方向鍵/vi 等）或其他未追蹤的編輯控制字元即進入
// 失準狀態並 fail-open（不阻斷），直到下一個 Enter 重置——
// 寧可漏擋不可誤擋——行模式以外的輸入本就不在本緩衝射程內：這是刻意的範圍限制，不是缺陷
type InputLineBuffer struct {
	line     strings.Builder
	unsynced bool // 跳脫序列或未追蹤的編輯字元之後，緩衝不可信
	// pending 目前正在辨識中的跳脫序列前綴。括號貼上的開始／結束標記可能被拆在兩個輸入幀之間，
	// 故前綴要跨幀保留，直到確認是標記（透明）或其他序列（失準）
	pending []byte
}

// InputLine 一個已提交（Enter）的行
type InputLine struct {
	Text    string
	Trusted bool // 提交當下緩衝是否可信；僅可信行做阻斷判定
}

// 括號貼上的開始與結束標記（視為透明）
const (
	bracketedPasteStart = "\x1b[200~"
	bracketedPasteEnd   = "\x1b[201~"
)

// NewInputLineBuffer 建立行緩衝
func NewInputLineBuffer() *InputLineBuffer {
	return &InputLineBuffer{}
}

// Feed 餵入一個輸入幀；回傳本幀內所有已提交的行（依序，各帶可信度）。
// 最後一個換行之後的殘段留在緩衝，供下一幀接續。
func (b *InputLineBuffer) Feed(data []byte) []InputLine {
	var lines []InputLine
	for i := 0; i < len(data); i++ {
		c := data[i]
		if len(b.pending) > 0 {
			if b.feedEscape(c) {
				continue
			}
			// 不是標記：序列失準，當前位元組照一般字元處理
			b.pending = b.pending[:0]
			b.unsynced = true
		}
		switch {
		case c == '\r' || c == '\n':
			lines = append(lines, InputLine{Text: b.line.String(), Trusted: !b.unsynced})
			b.Reset()
		case c == 0x7f || c == 0x08: // Backspace / DEL
			b.backspace()
		case c == 0x03 || c == 0x15: // Ctrl+C / Ctrl+U 清行
			b.Reset()
		case c == 0x1b: // ESC：可能是括號貼上標記，也可能是方向鍵/編輯模式
			b.pending = append(b.pending[:0], c)
		case c < 0x20:
			// 其餘控制字元（游標移動、刪字、補全等）改變遠端行內容但本緩衝不追蹤，緩衝失準
			b.unsynced = true
		default: // 可見字元（含 UTF-8 後續位元組）
			b.line.WriteByte(c)
		}
	}
	return lines
}

// feedEscape 把一個位元組接到辨識中的跳脫序列；回傳 true＝已被序列吸收（仍在辨識，或已確認為透明標記）
func (b *InputLineBuffer) feedEscape(c byte) bool {
	candidate := append(b.pending, c)
	s := string(candidate)
	if s == bracketedPasteStart || s == bracketedPasteEnd {
		b.pending = b.pending[:0]
		return true
	}
	if strings.HasPrefix(bracketedPasteStart, s) || strings.HasPrefix(bracketedPasteEnd, s) {
		b.pending = candidate
		return true
	}
	return false
}

// Reset 清空緩衝與解析狀態並恢復可信狀態
func (b *InputLineBuffer) Reset() {
	b.line.Reset()
	b.unsynced = false
	b.pending = b.pending[:0]
}

func (b *InputLineBuffer) backspace() {
	s := b.line.String()
	if len(s) == 0 {
		return
	}
	// 退一個 UTF-8 字元：自尾端跳過 continuation bytes
	i := len(s) - 1
	for i > 0 && (s[i]&0xC0) == 0x80 {
		i--
	}
	b.line.Reset()
	b.line.WriteString(s[:i])
}
