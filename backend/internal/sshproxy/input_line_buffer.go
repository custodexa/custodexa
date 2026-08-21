package sshproxy

import "strings"

// InputLineBuffer 輸入側行緩衝（command-blocking 輪 A）：
// 追蹤使用者正在鍵入的一行，Enter 時供阻斷判定。
// 適用互動 shell 行模式；偵測到 ESC 序列（方向鍵/vi 等）即進入
// 失準狀態並 fail-open（不阻斷），直到下一個 Enter 重置——
// 寧可漏擋不可誤擋——行模式以外的輸入本就不在本緩衝射程內：這是刻意的範圍限制，不是缺陷
type InputLineBuffer struct {
	line     strings.Builder
	unsynced bool // ESC 序列後緩衝不可信
}

// NewInputLineBuffer 建立行緩衝
func NewInputLineBuffer() *InputLineBuffer {
	return &InputLineBuffer{}
}

// Feed 餵入一段輸入；回傳 (完整行, 是否為 Enter 提交, 緩衝是否可信)
// 呼叫端僅在 submitted && trusted 時做阻斷判定
func (b *InputLineBuffer) Feed(data []byte) (line string, submitted bool, trusted bool) {
	for i := 0; i < len(data); i++ {
		c := data[i]
		switch {
		case c == '\r' || c == '\n':
			line = b.line.String()
			submitted = true
			trusted = !b.unsynced
			b.Reset()
			return line, submitted, trusted
		case c == 0x7f || c == 0x08: // Backspace / DEL
			b.backspace()
		case c == 0x03 || c == 0x15: // Ctrl+C / Ctrl+U 清行
			b.Reset()
		case c == 0x1b: // ESC：方向鍵/編輯模式，緩衝失準
			b.unsynced = true
		case c >= 0x20: // 可見字元（含 UTF-8 後續位元組）
			b.line.WriteByte(c)
		}
	}
	return "", false, false
}

// Reset 清空緩衝並恢復可信狀態
func (b *InputLineBuffer) Reset() {
	b.line.Reset()
	b.unsynced = false
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
