package vtscreen

import "unicode/utf8"

// 位元組級控制序列狀態機。
//
// 依據：ECMA-48（5th ed., 1991）對控制序列結構的定義——
//   - CSI 之後為 parameter bytes（0x30-0x3F）、intermediate bytes（0x20-0x2F），
//     以 final byte（0x40-0x7E）結束；
//   - 序列途中的 C0 控制字元仍即時生效；
//   - CAN（0x18）／SUB（0x1A）中止進行中的序列；
//   - 字串型控制（OSC／DCS／SOS／PM／APC）以 ST 結束，
//     另依 xterm ctlseqs 的慣例接受 BEL 作為 OSC 的終止。
//
// 本檔不引用任何第三方狀態圖或程式碼。

type parserState uint8

const (
	stateGround parserState = iota
	stateEscape
	stateCSIParam
	stateCSIIntermediate
	stateCSIIgnore
	stateString
)

const (
	// maxParamBytes 參數位元組上限；超出即整段忽略（防止畸形輸入撐大狀態）
	maxParamBytes = 64
	// maxParams 參數個數上限
	maxParams = 16
	// maxParamValue 單一參數的數值上限，避免後續運算做出巨量配置
	maxParamValue = 65535
)

// sink 是狀態機的動作接收端，由 Screen 實作。
// 拆成介面是為了讓狀態機可獨立於螢幕語義被測試。
type sink interface {
	print(r rune)                         // 可列印字元
	execute(b byte)                       // C0 控制字元
	csiDispatch(final byte, params []int) // 控制序列（無私有前綴、無中間位元組者才會分派）
	escDispatch(final byte)               // ESC 引導的非 CSI 序列
}

// parser 為位元組級狀態機。狀態跨 Write 呼叫保留：
// 輸入結束在序列中途時，序列停在狀態內、不輸出任何文字，下次餵入時續接。
type parser struct {
	state   parserState
	params  [maxParamBytes]byte
	nparams int
	values  [maxParams]int
	inter   bool // 本序列已出現 intermediate byte
	oscStr  bool // 目前的字串型控制是否為 OSC（唯一接受 BEL 終止者）

	// UTF-8 續接緩衝：多位元組字元被分塊切開時保留於此，不吐出殘骸
	utf8Buf  [4]byte
	utf8Len  int
	utf8Need int
}

// feed 餵入一個位元組。
func (p *parser) feed(b byte, s sink) {
	switch p.state {
	case stateGround:
		p.ground(b, s)
	case stateEscape:
		p.escape(b, s)
	case stateCSIParam, stateCSIIntermediate, stateCSIIgnore:
		p.csi(b, s)
	case stateString:
		p.str(b, s)
	}
}

func (p *parser) ground(b byte, s sink) {
	if b >= 0x80 {
		p.feedUTF8(b, s)
		return
	}
	// ASCII 或控制字元出現，代表未完成的多位元組序列已確定無效
	p.discardPartial(s)
	switch {
	case b == 0x1B:
		p.beginEscape()
	case b < 0x20 || b == 0x7F:
		s.execute(b)
	default:
		s.print(rune(b))
	}
}

func (p *parser) escape(b byte, s sink) {
	switch {
	case b == 0x1B:
		p.beginEscape()
	case b == 0x18 || b == 0x1A: // CAN／SUB 中止序列
		p.state = stateGround
	case b < 0x20:
		s.execute(b) // 序列途中的 C0 即時生效
	case b == 0x7F:
		// DEL：忽略
	case b <= 0x2F: // intermediate byte，例如字集指示的 ESC ( 、ESC #
		p.inter = true
	default: // 0x30-0x7E：final byte
		if !p.inter {
			switch b {
			case '[': // CSI
				p.beginCSI()
				return
			case ']': // OSC
				p.beginString(true)
				return
			case 'P', 'X', '^', '_': // DCS／SOS／PM／APC
				p.beginString(false)
				return
			}
		}
		s.escDispatch(b)
		p.state = stateGround
	}
}

func (p *parser) csi(b byte, s sink) {
	switch {
	case b == 0x1B:
		p.beginEscape()
	case b == 0x18 || b == 0x1A:
		p.state = stateGround
	case b < 0x20:
		s.execute(b) // 序列途中的 C0 即時生效
	case b == 0x7F:
		// DEL：忽略
	case b <= 0x2F: // intermediate byte
		p.inter = true
		if p.state != stateCSIIgnore {
			p.state = stateCSIIntermediate
		}
	case b <= 0x3F: // parameter byte
		// 參數位元組不得出現在中間位元組之後（ECMA-48 的序列結構）
		if p.state != stateCSIParam || p.nparams >= maxParamBytes {
			p.state = stateCSIIgnore
			return
		}
		p.params[p.nparams] = b
		p.nparams++
	default: // 0x40-0x7E：final byte
		if p.state == stateCSIParam && !p.inter {
			if params, ok := p.parseParams(); ok {
				s.csiDispatch(b, params)
			}
		}
		p.state = stateGround
	}
}

// str 處理字串型控制（OSC／DCS／SOS／PM／APC）的內容：一律吞掉。
// ESC 隱含終止字串——其後若為 '\' 即 7-bit ST，由 escape 分派後忽略；
// 若為其他位元組，則作為新序列的起頭處理。
func (p *parser) str(b byte, s sink) {
	switch {
	case b == 0x1B:
		p.beginEscape()
	case b == 0x18 || b == 0x1A:
		p.state = stateGround
	case b == 0x07 && p.oscStr: // BEL 為 OSC 的慣用終止
		p.state = stateGround
	}
}

func (p *parser) beginEscape() {
	p.state = stateEscape
	p.inter = false
}

func (p *parser) beginCSI() {
	p.state = stateCSIParam
	p.nparams = 0
	p.inter = false
}

func (p *parser) beginString(osc bool) {
	p.state = stateString
	p.oscStr = osc
}

// parseParams 把原始參數位元組解析為整數參數。
// 「不解讀」的形態（私有前綴 0x3C-0x3F、子參數分隔 0x3A）一律回傳 ok=false，
// 由呼叫端整段忽略——寧可少解析一種序列，不可解析錯。
func (p *parser) parseParams() ([]int, bool) {
	n, cur := 0, 0
	for i := 0; i < p.nparams; i++ {
		b := p.params[i]
		switch {
		case b >= '0' && b <= '9':
			if cur <= maxParamValue {
				cur = cur*10 + int(b-'0')
			}
		case b == ';':
			if n >= maxParams-1 {
				return nil, false
			}
			p.values[n] = clampParam(cur)
			n++
			cur = 0
		default:
			return nil, false
		}
	}
	p.values[n] = clampParam(cur)
	n++
	return p.values[:n], true
}

func clampParam(v int) int {
	if v > maxParamValue {
		return maxParamValue
	}
	if v < 0 {
		return 0
	}
	return v
}

// feedUTF8 累積多位元組字元。序列未收齊時保留於緩衝，不輸出任何內容。
func (p *parser) feedUTF8(b byte, s sink) {
	if p.utf8Len == 0 {
		need := utf8SeqLen(b)
		if need == 0 { // 非法起始位元組
			s.print(utf8.RuneError)
			return
		}
		p.utf8Need = need
		p.utf8Buf[0] = b
		p.utf8Len = 1
	} else {
		if b >= 0xC0 { // 不是續接位元組：前一段序列作廢，本位元組重新起算
			p.discardPartial(s)
			p.feedUTF8(b, s)
			return
		}
		p.utf8Buf[p.utf8Len] = b
		p.utf8Len++
	}
	if p.utf8Len < p.utf8Need {
		return
	}
	r, size := utf8.DecodeRune(p.utf8Buf[:p.utf8Len])
	p.utf8Len, p.utf8Need = 0, 0
	if r == utf8.RuneError && size <= 1 {
		s.print(utf8.RuneError)
		return
	}
	s.print(r)
}

// discardPartial 丟棄已確定無效的多位元組殘段，代之以替代字元。
func (p *parser) discardPartial(s sink) {
	if p.utf8Len == 0 {
		return
	}
	p.utf8Len, p.utf8Need = 0, 0
	s.print(utf8.RuneError)
}

// utf8SeqLen 由起始位元組推得序列長度；非法起始位元組回傳 0。
func utf8SeqLen(b byte) int {
	switch {
	case b >= 0xC2 && b <= 0xDF:
		return 2
	case b >= 0xE0 && b <= 0xEF:
		return 3
	case b >= 0xF0 && b <= 0xF4:
		return 4
	default:
		return 0
	}
}
