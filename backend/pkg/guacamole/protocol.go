package guacamole

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// 協議邊界上界（guacamole-protocol-conformance）。
//
// 改為依長度前綴串流讀取之後，**要讀多少由對端宣告**——沒有上界等於讓對端
// 指定我方配置多少記憶體。原先以 `strings.Split` 切分時資料已在記憶體中，
// 這個失敗面不存在；它是本次修法引入的，故一併封住。
const (
	// maxElementRunes 單一元素的 codepoint 上限。guac 的 blob 實務量級是數 KB
	// （官方 js 以 6048 位元組為單位切塊），1 MiB 遠高於正常流量又能封住無限增長。
	maxElementRunes = 1 << 20
	// maxElements 單一指令的元素數上限。RDP 的 args 實測約 40 個，128 留足裕度。
	maxElements = 128
	// maxLengthDigits 長度前綴的位數上限，防止對端以超長數字串拖住解析
	maxLengthDigits = 10
)

// Instruction 表示一個 Guacamole 協議指令
// 格式: length.element,length.element,...;
// 例如: 4.size,1.0,4.1024,3.768;
//
// **length 是 Unicode codepoint 數，不是 byte 數。** 官方三處實作一致：
//   - 規範文件：「This length denotes the number of Unicode characters」
//   - guacamole-server（C）：`guac_utf8_strlen`
//   - guacamole-common-js：`Guacamole.Parser.codePointCount`——UTF-16 長度
//     扣掉 surrogate pair 數，即 codepoint 數。見 `frontend/public/guacamole-1.5.5.min.js`，
//     **那是我方實際互通的對象**，比 C 端更有直接效力。
//
// 由此推出的第二件事同樣重要：**元素邊界只由長度前綴決定**。官方 Parser 讀滿宣告的
// codepoint 數之後才檢查該位置是 `,` 還是 `;`，故值本身可以合法含有 `,` 與 `;`。
// 以分隔符切分等於放棄規範給的邊界資訊——檔名、視窗標題、log／error 文字都會踩到。
type Instruction struct {
	Opcode string
	Args   []string
}

// Encode 將指令編碼為 Guacamole 協議格式（長度前綴為 codepoint 數）。
func (i *Instruction) Encode() string {
	var b strings.Builder
	writeElement(&b, i.Opcode)
	for _, arg := range i.Args {
		b.WriteByte(',')
		writeElement(&b, arg)
	}
	b.WriteByte(';')
	return b.String()
}

// writeElement 寫出單一 `length.value` 元素。
func writeElement(b *strings.Builder, value string) {
	b.WriteString(strconv.Itoa(utf8.RuneCountInString(value)))
	b.WriteByte('.')
	b.WriteString(value)
}

// NewInstruction 建立新的指令
func NewInstruction(opcode string, args ...string) *Instruction {
	return &Instruction{
		Opcode: opcode,
		Args:   args,
	}
}

// ReadInstruction 依協議規範自 r 讀取一個完整指令。
//
// 這是**串流入口**：`client.go` 直接餵 guacd 連線的 bufio.Reader。
// 原先該處以 `ReadString(';')` 切指令——值內含 `;` 時會提早截斷，
// 且截斷後的殘渣留在 reader 裡使其後每一個指令都錯位（有界串流失步）。
//
// fail-closed 不變：任一步失敗即回 error，呼叫端丟棄該指令。
func ReadInstruction(r io.RuneReader) (*Instruction, error) {
	elements := make([]string, 0, 8)
	for {
		if len(elements) >= maxElements {
			return nil, fmt.Errorf("指令元素數超過上限 %d", maxElements)
		}

		length, err := readElementLength(r)
		if err != nil {
			return nil, err
		}
		value, err := readElementValue(r, length)
		if err != nil {
			return nil, err
		}
		elements = append(elements, value)

		term, _, err := r.ReadRune()
		if err != nil {
			return nil, fmt.Errorf("讀取元素終止符失敗: %w", err)
		}
		switch term {
		case ',':
			// 還有元素
		case ';':
			return &Instruction{Opcode: elements[0], Args: elements[1:]}, nil
		default:
			return nil, fmt.Errorf("元素終止符既非 ',' 亦非 ';': %q", term)
		}
	}
}

// readElementLength 讀取 `length.` 的長度前綴。
func readElementLength(r io.RuneReader) (int, error) {
	var digits strings.Builder
	for {
		c, _, err := r.ReadRune()
		if err != nil {
			return 0, fmt.Errorf("讀取元素長度失敗: %w", err)
		}
		if c == '.' {
			break
		}
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("元素長度含非數字字元: %q", c)
		}
		if digits.Len() >= maxLengthDigits {
			return 0, fmt.Errorf("元素長度位數超過上限 %d", maxLengthDigits)
		}
		digits.WriteRune(c)
	}
	if digits.Len() == 0 {
		return 0, fmt.Errorf("元素缺少長度前綴")
	}
	n, err := strconv.Atoi(digits.String())
	if err != nil {
		return 0, fmt.Errorf("無效長度: %s", digits.String())
	}
	if n > maxElementRunes {
		return 0, fmt.Errorf("元素長度 %d 超過上限 %d", n, maxElementRunes)
	}
	return n, nil
}

// readElementValue 依長度前綴讀取 n 個 codepoint。
//
// 無效 UTF-8 一律回錯而非以 U+FFFD 替換：替換會**改寫**對端送來的內容，
// 而協議規範要求 UTF-8，收到無效序列時 fail-closed 才是正確的處置。
func readElementValue(r io.RuneReader, n int) (string, error) {
	var b strings.Builder
	for i := 0; i < n; i++ {
		c, size, err := r.ReadRune()
		if err != nil {
			return "", fmt.Errorf("讀取元素內容失敗（已讀 %d/%d 字元）: %w", i, n, err)
		}
		if c == utf8.RuneError && size == 1 {
			return "", fmt.Errorf("元素內容含無效 UTF-8 序列（位置 %d）", i)
		}
		b.WriteRune(c)
	}
	return b.String(), nil
}

// DecodeInstruction 從字串解碼一個 Guacamole 指令。
//
// 用於 WebSocket 訊息（一則訊息恰含一個指令）。尾端有殘留即回錯——
// fail-closed 勝過靜默丟棄看不見的那一段。
func DecodeInstruction(data string) (*Instruction, error) {
	if data == "" {
		return nil, fmt.Errorf("空指令")
	}
	r := strings.NewReader(data)
	inst, err := ReadInstruction(r)
	if err != nil {
		return nil, fmt.Errorf("解碼指令失敗: %w", err)
	}
	if r.Len() > 0 {
		return nil, fmt.Errorf("指令結尾後尚有 %d 位元組殘留", r.Len())
	}
	return inst, nil
}

// 常用指令建構函式

// NewConnectInstruction 建立 connect 指令
func NewConnectInstruction(protocol string) *Instruction {
	return NewInstruction("connect", protocol)
}

// NewSelectInstruction 建立 select 指令
func NewSelectInstruction(protocol string) *Instruction {
	return NewInstruction("select", protocol)
}

// NewSizeInstruction 建立 size 指令 (設定畫面大小)
// size 指令格式: size,width,height,dpi;
// 參數：width (寬度), height (高度), dpi (DPI，通常為 96)
func NewSizeInstruction(width, height int) *Instruction {
	return NewInstruction("size",
		strconv.Itoa(width),
		strconv.Itoa(height),
		"96", // 標準 DPI
	)
}

// NewAudioInstruction 建立 audio 指令
func NewAudioInstruction(mimetypes ...string) *Instruction {
	return NewInstruction("audio", mimetypes...)
}

// NewVideoInstruction 建立 video 指令
func NewVideoInstruction(mimetypes ...string) *Instruction {
	return NewInstruction("video", mimetypes...)
}

// NewImageInstruction 建立 image 指令
func NewImageInstruction(mimetypes ...string) *Instruction {
	return NewInstruction("image", mimetypes...)
}
