package proxy

import (
	"strconv"
	"strings"

	"github.com/custodexa/backend/internal/keystroke/format"
	"github.com/custodexa/backend/pkg/guacamole"
)

// keystrokeAppender 鍵盤紀錄寫入句柄的最小介面（session.KeystrokeRecorder 滿足）。
type keystrokeAppender interface {
	Append(kind, flags byte, payload []byte)
}

// KeystrokeTap 把「平台已轉送給圖形閘道」的 key 指令交給鍵盤紀錄。
//
// 只看 key：不觀察 connect（含明文密碼）、mouse、clipboard、file、put、blob、argv 等其他指令。
// 參數形狀不符（數目不對、keysym 不是 uint32 十進位、按放不是 0／1）一律記為
// KindKeysymRaw 並保留原始參數，不丟棄。佇列滿時 Append 同步等待，等於對 websocket
// 到圖形閘道的方向施加背壓；寫入端停擺才判失敗，其後 Append 立即返回，轉發不受影響。
// 明文按鍵不進任何 log 或錯誤訊息。
type KeystrokeTap struct {
	rec keystrokeAppender
}

// NewKeystrokeTap 建立 key tap；rec 為 nil 時回 nil（Observe 對 nil 接收者是 no-op）。
func NewKeystrokeTap(rec keystrokeAppender) *KeystrokeTap {
	if rec == nil {
		return nil
	}
	return &KeystrokeTap{rec: rec}
}

// Observe 在指令成功轉送之後呼叫。
func (t *KeystrokeTap) Observe(inst *guacamole.Instruction) {
	if t == nil || t.rec == nil || inst == nil || inst.Opcode != "key" {
		return
	}
	if ks, pressed, ok := parseKeyArgs(inst.Args); ok {
		t.rec.Append(format.KindKeysym, 0, format.EncodeKeysym(ks, pressed))
		return
	}
	t.rec.Append(format.KindKeysymRaw, 0, format.EncodeKeysymRaw([]byte(rawKeyArgs(inst))))
}

// rawKeyArgs 取指令原文的參數部分（保留各元素的長度前綴，參數內含逗號也不會產生歧義）。
func rawKeyArgs(inst *guacamole.Instruction) string {
	enc := inst.Encode()
	enc = strings.TrimPrefix(enc, "3.key")
	enc = strings.TrimPrefix(enc, ",")
	return strings.TrimSuffix(enc, ";")
}

// parseKeyArgs 解 key 指令參數：[keysym 十進位, "1"|"0", ...]。
// guacamole 的 key 指令固定兩個參數，多餘或不足皆視為無法解析。
func parseKeyArgs(args []string) (keysym uint32, pressed bool, ok bool) {
	if len(args) != 2 {
		return 0, false, false
	}
	v, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return 0, false, false
	}
	switch args[1] {
	case "1":
		return uint32(v), true, true
	case "0":
		return uint32(v), false, true
	}
	return 0, false, false
}
