package sshproxy

import "github.com/custodexa/backend/internal/keystroke/format"

// keystrokeAppender 鍵盤紀錄寫入句柄的最小介面（session.KeystrokeRecorder 滿足）。
type keystrokeAppender interface {
	Append(kind, flags byte, payload []byte)
}

// keystrokeTap 把平台「已轉送出去」的使用者輸入交給鍵盤紀錄。
//
// 三條入口、三種來源旗標：
//   - WriteInput：寫入 SSH channel／本機 PTY 成功之後才呼叫（無旗標）
//   - WriteBlockedInput：被指令阻斷、未轉送的那一塊（blocked）
//   - WritePlatformInput：阻斷後平台自己送出的 0x03（platform）
//
// 不經任何正規化、偵測或遮罩。佇列滿時 Append 在呼叫端（輸入泵）同步等待，
// 等於對輸入施加背壓；寫入端停擺才判失敗，其後 Append 立即返回，轉發不受影響。
// 本 tap 不在 outputSinks／resizeSinks。
type keystrokeTap struct {
	rec keystrokeAppender
}

func newKeystrokeTap(rec keystrokeAppender) *keystrokeTap { return &keystrokeTap{rec: rec} }

func (t *keystrokeTap) WriteInput(p []byte) {
	t.rec.Append(format.KindBytes, 0, p)
}

func (t *keystrokeTap) WriteBlockedInput(p []byte) {
	t.rec.Append(format.KindBytes, format.FlagBlocked, p)
}

func (t *keystrokeTap) WritePlatformInput(p []byte) {
	t.rec.Append(format.KindBytes, format.FlagPlatform, p)
}
