package sshproxy

import (
	"fmt"
	"strings"
	"sync"
)

// 轉錄錄影的虛擬終端尺寸。主控台沒有真的終端，但錄影與監看兩條既有管線都以
// 終端為形狀；固定尺寸使回放器不必處理一個不存在的視窗變化
const (
	consoleTranscriptCols = 120
	consoleTranscriptRows = 40
)

// consoleTranscriptMaxMessage 轉錄保存的目標端錯誤訊息上限（字元，rune 安全）。
//
// 訊息本身可能夾帶資料片段（唯一約束違反會回鍵值），而轉錄是長期保存的；
// 即時回給語句作者的訊息**不截斷**——他在目標端本來就看得到
const consoleTranscriptMaxMessage = 512

// consoleTranscriptSink 轉錄的落地面。錄影 tap 與監看 tap 同型，
// 故兩者由同一批位元組同時餵入——監看看到的就是回放會看到的
type consoleTranscriptSink interface {
	WriteOutput(p []byte)
}

// consoleTranscript 把主控台的事件寫成純文字轉錄。
//
// **不含任何結果資料列**：體積無上界，且含敏感資料而本產品沒有遮罩。
// 轉錄是自結構化語句紀錄派生的閱讀面，以事件識別逐行對應；兩者衝突時以紀錄為準
type consoleTranscript struct {
	mu    sync.Mutex
	sinks []consoleTranscriptSink
}

func newConsoleTranscript(sinks ...consoleTranscriptSink) *consoleTranscript {
	live := make([]consoleTranscriptSink, 0, len(sinks))
	for _, s := range sinks {
		if s != nil && !isNilSink(s) {
			live = append(live, s)
		}
	}
	return &consoleTranscript{sinks: live}
}

// isNilSink 具體型別的 nil 指標裝進介面後不等於 nil——錄影啟動失敗時
// 傳進來的正是那種值，不濾掉就會在第一次寫入時 panic
func isNilSink(s consoleTranscriptSink) bool {
	switch v := s.(type) {
	case *recordingTap:
		return v == nil
	case *monitorTap:
		return v == nil
	}
	return false
}

func (t *consoleTranscript) writeLine(line string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	// 終端換行：回放器與監看端都把 .cast 的內容當終端輸出，缺 CR 會讓每一行
	// 自上一行的結尾繼續縮排
	b := []byte(line + "\r\n")
	for _, s := range t.sinks {
		s.WriteOutput(b)
	}
}

// Statement 語句送出行
func (t *consoleTranscript) Statement(database, eventID, text string) {
	t.writeLine(fmt.Sprintf("[%s] %s> %s", database, eventID, text))
}

// OK 全部完成
func (t *consoleTranscript) OK(eventID string, rows int64, affected int64, sets int, ms int64) {
	t.writeLine(fmt.Sprintf("-- %s ok: %d rows, %d affected, %d sets (%d ms)",
		eventID, rows, affected, sets, ms))
}

// Partial 回錯前已有語句完成
func (t *consoleTranscript) Partial(eventID string, rows int64, affected int64, sets int, ms int64) {
	t.writeLine(fmt.Sprintf("-- %s partial: %d rows, %d affected, %d sets (%d ms)",
		eventID, rows, affected, sets, ms))
}

// Error 目標端回錯
func (t *consoleTranscript) Error(eventID, code, message string) {
	t.writeLine(fmt.Sprintf("-- %s error %s: %s", eventID, code,
		truncateRunes(message, consoleTranscriptMaxMessage)))
}

// Blocked 規則命中
func (t *consoleTranscript) Blocked(eventID, rule string) {
	t.writeLine(fmt.Sprintf("-- %s blocked by rule %s", eventID, rule))
}

// BlockerUnavailable 比對器不可用而 fail-close
func (t *consoleTranscript) BlockerUnavailable(eventID string) {
	t.writeLine(fmt.Sprintf("-- %s blocked: matcher unavailable", eventID))
}

// Terminal 其餘終態（cancelled／timeout／effect_unknown）
func (t *consoleTranscript) Terminal(eventID, status, reason string) {
	if reason == "" {
		t.writeLine(fmt.Sprintf("-- %s %s", eventID, status))
		return
	}
	t.writeLine(fmt.Sprintf("-- %s %s (%s)", eventID, status, reason))
}

// Switched 切庫成功
func (t *consoleTranscript) Switched(database string) {
	t.writeLine("-- switched database: " + database)
}

// SwitchFailed 切庫失敗只記分類，不記訊息——切庫屬連線階段
func (t *consoleTranscript) SwitchFailed(class string) {
	t.writeLine("-- switch failed: " + class)
}

// ConnectionClosed 目標連線關閉
func (t *consoleTranscript) ConnectionClosed(reason string) {
	t.writeLine("-- connection closed: " + reason)
}

// truncateRunes 以字元為單位截斷並標記。以 rune 切是必要的：
// 按位元組切會把多位元組字元切成兩半，寫進 .cast 就是一段無效 UTF-8
func truncateRunes(s string, limit int) string {
	if limit <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= limit {
		return strings.ReplaceAll(s, "\n", " ")
	}
	return strings.ReplaceAll(string(r[:limit]), "\n", " ") + "…"
}
