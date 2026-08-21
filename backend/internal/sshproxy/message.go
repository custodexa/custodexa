package sshproxy

import (
	"encoding/json"
	"fmt"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/notifycat"
)

// MessageType WebSocket 訊息類型（design D1：JSON envelope）
type MessageType string

const (
	// MsgData 終端 I/O 資料（雙向）：前端鍵入 → 後端 stdin；後端 stdout → 前端渲染
	MsgData MessageType = "data"
	// MsgResize 終端尺寸變更（前端 → 後端），data 為 ResizePayload JSON
	MsgResize MessageType = "resize"
	// MsgPing 前端保活訊息，後端以 MsgPong 回應
	MsgPing MessageType = "ping"
	// MsgPong 後端對 MsgPing 的回應
	MsgPong MessageType = "pong"
	// MsgConnected 後端通知 SSH 連線已建立（後端 → 前端）
	MsgConnected MessageType = "connected"
	// MsgError 後端錯誤通知（後端 → 前端），data 為使用者可讀訊息
	MsgError MessageType = "error"
	// MsgNotice 後端非錯誤的控制通知（後端 → 前端，backend-i18n-unification D7）：
	// 目前唯一用途是指令阻斷警告。與 MsgError 的差別在語義而非結構——會話未斷，
	// 前端以警示樣式注入終端後繼續連線。舊分頁忽略未知 type（已知限制，見 D7）
	MsgNotice MessageType = "notice"
)

// 終端尺寸上限：防止惡意 resize 造成 PTY/虛擬螢幕資源放大
const (
	maxCols = 1000
	maxRows = 500
)

// Message WebSocket 訊息封包。Code 由 MsgError 與 MsgNotice 使用：機器可讀碼
// （apierror registry，ssh-connect-error-surfacing／backend-i18n-unification D7），
// Data 為 zh fallback 文案，與 HTTP 錯誤封套 {error, code} 同構；
// 舊前端忽略未知欄位即退回 Data。
//
// Params 承載碼的插值參數（D7）：值一律為 opaque 自由字串，編碼時全數過
// notifycat.SanitizeOpaque（strip ANSI/控制字元＋限長），前端查譯後注入 xterm
// 前再 escape 一次（縱深防禦）。
type Message struct {
	Type   MessageType       `json:"type"`
	Data   string            `json:"data,omitempty"`
	Code   string            `json:"code,omitempty"`
	Params map[string]string `json:"params,omitempty"`
}

// ResizePayload resize 訊息的內容
type ResizePayload struct {
	Cols int `json:"cols"`
	Rows int `json:"rows"`
}

// EncodeMessage 將訊息編碼為 JSON bytes（僅限不帶碼的幀：data/resize/ping/pong/
// connected）。
//
// **不變量（D7）**：MsgError 與 MsgNotice 一律不得由本函式產生——它們的語義是
// 「機器可讀碼 + zh fallback」，少了 Code 欄前端就只剩伺服端硬寫的中文可顯示，
// i18n 收口當場破功。型別系統擋不住 `EncodeMessage(MsgError, "認證失敗")`
// （MessageType 是同一型別），故在此做執行期 fail-closed；靜態面另有
// TestNoUncodedErrorFrames 掃 sshproxy/proxy 的非測試碼。
func EncodeMessage(msgType MessageType, data string) ([]byte, error) {
	if msgType == MsgError || msgType == MsgNotice {
		return nil, fmt.Errorf(
			"sshproxy: %s 幀必須帶 apierror 碼，請改用 EncodeErrorMessage/EncodeCodedErrorMessage/EncodeNoticeMessage",
			msgType)
	}
	return json.Marshal(Message{Type: msgType, Data: data})
}

// zhFallbackOf 取碼在 apierror registry 的 zh-TW fallback 文案。
//
// 這是 D7「送碼、前端查譯」的伺服端半邊：串流出口的中文一律由 registry 提供，
// sshproxy／proxy 的非測試碼因此不再有使用者可見的中文字面量
// （由 TestNoChineseLiteralsInStreamExits 守衛）。未註冊碼在編譯期已被
// apierror.ErrCode 型別＋registry 常數擋下，此處僅為防禦性退回空字串。
func zhFallbackOf(code apierror.ErrCode) string {
	if d, ok := apierror.DescriptorOf(code); ok {
		return d.ZhFallback
	}
	return ""
}

// EncodeErrorMessage 編碼帶機器可讀錯誤碼的 MsgError。
//
// code 為 apierror.ErrCode 必填；data 為 zh fallback 文案——多數呼叫點傳
// zhFallbackOf(code)，撥號類則傳底層已分類的具體訊息（比通用 fallback 更有資訊）。
//
// **fail-closed**：ErrCode 的型別只保證「不是別的字串型別」，擋不住零值——
// 一個未初始化的 ErrCode 變數會編出 `{"type":"error","data":"…"}` 這種無碼幀，
// 正是 D7 要消滅的形態。空碼一律回 error（呼叫端已全數 log 並放棄該幀），
// 不容許靜默降級成無碼幀。
func EncodeErrorMessage(code apierror.ErrCode, data string) ([]byte, error) {
	if code == "" {
		return nil, fmt.Errorf("sshproxy: MsgError 幀必須帶非空 apierror 碼（D7 不變量）")
	}
	return json.Marshal(Message{Type: MsgError, Data: data, Code: string(code)})
}

// EncodeCodedErrorMessage 是 EncodeErrorMessage 的常見情形：Data 直接取碼的
// zh fallback，呼叫點無需碰任何文案。
func EncodeCodedErrorMessage(code apierror.ErrCode) ([]byte, error) {
	return EncodeErrorMessage(code, zhFallbackOf(code))
}

// EncodeNoticeMessage 編碼 MsgNotice 控制幀（D7）：Code＋zh fallback Data＋
// 淨化後的 Params。
//
// Data 保留 zh fallback（比照 MsgError）是安全 UX 要求而非冗餘——譯文漏鍵時
// 若無 fallback，阻斷會變成「指令沒送出且毫無提示」的靜默失敗。
// Params 的值全數過 notifycat.SanitizeOpaque：來源（如 AlertRule.Name）僅驗
// required，可含 ANSI 逸出序列與控制字元，直送終端即為注入面。
func EncodeNoticeMessage(code apierror.ErrCode, params map[string]string) ([]byte, error) {
	var clean map[string]string
	if len(params) > 0 {
		clean = make(map[string]string, len(params))
		for k, v := range params {
			clean[k] = notifycat.SanitizeOpaque(v)
		}
	}
	return json.Marshal(Message{
		Type:   MsgNotice,
		Data:   zhFallbackOf(code),
		Code:   string(code),
		Params: clean,
	})
}

// DecodeMessage 解析 JSON bytes 為訊息，未知類型回傳錯誤
func DecodeMessage(raw []byte) (Message, error) {
	var msg Message
	if err := json.Unmarshal(raw, &msg); err != nil {
		return Message{}, fmt.Errorf("訊息格式錯誤: %w", err)
	}

	switch msg.Type {
	case MsgData, MsgResize, MsgPing, MsgPong, MsgConnected, MsgError:
		return msg, nil
	default:
		return Message{}, fmt.Errorf("未知的訊息類型: %q", msg.Type)
	}
}

// ParseResizePayload 解析 resize 訊息內容並驗證尺寸範圍
func ParseResizePayload(data string) (ResizePayload, error) {
	var payload ResizePayload
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		return ResizePayload{}, fmt.Errorf("resize 內容格式錯誤: %w", err)
	}

	if payload.Cols < 1 || payload.Cols > maxCols {
		return ResizePayload{}, fmt.Errorf("cols 超出範圍 [1, %d]: %d", maxCols, payload.Cols)
	}
	if payload.Rows < 1 || payload.Rows > maxRows {
		return ResizePayload{}, fmt.Errorf("rows 超出範圍 [1, %d]: %d", maxRows, payload.Rows)
	}

	return payload, nil
}
