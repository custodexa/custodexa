package proxy

import (
	"strconv"

	"github.com/custodexa/backend/internal/modules/policy"
)

// applyTransferParams 依有效傳輸能力注入 guacd 連線參數（data-transfer-control D3）。
//
// **方向映射是本 change 最容易搞反的地方**（design D2 預警）：
//
//	ClipboardSend（本機→遠端，貼進資產）→ disable-paste
//	ClipboardRecv（遠端→本機，自資產抄出）→ disable-copy
//
// 政策鍵用 enable 語義、guacd 參數用 disable 語義，轉換只在此處單點取反。
// 取反的具體形狀：`disable-copy = !ClipboardRecv`／`disable-paste = !ClipboardSend`。
// `TestTransferParamsDirectionMapping` 以「兩個方向各對調一次」守衛之——
// 只驗一個方向的測試在映射對調後仍可能通過。
//
// **必須在 fillDefaults 之前呼叫**：fillDefaults 的 VNC 分支原本硬寫
// `disable-copy=""` 時填 "false"，本函式先寫入即使該預設分支不再命中
// （該兩段已於本 change 刪除，此處為第二道保險——即使有人把預設值加回來，
// 先寫的政策值也不會被 `== ""` 的條件蓋掉）。
//
// **這是縱深不是主強制點**：guacd 參數在握手時一次性送出，改政策不影響進行中
// 連線；檔案方向的主強制點在 tunnel／file_tap 側（逐次判定、即時生效）。
// 順序不可倒過來——guacd 版本一換，只靠參數的控制就消失了（D3 註 3）。
func applyTransferParams(params map[string]string, protocol string, caps policy.TransferCapabilities) {
	if params == nil {
		return
	}

	// 剪貼簿：RDP 與 VNC 兩分支皆送（RDP 分支原本完全不設，吃 guacd 預設＝允許）
	switch protocol {
	case "rdp", "vnc":
		params["disable-paste"] = strconv.FormatBool(!caps.ClipboardSend)
		params["disable-copy"] = strconv.FormatBool(!caps.ClipboardRecv)
	}

	switch protocol {
	case "rdp":
		// RDP 磁碟重導（enable-drive）的方向控制
		params["disable-upload"] = strconv.FormatBool(!caps.FileUpload)
		params["disable-download"] = strconv.FormatBool(!caps.FileDownload)
	case "vnc":
		// VNC 走 guacd SFTP 側車，參數帶 sftp- 前綴。
		// 側車未啟用（資產未開 SftpEnabled）時這兩個參數是無害的空轉
		params["sftp-disable-upload"] = strconv.FormatBool(!caps.FileUpload)
		params["sftp-disable-download"] = strconv.FormatBool(!caps.FileDownload)
	}
}
