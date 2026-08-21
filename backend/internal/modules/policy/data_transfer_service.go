package policy

import (
	"context"
)

// 資料傳輸動作枚舉（data-transfer-control D5）。
//
// **與政策鍵名刻意不同**：政策鍵是 `*_enabled` 的全域開關名，action 是「做什麼」的
// 語義名。期 2 的 `authorization_transfer_grants.action` 存的是本組值，且期 2 之後
// 1.x 會為 port_forward／agent_forward／x11 另立 action 值——action 欄自始是
// varchar＋註冊表而非固定五值枚舉，正是為此留的擴充位（D7）。
const (
	TransferActionClipboardSend = "clipboard_send"
	TransferActionClipboardRecv = "clipboard_recv"
	TransferActionFileUpload    = "file_upload"
	TransferActionFileDownload  = "file_download"
	TransferActionFileDelete    = "file_delete"
)

// 接入通道枚舉（D7）：1.0 的寫入面只接受 `web`，讀取面與解析函式自始支援全枚舉。
const (
	TransferChannelWeb           = "web"
	TransferChannelSCP           = "scp"
	TransferChannelSFTPSubsystem = "sftp_subsystem"
	TransferChannelPortForward   = "port_forward"
	TransferChannelAgentForward  = "agent_forward"
	TransferChannelX11           = "x11"
)

// TransferCapabilities 一次連線／一次動作的五項有效傳輸能力。
//
// true＝允許。零值是**全禁**，這是刻意的：解析失敗時呼叫端拿到的零值即最保守結果，
// 忘了判 error 也不會變成放行。
type TransferCapabilities struct {
	ClipboardSend bool `json:"clipboard_send"`
	ClipboardRecv bool `json:"clipboard_recv"`
	FileUpload    bool `json:"file_upload"`
	FileDownload  bool `json:"file_download"`
	FileDelete    bool `json:"file_delete"`
}

// Allowed 以 action 值取單項能力。未知 action 回 false（fail-close）。
func (c TransferCapabilities) Allowed(action string) bool {
	switch action {
	case TransferActionClipboardSend:
		return c.ClipboardSend
	case TransferActionClipboardRecv:
		return c.ClipboardRecv
	case TransferActionFileUpload:
		return c.FileUpload
	case TransferActionFileDownload:
		return c.FileDownload
	case TransferActionFileDelete:
		return c.FileDelete
	default:
		return false
	}
}

// DataTransferService 資料傳輸有效能力解析（data-transfer-control 第 2 組）。
//
// 期 1 只有全域政策鍵層；期 2 會加上 per-authorization 放寬
// （`effective = globalKey(action) OR ∃ grant(action, channel)`，D5），
// 屆時本結構會多持一個 grant repository，但**解析入口的簽名不變**。
type DataTransferService struct {
	policies *SecurityPolicyService
}

// NewDataTransferService 建構解析器。policies SHALL NOT 為 nil——沒有政策來源就
// 無從解析，靜默降級等同把五個閘全開。
func NewDataTransferService(policies *SecurityPolicyService) *DataTransferService {
	if policies == nil {
		panic("policy: DataTransferService 需要 SecurityPolicyService（nil 會使傳輸閘全開）")
	}
	return &DataTransferService{policies: policies}
}

// EffectiveTransfer 解析 (使用者, 資產) 的五項有效傳輸能力。
//
// **簽名自始帶 userID／assetID／channel**（期 1 未用到後兩者的解析語義，但期 2 的
// per-authorization 放寬與通道維度會用；改簽名會波及全部呼叫點，故一次到位，D7）。
//
// **不豁免任何角色**：函式內 SHALL NOT 有 role 分支。使用者已拍板不留 admin 例外，
// 且 admin 沒有授權列可掛 grant，故 admin 的有效值恆等於全域鍵值（D5「admin 短路」段）。
// `TestEffectiveTransferNoRoleExemption` 守衛此不變式。
//
// 回傳 error 是為期 2 預留（放寬查詢會碰 DB）；期 1 恆為 nil。呼叫端遇 error
// SHALL 視為全禁（`TransferCapabilities` 零值即全禁，見型別註解）。
func (s *DataTransferService) EffectiveTransfer(ctx context.Context, userID, assetID uint, channel string) (TransferCapabilities, error) {
	_ = ctx
	_ = userID
	_ = assetID
	_ = channel
	return TransferCapabilities{
		ClipboardSend: s.policies.GetBool(PolicyClipboardSendEnabled),
		ClipboardRecv: s.policies.GetBool(PolicyClipboardRecvEnabled),
		FileUpload:    s.policies.GetBool(PolicyFileUploadEnabled),
		FileDownload:  s.policies.GetBool(PolicyFileDownloadEnabled),
		FileDelete:    s.policies.GetBool(PolicyFileDeleteEnabled),
	}, nil
}

// AllowsAction 單動作判定的便捷入口（HTTP 端點閘與 tunnel 攔截的共用形態）。
// 解析失敗時回 false——fail-close。
func (s *DataTransferService) AllowsAction(ctx context.Context, userID, assetID uint, channel, action string) (bool, error) {
	caps, err := s.EffectiveTransfer(ctx, userID, assetID, channel)
	if err != nil {
		return false, err
	}
	return caps.Allowed(action), nil
}
