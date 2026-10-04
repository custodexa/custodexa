package sshproxy

import (
	"context"
	"encoding/json"
	"log"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
)

// auditTextTransferSnapshot records policy at successful session creation. Text
// clipboard operations have no server-side enforcement point; managed file
// operations continue to evaluate their policy when performed.
func (h *Handler) auditTextTransferSnapshot(sess *model.Session) {
	if sess.Protocol != model.ProtocolSSH && !sess.Protocol.IsDatabase() {
		return
	}
	if h.AuditService == nil {
		log.Printf("[SSHProxy] 稽核服務未注入，文字會話傳輸快照未留存（sessionID=%d）", sess.ID)
		return
	}
	var capabilities policy.TransferCapabilities
	resolved := false
	if h.DataTransfer != nil {
		value, err := h.DataTransfer.EffectiveTransfer(context.Background(), sess.UserID, *sess.AssetID, policy.TransferChannelWeb)
		if err == nil {
			capabilities = value
			resolved = true
		} else {
			log.Printf("[SSHProxy] 文字會話傳輸政策解析失敗（sessionID=%d）: %v", sess.ID, err)
		}
	}
	details, _ := json.Marshal(map[string]any{
		"session_id": sess.ID, "asset_id": *sess.AssetID, "protocol": sess.Protocol,
		"db_console": sess.DBConsole, "transfer_capabilities": capabilities,
		"clipboard_enforced": false, "transfer_capabilities_resolved": resolved,
	})
	h.AuditService.Log(&audit.AuditLogEntry{
		UserID: sess.UserID, ResourceID: &sess.ID, AssetID: sess.AssetID,
		Action: model.ActionCreate, Resource: model.ResourceSession, Status: model.StatusSuccess,
		ClientIP: sess.ClientIP, Details: string(details),
	})
}
