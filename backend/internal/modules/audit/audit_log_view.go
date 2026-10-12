package audit

import "github.com/custodexa/backend/internal/model"

// AuditLogView 操作日誌列表與單筆的回應列：原有欄位加原因碼與參數。
// model.AuditLog 本身不加欄位（完整性驗證碼與資料表結構都不受影響）
type AuditLogView struct {
	*model.AuditLog
	ReasonCode   string            `json:"reason_code,omitempty"`
	ReasonParams map[string]string `json:"reason_params,omitempty"`
}

// NewAuditLogView 為一筆審計列附上原因分類
func NewAuditLogView(l *model.AuditLog) AuditLogView {
	if l == nil {
		return AuditLogView{}
	}
	code, params := ClassifyAuditReason(AuditReasonInput{
		Action: string(l.Action), Resource: string(l.Resource), Status: string(l.Status),
		ErrorMsg: l.ErrorMsg, Details: l.Details, Path: l.Path,
	})
	return AuditLogView{AuditLog: l, ReasonCode: code, ReasonParams: params}
}
