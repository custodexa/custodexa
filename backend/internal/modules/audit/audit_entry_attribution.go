package audit

// WithAPIToken 在條目上標示這次操作經由的 API token（識別與名稱快照）；識別為零、名稱為空或條目已帶標示時不動。
func (e *AuditLogEntry) WithAPIToken(id uint, name string) *AuditLogEntry {
	if e == nil || id == 0 || name == "" || e.APITokenID != nil {
		return e
	}
	e.APITokenID, e.APITokenName = &id, name
	return e
}

// WithAPITokenOrigin 條目已帶 API token 標示時，請求識別、來源位址為空者補上經由 token 的那一次請求的值
// （已有值的欄位不覆寫）；不帶標示時不動。
func (e *AuditLogEntry) WithAPITokenOrigin(requestID, clientIP string) *AuditLogEntry {
	if e == nil || e.APITokenID == nil {
		return e
	}
	if e.RequestID == "" {
		e.RequestID = requestID
	}
	if e.ClientIP == "" {
		e.ClientIP = clientIP
	}
	return e
}
