package audit

// WithAPIToken 在條目上標示這次操作經由的 API token（識別與名稱快照）；識別為零、名稱為空或條目已帶標示時不動。
func (e *AuditLogEntry) WithAPIToken(id uint, name string) *AuditLogEntry {
	if e == nil || id == 0 || name == "" || e.APITokenID != nil {
		return e
	}
	e.APITokenID, e.APITokenName = &id, name
	return e
}
