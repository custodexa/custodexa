package apierror

// RetiredDenialCodes 回傳已退役的能力拒絕碼。
//
// 這些碼原本在回應中帶出角色、權限或專用的資格語意；能力拒絕收斂為單一形狀
// （CodePermissionDenied）之後，生產碼不得再寫出它們。登記與三語譯文仍保留，
// 供舊版前端與既有審計資料解讀。
//
// 守衛見 retired_codes_ast_test.go（TestRetiredDenialCodesNotEmitted）：
// 掃描 internal/ 與 cmd/ 的非測試檔，凡引用本清單的碼即報。
// 本函式是唯一允許引用這些常數的非登記處，守衛以函式名排除它。
func RetiredDenialCodes() []ErrCode {
	return []ErrCode{
		CodeRoleRequired,
		CodeTagListPrivilegedOnly,
		CodeTagGovernanceAdminOnly,
		CodeSessionTerminateAdminOnly,
		CodeMonitorRoleRequired,
		CodeApproverRequired,
		CodeAuthRoleAssignmentForbidden,
	}
}
