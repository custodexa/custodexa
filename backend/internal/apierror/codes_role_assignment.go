package apierror

// 使用者與群組角色指派的機器碼。拒絕訊息不帶角色名稱或權限名稱，
// 細節只進審計的拒絕原因。
var (
	// CodeAuthProtectedRoleAssignment 目標角色或群組帶有超級管理者或系統安全管理員身分，非超級管理者一律拒絕。
	CodeAuthProtectedRoleAssignment = register("AUTH_PROTECTED_ROLE_ASSIGNMENT",
		Descriptor{ZhFallback: "這個指派涉及受保護的角色，你無法執行此操作"})
	// CodeAuthProtectedAccountOperation 非超級管理者對超級管理者帳號的改密、停用多因素驗證、綁定外部身分與角色寫入，
	// 以及對持超級管理者或系統安全管理員身分的帳號停用（含解除綁定並停用）、啟用與刪除。
	CodeAuthProtectedAccountOperation = register("AUTH_PROTECTED_ACCOUNT_OPERATION",
		Descriptor{ZhFallback: "這個帳號受保護，你無法執行此操作"})
	// CodeAuthRoleAssignmentForbidden 操作者沒有指派角色的能力。已退役，不再寫出（見 RetiredDenialCodes）。
	CodeAuthRoleAssignmentForbidden = register("AUTH_ROLE_ASSIGNMENT_FORBIDDEN",
		Descriptor{ZhFallback: "你沒有指派角色的權限"})
	// CodeValidationRoleBindingScopeUnsupported 只收全系統指派的入口（追加、建帳號帶角色、釘住、映射）收到節點範圍或非全域範圍，整筆拒絕。
	CodeValidationRoleBindingScopeUnsupported = register("VALIDATION_ROLE_BINDING_SCOPE_UNSUPPORTED",
		Descriptor{ZhFallback: "這個入口只支援全系統的角色指派，不能指定節點範圍；要限定節點，請用整組替換指派的入口"})
	// CodeValidationRoleNotNodeScopable 角色含只能套用到全系統的權限，不能限定節點。
	CodeValidationRoleNotNodeScopable = register("VALIDATION_ROLE_NOT_NODE_SCOPABLE",
		Descriptor{ZhFallback: "這個角色含只能套用到全系統的權限，不能限定節點"})
	// CodeValidationRoleBindingNodesEmpty 節點範圍是空陣列。
	CodeValidationRoleBindingNodesEmpty = register("VALIDATION_ROLE_BINDING_NODES_EMPTY",
		Descriptor{ZhFallback: "請至少選擇一個節點，或改為全系統"})
	// CodeValidationRoleBindingNodesInvalid 節點範圍含不存在或已刪除的節點；兩者同形，不帶節點名稱。
	CodeValidationRoleBindingNodesInvalid = register("VALIDATION_ROLE_BINDING_NODES_INVALID",
		Descriptor{ZhFallback: "選擇的節點有些已不存在，請重新選擇"})
	// CodeValidationRoleNotGroupBindable 審核者身分不經使用者群組取得。
	CodeValidationRoleNotGroupBindable = register("VALIDATION_ROLE_NOT_GROUP_BINDABLE",
		Descriptor{ZhFallback: "這個角色不能指派給使用者群組"})
)

// CodeInternalRoleAssignmentPreview 預覽角色指派影響時的內部錯誤。
var CodeInternalRoleAssignmentPreview = register("INTERNAL_ROLE_ASSIGNMENT_PREVIEW",
	Descriptor{ZhFallback: "預覽角色指派的影響失敗"})
