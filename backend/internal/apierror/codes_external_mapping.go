package apierror

// 外部群組映射的機器碼。保護目標拒絕沿用指派關卡的共用碼。
var (
	// CodeMappingRoleNotDirectMappable 外部群組只能直接映射到無範圍的內建角色；自訂角色改走使用者群組。
	CodeMappingRoleNotDirectMappable = register("MAPPING_ROLE_NOT_DIRECT_MAPPABLE",
		Descriptor{ZhFallback: "這個角色不能直接映射到外部群組，請改用「外部群組對應使用者群組」，再為使用者群組指派角色"})
	// CodeMappingScopeFieldRejected 映射規則本身沒有範圍，請求帶任何範圍或節點欄位整筆拒絕。
	CodeMappingScopeFieldRejected = register("MAPPING_SCOPE_FIELD_REJECTED",
		Descriptor{ZhFallback: "映射規則不支援範圍或節點設定"})
)
