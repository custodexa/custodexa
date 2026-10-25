package apierror

// 角色定義服務的機器碼。目前只有內部服務使用，
// 對外入口由後續段接上；碼與三語詞條先登記，使接入時不必再改 registry。
// 無權沿既有 forbidden 碼，拒絕訊息不帶角色名稱或權限名稱。
var (
	// CodeRoleDefinitionLocked 內建角色與鎖定範本不可修改、刪除，超級管理者範本不可複製。
	CodeRoleDefinitionLocked = register("ROLE_DEFINITION_LOCKED",
		Descriptor{ZhFallback: "此角色為系統內建範本，不能修改、刪除或複製"})
	// CodeRoleDefinitionInUse 角色仍有直接指派、群組指派或有效的外部群組映射。
	CodeRoleDefinitionInUse = register("ROLE_DEFINITION_IN_USE",
		Descriptor{ZhFallback: "此角色仍在使用中，請先移除指派或映射再刪除"})
	// CodeRoleDefinitionConflict 版本已變動（有人先修改過）或名稱已被使用。
	CodeRoleDefinitionConflict = register("ROLE_DEFINITION_CONFLICT",
		Descriptor{ZhFallback: "角色已被其他人修改，或名稱已被使用，請重新載入後再試"})
	// CodeRolePermissionInvalid 權限集合含不合法的項目（整筆拒絕）。
	CodeRolePermissionInvalid = register("ROLE_PERMISSION_INVALID",
		Descriptor{ZhFallback: "權限集合含不合法的項目"})
	// CodeRolePermissionDependencyRequired 權限集合缺少必要的讀取或選擇器依賴的警示文案鍵（允許儲存、不拒絕、不自動補授）。
	CodeRolePermissionDependencyRequired = register("ROLE_PERMISSION_DEPENDENCY_REQUIRED",
		Descriptor{ZhFallback: "權限集合缺少必要的依賴權限"})
	// CodeInternalRoleDefinitionWrite 角色定義寫入的內部失敗（例如分級器或事件寫入器未注入、資料庫錯誤）；
	// 對外只回泛化訊息，原因只進伺服器日誌。
	CodeInternalRoleDefinitionWrite = register("INTERNAL_ROLE_DEFINITION_WRITE",
		Descriptor{ZhFallback: "儲存角色定義失敗"})
)
