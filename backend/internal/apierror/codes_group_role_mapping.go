package apierror

// 外部群組對角色映射（管理面）的 HTTP 出口碼。
//
// 本檔與 codes.go 同一 registry，分檔只為收斂範圍：對應 internal/api 的
// identity_source_handler.go 與 oidc_handler.go 的探索預覽一支。
//
// # 為什麼「需要確認」是一支錯誤碼而不是回應欄位
//
// 映射到管理員角色、以及指向尚未設定群組屬性名／宣告名的來源，兩者都是
// **警告加確認、不阻擋**：規則存得下去，但要求操作者顯式簽下風險，確認一併留痕。
// 表達成 422 加一支碼，用戶端只要不認得這支碼就不會誤以為存好了——把它做成
// 200 回應裡的一個 `warnings` 欄，未更新的用戶端會靜默略過警告而以為已儲存，
// 那正是「要防的是不知情」的反面。命中的警告以 Meta 的 `warnings` 帶出（機器碼，
// 文案由前端依碼決定）。
//
// # 警告碼不進 registry
//
// `MAPPING_TARGETS_ADMIN_ROLE` 一族是**警告**不是錯誤：它們只出現在本碼的
// Meta 與狀態彙總的 `warnings` 欄，由前端以 `warnings.*` 前綴查譯。registry 的
// 完整性守衛比對的是 apiError 區塊，把警告碼登記進去會要求它們也有 apiError
// 詞條，而它們的呈現位置根本不是錯誤提示。
var (
	// CodeValidationMappingMatchValueDN 目錄側的比對值不是可解析的辨識名稱。
	//
	// 目錄側的比對走辨識名稱解析後比較，值解析不了即這條規則永遠不命中，
	// 而症狀是「規則列在頁上、狀態是啟用、沒有一個人拿到角色」。存檔期擋下來
	// 是唯一有訊號的時刻。提供者側非空即可——各家宣告值的形態由提供者決定。
	CodeValidationMappingMatchValueDN = register("VALIDATION_MAPPING_MATCH_VALUE_DN",
		Descriptor{ZhFallback: "群組值必須是可解析的辨識名稱（DN）"})

	// CodeValidationMappingRoleUnknown 指定的角色名不存在
	CodeValidationMappingRoleUnknown = register("VALIDATION_MAPPING_ROLE_UNKNOWN",
		Descriptor{ZhFallback: "指定的角色不存在，無法建立映射規則"})

	// CodeValidationRoleNotMapped 釘住端點的目標角色目前不是由映射賦予。
	//
	// 釘住的語義是「把外部群組給的這一半固定下來」，目標角色沒有映射成分時
	// 該動作沒有意義；靜默當成一般追加會讓「釘住」與「指派」在審計上同形
	CodeValidationRoleNotMapped = register("VALIDATION_ROLE_NOT_MAPPED",
		Descriptor{ZhFallback: "此角色目前並非由群組映射賦予，無法釘住"})

	// CodeMappingAckRequired 命中風險情形且未帶確認（422；Meta.warnings 列出命中的警告碼）
	CodeMappingAckRequired = register("MAPPING_ACK_REQUIRED",
		Descriptor{ZhFallback: "這條規則需要先確認風險才能儲存"})

	// CodeMappingRuleNotFound 指定的映射規則不存在（或不屬於這個來源）
	CodeMappingRuleNotFound = register("MAPPING_RULE_NOT_FOUND",
		Descriptor{ZhFallback: "找不到指定的映射規則"})

	// CodeLDAPDirectoryHasMappings 目錄仍有映射規則，拒刪（409）
	CodeLDAPDirectoryHasMappings = register("LDAP_DIRECTORY_HAS_MAPPINGS",
		Descriptor{ZhFallback: "此目錄仍有群組映射規則，請先移除規則再刪除目錄設定"})

	// CodeOIDCProviderHasMappings 提供者仍有映射規則，拒刪（409）
	CodeOIDCProviderHasMappings = register("OIDC_PROVIDER_HAS_MAPPINGS",
		Descriptor{ZhFallback: "此提供者仍有群組映射規則，請先移除規則再刪除提供者"})

	// CodeOIDCDiscoveryPreviewFailed 探索預覽未能取得文件（502）。
	//
	// 成因（DNS、逾時、非 2xx、文件不合法）只落伺服端 log：對外收斂成一支碼，
	// 逐因回報等於把管理端變成一支可讀出內網探測結果的工具
	CodeOIDCDiscoveryPreviewFailed = register("OIDC_DISCOVERY_PREVIEW_FAILED",
		Descriptor{ZhFallback: "無法向該 issuer 取得探索文件，請確認位址與網路可達性"})
)

// 映射規則的警告機器碼（**不進 registry**，理由見檔頭）。
const (
	// WarningMappingTargetsAdminRole 這條規則會把管理員角色授予該群組全體成員
	WarningMappingTargetsAdminRole = "MAPPING_TARGETS_ADMIN_ROLE"
	// WarningMappingSourceAttrUnset 來源尚未設定群組屬性名／宣告名，規則存下也不會命中
	WarningMappingSourceAttrUnset = "MAPPING_SOURCE_ATTR_UNSET"
	// WarningMappingSourceAttrUnsetWithRules 來源已有啟用中的規則卻未設定群組屬性名／宣告名
	WarningMappingSourceAttrUnsetWithRules = "MAPPING_SOURCE_ATTR_UNSET_WITH_RULES"
	// WarningMappingGroupsScopeMissing 設了群組宣告名但授權範圍不含 groups。
	//
	// 多數提供者只在請求該範圍時才發出群組宣告，缺了它的症狀是鍵缺席、
	// 依既有判準視為空集合，於是全體映射角色被撤且沒有任何訊號
	WarningMappingGroupsScopeMissing = "MAPPING_GROUPS_SCOPE_MISSING"
)
