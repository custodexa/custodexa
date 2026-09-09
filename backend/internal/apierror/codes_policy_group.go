package apierror

// 政策組、合規對照與排程預覽的 HTTP 出口碼。
//
// 本檔與 codes.go 同一 registry，分檔只為收斂範圍：對應 internal/api 的
// policy_group_handler.go、compliance_handler.go、schedule_handler.go 與
// security_policy_handler.go 的套用預覽三支。
//
// # 為什麼碼要與資料存取層的錯誤一一對應
//
// 政策組的寫入被拒有十一種成因，修法各不相同：改代號、改條號、換比較方式、
// 換一個鍵、改要求值、或者根本不該編輯這一列（內建組）。收斂成單一「儲存失敗」
// 會讓管理者只能逐項試——而其中一種成因（內建組唯讀）試到底也不會成功。
// 故資料存取層每一個錯誤碼在此各有一支對外碼，訊息直接說出下一步。

// --- 政策組本體（非驗證類）---
var (
	// CodePolicyGroupBuiltinReadOnly 內建組的條文與要求隨產品版本發布，
	// 管理面只能改生效開關與加備註（403）
	CodePolicyGroupBuiltinReadOnly = register("POLICY_GROUP_BUILTIN_READONLY",
		Descriptor{ZhFallback: "內建政策組的內容不可編輯，只能切換生效與加註機構備註"})

	// CodePolicyGroupNotFound 指定的政策組不存在（404）。
	//
	// **不回空結果**：組代號打錯字與「這一組真的沒有任何對照」在畫面上長得一樣，
	// 而前者要改的是輸入、後者要改的是條文
	CodePolicyGroupNotFound = register("POLICY_GROUP_NOT_FOUND",
		Descriptor{ZhFallback: "找不到指定的政策組"})

	// CodePolicyGroupDuplicateCode 組代號已被其他政策組使用（409）
	CodePolicyGroupDuplicateCode = register("POLICY_GROUP_DUPLICATE_CODE",
		Descriptor{ZhFallback: "這個政策組代號已經存在，請換一個"})
)

// --- 政策組寫入的驗證（400）---
var (
	// CodeValidationPolicyGroupCode 組代號或組名稱不合法（空值或超過欄位長度）
	CodeValidationPolicyGroupCode = register("VALIDATION_POLICY_GROUP_CODE",
		Descriptor{ZhFallback: "政策組代號與名稱不得為空，且長度須在上限之內"})

	// CodeValidationPolicyGroupClauseNo 條號不合法（空值或超過欄位長度）
	CodeValidationPolicyGroupClauseNo = register("VALIDATION_POLICY_GROUP_CLAUSE_NO",
		Descriptor{ZhFallback: "條號不得為空，且長度須在上限之內"})

	// CodeValidationPolicyGroupClauseKind 條文型別與其要求數不相容：
	// 設定要求型至少要有一個要求，由機構自行確認型不得掛任何要求
	CodeValidationPolicyGroupClauseKind = register("VALIDATION_POLICY_GROUP_CLAUSE_KIND",
		Descriptor{ZhFallback: "條文型別與所填的設定要求不相符"})

	// CodeValidationPolicyGroupUnknownKey 要求指向一個不存在的安全設定
	CodeValidationPolicyGroupUnknownKey = register("VALIDATION_POLICY_GROUP_UNKNOWN_KEY",
		Descriptor{ZhFallback: "要求指向的安全設定不存在"})

	// CodeValidationPolicyGroupKeyType 該型別的設定不能作為設定要求的對象
	//（自由文字型沒有可比較的要求值）
	CodeValidationPolicyGroupKeyType = register("VALIDATION_POLICY_GROUP_KEY_TYPE",
		Descriptor{ZhFallback: "這個設定的型別無法作為條文要求的對象"})

	// CodeValidationPolicyGroupComparator 比較方式與設定的型別不符
	//（整數型才有「至少」「至多」，開關與選項型只能要求明確值）
	CodeValidationPolicyGroupComparator = register("VALIDATION_POLICY_GROUP_COMPARATOR",
		Descriptor{ZhFallback: "比較方式與這個設定的型別不符"})

	// CodeValidationPolicyGroupExpectedValue 要求值未通過該設定既有的值域驗證，
	// 或未定值的要求卻仍填了值
	CodeValidationPolicyGroupExpectedValue = register("VALIDATION_POLICY_GROUP_EXPECTED_VALUE",
		Descriptor{ZhFallback: "要求值不在這個設定的合法範圍內"})

	// CodeValidationPolicyGroupDuplicateKey 同一組內同一個設定已有另一條要求。
	//
	// 同組內對同一個設定給兩個要求，等於該組對自己自相矛盾，而判定結果會取決於
	// 資料列的讀取順序
	CodeValidationPolicyGroupDuplicateKey = register("VALIDATION_POLICY_GROUP_DUPLICATE_KEY",
		Descriptor{ZhFallback: "這一組已經有另一條條文對同一個設定提出要求"})
)

// --- 套用預覽與排程預覽 ---
var (
	// CodeValidationApplyPreviewMode 套用模式未知、指定單組卻未指名政策組，
	// 或指定的政策組未生效（400）
	CodeValidationApplyPreviewMode = register("VALIDATION_APPLY_PREVIEW_MODE",
		Descriptor{ZhFallback: "套用方式不正確，請指定一個生效中的政策組或改用一次滿足所有政策"})

	// CodeValidationScheduleBadCron 排程時刻的格式不正確（400）。
	//
	// 前端的頻率選擇器只在「自訂」欄可能產出解析不了的字串，故訊息直接指向欄位
	CodeValidationScheduleBadCron = register("VALIDATION_SCHEDULE_BAD_CRON",
		Descriptor{ZhFallback: "排程時刻的格式不正確，請確認是五欄格式"})

	// CodeValidationScheduleRunCount 要求的預覽筆數超出範圍（400）
	CodeValidationScheduleRunCount = register("VALIDATION_SCHEDULE_RUN_COUNT",
		Descriptor{ZhFallback: "預覽筆數須介於 1 與 10 之間"})
)

// --- 內部錯誤 ---
var (
	// CodeInternalComplianceSnapshot 判定結果建構失敗（500）。
	//
	// **不退回「零偏離」**：判定讀不到時回一份空結果，畫面會顯示全部符合——
	// 那是安全控制的呈現在失效方向上說謊，比整頁報錯嚴重得多
	CodeInternalComplianceSnapshot = register("INTERNAL_COMPLIANCE_SNAPSHOT",
		Descriptor{ZhFallback: "無法取得合規判定結果"})

	// CodeInternalPolicyGroupWrite 政策組寫入失敗（500，非驗證類的資料庫錯誤）
	CodeInternalPolicyGroupWrite = register("INTERNAL_POLICY_GROUP_WRITE",
		Descriptor{ZhFallback: "政策組寫入失敗"})

	// CodeInternalPolicyGroupRead 政策組讀取失敗（500）
	CodeInternalPolicyGroupRead = register("INTERNAL_POLICY_GROUP_READ",
		Descriptor{ZhFallback: "政策組讀取失敗"})
)
