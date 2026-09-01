package apierror

// 外部身分管理的出口碼。
//
// 本檔與 codes.go 同一 registry，分檔僅為並行開發隔離：收 internal/api 的
// user_handler.go 外部身分四操作。命名沿用既有慣例：VALIDATION_*（請求欄位）、
// CONFLICT_*（唯一性與狀態衝突）、NOTFOUND_*、RULE_*（規則拒絕）、
// INTERNAL_*（5xx，成因僅落伺服端日誌）。
//
// **不回填身分域內容**：issuer／subject／占用者帳號一律不入錯誤訊息——綁定端點
// 會因此成為「某個 subject 是否已存在於本系統」的枚舉 oracle，而 subject 是
// 請求方可控輸入。細節一律只落稽核與伺服端日誌。

// --- VALIDATION_* / NOTFOUND_* / CONFLICT_* ---
var (
	// subject 為空或逾長。空 subject 會使第一個異常 token 吸附該 provider
	// 後續全部異常 token，故為硬性拒絕而非靜默截斷
	CodeValidationExternalIdentitySubject = register("VALIDATION_EXTERNAL_IDENTITY_SUBJECT",
		Descriptor{ZhFallback: "外部身分識別碼（subject）不得為空，且長度不得超過 255 字元"})

	// 路徑參數的外部身分 ID 解析失敗
	CodeValidationExternalIdentityID = register("VALIDATION_EXTERNAL_IDENTITY_ID",
		Descriptor{ZhFallback: "無效的外部身分 ID"})

	CodeNotFoundExternalIdentity = register("NOTFOUND_EXTERNAL_IDENTITY",
		Descriptor{ZhFallback: "外部身分不存在或不屬於此帳號"})

	// 身分域三元組 (issuer, client_id, subject) 已被占用
	CodeConflictExternalIdentityExists = register("CONFLICT_EXTERNAL_IDENTITY_EXISTS",
		Descriptor{ZhFallback: "此外部身分已綁定至某個帳號，請先解除既有綁定"})

	// 已外部化（含 LDAP）的帳號不需也不可再轉換
	CodeConflictUserAlreadyExternal = register("CONFLICT_USER_ALREADY_EXTERNAL",
		Descriptor{ZhFallback: "此帳號的憑證已由外部身分提供者管理，無須再次轉換"})
)

// --- RULE_*（規則拒絕，皆為可行動的指引）---
var (
	// CodeLastLoginPath 解綁將使帳號失去全部可用登入途徑。
	// **必須指出出路**：拒絕而不告知「可改用解除綁定並停用帳號」，管理者會卡在
	// 「身分收不回、帳號也停不掉」的死路
	CodeLastLoginPath = register("RULE_USER_LAST_LOGIN_PATH",
		Descriptor{ZhFallback: "解除此外部身分將使該帳號失去全部可用登入途徑；如需移除，請改用「解除綁定並停用帳號」。"})

	// CodeExternalIdentityRequired 「改為僅外部登入」要求帳號至少已有一筆外部身分
	CodeExternalIdentityRequired = register("RULE_USER_EXTERNAL_IDENTITY_REQUIRED",
		Descriptor{ZhFallback: "此帳號尚未綁定任何外部身分，改為僅外部登入將使其無法登入；請先綁定外部身分"})
)

// --- INTERNAL_*（5xx）---
var (
	CodeInternalExternalIdentityQuery = register("INTERNAL_EXTERNAL_IDENTITY_QUERY",
		Descriptor{ZhFallback: "查詢外部身分失敗"})

	CodeInternalExternalIdentityBind = register("INTERNAL_EXTERNAL_IDENTITY_BIND",
		Descriptor{ZhFallback: "綁定外部身分失敗"})

	CodeInternalExternalIdentityUnbind = register("INTERNAL_EXTERNAL_IDENTITY_UNBIND",
		Descriptor{ZhFallback: "解除外部身分綁定失敗"})

	CodeInternalUserExternalOnly = register("INTERNAL_USER_EXTERNAL_ONLY",
		Descriptor{ZhFallback: "轉換為僅外部登入失敗"})
)
