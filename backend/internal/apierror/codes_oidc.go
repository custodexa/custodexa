package apierror

// OIDC 身分提供者整合的出口碼。
//
// 本檔與 codes.go 同一 registry，分檔僅為並行開發隔離：收 internal/api 的
// oidc_handler.go 一檔。命名沿用既有慣例：VALIDATION_*（請求欄位／參數）、
// CONFLICT_*（唯一性與生命週期）、NOTFOUND_*、AUTH_*（認證流程攔截）、
// INTERNAL_*（5xx，成因僅落伺服端日誌）。
//
// **登入流程的失敗碼一律收斂**：不回填 issuer、subject、claim 值等自由字串——
// 它們或為請求方可控輸入、或屬他人身分資訊，回填會使錯誤回應成為探測器
//（例如「此帳號是 OIDC 帳號」的枚舉 oracle）。細節一律只落稽核與伺服端日誌。

// --- VALIDATION_*（設定與請求欄位）---
var (
	CodeValidationOIDCProviderPayload = register("VALIDATION_OIDC_PROVIDER_PAYLOAD",
		Descriptor{ZhFallback: "OIDC provider 設定內容格式不正確"})

	// issuer 形狀或 scheme 不合法（非 https、帶使用者資訊/查詢字串/片段）
	CodeValidationOIDCIssuer = register("VALIDATION_OIDC_ISSUER",
		Descriptor{ZhFallback: "issuer 必須為 https 且不得包含使用者資訊、查詢字串或片段"})

	// issuer 與 client_id 建立後不可變更（身分域的組成，變更即使既有使用者失聯）
	CodeValidationOIDCImmutableField = register("VALIDATION_OIDC_IMMUTABLE_FIELD",
		Descriptor{ZhFallback: "issuer 與 client_id 建立後不可變更；如需更換請建立新的 provider"})

	// scope 不在允許清單（openid 由伺服端注入，附加項限 profile/email）
	CodeValidationOIDCScope = register("VALIDATION_OIDC_SCOPE",
		Descriptor{ZhFallback: "scope 不在允許清單內"})

	// 准入規則不合法：未知規則鍵、空規則集、共用身分域缺組織歸屬規則、
	// 消費者租戶值、email 網域未併同已驗證要求
	CodeValidationOIDCAdmissionRules = register("VALIDATION_OIDC_ADMISSION_RULES",
		Descriptor{ZhFallback: "准入規則不合法：請確認規則鍵有效、非空，且共用身分提供者須包含租戶或網域歸屬條件"})

	// 共用身分域不可被放寬為專用（spec oidc-auth L169-171）。
	// **不與 VALIDATION_OIDC_ADMISSION_RULES 併碼**：那支碼指向「規則本身不合法」，
	// 而本碼指向「身分域判定不接受你的表態」——兩者的修正動作完全不同
	//（前者改規則，後者須由部署層宣告 issuer 為專用）
	CodeValidationOIDCSharedWiden = register("VALIDATION_OIDC_SHARED_WIDEN",
		Descriptor{ZhFallback: "此 issuer 由系統判定為共用身分域，不可標記為專用；如為企業專屬 IdP 請於部署層宣告"})

	// begin 缺少瀏覽器綁定值（前端未產生 sessionStorage secret）
	CodeValidationOIDCBindingMissing = register("VALIDATION_OIDC_BINDING_MISSING",
		Descriptor{ZhFallback: "缺少瀏覽器綁定值"})

	// 路徑參數 provider id 解析失敗。不複用 VALIDATION_INVALID_ID：那支碼的
	// {resource} 是受控 enum，新增值會連帶要求前端 enum 命名空間補鍵，
	// 成本高於獨立一碼（同 CodeInvalidAccountID 的既有裁決）
	CodeValidationOIDCProviderID = register("VALIDATION_OIDC_PROVIDER_ID",
		Descriptor{ZhFallback: "無效的 provider ID"})

	CodeValidationOIDCTicketMissing = register("VALIDATION_OIDC_TICKET_MISSING",
		Descriptor{ZhFallback: "缺少登入憑證"})

	// 使用者列表的供應來源篩選值不在值域內。**不靜默忽略**：未知值被忽略時
	// 前端拼錯參數的症狀是「篩選看似沒生效」，比明確報錯難查得多
	CodeValidationUserOriginFilter = register("VALIDATION_USER_ORIGIN_FILTER",
		Descriptor{ZhFallback: "供應來源篩選值不正確（限 local、ldap、oidc）"})
)

// --- NOTFOUND_* / CONFLICT_* ---
var (
	CodeNotFoundOIDCProvider = register("NOTFOUND_OIDC_PROVIDER",
		Descriptor{ZhFallback: "OIDC provider 不存在"})

	// 有使用者外部身分關聯時不可刪除（刪除後將無從按 provider 收線或重新啟用）
	CodeConflictOIDCProviderInUse = register("CONFLICT_OIDC_PROVIDER_IN_USE",
		Descriptor{ZhFallback: "此 provider 仍有使用者外部身分關聯，請改為停用"})

	CodeConflictOIDCIdentityDomain = register("CONFLICT_OIDC_IDENTITY_DOMAIN",
		Descriptor{ZhFallback: "已存在相同 issuer 與 client_id 的 provider"})
)

// --- AUTH_*（登入流程）---
var (
	// provider 已停用、已刪除或設定不完整（如未設對外基準網址）
	CodeAuthOIDCProviderUnavailable = register("AUTH_OIDC_PROVIDER_UNAVAILABLE",
		Descriptor{ZhFallback: "此登入方式目前不可用"})

	// 未通過准入判定。**不回填未通過的規則細節**——那會讓外部使用者得以
	// 逐條試探組織的准入條件
	CodeAuthOIDCAdmissionDenied = register("AUTH_OIDC_ADMISSION_DENIED",
		Descriptor{ZhFallback: "您的帳號不符合此登入方式的准入條件，請聯繫管理員"})

	// 映射所得使用者名稱已被占用（同名不接管，需管理員處理）
	CodeAuthOIDCUsernameConflict = register("AUTH_OIDC_USERNAME_CONFLICT",
		Descriptor{ZhFallback: "帳號名稱衝突，請聯繫管理員處理"})

	// 流程狀態或交棒憑證失效：不存在／已消費／已過期／瀏覽器綁定不符——
	// 四者**對外不可區分**，避免成為憑證有效性的探測器
	CodeAuthOIDCFlowInvalid = register("AUTH_OIDC_FLOW_INVALID",
		Descriptor{ZhFallback: "登入流程已失效，請重新登入"})

	// 公開登入端點的濫用防護攔截（per-IP／全域速率、全域並發、flow state 全表
	// 容量上限，四者共用一碼）。**不回填任何限流參數**：門檻、剩餘額度與
	// 重試時間都會讓攻擊者把流量精確調到門檻之下持續消耗；正當使用者只需要
	// 知道「稍後再試」。四種成因對外亦不可區分，避免成為系統負載的探測器
	CodeAuthOIDCRateLimited = register("AUTH_OIDC_RATE_LIMITED",
		Descriptor{ZhFallback: "登入請求過於頻繁，請稍後再試"})

	// 監看訂閱因憑證撤銷而被收線（provider 停用/刪除/輪替、帳號停用、解綁外部身分）。
	// 與「會話已結束」分開一碼：兩者對觀察者的意義完全不同——前者要重新登入，
	// 後者只是被監看的人下線了
	CodeMonitorRevoked = register("AUTH_MONITOR_REVOKED",
		Descriptor{ZhFallback: "監看連線已因憑證撤銷而中止，請重新登入"})
)

// --- INTERNAL_*（5xx，成因僅落伺服端日誌）---
var (
	CodeInternalOIDCProviderList = register("INTERNAL_OIDC_PROVIDER_LIST",
		Descriptor{ZhFallback: "讀取 OIDC provider 清單失敗"})
	CodeInternalOIDCProviderSave = register("INTERNAL_OIDC_PROVIDER_SAVE",
		Descriptor{ZhFallback: "儲存 OIDC provider 設定失敗"})
	CodeInternalOIDCLogin = register("INTERNAL_OIDC_LOGIN",
		Descriptor{ZhFallback: "OIDC 登入處理失敗"})
)
