package apierror

// LDAP 目錄設定的 HTTP 出口碼。
//
// 本檔與 codes.go 同一 registry，分檔只為收斂範圍：對應 internal/api 的
// ldap_directory_handler.go 一檔。命名沿既有慣例——VALIDATION_*（請求欄位／
// 格式，使用者可據此改正）、CONFLICT_*（並發與狀態衝突，可重試）、NOTFOUND_*、
// RULE_*（規則攔截）、INTERNAL_*（5xx，成因僅落伺服端 log）。
//
// # 為什麼 URL 與 filter 的每個拒因各給一支碼
//
// 服務層的 LDAPURLError.Reason／LDAPFilterError.Reason 是靜態碼字串，若在 HTTP
// 層併成一支泛碼（「位址格式不合法」），admin 只會知道「有問題」而不知道**哪裡**
// 有問題——`ldap://user:pw@h/ou=x?q` 這種輸入同時踩到三條規則，泛碼下要靠猜。
// 逐因給碼使錯誤訊息本身即修正指引，且完全不需前端維護 reason→文案的對照表
// （參數化 enum 碼會把該對照表推給前端）。
//
// 反之，**欄位錯誤（required／too_long／format）只給三支碼＋Meta 帶 field**：
// 那三者的修正動作與欄位無關（填它／縮短／改格式），逐欄位給碼會產生 7×3 支
// 語義重複的碼，而欄位名本就是前端表單已知的機器值（用於高亮定位）。
//
// # 不在本檔的碼：連線測試階梯的失敗碼
//
// 階梯失敗（connect_failed／egress_blocked／bind_failed／search_failed／
// stage_timeout／bind_password_missing）**不是 HTTP 錯誤**：測試一旦執行過即回
// 200，失敗資訊在回應 body 的 stages[]／failed_stage／code。它們是 API 契約的
// 一部分（docs/API_SPEC.md 明文釘住小寫字面值），由前端以自有 i18n 鍵查譯，
// 不經 apierror 信封——把它們改寫成 registry 大寫碼會直接違反已定稿的回應形狀。
var (
	// --- VALIDATION_LDAP_URL_*：URL 文法逐拒因（對應 service.LDAPURLReason*）---

	CodeValidationLDAPURLEmpty = register("VALIDATION_LDAP_URL_EMPTY",
		Descriptor{ZhFallback: "目錄位址不可為空"})
	CodeValidationLDAPURLTooLong = register("VALIDATION_LDAP_URL_TOO_LONG",
		Descriptor{ZhFallback: "目錄位址過長"})
	CodeValidationLDAPURLMalformed = register("VALIDATION_LDAP_URL_MALFORMED",
		Descriptor{ZhFallback: "目錄位址格式不正確，須為 ldap://主機[:埠] 或 ldaps://主機[:埠]"})
	CodeValidationLDAPURLScheme = register("VALIDATION_LDAP_URL_SCHEME",
		Descriptor{ZhFallback: "目錄位址的通訊協定僅接受 ldap:// 或 ldaps://"})
	// 位址內嵌憑證會流入 UI 顯示、錯誤訊息與審計的目標欄位，故直接拒絕而非清洗
	CodeValidationLDAPURLUserinfo = register("VALIDATION_LDAP_URL_USERINFO",
		Descriptor{ZhFallback: "目錄位址不可包含帳號密碼，請改填於 bind DN 與 bind 密碼欄位"})
	CodeValidationLDAPURLPath = register("VALIDATION_LDAP_URL_PATH",
		Descriptor{ZhFallback: "目錄位址不可包含路徑，搜尋起點請填於 base DN 欄位"})
	CodeValidationLDAPURLQuery = register("VALIDATION_LDAP_URL_QUERY",
		Descriptor{ZhFallback: "目錄位址不可包含查詢字串"})
	CodeValidationLDAPURLFragment = register("VALIDATION_LDAP_URL_FRAGMENT",
		Descriptor{ZhFallback: "目錄位址不可包含片段（#）"})
	CodeValidationLDAPURLHost = register("VALIDATION_LDAP_URL_HOST",
		Descriptor{ZhFallback: "目錄位址的主機名稱不合法"})
	CodeValidationLDAPURLPort = register("VALIDATION_LDAP_URL_PORT",
		Descriptor{ZhFallback: "目錄位址的連接埠不合法，須為 1-65535"})

	// --- VALIDATION_LDAP_FILTER_*：user_filter 兩層驗證逐拒因 ---

	CodeValidationLDAPFilterEmpty = register("VALIDATION_LDAP_FILTER_EMPTY",
		Descriptor{ZhFallback: "使用者搜尋 filter 不可為空"})
	CodeValidationLDAPFilterTooLong = register("VALIDATION_LDAP_FILTER_TOO_LONG",
		Descriptor{ZhFallback: "使用者搜尋 filter 過長"})
	CodeValidationLDAPFilterPlaceholderMissing = register("VALIDATION_LDAP_FILTER_PLACEHOLDER_MISSING",
		Descriptor{ZhFallback: "使用者搜尋 filter 必須包含一組 %s 佔位符，用以代入登入帳號"})
	CodeValidationLDAPFilterPlaceholderMultiple = register("VALIDATION_LDAP_FILTER_PLACEHOLDER_MULTIPLE",
		Descriptor{ZhFallback: "使用者搜尋 filter 只能包含一組 %s 佔位符"})
	CodeValidationLDAPFilterFormatVerb = register("VALIDATION_LDAP_FILTER_FORMAT_VERB",
		Descriptor{ZhFallback: "使用者搜尋 filter 只接受 %s 佔位符，不可使用其他格式化動詞"})
	CodeValidationLDAPFilterParenUnbalanced = register("VALIDATION_LDAP_FILTER_PAREN_UNBALANCED",
		Descriptor{ZhFallback: "使用者搜尋 filter 的括號不配對"})
	CodeValidationLDAPFilterSyntax = register("VALIDATION_LDAP_FILTER_SYNTAX",
		Descriptor{ZhFallback: "使用者搜尋 filter 語法不合法，無法解析為 LDAP 搜尋條件"})
	// 結構層：placeholder 位於 OR／NOT 之下時，不含登入帳號的分支亦可命中，
	// 搜尋結果與登入身分脫鉤（(|(uid=%s)(uid=svc-admin)) 語法三規則全過）。
	//
	// **文案不得含字面 `|`**：前端以 vue-i18n 渲染本碼譯文，而 `|` 是其複數
	// 分隔符——含 `|` 的字串會被截成第一段（實測只顯示到「不可位於 OR（」）。
	// 故此處與三語譯文一律以文字敘述 OR／NOT，不放符號。
	CodeValidationLDAPFilterPlaceholderScope = register("VALIDATION_LDAP_FILTER_PLACEHOLDER_SCOPE",
		Descriptor{ZhFallback: "使用者搜尋 filter 的 %s 佔位符不可位於 OR 或 NOT 之下，否則不含登入帳號的分支也會命中"})
	CodeValidationLDAPFilterPlaceholderPosition = register("VALIDATION_LDAP_FILTER_PLACEHOLDER_POSITION",
		Descriptor{ZhFallback: "使用者搜尋 filter 的 %s 佔位符必須位於屬性值，不可用於屬性名稱"})

	// --- VALIDATION_LDAP_FIELD_*：欄位層（Meta 帶 field 供前端定位）---

	CodeValidationLDAPFieldRequired = register("VALIDATION_LDAP_FIELD_REQUIRED",
		Descriptor{ZhFallback: "啟用 LDAP 目錄前必須填妥所有必要欄位"})
	CodeValidationLDAPFieldTooLong = register("VALIDATION_LDAP_FIELD_TOO_LONG",
		Descriptor{ZhFallback: "LDAP 目錄設定欄位長度超出上限"})
	CodeValidationLDAPFieldFormat = register("VALIDATION_LDAP_FIELD_FORMAT",
		Descriptor{ZhFallback: "LDAP 目錄設定欄位格式不正確"})

	// --- VALIDATION_LDAP_BIND_PASSWORD_*：write-only 密碼的三條編輯規則 ---

	CodeValidationLDAPBindPasswordConflict = register("VALIDATION_LDAP_BIND_PASSWORD_CONFLICT",
		Descriptor{ZhFallback: "不可同時填寫新的 bind 密碼與勾選清除密碼"})
	// URL 變更且既存有密碼時的重供要求：「空=沿用」若跨端點生效，改指向＋留空
	// 即可把既存 service bind 憑證送往新位址
	CodeValidationLDAPBindPasswordRequired = register("VALIDATION_LDAP_BIND_PASSWORD_REQUIRED",
		Descriptor{ZhFallback: "目錄位址已變更，必須重新填寫 bind 密碼或勾選清除密碼——既有密碼不會沿用到新位址"})

	// --- CONFLICT_* / NOTFOUND_*：可重試的並發衝突與缺列 ---

	// 取不到交易範圍互斥（try 語義，不阻塞）。**刻意不是 500**：admin 重按即可
	CodeConflictLDAPDirectoryBusy = register("CONFLICT_LDAP_DIRECTORY_BUSY",
		Descriptor{ZhFallback: "另一項 LDAP 目錄設定操作進行中，請稍後重試"})
	// 單列約束的最後防線（unique violation）：鎖已使正常路徑不可能撞上
	CodeConflictLDAPDirectoryConcurrent = register("CONFLICT_LDAP_DIRECTORY_CONCURRENT",
		Descriptor{ZhFallback: "LDAP 目錄設定併發衝突，請重新讀取後再試"})
	CodeNotFoundLDAPDirectory = register("NOTFOUND_LDAP_DIRECTORY",
		Descriptor{ZhFallback: "LDAP 目錄設定不存在"})

	// --- RULE_LDAP_*：連線測試的資源上限（429）---

	// **不回填任何限流參數、不附 Retry-After**（沿 AUTH_OIDC_RATE_LIMITED 的裁決）：
	// 門檻與剩餘額度會讓攻擊者把流量精確調到界線之下持續消耗內網探測；
	// 正當使用者只需要知道「稍後再試」。命中哪一道界線僅落伺服端 log
	CodeRuleLDAPTestRateLimited = register("RULE_LDAP_TEST_RATE_LIMITED",
		Descriptor{ZhFallback: "LDAP 連線測試過於頻繁，請稍後再試"})

	// --- INTERNAL_*：5xx（成因僅落伺服端 log）---

	CodeInternalLDAPDirectoryQuery = register("INTERNAL_LDAP_DIRECTORY_QUERY",
		Descriptor{ZhFallback: "讀取 LDAP 目錄設定失敗"})
	CodeInternalLDAPDirectorySave = register("INTERNAL_LDAP_DIRECTORY_SAVE",
		Descriptor{ZhFallback: "儲存 LDAP 目錄設定失敗"})
	CodeInternalLDAPDirectoryDelete = register("INTERNAL_LDAP_DIRECTORY_DELETE",
		Descriptor{ZhFallback: "刪除 LDAP 目錄設定失敗"})
	CodeInternalLDAPDirectoryTest = register("INTERNAL_LDAP_DIRECTORY_TEST",
		Descriptor{ZhFallback: "執行 LDAP 連線測試失敗"})
	// 需沿用既存密碼但既存設定讀取／解密失敗。**獨立成碼而非併入 bind 失敗**：
	// 靜默改以空密碼測試會讓 admin 去查目錄權限，真因卻是本地金鑰事故
	CodeInternalLDAPStoredSettingsUnavailable = register("INTERNAL_LDAP_STORED_SETTINGS_UNAVAILABLE",
		Descriptor{ZhFallback: "既有 LDAP 目錄設定讀取失敗，無法沿用既存 bind 密碼"})

	// 以下三碼取代 handler 的 default 泛碼。三者都是 5xx，但**維運要採取的行動
	// 完全不同**：閘未注入是部署疏漏（重新部署即解）、加解密失敗是金鑰事故
	// （查 KEK／DEK 狀態）、服務未注入是組裝缺陷（改碼）。落入同一個泛碼會使
	// 三種成因在維運端不可區分，只能翻伺服端 log 逐一排除。

	// 傳輸政策閘未注入：存檔與連線測試一律 fail-close（nil 不得等於放行）
	CodeInternalLDAPTransmissionGateUnavailable = register("INTERNAL_LDAP_TRANSMISSION_GATE_UNAVAILABLE",
		Descriptor{ZhFallback: "傳輸安全政策未就緒，LDAP 目錄設定與連線測試暫停服務"})
	// bind 密碼加解密失敗（金鑰事故）。錯誤本身已在服務層轉為不含底層文字的
	// 靜態哨兵，避免 codec 錯誤夾帶密文片段
	CodeInternalLDAPBindPasswordCrypto = register("INTERNAL_LDAP_BIND_PASSWORD_CRYPTO",
		Descriptor{ZhFallback: "LDAP bind 密碼加解密失敗，請檢查金鑰狀態"})
	// 目錄設定服務未注入（組裝缺陷）
	CodeInternalLDAPDirectoryServiceUnavailable = register("INTERNAL_LDAP_DIRECTORY_SERVICE_UNAVAILABLE",
		Descriptor{ZhFallback: "LDAP 目錄設定服務未就緒"})
)
