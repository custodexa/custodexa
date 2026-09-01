package apierror

// 離機儲存（evidence-offsite-storage）的 HTTP 出口碼。
//
// 分檔理由沿 codes_ldap_directory.go：與 internal/api 的 offsite_storage_handler.go
// 一檔對應，命名沿既有慣例（VALIDATION_*／CONFLICT_*／NOTFOUND_*／INTERNAL_*）。
//
// # 兩層碼的分工
//
// `internal/offsite` 的靜態拒因是**小寫機器碼**（`offsite.integrity_mismatch` 等），
// 它是服務層與帳冊 `error_code` 欄共用的值域；本檔是它們的 HTTP 出口對照。
// 兩張表由守衛 `TestOffsiteReasonCodeTablesExhaustive` 雙向釘住——服務層每個拒因
// 都必須在此有出口，反向亦然。分兩層而不共用一組字面值，是因為帳冊欄位的值域
// 屬於資料模型（改動要遷移），而 HTTP 碼屬於 API 契約（改動要動前端 i18n），
// 兩者的變更成本與節奏不同。
//
// # 為什麼取回失敗是 409 而不是 404
//
// 404 的語義是「沒有這個東西」，而這三種失敗都是「東西在、但我們拒絕交付」：
// 內容與上傳當下不符（可能被外力覆寫）、設定世代對不上（資料損壞）、
// 該世代憑證已撤銷。把它們併進 404 會讓稽核員以為錄影不存在，
// 而真相是「存在但不可信／取不到」——那正是要被看見的訊號。
var (
	// CodeOffsiteIntegrityMismatch 取回內容的 SHA-256 或大小與上傳當下不符：
	// **已拒絕交付**（零位元組），帳冊轉 integrity_mismatch 並留痕
	CodeOffsiteIntegrityMismatch = register("CONFLICT_OFFSITE_INTEGRITY_MISMATCH",
		Descriptor{ZhFallback: "離機副本的內容與上傳當下不符，已拒絕交付"})
	// CodeOffsiteProfileMissing 帳冊列指向的設定世代不存在（部分還原、DB 手術）：
	// fail-close，不退回「用現行設定猜」
	CodeOffsiteProfileMissing = register("CONFLICT_OFFSITE_PROFILE_MISSING",
		Descriptor{ZhFallback: "找不到此證據所屬的離機儲存設定世代，無法取回"})
	// CodeOffsiteForeignCredentialsMissing 該世代的憑證已撤銷或缺席：
	// **絕不改用其他憑證重試**
	CodeOffsiteForeignCredentialsMissing = register("CONFLICT_OFFSITE_FOREIGN_CREDENTIALS_MISSING",
		Descriptor{ZhFallback: "此證據所屬離機儲存世代的憑證已撤銷，無法取回"})
	// CodeOffsiteCredentialsUnavailable 憑證解密失敗（金鑰事故）：
	// **不得併吞為「功能未設定」**
	CodeOffsiteCredentialsUnavailable = register("CONFLICT_OFFSITE_CREDENTIALS_UNAVAILABLE",
		Descriptor{ZhFallback: "離機儲存憑證目前無法使用，請檢查金鑰狀態"})
)

// 設定 CRUD 的靜態拒因出口。
//
// 與 `internal/offsite` 的 `Reason*` 常數**一一對應**，由守衛
// `TestOffsiteReasonCodeTablesExhaustive` 雙向釘住：服務層每一個拒因都必須在此
// 有出口，反向亦然。逐因給碼而不併成一支泛碼的理由沿 LDAP 那一檔——
// 泛碼下 admin 只知道「有問題」而不知道**哪裡**有問題，且逐因給碼使錯誤訊息
// 本身即修正指引，前端不必維護 reason→文案的對照表。
var (
	CodeValidationOffsiteCredentialConflict = register("VALIDATION_OFFSITE_CREDENTIAL_CONFLICT",
		Descriptor{ZhFallback: "不可同時輸入新憑證與勾選清除憑證"})
	CodeValidationOffsiteProviderInvalid = register("VALIDATION_OFFSITE_PROVIDER_INVALID",
		Descriptor{ZhFallback: "儲存類型僅接受 s3 或 gcs"})
	CodeValidationOffsiteBucketRequired = register("VALIDATION_OFFSITE_BUCKET_REQUIRED",
		Descriptor{ZhFallback: "bucket 名稱不可為空"})
	CodeValidationOffsiteEndpointInvalid = register("VALIDATION_OFFSITE_ENDPOINT_INVALID",
		Descriptor{ZhFallback: "端點格式不正確，須為 http:// 或 https:// 起始且含主機名稱"})
	// 端點內嵌的帳密／查詢字串會流入顯示、錯誤訊息與審計，故直接拒絕而非清洗
	CodeValidationOffsiteEndpointHasSecrets = register("VALIDATION_OFFSITE_ENDPOINT_HAS_SECRETS",
		Descriptor{ZhFallback: "端點不可包含帳號密碼、查詢字串或片段，請改填於憑證欄位"})
	CodeValidationOffsiteRegionOrEndpointRequired = register("VALIDATION_OFFSITE_REGION_OR_ENDPOINT_REQUIRED",
		Descriptor{ZhFallback: "使用 S3 時，端點與區域至少須填一項"})
	CodeValidationOffsiteCredentialHalfSet = register("VALIDATION_OFFSITE_CREDENTIAL_HALF_SET",
		Descriptor{ZhFallback: "存取金鑰與私密金鑰須同時填寫，或同時留空以使用預設憑證鏈"})
	// 落點變更而憑證留空：換位址必須重新輸入憑證，否則既存憑證會被送往新位址
	CodeRuleOffsiteCredentialReuseOnMove = register("RULE_OFFSITE_CREDENTIAL_REUSE_ON_MOVE",
		Descriptor{ZhFallback: "變更儲存類型、端點或 bucket 時必須重新輸入憑證"})
	CodeConflictOffsiteSettingsStaleConfirmation = register("CONFLICT_OFFSITE_SETTINGS_STALE_CONFIRMATION",
		Descriptor{ZhFallback: "設定已被其他操作變更，請重新讀取後再試"})
	CodeConflictOffsiteSettingsDigestMismatch = register("CONFLICT_OFFSITE_SETTINGS_DIGEST_MISMATCH",
		Descriptor{ZhFallback: "確認內容與送出的設定不一致，請重新確認"})
	CodeConflictOffsiteNoCurrentGeneration = register("CONFLICT_OFFSITE_NO_CURRENT_GENERATION",
		Descriptor{ZhFallback: "目前沒有啟用中的離機儲存設定"})
	CodeNotFoundOffsiteGeneration = register("NOTFOUND_OFFSITE_GENERATION",
		Descriptor{ZhFallback: "找不到指定的離機儲存設定世代"})
	CodeConflictOffsiteCredentialsAlreadyRevoked = register("CONFLICT_OFFSITE_CREDENTIALS_ALREADY_REVOKED",
		Descriptor{ZhFallback: "該世代的憑證已撤銷"})
	CodeInternalOffsiteCredentialEncrypt = register("INTERNAL_OFFSITE_CREDENTIAL_ENCRYPT",
		Descriptor{ZhFallback: "離機儲存憑證加密失敗，請檢查金鑰狀態"})
	CodeInternalOffsiteCredentialDecrypt = register("INTERNAL_OFFSITE_CREDENTIAL_DECRYPT",
		Descriptor{ZhFallback: "離機儲存憑證解密失敗，請檢查金鑰狀態"})
)

// 端點層的其餘出口（非服務層拒因，故**不進**拒因對照表）。
var (
	// CodeNotFoundOffsiteObject 帳冊查無此列，或該列不屬於本功能的可重試範圍：
	// **兩者收斂同一碼**——存在性細節不對外
	CodeNotFoundOffsiteObject = register("NOTFOUND_OFFSITE_OBJECT",
		Descriptor{ZhFallback: "找不到指定的離機物件"})
	// CodeConflictOffsiteProfileBusy 另一項設定操作進行中（try 鎖取不到）：
	// **可重試，不是 500**
	CodeConflictOffsiteProfileBusy = register("CONFLICT_OFFSITE_PROFILE_BUSY",
		Descriptor{ZhFallback: "另一項離機儲存設定操作進行中，請稍後重試"})
	// CodeRuleOffsiteTestRateLimited 連線測試超出資源上限；不揭露命中哪一道界線
	CodeRuleOffsiteTestRateLimited = register("RULE_OFFSITE_TEST_RATE_LIMITED",
		Descriptor{ZhFallback: "連線測試過於頻繁，請稍後再試"})
	CodeInternalOffsiteStatus = register("INTERNAL_OFFSITE_STATUS",
		Descriptor{ZhFallback: "查詢離機儲存狀態失敗"})
	CodeInternalOffsiteSettingsSave = register("INTERNAL_OFFSITE_SETTINGS_SAVE",
		Descriptor{ZhFallback: "儲存離機設定失敗"})
	CodeInternalOffsiteTest = register("INTERNAL_OFFSITE_TEST",
		Descriptor{ZhFallback: "離機儲存連線測試執行失敗"})
	CodeInternalOffsiteRetry = register("INTERNAL_OFFSITE_RETRY",
		Descriptor{ZhFallback: "重試離機上傳失敗"})
)
