package apierror

// 堡壘機專用帳號（平台自用、人員不可連線的執行身分）的出口碼。
//
// 本檔與 codes.go 同一 registry，分檔僅為並行開發隔離。錯誤一律不回填帳號名、資產名或
// 資產識別：台數確認只帶受控整數 count，其餘碼不帶參數。

// --- RULE_*（可預期的業務規則攔截）---
var (
	// 既有帳號端點（修改、刪除、設預設、改綁、卸載）的目標是專用帳號：只能經專用帳號端點處理
	CodeAccountExecutorManaged = register("RULE_ACCOUNT_EXECUTOR_MANAGED", Descriptor{ZhFallback: "這筆是堡壘機專用帳號，請由資產的專用帳號區塊處理"})
	// 同一組憑證的掛載用途（登入帳號／專用帳號）不得混用
	CodeCredentialPurposeMismatch   = register("RULE_CREDENTIAL_PURPOSE_MISMATCH", Descriptor{ZhFallback: "這組憑證已用於另一種用途（登入帳號或堡壘機專用帳號），不可混用"})
	CodeExecutorProtocolUnsupported = register("RULE_EXECUTOR_PROTOCOL_UNSUPPORTED", Descriptor{ZhFallback: "此資產協定不支援堡壘機專用帳號"})
	// Windows 族資產（RDP，或改密通道為 Windows 的 SSH 資產）不接受金鑰型專用帳號
	CodeExecutorSecretTypeUnsupported = register("RULE_EXECUTOR_SECRET_TYPE_UNSUPPORTED", Descriptor{ZhFallback: "此資產不支援以金鑰作為堡壘機專用帳號"})
	// 共用來源的台數確認缺漏或不符；count＝當下應確認的總台數（含本台）
	CodeExecutorSharedHostCount = register("RULE_EXECUTOR_SHARED_HOST_COUNT", Descriptor{
		ZhFallback: "這組秘密設定後將在 {count} 台主機上作為堡壘機專用帳號，請確認台數後再送出",
		Params:     []ParamSpec{{Key: "count", Kind: ParamInt}},
	})
	// 送出時認定的專用帳號與當下不符（已被他人設定、更換或清除）
	CodeExecutorStateChanged = register("RULE_EXECUTOR_STATE_CHANGED", Descriptor{ZhFallback: "堡壘機專用帳號已被變更，請重新載入後再試"})
	// 要轉換的帳號仍有未驗證的候選秘密
	CodeExecutorConvertCandidatePending = register("RULE_EXECUTOR_CONVERT_CANDIDATE_PENDING", Descriptor{ZhFallback: "此帳號仍有未驗證的候選秘密，請先收斂後再轉換"})
)

// --- NOTFOUND_* / VALIDATION_* ---
var (
	CodeAssetExecutorNotFound = register("NOTFOUND_ASSET_EXECUTOR", Descriptor{ZhFallback: "此資產尚未設定堡壘機專用帳號"})
	// 非金鑰型、沒有公鑰、或所引用的共用憑證不可見，三者同形
	CodeAssetExecutorPublicKeyNotFound = register("NOTFOUND_ASSET_EXECUTOR_PUBLIC_KEY", Descriptor{ZhFallback: "此堡壘機專用帳號沒有可匯出的公鑰"})
	// 設定請求缺少來源、來源不明、缺 expected_account_id 或來源欄位不完整
	CodeExecutorSourceInvalid = register("VALIDATION_EXECUTOR_SOURCE_INVALID", Descriptor{ZhFallback: "堡壘機專用帳號的設定內容不完整或來源不正確"})
)

// --- INTERNAL_*（5xx；成因僅落伺服端日誌）---
var (
	CodeInternalAssetExecutorRead  = register("INTERNAL_ASSET_EXECUTOR_READ", Descriptor{ZhFallback: "讀取堡壘機專用帳號失敗"})
	CodeInternalAssetExecutorWrite = register("INTERNAL_ASSET_EXECUTOR_WRITE", Descriptor{ZhFallback: "設定堡壘機專用帳號失敗"})
)
