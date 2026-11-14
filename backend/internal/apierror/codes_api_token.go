package apierror

// 個人 API token：建立時的輸入與資格、名稱占用，以及以 API token 認證的請求被拒絕的原因。
// API token 認證失敗對外沿用既有的未認證錯誤碼（AUTH_TOKEN_INVALID），真實原因只進稽核。
var (
	CodeAPITokenNameInvalid                      = register("API_TOKEN_NAME_INVALID", Descriptor{ZhFallback: "API token 名稱必填，且不能超過 100 個字"})
	CodeAPITokenRoleRequired                     = register("API_TOKEN_ROLE_REQUIRED", Descriptor{ZhFallback: "請至少選擇一個角色"})
	CodeAPITokenRoleNotGrantable                 = register("API_TOKEN_ROLE_NOT_GRANTABLE", Descriptor{ZhFallback: "勾選的角色中有你目前已沒有的管理角色，請重新選擇"})
	CodeAPITokenExpiryRequired                   = register("API_TOKEN_EXPIRY_REQUIRED", Descriptor{ZhFallback: "請選擇到期時間"})
	CodeAPITokenExpiryInvalid                    = register("API_TOKEN_EXPIRY_INVALID", Descriptor{ZhFallback: "到期時間必須在未來，且不能同時選擇永不到期"})
	CodeAPITokenNotEligible                      = register("API_TOKEN_NOT_ELIGIBLE", Descriptor{ZhFallback: "你目前沒有管理權限，不能建立 API token"})
	CodeConflictAPITokenName                     = register("CONFLICT_API_TOKEN_NAME", Descriptor{ZhFallback: "你已經有同名的 API token，請換一個名稱"})
	CodeAuthAPITokenForbiddenRoute               = register("AUTH_API_TOKEN_FORBIDDEN_ROUTE", Descriptor{ZhFallback: "API token 不能使用這個功能"})
	CodeAuthAPITokenSelfChangeForbidden          = register("AUTH_API_TOKEN_SELF_CHANGE_FORBIDDEN", Descriptor{ZhFallback: "API token 不能變更所屬帳號本人的這項設定"})
	CodeAPITokenNotFound                         = register("NOTFOUND_API_TOKEN", Descriptor{ZhFallback: "API token 不存在"})
	CodeAuthAPITokenCredentialReferenceForbidden = register("AUTH_API_TOKEN_CREDENTIAL_REFERENCE_FORBIDDEN", Descriptor{ZhFallback: "API token 不能引用系統已保存的憑證，請在請求中自帶密碼或金鑰"})
)
