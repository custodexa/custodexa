package apierror

// P1 error codes (i18n-backend-error-codes). Each code registers its zh-TW
// fallback template here; the three-language display strings live in the
// frontend apiError.* locale, bound by the bijection completeness test.
//
// Namespaces: AUTH_* / VALIDATION_* / NOTFOUND_* / CONFLICT_* / INTERNAL_* /
// RULE_<DOMAIN>_* — all uppercase (grammar ^[A-Z][A-Z0-9_]{0,63}$).

// resourceZhLabels maps semantic resource ids to their zh label for the wire
// fallback of parametrized codes (frontend re-translates via its enum getter).
var resourceZhLabels = map[string]string{
	"asset":              "資產",
	"user":               "用戶",
	"change_secret_plan": "計劃",
	"snippet":            "片段",
	"user_group":         "使用者群組",
	"session":            "Session",
	"recording":          "錄製",
	"audit_log":          "審計日誌",
}

// roleZhLabels is the allowlist + zh label for the {role} param of AUTH_ROLE_REQUIRED
// (RequireRole is only ever called with these developer-controlled role ids).
var roleZhLabels = map[string]string{
	"admin":    "管理員",
	"auditor":  "稽核人員",
	"approver": "審核人員",
	"user":     "一般使用者",
}

// --- Shared auth / middleware ---
var (
	// AUTH_UNAUTHENTICATED is shared by every middleware guard for a missing/blank identity.
	CodeUnauthenticated = register("AUTH_UNAUTHENTICATED", Descriptor{ZhFallback: "未認證"})

	CodeTokenMissing = register("AUTH_TOKEN_MISSING", Descriptor{ZhFallback: "未提供認證 token"})
	CodeTokenInvalid = register("AUTH_TOKEN_INVALID", Descriptor{ZhFallback: "無效或過期的 token"})

	// scoped/intermediate token trying to reach a general API
	CodeScopedTokenDenied = register("AUTH_SCOPED_TOKEN_DENIED", Descriptor{ZhFallback: "此 token 尚未完成登入流程，不可存取一般 API"})
	CodeMFAIncomplete     = register("AUTH_MFA_INCOMPLETE", Descriptor{ZhFallback: "MFA 驗證尚未完成"})

	// role gate; {role} is interpolated raw in the fallback (matches current text)
	CodeRoleRequired = register("AUTH_ROLE_REQUIRED", Descriptor{
		ZhFallback: "權限不足：此操作需要 {role} 角色",
		Params:     []ParamSpec{{Key: "role", Kind: ParamEnum, EnumNS: "role", ZhLabels: roleZhLabels}},
	})

	// generic permission gate; required_permission travels as Meta, not text
	CodePermissionDenied = register("AUTH_PERMISSION_DENIED", Descriptor{ZhFallback: "權限不足"})

	CodeApproverRequired = register("AUTH_APPROVER_REQUIRED", Descriptor{ZhFallback: "權限不足：需審核人員或管理員身分"})
)

// --- Validation ---
var (
	// VALIDATION_INVALID_ID carries the resource as a param so one code serves
	// every "無效的X ID"; {resource} renders to its zh label in the fallback.
	CodeInvalidID = register("VALIDATION_INVALID_ID", Descriptor{
		ZhFallback: "無效的{resource} ID",
		Params:     []ParamSpec{{Key: "resource", Kind: ParamEnum, EnumNS: "resource", ZhLabels: resourceZhLabels}},
	})
)

// --- Not found ---
var (
	CodeAssetNotFound = register("NOTFOUND_ASSET", Descriptor{ZhFallback: "資產不存在"})
)

// --- Internal (P1 exceptions: the three middleware 500s, and security fixes) ---
var (
	CodeInternalRoleQuery     = register("INTERNAL_ROLE_QUERY", Descriptor{ZhFallback: "查詢角色失敗"})
	CodeInternalApproverQuery = register("INTERNAL_APPROVER_QUERY", Descriptor{ZhFallback: "查詢審核資格失敗"})
	CodeInternalAssetQuery    = register("INTERNAL_ASSET_QUERY", Descriptor{ZhFallback: "查詢資產失敗"})
)

// ============================================================================
// Group 5: auth / mfa / user handler codes (i18n-backend-error-codes).
// Namespaces continue the middleware set. Each ZhFallback is byte-exact to the
// pre-migration c.JSON text (bijection test pins zh-TW == ZhFallback template).
// ============================================================================

// --- AUTH_* (login / token / credential) ---
var (
	CodeUserInactive       = register("AUTH_USER_INACTIVE", Descriptor{ZhFallback: "使用者帳號未啟用"})
	CodeAccountLocked      = register("AUTH_ACCOUNT_LOCKED", Descriptor{ZhFallback: "嘗試次數過多，帳號已暫時鎖定，請稍後再試或聯繫管理員"})
	CodeInvalidCredentials = register("AUTH_INVALID_CREDENTIALS", Descriptor{ZhFallback: "使用者名稱或密碼錯誤"})
	CodeUserNotFound       = register("AUTH_USER_NOT_FOUND", Descriptor{ZhFallback: "使用者不存在"})
	// CodeAuthLoginRateLimited 本地登入端點的來源濫用防護攔截
	// （security-backlog-settlement D3）。**不回填任何限流參數**：門檻、剩餘額度
	// 與重試時間都會讓攻擊者把流量精確調到門檻之下持續消耗；正當使用者只需要
	// 知道「稍後再試」。與帳號鎖定「不透露剩餘時間與次數」同一紀律
	CodeAuthLoginRateLimited = register("AUTH_LOGIN_RATE_LIMITED",
		Descriptor{ZhFallback: "登入請求過於頻繁，請稍後再試"})
	// CodeAuthChangePasswordRateLimited 自助改密端點的來源濫用防護攔截
	// （auth-cost-based-concurrency）。**與登入分開的理由是文案而非語義**：
	// 兩者的限流紀律相同（皆不回填門檻、剩餘額度與重試時間），
	// 但沿用登入的碼會讓使用者在**改密**時看到「登入請求過於頻繁」——
	// 訊息指向一個他當下沒在做的動作，只會讓人以為是別的問題
	CodeAuthChangePasswordRateLimited = register("AUTH_CHANGE_PASSWORD_RATE_LIMITED",
		Descriptor{ZhFallback: "改密請求過於頻繁，請稍後再試"})
	// CodeLDAPTransportRejected strict 檔位拒絕 LDAP 登入。
	// 修復指引指向身分管理的目錄設定頁（ldap-settings-migration D6：設定已自
	// env 遷入 DB，改 LDAP_URL 重啟不再生效）；**與 identity.ErrLDAPTransportRejected
	// 的訊息逐字相同**，改一處必改另一處
	CodeLDAPTransportRejected = register("AUTH_LDAP_TRANSPORT_REJECTED", Descriptor{ZhFallback: "LDAP 登入被傳輸安全政策拒絕：目錄連線未達加密要求，請管理員於身分管理的目錄設定頁改用 ldaps://"})

	// CodeExternalUserPassword 外部身分帳號的密碼由身分提供者管理（idp-oidc-integration D8）。
	// 涵蓋 LDAP 與 OIDC 供應帳號；僅用於**已認證的管理操作**（admin 重設、自助改密）
	// 的拒絕，登入路徑的拒絕一律沿用一般憑證錯誤形狀——否則此碼即成帳號枚舉 oracle
	CodeExternalUserPassword = register("AUTH_EXTERNAL_USER_PASSWORD", Descriptor{ZhFallback: "此帳號的密碼由外部身分提供者管理，無法在本系統修改"})
	CodeSessionExpired       = register("AUTH_SESSION_EXPIRED", Descriptor{ZhFallback: "會話已失效，請重新登入"})
	// scoped token whose scope is neither empty nor password_change reaching change-password
	CodeTokenNotForPasswordChange = register("AUTH_TOKEN_NOT_FOR_PASSWORD_CHANGE", Descriptor{ZhFallback: "此 token 不可用於改密"})
)

// --- AUTH_MFA_* (MFA token / enrollment state) ---
var (
	CodeMFAEnrollTokenMissing  = register("AUTH_MFA_ENROLL_TOKEN_MISSING", Descriptor{ZhFallback: "未提供註冊 token"})
	CodeMFANotEnabled          = register("AUTH_MFA_NOT_ENABLED", Descriptor{ZhFallback: "此帳號未啟用 MFA"})
	CodeMFASetupRequired       = register("AUTH_MFA_SETUP_REQUIRED", Descriptor{ZhFallback: "請先產生 MFA 設定"})
	CodeMFAPendingTokenInvalid = register("AUTH_MFA_PENDING_TOKEN_INVALID", Descriptor{ZhFallback: "無效或過期的 MFA 驗證 token"})
)

// --- RULE_MFA_* (TOTP verification rule violations) ---
var (
	CodeMFAInvalidCode = register("RULE_MFA_INVALID_CODE", Descriptor{ZhFallback: "MFA 驗證碼錯誤"})
	CodeMFAReplay      = register("RULE_MFA_REPLAY", Descriptor{ZhFallback: "MFA 驗證碼已使用過"})
)

// --- CONFLICT_* (uniqueness / already-in-state) ---
var (
	CodeUsernameExists     = register("CONFLICT_USERNAME_EXISTS", Descriptor{ZhFallback: "使用者名稱已存在"})
	CodeMFAAlreadyEnrolled = register("CONFLICT_MFA_ALREADY_ENROLLED", Descriptor{ZhFallback: "此帳號已完成 MFA 註冊"})
	// admin 更新 email 撞其他 live 帳號（profile-display-name R1）：取代原直寫撞 DB 唯一索引的通用 500
	CodeEmailConflict = register("CONFLICT_EMAIL", Descriptor{ZhFallback: "此 email 已被其他帳號使用"})

	// 金鑰管理的前置狀態衝突（kek-rewrap-hygiene-hardening）：全數走機器碼，
	// 前端查譯——本子系統原有五條 409 走 RespondError 裸中文訊息，
	// 於本 change 一併補碼（全域 i18n 規範：使用者可見的 API 錯誤一律機器碼）
	CodeKeyOpBusy = register("CONFLICT_KEY_OP_BUSY", Descriptor{ZhFallback: "另一金鑰操作進行中或互斥鎖被佔用，請稍後重試"})

	// 清理退役金鑰資料的全收斂閘（kek-rewrap-hygiene-hardening D9）
	CodeKeyCleanupNotConverged = register("CONFLICT_KEY_CLEANUP_NOT_CONVERGED", Descriptor{ZhFallback: "金鑰輪換尚未全數收斂（存在待切換 pending 或退役 backlog），請先完成切換或重啟收斂後再清理"})
	// CodeKeyCleanupResidueDetected 引用掃描遇不可歸屬版本的非終態格式殘值：
	// 保守拒清（release-transitional-cleanup 3.3）
	CodeKeyCleanupResidueDetected = register("CONFLICT_KEY_CLEANUP_RESIDUE_DETECTED", Descriptor{ZhFallback: "偵測到無法歸屬版本的非終態格式殘值：已保守拒絕本次清理，請先排除該些值（其可能由退役版本加密，銷毀材料將永久不可解）"})

	// 本實例金鑰狀態過期（另一實例已完成輪替或 KEK 切換）——須重啟本實例
	CodeKeyStaleCache = register("CONFLICT_KEY_STALE_CACHE", Descriptor{ZhFallback: "本實例金鑰狀態已過期（另一實例已完成輪替或 KEK 切換），請重啟本實例後重試"})

	// KEK 重包待切換期間拒絕 DEK 輪替
	CodeKeyRewrapPending = register("CONFLICT_KEY_REWRAP_PENDING", Descriptor{ZhFallback: "KEK 重包待切換：請先更新 ENCRYPTION_KEY 並重啟完成切換，再執行金鑰輪替"})

	// 已有待切換 pending 時拒絕新重包（不靜默作廢已交付的新 KEK）
	CodeKeyRewrapPendingExists = register("CONFLICT_KEY_REWRAP_PENDING_EXISTS", Descriptor{ZhFallback: "已有待切換的 KEK 重包：請先完成切換（更新 ENCRYPTION_KEY 重啟）或放棄重包，再開始新重包"})

	// 前次切換的退役收尾未收斂時拒絕新重包
	CodeKeyRetireBacklog = register("CONFLICT_KEY_RETIRE_BACKLOG", Descriptor{ZhFallback: "前次 KEK 切換的舊列尚未完成退役收斂：請先重啟後端讓其自動收斂，再開始新重包"})

	// 信封遷移未完成時拒絕重包

	// 無待切換重包時拒絕放棄
	CodeKeyNoRewrapPending = register("CONFLICT_KEY_NO_REWRAP_PENDING", Descriptor{ZhFallback: "目前無待切換的 KEK 重包，無需放棄"})
)

// --- VALIDATION_* (request binding / field checks) ---
var (
	CodeBadRequestFormat     = register("VALIDATION_BAD_REQUEST", Descriptor{ZhFallback: "請求格式錯誤"})
	CodeBadParams            = register("VALIDATION_BAD_PARAMS", Descriptor{ZhFallback: "請求參數錯誤"})
	CodeChangePasswordFields = register("VALIDATION_CHANGE_PASSWORD_FIELDS", Descriptor{ZhFallback: "請求格式錯誤：需提供 old_password 與 new_password"})
	CodePasswordFieldMissing = register("VALIDATION_PASSWORD_FIELD_MISSING", Descriptor{ZhFallback: "請求參數錯誤，缺少密碼欄位"})
	CodeActiveRequired       = register("VALIDATION_ACTIVE_REQUIRED", Descriptor{ZhFallback: "active 參數不能為空"})
	CodeExemptRequired       = register("VALIDATION_EXEMPT_REQUIRED", Descriptor{ZhFallback: "請求參數錯誤：需提供 exempt"})
	CodeRoleNotFound         = register("VALIDATION_ROLE_NOT_FOUND", Descriptor{ZhFallback: "指定的角色不存在"})
	// 自助顯示名格式驗證（profile-display-name R1）：長度上限 100、不可含控制字元或換行
	CodeInvalidDisplayName = register("VALIDATION_DISPLAY_NAME", Descriptor{ZhFallback: "顯示名稱格式不正確：長度上限 100，且不可含控制字元或換行"})
)

// --- NOTFOUND_* ---
var (
	// NOTFOUND_USER is the admin user-management "用戶不存在"; distinct from the
	// auth-domain AUTH_USER_NOT_FOUND ("使用者不存在") by wording (用戶 vs 使用者).
	CodeUserNotExist = register("NOTFOUND_USER", Descriptor{ZhFallback: "用戶不存在"})
)

// --- RULE_USER_* (user management / password policy rules) ---
var (
	CodeLastAdminDelete     = register("RULE_USER_LAST_ADMIN_DELETE", Descriptor{ZhFallback: "不能刪除最後一個管理員帳號"})
	CodeLastAdminDisable    = register("RULE_USER_LAST_ADMIN_DISABLE", Descriptor{ZhFallback: "不能禁用最後一個管理員帳號"})
	CodeOldPasswordMismatch = register("RULE_USER_OLD_PASSWORD_MISMATCH", Descriptor{ZhFallback: "目前密碼錯誤"})
	CodeLDAPUserPassword    = register("RULE_USER_LDAP_PASSWORD", Descriptor{ZhFallback: "LDAP 使用者的密碼由目錄服務管理，無法在本系統修改"})

	// Password policy violations. {limit}/{min}/{count} come from the policy at
	// construction time (service attaches them to PasswordPolicyViolation.Params).
	CodePasswordTooLong = register("RULE_USER_PASSWORD_TOO_LONG", Descriptor{
		ZhFallback: "密碼過長（上限 {limit} 位元組）",
		Params:     []ParamSpec{{Key: "limit", Kind: ParamInt}},
	})
	CodePasswordTooShort = register("RULE_USER_PASSWORD_TOO_SHORT", Descriptor{
		ZhFallback: "密碼長度至少需 {min} 字元",
		Params:     []ParamSpec{{Key: "min", Kind: ParamInt}},
	})
	CodePasswordComplexity = register("RULE_USER_PASSWORD_COMPLEXITY", Descriptor{ZhFallback: "密碼必須同時包含字母與數字"})
	CodePasswordReused     = register("RULE_USER_PASSWORD_REUSED", Descriptor{
		ZhFallback: "新密碼不可與最近 {count} 次使用過的密碼相同",
		Params:     []ParamSpec{{Key: "count", Kind: ParamInt}},
	})
	CodePasswordSameAsCurrent = register("RULE_USER_PASSWORD_SAME_AS_CURRENT", Descriptor{ZhFallback: "新密碼不可與目前密碼相同"})
)

// --- RULE_SSH_* (terminal dial failures surfaced over the WS error message;
// ssh-connect-error-surfacing). ZhFallback mirrors the sshproxy sentinel texts. ---
var (
	CodeSSHHostKeyChanged = register("RULE_SSH_HOST_KEY_CHANGED", Descriptor{ZhFallback: "主機金鑰已變更，連線已拒絕；若主機確實重灌，請聯繫管理員重置 host key"})
	CodeSSHAuthFailed     = register("RULE_SSH_AUTH_FAILED", Descriptor{ZhFallback: "SSH 認證失敗，請確認資產憑證"})
	CodeSSHDialTimeout    = register("RULE_SSH_DIAL_TIMEOUT", Descriptor{ZhFallback: "連線目標主機逾時"})
	CodeSSHUnreachable    = register("RULE_SSH_UNREACHABLE", Descriptor{ZhFallback: "無法連線到目標主機"})
)

// --- INTERNAL_* (generalized 5xx / service-unavailable; cause logged server-side) ---
var (
	CodeInternalLogin                    = register("INTERNAL_LOGIN", Descriptor{ZhFallback: "登入失敗"})
	CodeInternalRefresh                  = register("INTERNAL_REFRESH", Descriptor{ZhFallback: "刷新失敗"})
	CodeInternalUserInfoQuery            = register("INTERNAL_USER_INFO_QUERY", Descriptor{ZhFallback: "無法取得使用者資訊"})
	CodeInternalChangePasswordTokenIssue = register("INTERNAL_CHANGE_PASSWORD_TOKEN_ISSUE", Descriptor{ZhFallback: "改密成功但換發 token 失敗，請重新登入"})
	CodeInternalChangePassword           = register("INTERNAL_CHANGE_PASSWORD", Descriptor{ZhFallback: "修改密碼失敗"})
	CodeChangePasswordUnavailable        = register("INTERNAL_CHANGE_PASSWORD_UNAVAILABLE", Descriptor{ZhFallback: "改密服務未啟用"})

	CodeInternalUserQuery        = register("INTERNAL_USER_QUERY", Descriptor{ZhFallback: "查詢用戶失敗"})
	CodeInternalUserCreate       = register("INTERNAL_USER_CREATE", Descriptor{ZhFallback: "創建用戶失敗"})
	CodeInternalUserUpdate       = register("INTERNAL_USER_UPDATE", Descriptor{ZhFallback: "更新用戶失敗"})
	CodeInternalUserDelete       = register("INTERNAL_USER_DELETE", Descriptor{ZhFallback: "刪除用戶失敗"})
	CodeInternalRoleAssign       = register("INTERNAL_ROLE_ASSIGN", Descriptor{ZhFallback: "分配角色失敗"})
	CodeInternalRoleAdd          = register("INTERNAL_ROLE_ADD", Descriptor{ZhFallback: "追加角色失敗"})
	CodeInternalStatusUpdate     = register("INTERNAL_STATUS_UPDATE", Descriptor{ZhFallback: "更新狀態失敗"})
	CodeInternalUnlock           = register("INTERNAL_UNLOCK", Descriptor{ZhFallback: "解鎖失敗"})
	CodeInternalInactivityExempt = register("INTERNAL_INACTIVITY_EXEMPT", Descriptor{ZhFallback: "設定豁免失敗"})

	CodeInternalMFASetup        = register("INTERNAL_MFA_SETUP", Descriptor{ZhFallback: "產生 MFA 設定失敗"})
	CodeInternalMFAEnable       = register("INTERNAL_MFA_ENABLE", Descriptor{ZhFallback: "啟用 MFA 失敗"})
	CodeInternalMFAEnroll       = register("INTERNAL_MFA_ENROLL", Descriptor{ZhFallback: "完成 MFA 綁定失敗"})
	CodeInternalMFADisable      = register("INTERNAL_MFA_DISABLE", Descriptor{ZhFallback: "停用 MFA 失敗"})
	CodeInternalMFAVerify       = register("INTERNAL_MFA_VERIFY", Descriptor{ZhFallback: "MFA 驗證失敗"})
	CodeInternalMFAAdminDisable = register("INTERNAL_MFA_ADMIN_DISABLE", Descriptor{ZhFallback: "停用用戶 MFA 失敗"})
)

// ============================================================================
// Group 6: security-fix internal codes (i18n-backend-error-codes).
// Sinks that previously emitted raw err.Error() are generalized through these.
// ============================================================================
var (
	CodeK8sCopy          = register("INTERNAL_K8S_COPY", Descriptor{ZhFallback: "檔案傳輸失敗"})
	CodeGuacdHandshake   = register("INTERNAL_GUACD_HANDSHAKE", Descriptor{ZhFallback: "連線建立失敗"})
	CodeRecordingConvert = register("INTERNAL_RECORDING_CONVERT", Descriptor{ZhFallback: "轉換錄製格式失敗"})
	// Syslog test delivery failure. Single generalized code by design: splitting it
	// by cause (connection refused / timeout / TLS verification) would turn the
	// destination's reachability and TLS posture into a probe signal. The concrete
	// cause is logged server-side only (asset-syslog-debt-cleanup D1).
	CodeSyslogTestFailed = register("INTERNAL_SYSLOG_TEST_FAILED", Descriptor{ZhFallback: "syslog 測試訊息傳送失敗，請確認主機、連接埠與 TLS 設定"})
)
