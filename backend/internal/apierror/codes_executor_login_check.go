package apierror

// 堡壘機專用帳號測試登入的出口碼。
//
// 前九個是「結果碼」：測試完成但沒有通過時，HTTP 200 回應的 code 欄就是它們，同時存入結果表；
// 後四個是 HTTP 錯誤。含 {account} 的文案以回應的 account_username 代入。
// 錯誤與結果一律不帶遠端輸出、指紋或限流數值。

// --- 結果碼 ---
var (
	CodeExecutorCheckConnectionFailed = register("RULE_EXECUTOR_CHECK_CONNECTION_FAILED",
		Descriptor{ZhFallback: "連不到這台主機。請確認位址、通訊埠與網路後再試。"})
	CodeExecutorCheckLoginFailed = register("RULE_EXECUTOR_CHECK_LOGIN_FAILED", Descriptor{
		ZhFallback: "主機拒絕了專用帳號 {account} 的登入。請確認主機上有這個帳號，並已加入平台的公鑰（金鑰型）或密碼正確（密碼型）。",
		Params:     []ParamSpec{{Key: "account", Kind: ParamOpaque}},
	})
	CodeExecutorCheckHostKeyMismatch = register("RULE_EXECUTOR_CHECK_HOST_KEY_MISMATCH",
		Descriptor{ZhFallback: "主機的身分指紋和記錄不同，平台沒有送出專用帳號的憑證。請確認主機後，採用新指紋或重置。"})
	CodeExecutorCheckHostKeyCheckFailed = register("RULE_EXECUTOR_CHECK_HOST_KEY_CHECK_FAILED",
		Descriptor{ZhFallback: "無法核對主機的身分指紋，平台沒有登入。請稍後再試。"})
	CodeExecutorCheckEscalationDenied = register("RULE_EXECUTOR_CHECK_ESCALATION_DENIED", Descriptor{
		ZhFallback: "登入成功，但 {account} 沒有替其他帳號改密的權限。請在主機上為它加上改密程式的 sudo 規則。",
		Params:     []ParamSpec{{Key: "account", Kind: ParamOpaque}},
	})
	CodeExecutorCheckEscalationNeedsNopasswd = register("RULE_EXECUTOR_CHECK_ESCALATION_NEEDS_NOPASSWD", Descriptor{
		ZhFallback: "登入成功，但主機沒有允許 {account} 免密碼執行改密程式的 sudo 規則：可能還沒加規則，或規則沒有設為免密碼（NOPASSWD）。金鑰型專用帳號需要一條免密碼的改密規則。",
		Params:     []ParamSpec{{Key: "account", Kind: ParamOpaque}},
	})
	CodeExecutorCheckUnavailable = register("RULE_EXECUTOR_CHECK_UNAVAILABLE",
		Descriptor{ZhFallback: "專用帳號目前沒有可用的秘密，沒有登入。請重新設定專用帳號。"})
	CodeExecutorCheckRotationPending = register("RULE_EXECUTOR_CHECK_ROTATION_PENDING",
		Descriptor{ZhFallback: "專用帳號正在改密，這次沒有登入。改密完成後再測試。"})
	CodeExecutorCheckTimeout = register("RULE_EXECUTOR_CHECK_TIMEOUT",
		Descriptor{ZhFallback: "主機沒有在時間內回應，結果不確定。請稍後再試。"})
)

// --- HTTP 錯誤 ---
var (
	CodeExecutorCheckPlatformUnsupported = register("RULE_EXECUTOR_CHECK_PLATFORM_UNSUPPORTED",
		Descriptor{ZhFallback: "這類主機目前不支援測試登入。"})
	CodeExecutorCheckRateLimited = register("RULE_EXECUTOR_CHECK_RATE_LIMITED",
		Descriptor{ZhFallback: "測試太頻繁，請稍後再試。"})
	CodeExecutorCheckBusy = register("CONFLICT_EXECUTOR_CHECK_BUSY",
		Descriptor{ZhFallback: "專用帳號正在執行其他作業（改密或盤點），這次沒有登入。請稍後再試。"})
	CodeInternalExecutorCheck = register("INTERNAL_EXECUTOR_CHECK",
		Descriptor{ZhFallback: "測試登入沒有完成（伺服器內部錯誤），請稍後再試。"})
)
