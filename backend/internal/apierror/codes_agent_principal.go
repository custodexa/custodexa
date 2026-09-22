package apierror

var CodeValidationAgentOwnerRequired = register("VALIDATION_AGENT_OWNER_REQUIRED", Descriptor{ZhFallback: "自動化主體須指定啟用中的人類帳號為擁有者"})

var (
	CodeRuleAgentSelfCreateDisabled     = register("RULE_AGENT_SELF_CREATE_DISABLED", Descriptor{ZhFallback: "未開放自助建立自動化帳號"})
	CodeRuleAgentSelfCreateLimit        = register("RULE_AGENT_SELF_CREATE_LIMIT", Descriptor{ZhFallback: "名下自動化帳號已達自助建立上限"})
	CodeAuthAgentTokenInvalid           = register("AUTH_AGENT_TOKEN_INVALID", Descriptor{ZhFallback: "自動化權杖無效"})
	CodeAuthAgentForbiddenRoute         = register("AUTH_AGENT_FORBIDDEN_ROUTE", Descriptor{ZhFallback: "自動化主體不可使用此端點"})
	CodeAuthRequestItemMismatch         = register("AUTH_REQUEST_ITEM_MISMATCH", Descriptor{ZhFallback: "存取申請項目不符"})
	CodeValidationAccountNotOnAsset     = register("VALIDATION_ACCOUNT_NOT_ON_ASSET", Descriptor{ZhFallback: "帳號不屬於指定資產"})
	CodeValidationAgentAccountsRequired = register("VALIDATION_AGENT_ACCOUNTS_REQUIRED", Descriptor{ZhFallback: "自動化任務須指定帳號"})
	CodeRuleAgentBreakerPending         = register("RULE_AGENT_BREAKER_PENDING", Descriptor{ZhFallback: "自動化主體熔斷待處置，無法建立權杖"})
	CodeRuleAgentRequestRate            = register("RULE_AGENT_REQUEST_RATE", Descriptor{ZhFallback: "自動化主體已達申請速率上限"})
	CodeRuleAgentBreakerTripped         = register("RULE_AGENT_BREAKER_TRIPPED", Descriptor{ZhFallback: "自動化主體已觸發熔斷"})
	CodeConflictAgentBreakerNotPending  = register("CONFLICT_AGENT_BREAKER_NOT_PENDING", Descriptor{ZhFallback: "自動化主體目前沒有待處置的熔斷"})
	CodeValidationExecutorNotAgent      = register("VALIDATION_EXECUTOR_NOT_AGENT", Descriptor{ZhFallback: "執行主體必須為自動化主體"})
	CodeAuthAgentTokenRevoked           = register("AUTH_AGENT_TOKEN_REVOKED", Descriptor{ZhFallback: "自動化權杖已撤銷", AuditOnly: true})
	CodeAuthAgentTokenSuspended         = register("AUTH_AGENT_TOKEN_SUSPENDED", Descriptor{ZhFallback: "自動化權杖已停用", AuditOnly: true})
)
