package apierror

// change-secret-plans / snippets / host-key handler 出口碼
// 與 codes.go 同一 registry，分檔僅為
// 批次隔離；命名沿用 codes.go 既有慣例（VALIDATION_* / CONFLICT_* /
// NOTFOUND_* / INTERNAL_<RESOURCE>_<VERB>）。ZhFallback 逐字取自遷移前
// c.JSON 文字（含既有 RespondInternalError 的 action+"失敗" 拼接結果），
// 只換形狀不動文案。

// --- 改密計劃（change_secret_handler.go）---
var (
	CodePlanNoAssets   = register("VALIDATION_PLAN_NO_ASSETS", Descriptor{ZhFallback: "計劃必須包含至少一個資產"})
	CodePlanBadCron    = register("VALIDATION_PLAN_BAD_CRON", Descriptor{ZhFallback: "排程格式錯誤（標準 5 欄 cron）"})
	CodePlanNameExists = register("CONFLICT_PLAN_NAME_EXISTS", Descriptor{ZhFallback: "計劃名稱已存在"})
	CodePlanNotFound   = register("NOTFOUND_CHANGE_SECRET_PLAN", Descriptor{ZhFallback: "改密計劃不存在"})

	CodeInternalChangeSecretPlanQuery   = register("INTERNAL_CHANGE_SECRET_PLAN_QUERY", Descriptor{ZhFallback: "查詢改密計劃失敗"})
	CodeInternalChangeSecretPlanCreate  = register("INTERNAL_CHANGE_SECRET_PLAN_CREATE", Descriptor{ZhFallback: "建立改密計劃失敗"})
	CodeInternalChangeSecretPlanUpdate  = register("INTERNAL_CHANGE_SECRET_PLAN_UPDATE", Descriptor{ZhFallback: "更新改密計劃失敗"})
	CodeInternalChangeSecretPlanDelete  = register("INTERNAL_CHANGE_SECRET_PLAN_DELETE", Descriptor{ZhFallback: "刪除改密計劃失敗"})
	CodeInternalChangeSecretRecordQuery = register("INTERNAL_CHANGE_SECRET_RECORD_QUERY", Descriptor{ZhFallback: "查詢改密記錄失敗"})
)

// --- 改密期 1：秘密型別／策略／候選憑證---
var (
	CodePlanBadSecretType  = register("VALIDATION_PLAN_BAD_SECRET_TYPE", Descriptor{ZhFallback: "秘密型別僅支援 password 或 ssh_key"})
	CodePlanBadKeyStrategy = register("VALIDATION_PLAN_BAD_KEY_STRATEGY", Descriptor{ZhFallback: "金鑰策略僅支援 append_replace 或 exclusive"})
	CodePlanBadPasswordLen = register("VALIDATION_PLAN_BAD_PASSWORD_LENGTH", Descriptor{ZhFallback: "密碼長度須介於 12 與 64 之間"})

	// CodePlanBadMaxAgeDays 計劃層的憑證最長使用天數覆蓋越界（0＝沿用全域，否則 1–3650）
	CodePlanBadMaxAgeDays = register("VALIDATION_PLAN_BAD_MAX_AGE_DAYS", Descriptor{ZhFallback: "憑證最長使用天數覆蓋須為 0（沿用全域）或 1 至 3650"})

	CodeCandidateNotFound = register("NOTFOUND_CHANGE_SECRET_CANDIDATE", Descriptor{ZhFallback: "候選憑證不存在"})

	CodeInternalChangeSecretCandidateQuery   = register("INTERNAL_CHANGE_SECRET_CANDIDATE_QUERY", Descriptor{ZhFallback: "查詢候選憑證失敗"})
	CodeInternalChangeSecretCandidateDiscard = register("INTERNAL_CHANGE_SECRET_CANDIDATE_DISCARD", Descriptor{ZhFallback: "清除候選憑證失敗"})
)

// --- 命令片段（snippet_handler.go）---
var (
	CodeSnippetNameEmpty = register("VALIDATION_SNIPPET_NAME_EMPTY", Descriptor{ZhFallback: "片段名稱不可為空"})
	CodeSnippetTooLong   = register("VALIDATION_SNIPPET_TOO_LONG", Descriptor{ZhFallback: "片段內容超過 4096 字元上限"})
	CodeSnippetNotFound  = register("NOTFOUND_SNIPPET", Descriptor{ZhFallback: "片段不存在"})

	CodeInternalSnippetQuery  = register("INTERNAL_SNIPPET_QUERY", Descriptor{ZhFallback: "查詢片段失敗"})
	CodeInternalSnippetCreate = register("INTERNAL_SNIPPET_CREATE", Descriptor{ZhFallback: "建立片段失敗"})
	CodeInternalSnippetUpdate = register("INTERNAL_SNIPPET_UPDATE", Descriptor{ZhFallback: "更新片段失敗"})
	CodeInternalSnippetDelete = register("INTERNAL_SNIPPET_DELETE", Descriptor{ZhFallback: "刪除片段失敗"})
)

// --- 資產 host key（host_key_handler.go）---
var (
	// CodeHostKeyNotFound Get 端點：ErrRecordNotFound（尚無記錄，首次連線時記錄）
	CodeHostKeyNotFound = register("NOTFOUND_HOST_KEY", Descriptor{ZhFallback: "尚無 host key 記錄（首次連線時記錄）"})
	// CodeHostKeyNoRecordToReset Reset 端點：existed=false（無記錄可重置），
	// 文字不含 Get 端點的括注，故另立一碼（byte-exact 慣例不可合併）
	CodeHostKeyNoRecordToReset = register("NOTFOUND_HOST_KEY_TO_RESET", Descriptor{ZhFallback: "尚無 host key 記錄"})

	CodeInternalHostKeyQuery = register("INTERNAL_HOST_KEY_QUERY", Descriptor{ZhFallback: "查詢 host key失敗"})
	CodeInternalHostKeyReset = register("INTERNAL_HOST_KEY_RESET", Descriptor{ZhFallback: "重置 host key失敗"})
)

// --- 輪替證據報告（rotation_report_handler.go）---
var (
	CodeReportBadScope         = register("VALIDATION_ROTATION_REPORT_BAD_SCOPE", Descriptor{ZhFallback: "報告範圍不合法或不存在"})
	CodeReportBadLanguage      = register("VALIDATION_ROTATION_REPORT_BAD_LANGUAGE", Descriptor{ZhFallback: "報告語言不在支援清單內"})
	CodeReportBadPeriod        = register("VALIDATION_ROTATION_REPORT_BAD_PERIOD", Descriptor{ZhFallback: "記錄區間的起點須早於迄點"})
	CodeReportBadCron          = register("VALIDATION_ROTATION_SCHEDULE_BAD_CRON", Descriptor{ZhFallback: "排程格式錯誤（標準 5 欄 cron）"})
	CodeReportBadRetention     = register("VALIDATION_ROTATION_SCHEDULE_BAD_RETENTION", Descriptor{ZhFallback: "留存天數須介於 1 與 3650 之間"})
	CodeReportNameEmpty        = register("VALIDATION_ROTATION_SCHEDULE_NAME_EMPTY", Descriptor{ZhFallback: "排程名稱不可為空"})
	CodeReportNameTooLong      = register("VALIDATION_ROTATION_SCHEDULE_NAME_TOO_LONG", Descriptor{ZhFallback: "排程名稱長度上限 128 字"})
	CodeReportNameExists       = register("CONFLICT_ROTATION_SCHEDULE_NAME_EXISTS", Descriptor{ZhFallback: "排程名稱已存在"})
	CodeReportScheduleBusy     = register("CONFLICT_ROTATION_SCHEDULE_INFLIGHT", Descriptor{ZhFallback: "該排程已有一張進行中的報告工作單"})
	CodeReportScheduleNotFound = register("NOTFOUND_ROTATION_SCHEDULE", Descriptor{ZhFallback: "報告排程不存在"})

	CodeInternalRotationReportBuild    = register("INTERNAL_ROTATION_REPORT_BUILD", Descriptor{ZhFallback: "產生輪替證據報告失敗"})
	CodeInternalRotationScheduleQuery  = register("INTERNAL_ROTATION_SCHEDULE_QUERY", Descriptor{ZhFallback: "查詢報告排程失敗"})
	CodeInternalRotationScheduleCreate = register("INTERNAL_ROTATION_SCHEDULE_CREATE", Descriptor{ZhFallback: "建立報告排程失敗"})
	CodeInternalRotationScheduleUpdate = register("INTERNAL_ROTATION_SCHEDULE_UPDATE", Descriptor{ZhFallback: "更新報告排程失敗"})
	CodeInternalRotationScheduleDelete = register("INTERNAL_ROTATION_SCHEDULE_DELETE", Descriptor{ZhFallback: "刪除報告排程失敗"})
	CodeInternalRotationReportJob      = register("INTERNAL_ROTATION_REPORT_JOB", Descriptor{ZhFallback: "建立報告工作單失敗"})
)
