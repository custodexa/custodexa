package apierror

// 申請核准流／存取複審／每日審閱三個 handler 的出口碼。
//
// 本檔與 codes.go / codes_stream.go 同一 registry，分檔僅為並行遷移隔離。
// 涵蓋範圍：
//   - internal/api/access_request_handler.go（申請、破窗、撤銷、補審、審核範圍）
//   - internal/api/access_review_handler.go（週期性存取複審，PCI 7.2.4）
//   - internal/api/daily_review_handler.go（每日審閱簽核，PCI 10.4.1）
//
// ZhFallback 與遷移前的裸文字逐字相同（service sentinel 文字或 handler 內字面量），
// 三語譯文由 frontend apiError.* 綁定，完備性測試把關。
//
// 命名沿用既有 taxonomy：
//   NOTFOUND_*   資源不存在（404）
//   CONFLICT_*   狀態衝突／重複（409）
//   RULE_*       可預期的業務規則攔截（400/403）
//   VALIDATION_* 請求格式／欄位檢查（400）
//   INTERNAL_*   泛化 5xx，action-scoped（INTERNAL_<RESOURCE>_<VERB>）

// --- NOTFOUND_* ---
var (
	CodeAccessRequestNotFound = register("NOTFOUND_ACCESS_REQUEST", Descriptor{ZhFallback: "申請單不存在"})
	CodeApproverScopeNotFound = register("NOTFOUND_APPROVER_SCOPE", Descriptor{ZhFallback: "審核範圍不存在"})
	CodeAccessReviewNotFound  = register("NOTFOUND_ACCESS_REVIEW", Descriptor{ZhFallback: "複審紀錄不存在"})
)

// --- CONFLICT_* ---
var (
	CodeAccessRequestStateChanged = register("CONFLICT_ACCESS_REQUEST_STATE", Descriptor{ZhFallback: "申請單狀態已變更，請重新整理"})
	// 服務層以 fmt.Errorf("%w（單號 %d）", …) 附帶單號，碼化後單號不再進 wire
	// （附帶值需服務層改為具名欄位才能轉 param，尚未實作）。
	CodeDuplicatePendingRequest   = register("CONFLICT_ACCESS_REQUEST_DUPLICATE_PENDING", Descriptor{ZhFallback: "同資產已有在途申請"})
	CodeAlreadyApprovedByActor    = register("CONFLICT_ACCESS_REQUEST_ALREADY_APPROVED", Descriptor{ZhFallback: "您已核准過此申請"})
	CodeDuplicateBreakGlass       = register("CONFLICT_BREAK_GLASS_DUPLICATE", Descriptor{ZhFallback: "同資產已有有效的破窗連線"})
	CodeBreakGlassAlreadyReviewed = register("CONFLICT_BREAK_GLASS_ALREADY_REVIEWED", Descriptor{ZhFallback: "此破窗連線已完成補審"})
	CodeAccessTicketNotActive     = register("CONFLICT_ACCESS_TICKET_NOT_ACTIVE", Descriptor{ZhFallback: "無有效臨時授權可撤銷"})
	CodeApproverScopeExists       = register("CONFLICT_APPROVER_SCOPE_EXISTS", Descriptor{ZhFallback: "審核範圍已存在"})
	// 「誰在幾點簽的」是使用者判斷「不是我漏簽、無須再追」的必需資訊，故以
	// params 還原（service.AlreadySignedError 提供具名欄位）。兩者皆為
	// ParamOpaque：簽核者是自由字串（顯示名／帳號），時刻是格式化後的字面值，
	// 值域皆不可枚舉，走淨化不走允許清單。
	CodeDailyReviewAlreadySigned = register("CONFLICT_DAILY_REVIEW_SIGNED", Descriptor{
		ZhFallback: "當日已完成簽核（{time} 由 {signer} 簽核）",
		Params: []ParamSpec{
			{Key: "time", Kind: ParamOpaque},
			{Key: "signer", Kind: ParamOpaque},
		},
	})
)

// --- RULE_* （業務規則攔截：400/403）---
var (
	// 上限值是使用者改單重送的必需資訊（不知上限就只能盲試），故以 param 還原；
	// 值由 authz.DurationExceedsPolicyError 具名帶出（政策讀值，非使用者輸入）。
	CodeAccessRequestDurationExceeds = register("RULE_ACCESS_REQUEST_DURATION_EXCEEDS", Descriptor{
		ZhFallback: "申請時長超過政策上限（上限 {minutes} 分鐘）",
		Params:     []ParamSpec{{Key: "minutes", Kind: ParamInt}},
	})
	// 無參 sibling：裸 sentinel 保底分支用（typed error 為唯一現實路徑，此碼
	// 只在防禦分支出現）——帶參碼缺參會剝除佔位符產生破碎文案，故保底走本碼
	CodeAccessRequestDurationExceedsNoLimit = register("RULE_ACCESS_REQUEST_DURATION_EXCEEDS_POLICY", Descriptor{
		ZhFallback: "申請時長超過政策上限"})
	CodeAccessRequestDecisionIncrease = register("RULE_ACCESS_REQUEST_DECISION_INCREASE", Descriptor{ZhFallback: "核准值不得優於申請值（時長僅可下修、起始僅可推遲）"})
	CodeAccessRequestPolicyOpen       = register("RULE_ACCESS_REQUEST_POLICY_OPEN", Descriptor{ZhFallback: "該資產不需申請即可連線"})
	CodeAccessRequestStartInPast      = register("RULE_ACCESS_REQUEST_START_IN_PAST", Descriptor{ZhFallback: "預約起始時間不得早於現在"})
	CodeAccessRequestSelfApproval     = register("RULE_ACCESS_REQUEST_SELF_APPROVAL", Descriptor{ZhFallback: "不得核准或拒絕自己的申請"})
	CodeNotEligibleApprover           = register("RULE_ACCESS_REQUEST_NOT_ELIGIBLE_APPROVER", Descriptor{ZhFallback: "申請資產不在您的審核範圍內"})
	CodeRequesterExempt               = register("RULE_ACCESS_REQUEST_REQUESTER_EXEMPT", Descriptor{ZhFallback: "此角色不需或不得提出連線申請"})
	CodeNotRevokeEligible             = register("RULE_ACCESS_TICKET_NOT_REVOKE_ELIGIBLE", Descriptor{ZhFallback: "僅管理員或原核准人可撤銷此臨時授權"})

	// 破窗開關關閉＝封 API；前端據此碼隱藏入口自癒（原 legacy 小寫碼
	// break_glass_disabled，改走 registry 後 code 值變更，見 change 回報）。
	CodeBreakGlassDisabled    = register("RULE_BREAK_GLASS_DISABLED", Descriptor{ZhFallback: "破窗緊急連線未開放"})
	CodeBreakGlassNotEligible = register("RULE_BREAK_GLASS_NOT_ELIGIBLE", Descriptor{ZhFallback: "無破窗資格（需持有該資產的常設連線授權）"})
	CodeBreakGlassSelfReview  = register("RULE_BREAK_GLASS_SELF_REVIEW", Descriptor{ZhFallback: "不得補審自己的破窗連線"})
	CodeNotBreakGlass         = register("RULE_BREAK_GLASS_NOT_APPLICABLE", Descriptor{ZhFallback: "此申請單非破窗連線，無需補審"})

	CodeScopeNotApproverRole = register("RULE_APPROVER_SCOPE_NOT_APPROVER_ROLE", Descriptor{ZhFallback: "目標使用者不具 approver 角色"})
	CodeDailyReviewDisabled  = register("RULE_DAILY_REVIEW_DISABLED", Descriptor{ZhFallback: "每日審閱功能未啟用"})
)

// --- VALIDATION_* ---
var (
	// 路徑參數 ID 解析失敗。既有 VALIDATION_INVALID_ID 以 {resource} enum 承載資源，
	// 但其 ZhLabels 允許清單在 codes.go，不跨檔擴充，故三個資源各自建碼。
	CodeInvalidAccessRequestID = register("VALIDATION_INVALID_ACCESS_REQUEST_ID", Descriptor{ZhFallback: "無效的申請單 ID"})
	CodeInvalidApproverScopeID = register("VALIDATION_INVALID_APPROVER_SCOPE_ID", Descriptor{ZhFallback: "無效的範圍 ID"})
	CodeInvalidAccessReviewID  = register("VALIDATION_INVALID_ACCESS_REVIEW_ID", Descriptor{ZhFallback: "無效的複審 ID"})

	CodeAccessRequestFields = register("VALIDATION_ACCESS_REQUEST_FIELDS", Descriptor{ZhFallback: "請求參數錯誤：事由與時長必填"})
	CodeBreakGlassFields    = register("VALIDATION_BREAK_GLASS_FIELDS", Descriptor{ZhFallback: "請求參數錯誤：資產與事由必填"})
	// 拒絕缺事由：binding 失敗與服務層 ErrDecisionNoteRequired 同一使用者動作
	// （補上事由重送），合併為一碼。
	CodeDecisionNoteRequired      = register("VALIDATION_DECISION_NOTE_REQUIRED", Descriptor{ZhFallback: "拒絕申請必須填寫事由"})
	CodeRevokeNoteRequired        = register("VALIDATION_REVOKE_NOTE_REQUIRED", Descriptor{ZhFallback: "撤銷必須填寫事由"})
	CodeReviewDispositionRequired = register("VALIDATION_REVIEW_DISPOSITION_REQUIRED", Descriptor{ZhFallback: "補審必須指定處置"})
	CodeInvalidReviewDisposition  = register("VALIDATION_REVIEW_DISPOSITION", Descriptor{ZhFallback: "補審處置僅接受 confirmed 或 violation"})

	CodeScopeTargetInvalid = register("VALIDATION_APPROVER_SCOPE_TARGET", Descriptor{ZhFallback: "審核範圍客體必須恰一（asset_id/asset_group_id/subject_user_id/subject_group_id 四擇一）"})
	CodeScopeActorInvalid  = register("VALIDATION_APPROVER_SCOPE_ACTOR", Descriptor{ZhFallback: "審核方必須恰一（approver_id/approver_group_id 二擇一）"})
)

// --- INTERNAL_*（action-scoped 泛化 5xx）---
var (
	CodeInternalAccessRequestCreate  = register("INTERNAL_ACCESS_REQUEST_CREATE", Descriptor{ZhFallback: "建立連線申請失敗"})
	CodeInternalAccessRequestCancel  = register("INTERNAL_ACCESS_REQUEST_CANCEL", Descriptor{ZhFallback: "撤回連線申請失敗"})
	CodeInternalAccessRequestApprove = register("INTERNAL_ACCESS_REQUEST_APPROVE", Descriptor{ZhFallback: "核准連線申請失敗"})
	CodeInternalAccessRequestReject  = register("INTERNAL_ACCESS_REQUEST_REJECT", Descriptor{ZhFallback: "拒絕連線申請失敗"})
	CodeInternalBreakGlassSubmit     = register("INTERNAL_BREAK_GLASS_SUBMIT", Descriptor{ZhFallback: "破窗緊急連線失敗"})
	CodeInternalAccessTicketRevoke   = register("INTERNAL_ACCESS_TICKET_REVOKE", Descriptor{ZhFallback: "撤銷臨時授權失敗"})
	CodeInternalBreakGlassReview     = register("INTERNAL_BREAK_GLASS_REVIEW", Descriptor{ZhFallback: "補審破窗連線失敗"})

	CodeInternalAccessRequestMineQuery    = register("INTERNAL_ACCESS_REQUEST_MINE_QUERY", Descriptor{ZhFallback: "查詢我的申請失敗"})
	CodeInternalAccessTicketQuery         = register("INTERNAL_ACCESS_TICKET_QUERY", Descriptor{ZhFallback: "查詢有效臨時授權失敗"})
	CodeInternalAccessRequestPendingQuery = register("INTERNAL_ACCESS_REQUEST_PENDING_QUERY", Descriptor{ZhFallback: "查詢待審申請失敗"})
	CodeInternalAccessRequestPendingCount = register("INTERNAL_ACCESS_REQUEST_PENDING_COUNT", Descriptor{ZhFallback: "查詢待審計數失敗"})
	CodeInternalBreakGlassReviewCount     = register("INTERNAL_BREAK_GLASS_REVIEW_COUNT", Descriptor{ZhFallback: "查詢待補審計數失敗"})
	CodeInternalAccessRequestHistoryQuery = register("INTERNAL_ACCESS_REQUEST_HISTORY_QUERY", Descriptor{ZhFallback: "查詢申請歷史失敗"})
	CodeInternalBreakGlassReviewQuery     = register("INTERNAL_BREAK_GLASS_REVIEW_QUERY", Descriptor{ZhFallback: "查詢待補審破窗單失敗"})

	CodeInternalApproverScopeQuery  = register("INTERNAL_APPROVER_SCOPE_QUERY", Descriptor{ZhFallback: "查詢審核範圍失敗"})
	CodeInternalApproverScopeCreate = register("INTERNAL_APPROVER_SCOPE_CREATE", Descriptor{ZhFallback: "分配審核範圍失敗"})
	CodeInternalApproverScopeDelete = register("INTERNAL_APPROVER_SCOPE_DELETE", Descriptor{ZhFallback: "移除審核範圍失敗"})

	CodeInternalAccessMatrixQuery       = register("INTERNAL_ACCESS_MATRIX_QUERY", Descriptor{ZhFallback: "查詢存取矩陣失敗"})
	CodeInternalAccessReviewQuery       = register("INTERNAL_ACCESS_REVIEW_QUERY", Descriptor{ZhFallback: "查詢複審歷史失敗"})
	CodeInternalAccessReviewLastQuery   = register("INTERNAL_ACCESS_REVIEW_LAST_QUERY", Descriptor{ZhFallback: "查詢上次複審失敗"})
	CodeInternalAccessReviewDetailQuery = register("INTERNAL_ACCESS_REVIEW_DETAIL_QUERY", Descriptor{ZhFallback: "查詢複審詳情失敗"})
	CodeInternalAccessReviewCreate      = register("INTERNAL_ACCESS_REVIEW_CREATE", Descriptor{ZhFallback: "建立複審紀錄失敗"})
	// 快照損壞是策劃過的 sentinel（可安全回顯的具體原因），與泛化 500 區隔。
	CodeAccessReviewSnapshotCorrupted = register("INTERNAL_ACCESS_REVIEW_SNAPSHOT_CORRUPTED", Descriptor{ZhFallback: "複審快照損壞，無法解析"})

	CodeInternalDailyReviewStatusQuery = register("INTERNAL_DAILY_REVIEW_STATUS_QUERY", Descriptor{ZhFallback: "取得審閱狀態失敗"})
	CodeInternalDailyReviewSign        = register("INTERNAL_DAILY_REVIEW_SIGN", Descriptor{ZhFallback: "簽核失敗"})
	CodeInternalDailyReviewListQuery   = register("INTERNAL_DAILY_REVIEW_LIST_QUERY", Descriptor{ZhFallback: "查詢簽核歷史失敗"})
)
