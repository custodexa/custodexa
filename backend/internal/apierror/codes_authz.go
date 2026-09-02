package apierror

// 本檔專收 internal/api/{authorization_handler,user_group_handler,role_handler}.go
// 的新碼；复用既有碼（AUTH_UNAUTHENTICATED、VALIDATION_BAD_REQUEST、
// VALIDATION_BAD_PARAMS、AUTH_USER_NOT_FOUND、NOTFOUND_ASSET、
// INTERNAL_ROLE_QUERY、VALIDATION_INVALID_ID）直接沿用 codes.go，不重複註冊。

// grantEntityZhLabels 是授權建立/批次建立引用完整性檢查涉及的四種實體
// （主體：user/user_group；客體：asset/asset_group）的 zh 顯示字。
var grantEntityZhLabels = map[string]string{
	"user":        "用戶",
	"user_group":  "使用者群組",
	"asset":       "資產",
	"asset_group": "資產分組",
}

// queryFieldZhLabels 是查詢參數驗證錯誤涉及的欄位（List 的 XOR 篩選、
// EffectiveAssets/EffectiveUsers 的必要參數）zh 顯示字。前端 PARAM_ENUM_GETTERS
// 尚無 "field" getter（待補，見 pending decision）；code-aware 路徑目前會顯示
// 原始 key（如 "user_id"），不影響後端 fallback 正確性。
var queryFieldZhLabels = map[string]string{
	"user_id":       "使用者 ID",
	"user_group_id": "使用者群組 ID",
	"asset_id":      "資產 ID",
	"node_id":       "節點 ID",
	// 稽核調查工作台（auditor-workbench）：復用本泛用碼而不另立四個新碼——
	// 新碼須同步三語 locale 檔（同期另有兩個 change 在動同一批檔），
	// 而這四種失敗本質上是同一件事「查詢參數值不合法」
	"subject": "調查樞紐",
	"range":   "時間窗",
	"types":   "事件類別",
	"cursor":  "分頁游標",
	// 稽核證據匯出：同樣復用本泛用碼。
	// 這三個欄位原本解析失敗是**靜默丟棄**的，等於把打錯字的查詢當成
	// 「沒帶這個條件」照樣匯出——受害者拿到的是一包範圍不同、卻看不出異狀的證據
	"session_id": "連線 ID",
	"start_time": "起始時間",
	"end_time":   "結束時間",
	// 匯出包型：證據包也吃樞紐後，
	// subject 不再分辨得出包型，故包型改由 pack 明示；打錯字不得被當成缺席
	"pack": "匯出包型",
	// 工作單清單的種類欄：閉集外的值不得被當成缺席，且錯誤訊息要指得出是哪個參數
	"kind": "工作單種類",
}

// --- authorization_handler.go: Create ---
var (
	CodeGrantSubjectXOR = register("VALIDATION_GRANT_SUBJECT_XOR", Descriptor{
		ZhFallback: "user_id 與 user_group_id 必須二擇一"})
	CodeGrantObjectXOR = register("VALIDATION_GRANT_OBJECT_XOR", Descriptor{
		ZhFallback: "asset_id 與 asset_group_id 必須二擇一"})
	// CodeInvalidGrantSubject 對應 authz.ErrInvalidGrantSubject（errors.Is 映射）
	CodeInvalidGrantSubject = register("VALIDATION_INVALID_GRANT_SUBJECT", Descriptor{
		ZhFallback: "授權主體與客體必須各恰一（user_id/user_group_id 二擇一、asset_id/asset_group_id 二擇一）"})
	// CodeAuthorizationExists 對應 authz.ErrAuthorizationExists
	CodeAuthorizationExists = register("CONFLICT_AUTHORIZATION_EXISTS", Descriptor{
		ZhFallback: "授權已存在"})
	// CodeGrantReferenceNotFound 對應 Grant() 內「主體/客體引用不存在」（單筆）；
	// entity 由 handler 對 err.Error() 做子字串判定後帶入（service 未曝露 sentinel，
	// 僅 fmt.Errorf 動態訊息，handler 不擁有 service 檔無法補 sentinel）。
	CodeGrantReferenceNotFound = register("NOTFOUND_GRANT_REFERENCE", Descriptor{
		ZhFallback: "{entity}不存在",
		Params:     []ParamSpec{{Key: "entity", Kind: ParamEnum, EnumNS: "grantEntity", ZhLabels: grantEntityZhLabels}},
	})
	CodeInternalAuthorizationCreate = register("INTERNAL_AUTHORIZATION_CREATE", Descriptor{ZhFallback: "建立授權失敗"})
)

// --- authorization_handler.go: BatchCreate ---
var (
	// CodeBatchEmpty 對應 authz.ErrBatchEmpty
	CodeBatchEmpty = register("VALIDATION_BATCH_EMPTY", Descriptor{
		ZhFallback: "批次授權須至少各含一個主體（使用者或群組）與客體（資產或資產組）"})
	// CodeBatchTooLarge 對應 authz.ErrBatchTooLarge；limit=authz.MaxBatchExpansion
	CodeBatchTooLarge = register("VALIDATION_BATCH_TOO_LARGE", Descriptor{
		ZhFallback: "批次授權展開筆數超過上限 {limit}，請縮小範圍",
		Params:     []ParamSpec{{Key: "limit", Kind: ParamInt}},
	})
	// CodeBatchReferenceNotFound 對應 validateBatchRefs()「XX 名單含不存在的 ID」（複數/名單語意，
	// 措辭與單筆 NOTFOUND_GRANT_REFERENCE 不同，故另開一碼）
	CodeBatchReferenceNotFound = register("NOTFOUND_BATCH_GRANT_REFERENCE", Descriptor{
		ZhFallback: "{entity}名單含不存在的 ID",
		Params:     []ParamSpec{{Key: "entity", Kind: ParamEnum, EnumNS: "grantEntity", ZhLabels: grantEntityZhLabels}},
	})
	CodeInternalAuthorizationBatchGrant = register("INTERNAL_AUTHORIZATION_BATCH_GRANT", Descriptor{ZhFallback: "批次授權失敗"})
)

// --- authorization_handler.go: Delete ---
var (
	// CodeInvalidAuthorizationID 不走 VALIDATION_INVALID_ID 複用：
	// "authorization" 尚未在前端 audit-enums 的 resource 值域中（本 change 禁動
	// frontend，待裁決另補），獨立碼可不依賴該值域。
	CodeInvalidAuthorizationID = register("VALIDATION_INVALID_AUTHORIZATION_ID", Descriptor{ZhFallback: "無效的授權 ID"})
	// CodeAuthorizationNotFound 對應 authz.ErrAuthorizationNotFound
	CodeAuthorizationNotFound = register("NOTFOUND_AUTHORIZATION", Descriptor{ZhFallback: "授權不存在"})
	// CodeTicketRevocationRequired 對應 authz.ErrTicketRevocationRequired
	CodeTicketRevocationRequired = register("CONFLICT_TICKET_REVOCATION_REQUIRED", Descriptor{
		ZhFallback: "臨時授權須經申請單撤銷流處理，不可直接刪除"})
	CodeInternalAuthorizationRevoke = register("INTERNAL_AUTHORIZATION_REVOKE", Descriptor{ZhFallback: "撤銷授權失敗"})
)

// --- authorization_handler.go: 帳號範圍---
var (
	// CodeAccountScopeInvalid 對應 authz.ErrAccountScopeInvalid。
	// 不回填違規的 username：帳號名是請求方可控輸入，apierror 的 params 僅收
	// 受控 enum/int（見 codes_asset_account.go 同段理由）
	CodeAccountScopeInvalid = register("VALIDATION_ACCOUNT_SCOPE_INVALID", Descriptor{
		ZhFallback: "帳號範圍不合法（不得為空清單、全空白項或含控制字元、冒號）"})
	// CodeAccountScopeRequired 對應 authz.ErrAccountScopeRequired：
	// PUT .../accounts 未提供 accounts 欄。不與 INVALID 併為一碼——
	// 「你沒給」與「你給的不合法」對前端是不同的修正動作
	CodeAccountScopeRequired = register("VALIDATION_ACCOUNT_SCOPE_REQUIRED", Descriptor{
		ZhFallback: "必須顯式提供帳號範圍（要全部帳號請送 [\"@ALL\"]）"})
	// CodeTicketAccountScopeImmutable 對應 authz.ErrTicketAccountScopeImmutable：
	// 臨時授權的帳號範圍源自申請單，於授權管理頁改等於繞過申請與核准的一致性
	CodeTicketAccountScopeImmutable = register("CONFLICT_TICKET_ACCOUNT_SCOPE_IMMUTABLE", Descriptor{
		ZhFallback: "臨時授權的帳號範圍由申請單決定，不可直接調整"})
	CodeInternalAuthorizationUpdate = register("INTERNAL_AUTHORIZATION_UPDATE", Descriptor{
		ZhFallback: "更新授權失敗"})
)

// --- authorization_handler.go: List / EffectiveAssets / EffectiveUsers ---
var (
	CodeAuthFilterXOR = register("VALIDATION_AUTH_FILTER_XOR", Descriptor{
		ZhFallback: "user_id、user_group_id、asset_id、node_id 至多指定一個"})
	// CodeInvalidQueryParam 泛用查詢參數驗證失敗；field 為受控 enum（見 queryFieldZhLabels）
	CodeInvalidQueryParam = register("VALIDATION_INVALID_QUERY_PARAM", Descriptor{
		ZhFallback: "無效的 {field}",
		Params:     []ParamSpec{{Key: "field", Kind: ParamEnum, EnumNS: "field", ZhLabels: queryFieldZhLabels}},
	})
	CodeInvalidValidityFilter = register("VALIDATION_INVALID_VALIDITY_FILTER", Descriptor{
		ZhFallback: "無效的 validity（active/scheduled/expired）"})
	CodeInvalidSourceFilter = register("VALIDATION_INVALID_SOURCE_FILTER", Descriptor{
		ZhFallback: "無效的 source（manual/ticket）"})
	CodeInternalAuthorizationQuery = register("INTERNAL_AUTHORIZATION_QUERY", Descriptor{ZhFallback: "查詢授權失敗"})
	// CodeInternalAuthorizationEffective 供 EffectiveAssets 與 EffectiveUsers 共用
	CodeInternalAuthorizationEffective = register("INTERNAL_AUTHORIZATION_EFFECTIVE", Descriptor{ZhFallback: "查詢有效權限失敗"})
)

// --- user_group_handler.go ---
var (
	// CodeUserGroupNameExists 對應 identity.ErrUserGroupNameExists
	CodeUserGroupNameExists = register("CONFLICT_USER_GROUP_NAME_EXISTS", Descriptor{ZhFallback: "使用者群組名稱已存在"})
	// CodeUserGroupNotFound 對應 identity.ErrUserGroupNotFound
	CodeUserGroupNotFound = register("NOTFOUND_USER_GROUP", Descriptor{ZhFallback: "使用者群組不存在"})
	// CodeUserGroupMemberNotFound 對應 identity.ErrUserGroupMemberNotFound
	CodeUserGroupMemberNotFound = register("VALIDATION_USER_GROUP_MEMBER_NOT_FOUND", Descriptor{ZhFallback: "成員名單含不存在的使用者"})

	CodeInternalUserGroupQuery         = register("INTERNAL_USER_GROUP_QUERY", Descriptor{ZhFallback: "查詢使用者群組失敗"})
	CodeInternalUserGroupCreate        = register("INTERNAL_USER_GROUP_CREATE", Descriptor{ZhFallback: "建立使用者群組失敗"})
	CodeInternalUserGroupUpdate        = register("INTERNAL_USER_GROUP_UPDATE", Descriptor{ZhFallback: "更新使用者群組失敗"})
	CodeInternalUserGroupDelete        = register("INTERNAL_USER_GROUP_DELETE", Descriptor{ZhFallback: "刪除使用者群組失敗"})
	CodeInternalUserGroupMembersUpdate = register("INTERNAL_USER_GROUP_MEMBERS_UPDATE", Descriptor{ZhFallback: "更新群組成員失敗"})
	CodeInternalUserGroupAuthCount     = register("INTERNAL_USER_GROUP_AUTH_COUNT", Descriptor{ZhFallback: "查詢群組授權數失敗"})
)
