package apierror

// 連線端點（internal/sshproxy、internal/proxy）的 HTTP JSON 出口碼。
//
// 分檔理由同 codes_stream.go：同一 registry，只為並行開發隔離——codes.go 是
// internal/api 大掃除的地盤，本檔專收兩個連線 handler 的 HTTP 出口。
// 串流幀（MsgError/MsgNotice）與連線決策閘的碼在 codes_stream.go，不重複。
//
// ZhFallback 逐字沿用遷移前的 c.JSON 文案（bijection 測試釘 zh-TW == ZhFallback）；
// 少數合併多站點的碼（會話 ID、分享擁有者）取語義涵蓋兩者的措辭，於註解標記。

// --- AUTH_*（連線 token 兌換與授權邊界）---
var (
	CodeConnectTokenMissing = register("AUTH_CONNECT_TOKEN_MISSING", Descriptor{
		ZhFallback: "缺少 connect_token，請經由簽發端點建立連線"})
	CodeConnectTokenInvalid = register("AUTH_CONNECT_TOKEN_INVALID", Descriptor{
		ZhFallback: "連線 token 無效或已使用"})
	// CodeConnectionNotAuthorized 對應 identity.ErrConnectionNotAuthorized
	// （一般 API token 拿來建連線）。
	CodeConnectionNotAuthorized = register("AUTH_CONNECTION_NOT_AUTHORIZED", Descriptor{
		ZhFallback: "此 token 不可用於建立連線"})
	CodeAssetConnectDenied = register("AUTH_ASSET_CONNECT_DENIED", Descriptor{
		ZhFallback: "您沒有連線此資產的權限，請聯繫管理員"})
	CodeMonitorRoleRequired = register("AUTH_MONITOR_ROLE_REQUIRED", Descriptor{
		ZhFallback: "僅管理員與稽核員可監看會話"})
	CodeSessionStatsDenied = register("AUTH_SESSION_STATS_DENIED", Descriptor{
		ZhFallback: "您沒有檢視此會話指標的權限"})
	// CodeSessionShareOwnerOnly 合併「建立分享」與「撤銷分享」兩站點：
	// 兩者的使用者處置完全相同（不是會話擁有者，換人操作），故共用一碼。
	CodeSessionShareOwnerOnly = register("AUTH_SESSION_SHARE_OWNER_ONLY", Descriptor{
		ZhFallback: "僅會話擁有者可管理分享"})
)

// --- VALIDATION_*（請求參數）---
var (
	// CodeInvalidSessionID 合併「無效的會話 ID」與「無效的 Session ID」
	// （monitor / stats / share 三處原文案僅用詞不同，語義同一）。
	CodeInvalidSessionID = register("VALIDATION_INVALID_SESSION_ID", Descriptor{
		ZhFallback: "無效的會話 ID"})
	CodeTerminalColsInvalid = register("VALIDATION_TERMINAL_COLS", Descriptor{
		ZhFallback: "缺少或無效的 cols"})
	CodeTerminalRowsInvalid = register("VALIDATION_TERMINAL_ROWS", Descriptor{
		ZhFallback: "缺少或無效的 rows"})
	CodeK8sPodRequired = register("VALIDATION_K8S_POD_REQUIRED", Descriptor{
		ZhFallback: "請先選擇要連線的 pod"})
)

// --- NOTFOUND_* ---
var (
	// CodeAssetCredentialUnavailable 兌換點取資產＋憑證失敗：不分「資產不存在」
	// 與「憑證讀取失敗」（不對外洩漏資產存在性）。
	CodeAssetCredentialUnavailable = register("NOTFOUND_ASSET_CREDENTIAL", Descriptor{
		ZhFallback: "資產不存在或憑證讀取失敗"})
	// 會話不存在（monitor/stats/share 三處）复用 codes_audit.go 的
	// CodeSessionNotFound（NOTFOUND_SESSION，ZhFallback「Session 不存在」）——
	// 同一事實不重複配碼，故本檔不另宣告。
	// CodeShareNotFound 合併「分享不存在或已過期」（加入端）與
	// 「此會話沒有有效分享」（撤銷端）：同一事實的兩個入口。
	CodeShareNotFound = register("NOTFOUND_SESSION_SHARE", Descriptor{
		ZhFallback: "分享不存在或已過期"})
)

// --- RULE_*（可預期的連線業務規則攔截）---
var (
	CodeAssetNotTextTerminal = register("RULE_ASSET_NOT_TEXT_TERMINAL", Descriptor{
		ZhFallback: "此資產不是文字終端類協議"})
	CodeK8sOneShotDisabled = register("RULE_K8S_ONESHOT_DISABLED", Descriptor{
		ZhFallback: "one-shot 單指令模態尚未開放"})
	CodeSessionMonitorNotActive = register("RULE_SESSION_MONITOR_NOT_ACTIVE", Descriptor{
		ZhFallback: "僅進行中的文字終端會話可監看"})
	CodeSessionShareNotActive = register("RULE_SESSION_SHARE_NOT_ACTIVE", Descriptor{
		ZhFallback: "僅進行中的會話可分享"})
	// CodeSessionNotOnline 會話不在本實例的活躍連線表內（HTTP 404 語義不變）。
	CodeSessionNotOnline = register("RULE_SESSION_NOT_ONLINE", Descriptor{
		ZhFallback: "會話不在線上"})
	CodeStatsUnsupported = register("RULE_STATS_UNSUPPORTED", Descriptor{
		ZhFallback: "目標主機不支援指標採集"})
	// CodeConnectTargetParamsRejected 連線收口防呆：URL 帶 hostname/password 直接拒。
	CodeConnectTargetParamsRejected = register("RULE_CONNECT_TARGET_PARAMS_REJECTED", Descriptor{
		ZhFallback: "不接受連線目標參數：連線一律以資產為入口，請經由簽發端點建立連線"})
	CodeSSHEndpointMoved = register("RULE_SSH_ENDPOINT_MOVED", Descriptor{
		ZhFallback: "SSH 不再經由此端點，請使用原生終端端點 GET /api/v1/ssh"})
	// CodeConnectTokenCapacity 未兌換的連線 token 已達上限（全域或該使用者），
	// 本次拒發（503）。**不回填任何門檻或當前用量**：同 AUTH_OIDC_RATE_LIMITED
	// 的理由，那些數字讓攻擊者能把流量精確調到門檻之下持續佔用，正當使用者
	// 只需要知道稍後再試（成因細節僅落伺服端日誌）
	CodeConnectTokenCapacity = register("RULE_CONNECT_TOKEN_CAPACITY", Descriptor{
		ZhFallback: "連線簽發暫時達到上限，請稍後再試"})
)

// --- RULE_TRANSMISSION_* / RULE_CONSENT_*（傳輸安全閘與同意立據）---
//
// 傳輸閘的回應除 error/code 外仍帶 channel/level/risks **機器欄**（前端 connect.js
// 依 428 與 risks 陣列彈同意對話框），經 ErrorResponse.Meta 平鋪回封套 top-level，
// 欄位名與值一字不改。
var (
	CodeTransmissionStrictReject = register("RULE_TRANSMISSION_STRICT_REJECT", Descriptor{
		ZhFallback: "傳輸安全政策（嚴格）拒絕連線：資產傳輸設定不符要求"})
	CodeTransmissionConsentRequired = register("RULE_TRANSMISSION_CONSENT_REQUIRED", Descriptor{
		ZhFallback: "連線前需確認傳輸風險"})
	// 以下三碼對應 service 的同意立據 sentinel（ZhFallback 逐字同 sentinel 文案）。
	CodeConsentRisksChanged = register("RULE_CONSENT_RISKS_CHANGED", Descriptor{
		ZhFallback: "風險項已變更，請重新確認"})
	CodeConsentNoRisks = register("RULE_CONSENT_NO_RISKS", Descriptor{
		ZhFallback: "資產目前無傳輸風險項，無需同意"})
	CodeConsentNotApplicable = register("RULE_CONSENT_NOT_APPLICABLE", Descriptor{
		ZhFallback: "目前政策檔位不受理連線同意"})
)

// --- INTERNAL_*（5xx／服務未啟用；原因僅落伺服端 log）---
var (
	CodeInternalPermissionCheck = register("INTERNAL_PERMISSION_CHECK", Descriptor{
		ZhFallback: "權限檢查失敗"})
	CodeInternalAccessPolicyCheck = register("INTERNAL_ACCESS_POLICY_CHECK", Descriptor{
		ZhFallback: "存取政策檢查失敗"})
	CodeInternalSessionShareCreate = register("INTERNAL_SESSION_SHARE_CREATE", Descriptor{
		ZhFallback: "建立分享失敗"})
	CodeInternalConnectTokenIssue = register("INTERNAL_CONNECT_TOKEN_ISSUE", Descriptor{
		ZhFallback: "簽發連線 token 失敗"})
	CodeInternalConsentRecord = register("INTERNAL_CONSENT_RECORD", Descriptor{
		ZhFallback: "同意記錄寫入失敗"})
	// CodeTransmissionUnavailable 503：組裝端未注入傳輸安全服務。
	CodeTransmissionUnavailable = register("INTERNAL_TRANSMISSION_UNAVAILABLE", Descriptor{
		ZhFallback: "傳輸安全服務未啟用"})
)
