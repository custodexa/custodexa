package authcontext

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// 認證脈絡貫穿點清冊與守衛。
//
// 背景：監看、分享與 IssueSessionResponse 的同一類缺口連續多次靠人工
// 審查才發現，說明「貫穿點清單不完整」是機制問題而非個案。本守衛比照
// envelopeMigrationTargets／envelope_targets_guard_test.go 的形狀，把「哪些位置
// 必須攜帶或驗證認證脈絡」變成宣告式清冊，並以 AST 掃描擋住未登記的新呼叫點。
//
// 判定方向為**單向**：只斷言「沒有未登記的呼叫點」，**不反向斷言「登記項都存在」**。
// 理由：exchange／callback／ticket 等點分批交付，雙向斷言會使早批當場紅；且清冊
// 允許超前登記尚未存在的位置（登記多了不會紅）。
//
// 掃描範圍為 backend/ 全樹的非測試 Go 檔（_test.go 排除——測試自造的簽發呼叫
// 不是產品路徑，納入只會製造噪音）。
//
// 同名但語義無關的方法（strings.Join、db.Begin、hostKeys.Callback……）以
// authContextHomonyms 顯式承認例外，比照 knownNonEncColumns 的做法：例外必須寫出來，
// 守衛才不會因「無法辨識」而靜默放行。

// authContextTouchpoint 清冊項：一個必須攜帶／驗證認證脈絡的呼叫點。
//
// 判定鍵為 (symbol, file, fn)；count 為該函式內允許的呼叫次數。實際次數超過
// count 即視為出現未登記的新呼叫點（同一函式內複製一行也擋得住）。
type authContextTouchpoint struct {
	symbol string // 被呼叫的符號名（函式名，或方法選擇器的方法名）
	file   string // 相對 backend/ 的檔案路徑
	fn     string // 所在函式（方法記為 Type.Method；檔案層級初始化記為 <file-scope>）
	count  int    // 該函式內的呼叫次數上限
	source string // 脈絡來源／用途（每一項都必須含函式與脈絡來源）
}

// authContextTouchpoints 認證脈絡貫穿點清冊。
//
// 新增任何簽發／驗證／換發／訂閱路徑時，必須在此登記其呼叫點並寫明脈絡來源；
// 未登記者由 TestAuthContextTouchpointsGuard 擋下。
//
// 清單可超前登記尚未存在的位置（單向判定，登記多了不會紅）——分批交付時，
// 後批才出現的貫穿點可先寫進來備查。
var authContextTouchpoints = []authContextTouchpoint{
	// ── 簽發側：JWT ─────────────────────────────────────────────
	{symbol: "GenerateToken", file: "internal/modules/identity/auth_service.go", fn: "AuthService.buildLoginResponse", count: 1,
		source: "呼叫端傳入的 crypto.AuthContext（登入／MFA 完成／換發皆經此收口）"},
	{symbol: "GenerateTokenNotAfter", file: "internal/modules/identity/auth_refresh_service.go", fn: "AuthService.RefreshSession", count: 1,
		source: "refresh 列自身的 auth_method/provider_id/auth_epoch/cred_epoch（**不現查**：" +
			"交易內剛驗過，現查會在競態下把舊能力洗白，F-C）；到期以 refresh 列 expires_at 裁切（4.12）"},
	{symbol: "GenerateScopedToken", file: "internal/modules/identity/auth_service.go", fn: "AuthService.Login", count: 2,
		source: "buildAuthContext（本地／LDAP 登入的 MFA pending 與 enrollment scoped token）"},
	{symbol: "GenerateScopedToken", file: "internal/modules/identity/auth_service.go", fn: "AuthService.LoginWithExternalIdentity", count: 2,
		source: "OIDC 登入的 MFA pending 與 enrollment scoped token（脈絡自 provider 帶入）"},
	{symbol: "GenerateScopedToken", file: "internal/modules/identity/auth_service.go", fn: "AuthService.finishLogin", count: 1,
		source: "強制改密 scoped token；脈絡沿用本次登入的 authCtx"},
	{symbol: "issueRefreshToken", file: "internal/modules/identity/auth_service.go", fn: "AuthService.buildLoginResponse", count: 1,
		source: "authCtx 寫入 refresh_tokens 四欄，供輪替與換發沿用"},

	// ── 簽發側：脈絡組裝與登入收口 ───────────────────────────────
	{symbol: "buildAuthContext", file: "internal/modules/identity/auth_service.go", fn: "AuthService.Login", count: 1,
		source: "本地／LDAP：method 由 verifyCredentials 分派，providerID=0，世代現查 DB"},
	{symbol: "buildAuthContext", file: "internal/modules/identity/auth_service.go", fn: "AuthService.IssueSessionResponse", count: 1,
		source: "改密後換發：method/providerID 自 scoped token 繼承，世代必須現查（繼承舊值會卡在改密迴圈）"},
	{symbol: "buildAuthContext", file: "internal/modules/identity/auth_mfa_service.go", fn: "AuthService.finishLoginCarryingContext", count: 1,
		source: "scoped token 的 claims.EffectiveMethod()/ProviderID，世代現查。**VerifyMFALogin 與 " +
			"CompleteEnrollment 兩條路徑共用此處**：兩者原本各自呼叫，" +
			"合併後同時回帶認證脈絡供 handler 落審計（spec 要求 MFA 完成路徑保留 provider 標註）"},
	// 註：RefreshSession 已**不再**呼叫 buildAuthContext（F-C：改以 refresh 列自身的
	// 世代簽發，現查會在競態下洗白舊能力）。清冊為單向判定，故此處僅留說明不留登記。
	{symbol: "finishLogin", file: "internal/modules/identity/auth_service.go", fn: "AuthService.Login", count: 1,
		source: "authCtx 由 Login 組裝後貫穿至 buildLoginResponse"},
	{symbol: "finishLogin", file: "internal/modules/identity/auth_service.go", fn: "AuthService.LoginWithExternalIdentity", count: 1,
		source: "OIDC ticket exchange 後的正式會話簽發"},
	{symbol: "finishLogin", file: "internal/modules/identity/auth_mfa_service.go", fn: "AuthService.finishLoginCarryingContext", count: 1,
		source: "buildAuthContext 現場組裝（scoped token 繼承 method/provider）；MFA 驗證完成與強制註冊完成兩條路徑共用"},
	{symbol: "buildLoginResponse", file: "internal/modules/identity/auth_service.go", fn: "AuthService.finishLogin", count: 1,
		source: "登入主路徑；脈絡為參數，零值即代表 local_password"},
	{symbol: "buildLoginResponse", file: "internal/modules/identity/auth_service.go", fn: "AuthService.IssueSessionResponse", count: 1,
		source: "改密換發路徑"},
	{symbol: "IssueSessionResponse", file: "internal/api/auth_handler.go", fn: "AuthHandler.ChangePassword", count: 1,
		source: "scoped token 的 claims.EffectiveMethod()/ProviderID；世代由 service 內部現查"},

	// ── 簽發側：非 JWT 的短期能力（連線／錄影／監看） ─────────────
	{symbol: "IssueConnectToken", file: "internal/sshproxy/handler.go", fn: "Handler.HandleCreateConnectToken", count: 1,
		source: "ConnectTokenManager（接線後方法名對齊 gatewayapi.TokenService，原名 Issue）：" +
			"middleware.GetAuthContext(c) 經 subj 填入 proxy.ConnectGrant"},
	{symbol: "Issue", file: "internal/api/recording_handler.go", fn: "RecordingHandler.IssueRecordingToken", count: 1,
		source: "RecordingTokenManager：middleware.GetAuthContext(c).ProviderID（不得列為例外）"},
	{symbol: "Join", file: "internal/sshproxy/handler.go", fn: "Handler.HandleMonitor", count: 1,
		source: "MonitorHub 監看訂閱：ObserverContext 帶 userID/providerID/世代，供按 provider／user 收線"},
	{symbol: "Join", file: "internal/sshproxy/handler.go", fn: "Handler.HandleShareJoin", count: 1,
		source: "MonitorHub 分享訂閱（權限更低，r8 缺口來源）：同上"},

	// ── 簽發側：OIDC flow state 與 login ticket ──────────────────
	{symbol: "Begin", file: "internal/api/oidc_handler.go", fn: "OIDCHandler.Begin", count: 1,
		source: "建立 flow state：provider 的 auth_epoch 快照入列（begin 時尚未認證，不帶 cred_epoch）"},
	{symbol: "issueTicket", file: "internal/modules/identity/oidc_login_service.go", fn: "OIDCLoginService.callback", count: 1,
		source: "login ticket 是使用者世代的第一個攜帶者（auth_epoch/cred_epoch 皆於此現查寫入）。" +
			"**fn 是小寫的 callback**：外層 Callback 為薄包覆，" +
			"只負責把審計意向掛到結果或錯誤上，流程本體與其世代寫入未變"},

	// ── 驗證側：token 與世代閘 ───────────────────────────────────
	{symbol: "VerifyCredentialGenerationByUserID", file: "internal/middleware/auth.go", fn: "AuthMiddleware", count: 1,
		source: "access token 的 claims.AuthContext 對 DB 現值比對"},
	{symbol: "VerifyCredentialGenerationByUserID", file: "internal/modules/identity/auth_service.go", fn: "AuthService.ValidateConnectionToken", count: 1,
		source: "WS ?token= 旁路（三條路由不掛 middleware，漏此即停用後仍可開監看）"},
	// 兩階段閘序收斂：兩處自 handler.go 的 Handle* 遷入 connect_gates.go 的
	// 閘序宣告（G-S4／G-G5），呼叫本身逐字未改，只是改由 Gate.Eval 承載
	{symbol: "VerifyCredentialGenerationByUserID", file: "internal/sshproxy/connect_gates.go", fn: "Handler.redeemPreResolveGates", count: 1,
		source: "connect token 兌換：grant 內的脈絡對 DB 現值比對（G-S4）"},
	{symbol: "VerifyCredentialGenerationByUserID", file: "internal/proxy/connect_gates.go", fn: "ConnectionHandler.redeemPreResolveGates", count: 1,
		source: "同上（guacamole 協議側兌換，G-G5）"},
	{symbol: "VerifyCredentialGeneration", file: "internal/modules/identity/auth_epoch_gate.go", fn: "AuthService.VerifyCredentialGenerationByUserID", count: 1,
		source: "閘門內部：自行載入 user 後委派"},
	// **已刪除的陳舊登記**：原有一列 {VerifyCredentialGeneration,
	// oidc_login_service.go, OIDCLoginService.Exchange}。反向完備性斷言上線後當場
	// 打出「登記 1 處、實際掃到 0 處」——`Exchange` 走的是交易內版本
	// （下方 VerifyCredentialGenerationTx 那一列），非交易版從未在該函式出現過。
	// 清冊過去是單向判定，故這筆錯誤登記從未讓任何測試轉紅。
	{symbol: "VerifyCredentialGeneration", file: "internal/modules/identity/auth_mfa_service.go", fn: "AuthService.VerifyMFALogin", count: 1,
		source: "MFA pending scoped token 的世代對剛載入的 user 比對（2.8：轉為僅外部登入後不得完成驗證）"},
	{symbol: "VerifyCredentialGenerationByUserID", file: "internal/modules/identity/auth_mfa_service.go", fn: "AuthService.CompleteEnrollment", count: 1,
		source: "enrollment scoped token 的世代現查；置於 EnableMFA 之前，失效憑證不得寫入 TOTP 因子"},
	{symbol: "ValidateConnectionToken", file: "internal/modules/identity/auth_service.go", fn: "AuthService.VerifySession", count: 1,
		source: "gatewayapi.SessionVerifier 的實作出口（閘道接線）：判定本體即 ValidateConnectionToken，" +
			"本方法只做 claims → gatewayapi.Principal 的欄位對映，不新增亦不放寬任何判定"},
	{symbol: "VerifySession", file: "internal/sshproxy/handler.go", fn: "Handler.authenticate", count: 1,
		source: "WS 連線認證出口（只經 gatewayapi.SessionVerifier 介面消費，" +
			"判定本體仍是 ValidateConnectionToken）；驗過的認證脈絡由本函式 c.Set(\"authContext\", …) " +
			"寫入 gin context——`?token=` 分支上它是唯一寫入者，下游 HandleMonitor／HandleShareJoin " +
			"的 middleware.GetAuthContext(c) 全靠這一步（方向性由 authContextWriterSites 斷言）"},
	{symbol: "RefreshSession", file: "internal/api/auth_handler.go", fn: "AuthHandler.Refresh", count: 1,
		source: "refresh 換發入口；脈絡自 refresh 列讀出、世代現查"},

	// ── 驗證側：一次性能力兌換 ───────────────────────────────────
	{symbol: "RedeemConnectTokenWithReason", file: "internal/sshproxy/handler.go", fn: "Handler.HandleSSH", count: 1,
		source: "ConnectTokenManager 兌換（接線後方法名對齊 gatewayapi.TokenService，原名 Resolve）：" +
			"取出 grant 後須複查 provider 啟用與世代。此處呼叫帶原因的版本——" +
			"**判定本體逐字不變**（RedeemConnectToken 即以本方法實作），多回傳的原因只供審計分辨" +
			"票證無效／過期；對外回應仍收斂為同一則「token 無效」，不給票證存在性探測面"},
	{symbol: "RedeemConnectTokenWithReason", file: "internal/proxy/connect_token.go", fn: "ConnectTokenManager.RedeemConnectToken", count: 1,
		source: "**同一份判定的唯一實作**：RedeemConnectToken 即以本方法實作，故兩條兌換路徑" +
			"不可能分化成「回應說無效、審計說過期」。本列釘住那個委派仍在——被拆成兩份實作時轉紅"},
	{symbol: "RedeemConnectTokenWithReason", file: "internal/proxy/handler.go", fn: "ConnectionHandler.HandleConnect", count: 1,
		source: "同上（guacamole 協議側）。此處呼叫帶原因的版本——" +
			"**判定本體逐字不變**（RedeemConnectToken 即以本方法實作），多回傳的原因只供審計" +
			"分辨票證無效／過期；對外回應仍收斂為同一則「token 無效」，不給票證存在性探測面"},
	{symbol: "Resolve", file: "internal/api/recording_handler.go", fn: "RecordingHandler.StreamRecordingByToken", count: 1,
		source: "RecordingTokenManager 兌換：失效採直接撤銷（RevokeByUser／RevokeByProvider），非世代比對"},
	{symbol: "Resolve", file: "internal/sshproxy/handler.go", fn: "Handler.HandleShareJoin", count: 1,
		source: "分享碼兌換：兌換後的訂閱脈絡取自 GetAuthContext，非分享碼本身"},

	// ── 驗證側：OIDC 流程出入口 ──────────────────────────────────
	{symbol: "Callback", file: "internal/api/oidc_handler.go", fn: "OIDCHandler.Callback", count: 1,
		source: "flow state 原子 consume ＋ provider 世代比對後才簽 ticket"},
	{symbol: "Exchange", file: "internal/api/oidc_handler.go", fn: "OIDCHandler.Exchange", count: 1,
		source: "ticket 兌換正式會話：binding 驗證＋世代比對＋原子 consume"},
	{symbol: "consumeFlowState", file: "internal/modules/identity/oidc_login_service.go", fn: "OIDCLoginService.callback", count: 1,
		source: "flow state 的唯一消費點（未過期才成立，一次性）。fn 改名理由同 issueTicket 那一列"},

	// ── 驗證側：路由掛載認證中介層 ───────────────────────────────
	// 以下每項皆為「該路由群組經 AuthMiddleware 驗證 access token 與世代」；
	// 脈絡來源一律為 JWT claims，由中介層寫入 gin context 供下游簽發點取用。
	// 新增路由群組時須在此登記——登記動作本身即是「這組路由要不要掛認證」的覆核點。
	{symbol: "AuthMiddleware", file: "cmd/server/main.go", fn: "registerRoutes", count: 5},
	{symbol: "AuthMiddleware", file: "internal/api/access_request_handler.go", fn: "AccessRequestHandler.RegisterRoutes", count: 2},
	{symbol: "AuthMiddleware", file: "internal/api/access_review_handler.go", fn: "AccessReviewHandler.RegisterRoutes", count: 1},
	{symbol: "AuthMiddleware", file: "internal/api/alert_rule_handler.go", fn: "AlertRuleHandler.RegisterRoutes", count: 1},
	{symbol: "AuthMiddleware", file: "internal/api/asset_account_handler.go", fn: "AssetAccountHandler.RegisterRoutes", count: 1},
	{symbol: "AuthMiddleware", file: "internal/api/asset_group_handler.go", fn: "AssetGroupHandler.RegisterRoutes", count: 1},
	{symbol: "AuthMiddleware", file: "internal/api/asset_handler.go", fn: "AssetHandler.RegisterRoutes", count: 1},
	{symbol: "AuthMiddleware", file: "internal/api/audit_export_handler.go", fn: "AuditExportHandler.RegisterRoutes", count: 1},
	{symbol: "AuthMiddleware", file: "internal/api/audit_checkpoint_handler.go", fn: "AuditCheckpointHandler.RegisterRoutes", count: 1},
	{symbol: "AuthMiddleware", file: "internal/api/audit_failure_handler.go", fn: "AuditFailureHandler.RegisterRoutes", count: 1},
	{symbol: "AuthMiddleware", file: "internal/api/audit_integrity_handler.go", fn: "AuditIntegrityHandler.RegisterRoutes", count: 1},
	{symbol: "AuthMiddleware", file: "internal/api/audit_log_handler.go", fn: "AuditLogHandler.RegisterRoutes", count: 1},
	// auditor-workbench：時間軸／主體兩支端點一次橫跨六類審計資料，是全站可讀範圍最寬的
	// 讀取面之一。漏掛（或漏登記後被人取下）＝稽核資料以匿名身分全站可讀，且該路徑簽發／
	// 使用的憑證對 provider 停用與使用者憑證世代免疫。此處另以 RequirePermission 無條件疊加。
	{symbol: "AuthMiddleware", file: "internal/api/audit_timeline_handler.go", fn: "AuditTimelineHandler.RegisterRoutes", count: 1},
	{symbol: "AuthMiddleware", file: "internal/api/auth_handler.go", fn: "AuthHandler.RegisterRoutes", count: 2},
	{symbol: "AuthMiddleware", file: "internal/api/authorization_handler.go", fn: "AuthorizationHandler.RegisterRoutes", count: 1},
	{symbol: "AuthMiddleware", file: "internal/api/change_secret_handler.go", fn: "ChangeSecretHandler.RegisterRoutes", count: 2},
	{symbol: "AuthMiddleware", file: "internal/api/clipboard_event_handler.go", fn: "ClipboardEventHandler.RegisterRoutes", count: 1},
	{symbol: "AuthMiddleware", file: "internal/api/command_alert_handler.go", fn: "CommandAlertHandler.RegisterRoutes", count: 1},
	{symbol: "AuthMiddleware", file: "internal/api/daily_review_handler.go", fn: "DailyReviewHandler.RegisterRoutes", count: 1},
	{symbol: "AuthMiddleware", file: "internal/api/export_signing_handler.go", fn: "ExportSigningHandler.RegisterRoutes", count: 1},
	{symbol: "AuthMiddleware", file: "internal/api/host_key_handler.go", fn: "HostKeyHandler.RegisterRoutes", count: 1},
	// 單實例守衛快照：唯讀端點，但它回答「這個部署現在有幾個實例、鎖在誰手上、
	// 持鎖者的指紋是什麼」。漏掛認證＝把部署拓撲與確認碼線索交給匿名探測。
	// 鏈上另以 RequireRole("admin") 疊加。
	{symbol: "AuthMiddleware", file: "internal/api/instance_guard_handler.go", fn: "InstanceGuardHandler.RegisterRoutes", count: 1},
	{symbol: "AuthMiddleware", file: "internal/api/key_management_handler.go", fn: "KeyManagementHandler.RegisterRoutes", count: 1},
	{symbol: "AuthMiddleware", file: "internal/api/ldap_directory_handler.go", fn: "LDAPDirectoryHandler.RegisterRoutes", count: 1},
	{symbol: "AuthMiddleware", file: "internal/api/my_connection_handler.go", fn: "MyConnectionHandler.RegisterRoutes", count: 1},
	{symbol: "AuthMiddleware", file: "internal/api/notification_channel_handler.go", fn: "NotificationChannelHandler.RegisterRoutes", count: 1},
	{symbol: "AuthMiddleware", file: "internal/api/oidc_handler.go", fn: "OIDCHandler.RegisterRoutes", count: 1},
	// 離機儲存設定：端點群組同時承載儲存目的地的讀取、連線測試與寫入。漏掛認證＝
	// 匿名即可讀出備份落在哪個 bucket／endpoint（審計副本的存放位置本身就是攻擊
	// 路線圖），並可改寫目的地把後續離機副本導向外部端點。鏈上另以
	// RequireRole("admin") 疊加。
	{symbol: "AuthMiddleware", file: "internal/api/offsite_storage_handler.go", fn: "OffsiteStorageHandler.RegisterRoutes", count: 1},
	{symbol: "AuthMiddleware", file: "internal/api/recording_handler.go", fn: "RecordingHandler.RegisterRoutes", count: 2},
	{symbol: "AuthMiddleware", file: "internal/api/role_handler.go", fn: "RoleHandler.RegisterRoutes", count: 1},
	{symbol: "AuthMiddleware", file: "internal/api/security_policy_handler.go", fn: "SecurityPolicyHandler.RegisterRoutes", count: 1},
	{symbol: "AuthMiddleware", file: "internal/api/session_command_handler.go", fn: "SessionCommandHandler.RegisterRoutes", count: 2},
	{symbol: "AuthMiddleware", file: "internal/api/session_handler.go", fn: "SessionHandler.RegisterRoutes", count: 1},
	// data-transfer-control 6.2 起為 2 處：檔案端點群組，以及資料傳輸能力查詢端點
	// （`/assets/:id/transfer-capabilities`）。後者雖是唯讀呈現面，仍須掛認證——
	// 它回答「這個人對這台機器能不能傳檔」，無認證即成為授權關係的匿名探測器。
	{symbol: "AuthMiddleware", file: "internal/api/sftp_handler.go", fn: "SFTPHandler.RegisterRoutes", count: 2},
	{symbol: "AuthMiddleware", file: "internal/api/snippet_handler.go", fn: "SnippetHandler.RegisterRoutes", count: 1},
	{symbol: "AuthMiddleware", file: "internal/api/syslog_setting_handler.go", fn: "SyslogSettingHandler.RegisterRoutes", count: 1},
	{symbol: "AuthMiddleware", file: "internal/api/transmission_inventory_handler.go", fn: "TransmissionInventoryHandler.RegisterRoutes", count: 1},
	{symbol: "AuthMiddleware", file: "internal/api/user_group_handler.go", fn: "UserGroupHandler.RegisterRoutes", count: 1},
	{symbol: "AuthMiddleware", file: "internal/api/user_handler.go", fn: "UserHandler.RegisterRoutes", count: 1},

	// ── 失效側：RecordingTokenManager 撤銷與唯讀訂閱收線 ─────────
	// 「哪些事件會撤銷錄影 token／收線訂閱」的單一可查清冊。
	{symbol: "RevokeByUser", file: "internal/modules/identity/external_identity_service.go", fn: "UserService.revokeUserAccess", count: 1,
		source: "credential_epoch 推進後的鎖外收線（解綁／解綁＋停用／改為僅外部登入／" +
			"帳號停用 UpdateStatus／帳號刪除 Delete 共用此出口）：" +
			"錄影 token 為 in-memory 且不做世代比對，唯一失效途徑是按 user 直接撤銷"},
	{symbol: "RevokeByProvider", file: "internal/modules/identity/oidc_provider_revocation.go", fn: "OIDCProviderService.revokeProviderAccess", count: 1,
		source: "auth_epoch 推進後的鎖外收線（provider 停用／刪除／密鑰輪替，3.8）：" +
			"同上，錄影 token 唯一的失效途徑是按 provider 直接撤銷"},
	{symbol: "DisconnectByUser", file: "internal/modules/identity/external_identity_service.go", fn: "UserService.revokeUserAccess", count: 1,
		source: "同上批次的唯讀訂閱管道：監看／分享不建 sessions 列，會話掃描完全掃不到"},
	{symbol: "DisconnectByProvider", file: "internal/modules/identity/oidc_provider_revocation.go", fn: "OIDCProviderService.revokeProviderAccess", count: 1,
		source: "provider 停用／刪除的唯讀訂閱管道（3.8 第四條）：同上"},

	// ── 序列化側：以既有身分或憑證產生新長效能力（3.8b 通則） ────
	// **本段即 3.8b 所稱「凡…的位置」的清冊本體**：每一項都必須於 provider／user
	// 鎖內完成「重查前提 → 讀世代 → 建立」三步。新增任何長效能力的建立點卻未經
	// WithCapabilityLocks，守衛不會紅（它擋的是未登記的呼叫）——但反過來，
	// 任何新增的 WithCapabilityLocks 呼叫都必須在此說明它序列化的是哪一種能力，
	// 使「哪些能力已被序列化」可被逐項覆核。
	{symbol: "WithCapabilityLocks", file: "internal/modules/identity/oidc_provider_lock.go", fn: "WithOIDCProviderLock", count: 1,
		source: "provider 單鎖的薄包裝（停用／刪除／密鑰輪替的失效流程用）"},
	{symbol: "WithCapabilityLocks", file: "internal/modules/session/session_provider_termination.go", fn: "SessionService.CreateWithGenerationGuard", count: 1,
		source: "connect token 兌換建 session：grant 的 method/provider/兩種世代"},
	{symbol: "WithCapabilityLocks", file: "internal/modules/session/session_provider_termination.go", fn: "JoinWithGenerationGuard", count: 1,
		source: "監看／分享訂閱 Join：觀察者自身的 ObserverContext 脈絡"},
	{symbol: "WithCapabilityLocks", file: "internal/modules/identity/oidc_login_service.go", fn: "OIDCLoginService.issueTicket", count: 1,
		source: "callback 簽 ticket：ticket 是使用者世代的第一個攜帶者（flow state 不帶）"},
	{symbol: "WithCapabilityLocks", file: "internal/modules/identity/oidc_login_service.go", fn: "OIDCLoginService.Exchange", count: 1,
		source: "ticket 兌換正式會話：ticket 列的 auth_epoch/cred_epoch"},
	{symbol: "WithCapabilityLocks", file: "internal/modules/identity/auth_refresh_service.go", fn: "AuthService.RefreshSession", count: 1,
		source: "refresh 輪替：refresh 列自身攜帶的 auth_epoch/cred_epoch"},

	{symbol: "CreateWithGenerationGuard", file: "internal/sshproxy/handler.go", fn: "Handler.createSession", count: 1,
		source: "SSH/K8s/DB 三協議共用的兌換建 session（脈絡自 connect grant 原樣帶入）"},
	{symbol: "CreateWithGenerationGuard", file: "internal/proxy/handler.go", fn: "ConnectionHandler.HandleConnect", count: 1,
		source: "guacamole 協議側的兌換建 session（同上語義）"},
	{symbol: "JoinWithGenerationGuard", file: "internal/sshproxy/handler.go", fn: "Handler.HandleMonitor", count: 1,
		source: "監看訂閱建立前的鎖內世代複查（middleware.GetAuthContext 的脈絡）"},
	{symbol: "JoinWithGenerationGuard", file: "internal/sshproxy/handler.go", fn: "Handler.HandleShareJoin", count: 1,
		source: "分享訂閱建立前的鎖內世代複查（撤銷治理須與監看一致）"},
	{symbol: "JoinWithGenerationGuard", file: "internal/api/recording_token.go", fn: "RecordingTokenManager.Issue", count: 1,
		source: "錄影 token 簽發：借用同一「鎖內重讀前提 → 世代比對 → 非阻塞集合操作」契約，" +
			"使簽發與 RevokeByUser／RevokeByProvider 的掃描不會交錯出漏網的 grant"},

	// ── 跨包測試接縫（獨立驗收後已無登記列）──────────────────
	// 原本這裡有兩列：`internal/modules/identity/testseams.go` 內
	// `BuildAuthContextForTest`／`IssueTicketForTest` 對 `buildAuthContext`／
	// `issueTicket` 的委派。那個生產檔已收斂為 `identity/export_test.go`
	// （export budget 收斂：16 個純測試用匯出收回未匯出），而本守衛的掃描範圍
	// **本來就排除 `_test.go`**，故兩個貫穿點自掃描範圍消失，登記列隨之刪除。
	// **這不是把它們排除在掃描外**——委派本體仍在，只是不再屬於生產面；
	// 生產面的 `buildAuthContext`／`issueTicket` 呼叫點仍各自登記於上方。

	// ── 驗證側：世代閘的交易內版本 ───────────────────────────────
	{symbol: "VerifyCredentialGenerationTx", file: "internal/modules/identity/auth_epoch_gate.go", fn: "AuthService.VerifyCredentialGeneration", count: 1,
		source: "閘門本體：以 database.DB 委派（單一實作，交易版與非交易版同源）"},
	{symbol: "VerifyCredentialGenerationTx", file: "internal/modules/session/session_provider_termination.go", fn: "SessionService.CreateWithGenerationGuard", count: 1,
		source: "兌換建 session 的鎖內世代比對（讀與寫須同交易視圖）"},
	{symbol: "VerifyCredentialGenerationTx", file: "internal/modules/session/session_provider_termination.go", fn: "JoinWithGenerationGuard", count: 1,
		source: "訂閱建立的鎖內世代比對"},
	{symbol: "VerifyCredentialGenerationTx", file: "internal/modules/identity/oidc_login_service.go", fn: "OIDCLoginService.Exchange", count: 1,
		source: "ticket 兌換的鎖內世代比對（與原子消費同鎖同交易）"},
	{symbol: "VerifyCredentialGenerationTx", file: "internal/modules/identity/auth_refresh_service.go", fn: "AuthService.RefreshSession", count: 1,
		source: "refresh 輪替的鎖內世代比對：缺此則密鑰輪替前簽出的 refresh 會換出帶現行世代的 access"},
}

// authContextHomonymDecls 與清冊符號同名、但語義無關的**宣告**（本 module 內）。
//
// **判準已由「名稱＋接收者運算式字串」改為「go/types 解析出的宣告」**：
// 呼叫點的 callee 先經 `TypesInfo.Uses` 解析成 `types.Object`，非本 module 的宣告
// （`strings.Join`／`gorm.DB.Begin`／`oauth2.Config.Exchange`……）**在型別層就被排除**，
// 不再需要逐個接收者變數名去猜。留在本表的只有「同一個 module 內、同名但語義無關」
// 這一類，且鍵是宣告位置而不是呼叫端寫法——改個變數名或加個 alias 都繞不過。
//
// 鍵格式：`<包路徑>.<接收者型別>.<符號>`；包級函式的接收者段為空。
//
// **本表受 maxAuthContextHomonymDecls（條數上限）與「登記了必須命中」的反向斷言
// 雙重節制**，形態比照 auditPointTxMachineUndeterminable／maxTxMachineUndeterminable。
// 在此之前它兩者皆無：往表裡加一筆就能把一個宣告移出掃描面，不必調高任何數字、
// 也不必證明那個宣告真的存在——「允許清單只驗刪除、不驗放寬」的教科書形態。
var authContextHomonymDecls = map[string]string{
	// 審計失敗機制的復原標記，與認證脈絡無關。**三個宣告都要列**：實作在 audit，
	// 而 keyvault 與鏈驗證編排者各自以窄介面消費（1.11 的環拆解形態），
	// 呼叫點解析到的是各自的介面方法而非實作
	"github.com/custodexa/backend/internal/modules/audit.AuditFailureService.Resolve":     "審計失敗復原標記（實作）",
	"github.com/custodexa/backend/internal/modules/keyvault.AuditFailureReporter.Resolve": "審計失敗復原標記（keyvault 側窄介面）",
	// `ChainVerifyService` 以自宣告的
	// `ChainVerifyAlerter`（chain_verify_service.go:102）消費同一個
	// `AuditFailureService.Resolve`，故是第三個需列管的宣告位置。
	// 四個呼叫點（`Tick`／`runNow`／`syncAlerts`×2）傳的都是 `model.Mechanism*`
	// 字串常數＝把某個審計失效機制標記為已恢復，不簽發、不驗證、不失效任何憑證
	"github.com/custodexa/backend/internal/modules/audit.ChainVerifyAlerter.Resolve": "審計失敗復原標記（鏈驗證編排者側窄介面）",
	// 離機上傳器以自宣告的 `FailureReporter`（offsite/uploader.go:109）消費同一個
	// `AuditFailureService.Resolve`，是同一家族的第四個宣告位置。唯一呼叫點
	// （`Uploader.resolve`）傳的是 `model.Mechanism*` 常數＝把某個離機失效機制
	// 標記為已恢復，不簽發、不驗證、不失效任何憑證
	"github.com/custodexa/backend/internal/offsite.FailureReporter.Resolve": "審計失敗復原標記（離機上傳側窄介面）",
	// internal/seal 狀態機的套件級 Resolve(Situation)
	"github.com/custodexa/backend/internal/seal..Resolve": "封印狀態機的情境解析",
	// host key TOFU 驗證回呼（`hostKeys.Callback(assetID)` 回 ssh.HostKeyCallback），
	// 與認證脈絡無關
	"github.com/custodexa/backend/internal/modules/asset.HostKeyService.Callback": "host key TOFU 回呼",
	// 交易級聯撤銷 authz 的 approver_scopes（7.4 的 tx-taking 窄 port），
	// 與 `RecordingTokenManager.RevokeByUser`（錄影 token 失效）**只是同名**。
	// 它撤的是「審核者範圍」這種授權資料，不簽發也不失效任何憑證。
	// **兩個宣告都要列**：authz 的實作，與 identity／asset 側消費者自宣告的窄介面。
	"github.com/custodexa/backend/internal/modules/authz.AssetAuthorizationService.RevokeByUser":      "交易級聯撤銷授權資料（實作）",
	"github.com/custodexa/backend/internal/modules/identity.authorizationCascadeRevoker.RevokeByUser": "交易級聯撤銷授權資料（identity 側窄介面）",
}

// maxAuthContextHomonymDecls 同名例外的條數上限（現況 8）。
//
// **這個常數是本表的付費閘**：沒有它，允許清單可以無聲長大——每加一筆就有一個
// 宣告自貫穿點掃描面消失，而消失本身不需要任何人簽字，也不會有任何數字在 PR diff
// 裡動。要新增例外就得在同一個 diff 裡把這個數字調高，那是一個必須被質問的動作。
//
// 上限是**收緊用的**：發現某個例外其實不該存在時刪掉它並調低此數，是正確方向；
// 為了讓守衛變綠而調高它，等同於宣告「這一批認證脈絡不再有人看守」。
const maxAuthContextHomonymDecls = 8

// authContextWatchedSymbols 需要掃描呼叫點的符號集合。
//
// **每一個都必須在本 module 內解析到至少一個宣告**（見 assertWatchedDeclsResolved）
// ——這是後補的反向斷言：改名（例如 `verifyCredentialGenerationTx` 匯出為
// `VerifyCredentialGenerationTx`）會讓舊名匹配不到任何東西，那一整批貫穿點就
// **靜默地**自掃描面消失而測試照樣綠。字串型定位子上已實證過同一形態。
var authContextWatchedSymbols = []string{
	// 簽發側
	"GenerateToken", "GenerateTokenNotAfter", "GenerateScopedToken", "issueRefreshToken",
	"buildLoginResponse", "IssueSessionResponse", "buildAuthContext", "finishLogin",
	"Issue", "IssueConnectToken", "Join", "issueTicket", "Begin",
	// 驗證側
	"AuthMiddleware", "ValidateConnectionToken", "VerifySession", "RefreshSession",
	"Callback", "Exchange", "consumeFlowState", "Resolve", "RedeemConnectToken",
	"RedeemConnectTokenWithReason",
	"VerifyCredentialGeneration", "VerifyCredentialGenerationByUserID",
	"VerifyCredentialGenerationTx",
	// 序列化側（3.8b 通則：以既有身分或憑證產生新長效能力的位置）
	"WithCapabilityLocks", "CreateWithGenerationGuard", "JoinWithGenerationGuard",
	// 失效側（RecordingTokenManager 不得列為例外）
	"RevokeByUser", "RevokeByProvider",
	"DisconnectByUser", "DisconnectByProvider",
}

// minAuthContextPackages `packages.Load("./...")` 的載入包數下限（空圖＝零命中＝綠）。
// 實測 36 個包；取 30 為下界（遷移只會增加包）。
const minAuthContextPackages = 30

// minAuthContextCallSites 掃到的貫穿點呼叫數下限。
// **這是「掃得到東西但掃錯範圍」的反向斷言**：把掃描根指到別的樹、或 watched
// 清單因改名而失配時，命中數會塌陷而不是變成 0（清單裡總有幾個名字還在）。
// 實測 106 處（掃 311 檔／36 包）；取 90 為下界——留 15% 餘裕給正當的收口，
// 但任何整批消失（改名、掃描根偏移）都會遠低於它。
const minAuthContextCallSites = 90

// authContextDeclKey 宣告鍵：`<包路徑>.<接收者型別>.<符號>`
func authContextDeclKey(pkgPath, recv, name string) string {
	return pkgPath + "." + recv + "." + name
}

// authContextHomonymDeclListed 該宣告鍵是否登記為同名例外。
func authContextHomonymDeclListed(key string) bool {
	_, ok := authContextHomonymDecls[key]
	return ok
}

// authContextScan 一次掃描的結果
type authContextScan struct {
	Packages int
	Files    int
	Sites    map[string][]string // "symbol|file|fn" → file:line
	Resolved map[string]bool     // watched 符號 → 是否解析到本 module 的宣告
	// HomonymHits 例外鍵 → 實際命中的宣告數（含函式／方法宣告與介面方法宣告）。
	// 零命中即代表該例外所描述的宣告在本 module 內根本不存在：它沒有排除任何東西，
	// 只是留在表上佔一個名額。反向完備性斷言據此判紅。
	HomonymHits map[string]int
	CallCount   int
}

// scanAuthContextTouchpoints 以 go/types 解析全 module 的貫穿點呼叫。
//
// 三步：(1) 收集本 module 內所有「名字在 watched 清單裡」的宣告物件
// （含介面方法——經介面呼叫時 Uses 指向的是介面方法）；(2) 扣掉同名但語義無關的
// 宣告（authContextHomonymDecls）；(3) 掃全部非測試檔的呼叫，callee 物件落在
// 集合內即記一筆。
func scanAuthContextTouchpoints(t *testing.T) authContextScan {
	t.Helper()
	root := lifecycleModuleRoot(t)
	fset := token.NewFileSet()
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo |
			packages.NeedImports | packages.NeedDeps,
		Dir:   root,
		Fset:  fset,
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		t.Fatalf("packages.Load 失敗（守衛無法在無視野下宣稱通過）: %v", err)
	}
	if len(pkgs) < minAuthContextPackages {
		t.Fatalf("只載入 %d 個包（下限 %d）：掃描範圍已失真，守衛將在近乎空集合下假綠",
			len(pkgs), minAuthContextPackages)
	}
	for _, p := range pkgs {
		if len(p.Errors) > 0 {
			t.Fatalf("包 %s 有 %d 個載入／型別錯誤（首個：%v）：拒絕在殘缺的 AST 上作判定",
				p.PkgPath, len(p.Errors), p.Errors[0])
		}
	}

	watched := map[string]bool{}
	for _, s := range authContextWatchedSymbols {
		watched[s] = true
	}

	scan := authContextScan{
		Sites:       map[string][]string{},
		Resolved:    map[string]bool{},
		HomonymHits: map[string]int{},
	}
	scan.Packages = len(pkgs)

	rel := func(abs string) string {
		r, err := filepath.Rel(root, abs)
		if err != nil {
			return abs
		}
		return filepath.ToSlash(r)
	}

	// 步驟 1／2：收集 watched 宣告物件
	targets := map[types.Object]string{} // 物件 → 符號名
	for _, p := range pkgs {
		if p.TypesInfo == nil {
			continue
		}
		for _, f := range p.Syntax {
			// 具名函式與方法
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || !watched[fd.Name.Name] {
					continue
				}
				obj := p.TypesInfo.Defs[fd.Name]
				if obj == nil {
					continue
				}
				recv := ""
				if disp := funcDisplayName(fd); disp != fd.Name.Name {
					recv = strings.TrimSuffix(disp, "."+fd.Name.Name)
				}
				if key := authContextDeclKey(p.PkgPath, recv, fd.Name.Name); authContextHomonymDeclListed(key) {
					scan.HomonymHits[key]++
					continue
				}
				targets[obj] = fd.Name.Name
				scan.Resolved[fd.Name.Name] = true
			}
			// 介面方法（經介面呼叫時 Uses 指向這裡）
			ast.Inspect(f, func(n ast.Node) bool {
				ts, ok := n.(*ast.TypeSpec)
				if !ok {
					return true
				}
				it, ok := ts.Type.(*ast.InterfaceType)
				if !ok || it.Methods == nil {
					return true
				}
				for _, m := range it.Methods.List {
					for _, nm := range m.Names {
						if !watched[nm.Name] {
							continue
						}
						obj := p.TypesInfo.Defs[nm]
						if obj == nil {
							continue
						}
						if key := authContextDeclKey(p.PkgPath, ts.Name.Name, nm.Name); authContextHomonymDeclListed(key) {
							scan.HomonymHits[key]++
							continue
						}
						targets[obj] = nm.Name
						scan.Resolved[nm.Name] = true
					}
				}
				return true
			})
		}
	}

	// 步驟 3：掃呼叫點
	seenFile := map[string]bool{}
	for _, p := range pkgs {
		if p.TypesInfo == nil {
			continue
		}
		for _, f := range p.Syntax {
			path := fset.Position(f.Pos()).Filename
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			r := rel(path)
			if !seenFile[r] {
				seenFile[r] = true
				scan.Files++
			}

			type fnRange struct {
				name       string
				start, end token.Pos
			}
			var fns []fnRange
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				fns = append(fns, fnRange{name: funcDisplayName(fd), start: fd.Pos(), end: fd.End()})
			}
			enclosing := func(pos token.Pos) string {
				for _, fr := range fns {
					if pos >= fr.start && pos < fr.end {
						return fr.name
					}
				}
				return "<file-scope>"
			}

			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				var id *ast.Ident
				switch fun := call.Fun.(type) {
				case *ast.Ident:
					id = fun
				case *ast.SelectorExpr:
					id = fun.Sel
				default:
					return true
				}
				obj := p.TypesInfo.Uses[id]
				if obj == nil {
					return true
				}
				name, ok := targets[obj]
				if !ok {
					return true
				}
				key := name + "|" + r + "|" + enclosing(call.Pos())
				scan.Sites[key] = append(scan.Sites[key], r+":"+itoa(fset.Position(call.Pos()).Line))
				scan.CallCount++
				return true
			})
		}
	}
	return scan
}

// TestAuthContextTouchpointsGuard 認證脈絡貫穿點清冊守衛（**雙向**）。
//
// 三條斷言，缺一不可：
//   - **watched 清單全數解析得到**：任一符號在本 module 內找不到宣告即 t.Fatal
//     ——改名會讓那一批貫穿點靜默消失，這條是它的攔截點；
//   - **現實 → 清冊**：未登記的呼叫點即紅（原有語義）；
//   - **清冊 → 現實**：登記了卻掃不到即紅（後補的反向完備性）。
//     原註解以「分批交付、允許超前登記」為由刻意做成單向；那批交付早已完成，
//     而單向的代價是「清冊描述的行為其實不存在」不會有任何東西轉紅
//     ——`authContextWriterSites` 當年正是為了同一個理由才做成雙向。
//
// 第四條由 assertAuthContextHomonymsAreBounded 承擔：**同名例外表本身**也受條數
// 上限與「登記了必須命中」的反向斷言節制（形態同 maxTxMachineUndeterminable）。
func TestAuthContextTouchpointsGuard(t *testing.T) {
	scan := scanAuthContextTouchpoints(t)
	assertAuthContextScanBreadth(t, scan.Files)
	assertAuthContextHomonymsAreBounded(t, scan)
	t.Logf("auth-context 貫穿點命中數=%d（下限 %d）／載入包數=%d", scan.CallCount, minAuthContextCallSites, scan.Packages)
	if scan.CallCount < minAuthContextCallSites {
		t.Fatalf("只掃到 %d 處貫穿點呼叫（下限 %d）：命中數塌陷代表掃描根或 watched 清單失配，"+
			"此時「沒有未登記的貫穿點」不成立", scan.CallCount, minAuthContextCallSites)
	}
	for _, sym := range authContextWatchedSymbols {
		if !scan.Resolved[sym] {
			t.Errorf("watched 符號 %q 在本 module 內找不到任何宣告：它可能被改名或刪除，"+
				"而清冊對它的所有登記從此無人比對（守衛射程靜默歸零）", sym)
		}
	}
	if t.Failed() {
		t.FailNow()
	}

	registered := map[string]int{}
	for _, tp := range authContextTouchpoints {
		registered[tp.symbol+"|"+tp.file+"|"+tp.fn] += tp.count
	}

	var keys []string
	for k := range scan.Sites {
		keys = append(keys, k)
	}
	for k := range registered {
		if _, ok := scan.Sites[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	var extra, missing []string
	for _, k := range keys {
		sites := scan.Sites[k]
		parts := strings.SplitN(k, "|", 3)
		switch {
		case len(sites) > registered[k]:
			extra = append(extra, "  symbol="+parts[0]+" file="+parts[1]+" fn="+parts[2]+
				" 實際 "+itoa(len(sites))+" 處（已登記 "+itoa(registered[k])+"）: "+strings.Join(sites, ", "))
		case len(sites) < registered[k]:
			missing = append(missing, "  symbol="+parts[0]+" file="+parts[1]+" fn="+parts[2]+
				" 登記 "+itoa(registered[k])+" 處，實際只掃到 "+itoa(len(sites)))
		}
	}
	if len(extra) > 0 {
		t.Errorf("發現未登記的認證脈絡貫穿點：\n%s\n\n"+
			"新增的簽發／驗證路徑必須攜帶認證脈絡，否則該路徑產生的憑證對 provider 停用與"+
			"使用者憑證世代免疫（既簽 token 不會被拒、既有連線不會被收線）。\n"+
			"請於 authContextTouchpoints 登記該呼叫點並寫明脈絡來源；若確為同名但語義無關的"+
			"呼叫，於 authContextHomonymDecls 以其**宣告位置**顯式列管。",
			strings.Join(extra, "\n"))
	}
	if len(missing) > 0 {
		t.Errorf("清冊登記了不存在的貫穿點：\n%s\n\n"+
			"清冊描述的行為若其實不存在於程式碼，讀者會據以相信某條路徑「已經驗過脈絡」。"+
			"搬檔／改名後請同步 file 與 fn 欄；若該呼叫點確已移除，刪除該列並在 change 中說明。",
			strings.Join(missing, "\n"))
	}
}

// assertAuthContextHomonymsAreBounded 同名例外表的兩條節制（對稱於
// auditPointTxMachineUndeterminable 的 maxTxMachineUndeterminable ＋ 反向完備）。
//
//   - **條數上限**：超過 maxAuthContextHomonymDecls 即 Fatal。允許清單長大必須
//     在 PR diff 裡動一個數字，不得無聲進行。
//   - **反向完備（登記了必須命中）**：每一筆例外都必須真的排除到至少一個宣告。
//     零命中的例外沒有排除任何東西——它可能是改名／搬包後的殘留，也可能是
//     打錯字的新登記；兩種情況下讀者都會誤以為「那個同名符號已經有人判斷過了」。
//     此外，零命中的殘留還會白白佔用上限名額，把真正需要的例外擠出去。
//   - 附帶：理由欄不得留白——例外的成本是「這個宣告從此無人看守」，寫不出理由
//     就不該登記。
func assertAuthContextHomonymsAreBounded(t *testing.T, scan authContextScan) {
	t.Helper()
	if n := len(authContextHomonymDecls); n > maxAuthContextHomonymDecls {
		t.Fatalf("authContextHomonymDecls 已達 %d 筆（上限 %d）：同名例外清單正在稀釋貫穿點掃描面。"+
			"每一筆例外都讓一個宣告自掃描中消失，新增例外必須同時調高 maxAuthContextHomonymDecls，"+
			"該動作在 PR diff 中必須被質問", n, maxAuthContextHomonymDecls)
	}
	var keys []string
	for k := range authContextHomonymDecls {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.TrimSpace(authContextHomonymDecls[k]) == "" {
			t.Errorf("同名例外 %s 的理由欄為空：例外的代價是該宣告從此不受貫穿點守衛看守，"+
				"寫不出「它為什麼與認證脈絡無關」就不該登記", k)
		}
		if scan.HomonymHits[k] == 0 {
			t.Errorf("同名例外 %s（%s）登記了卻零命中：本 module 內找不到這個宣告，"+
				"它沒有排除掉任何東西。\n"+
				"    可能是符號被改名／搬包後的殘留，也可能是鍵打錯——兩種情況下讀者都會誤信"+
				"「那個同名符號已經有人判斷過」，而真正的同名宣告（若存在）其實正被當成貫穿點或漏掉。\n"+
				"    請刪除該列並調低 maxAuthContextHomonymDecls，或訂正鍵（格式："+
				"`<包路徑>.<接收者型別>.<符號>`，包級函式的接收者段為空）", k, authContextHomonymDecls[k])
		}
	}
	t.Logf("auth-context 同名例外 %d 筆（上限 %d），命中 %d 筆",
		len(authContextHomonymDecls), maxAuthContextHomonymDecls, len(scan.HomonymHits))
}

// authContextWriterSites 寫入 gin context 之 "authContext" 的完整位置清冊。
//
// 與 authContextTouchpoints 的**方向相反**：清冊本體是單向的
// （只擋未登記的呼叫），所以「某個登記項所描述的行為其實不存在於程式碼」不會讓
// 任何測試轉紅——曾有一處正是這樣被漏掉的：清冊寫著 authenticate「回傳 claims 供訂閱
// 脈絡使用」，而該函式從未寫入脈絡，監看／分享訂閱因此一律拿到零值。
//
// 本清冊採**雙向**判定：登記的位置必須真的寫入（漏寫即紅），未登記的位置不得寫入
// （新增寫入點必須經覆核，避免第三處以不同語義覆蓋脈絡）。
var authContextWriterSites = map[string]string{
	"internal/middleware/auth.go|AuthMiddleware": "一般 API 路徑：自 access token 的 claims 解出後寫入",
	"internal/sshproxy/handler.go|Handler.authenticate": "WS `?token=` 旁路（/monitor、/share/:code/ws、" +
		"/ssh、/connect 四條路由不掛 AuthMiddleware）：ValidateConnectionToken 驗過的 claims.AuthContext",
}

// TestAuthContextWriterSitesGuard 斷言 authContext 的寫入點與清冊完全一致。
func TestAuthContextWriterSitesGuard(t *testing.T) {
	found := map[string]string{} // "file|fn" → file:line
	// 掃描根同上，以 go.mod module 身分為錨（見 TestAuthContextTouchpointsGuard 註解）。
	root := lifecycleModuleRoot(t)
	scanned := 0
	fset := token.NewFileSet()

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "tmp", "vendor", "node_modules", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		scanned++
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)

		type fnRange struct {
			name       string
			start, end token.Pos
		}
		var fns []fnRange
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			fns = append(fns, fnRange{name: funcDisplayName(fd), start: fd.Pos(), end: fd.End()})
		}
		enclosing := func(pos token.Pos) string {
			for _, f := range fns {
				if pos >= f.start && pos < f.end {
					return f.name
				}
			}
			return "<file-scope>"
		}

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Set" || len(call.Args) != 2 {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING || lit.Value != `"authContext"` {
				return true
			}
			found[rel+"|"+enclosing(call.Pos())] = rel + ":" + itoa(fset.Position(call.Pos()).Line)
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("掃描 backend 原始碼失敗: %v", err)
	}
	assertAuthContextScanBreadth(t, scanned)

	var keys []string
	for k := range found {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, ok := authContextWriterSites[k]; !ok {
			t.Errorf("未登記的認證脈絡寫入點 %s（%s）：新的寫入點可能以不同語義覆蓋既有脈絡，"+
				"請於 authContextWriterSites 登記並說明來源", k, found[k])
		}
	}
	for k, why := range authContextWriterSites {
		if _, ok := found[k]; !ok {
			t.Errorf("清冊宣稱 %s 會寫入 authContext（%s），但程式碼中找不到該寫入——"+
				"下游 middleware.GetAuthContext(c) 將恆回零值：provider 停用收線一筆都匹配不到，"+
				"且 credential_epoch>0 的使用者會被世代閘恆拒", k, why)
		}
	}
}

// minAuthContextScannedFiles 全 backend 掃描的檔數下限（防空集合假綠）。
// 2026-08-09 全 backend 實測 299 檔（見兩個守衛的 t.Logf），門檻取 270。掃描根失效／被誤縮時，
// 本斷言使守衛當場轉紅，而不是在零命中下宣稱「沒有未登記的貫穿點」。
const minAuthContextScannedFiles = 270

func assertAuthContextScanBreadth(t *testing.T, scanned int) {
	t.Helper()
	if scanned < minAuthContextScannedFiles {
		t.Fatalf("只掃到 %d 個非測試 .go（下限 %d）：掃描根已失真，守衛將在近乎空集合下假綠。"+
			"若目錄結構改變，改的是掃描根而不是下限", scanned, minAuthContextScannedFiles)
	}
	t.Logf("auth-context 守衛掃描檔數=%d（下限 %d）", scanned, minAuthContextScannedFiles)
}

// funcDisplayName 函式顯示名（方法記為 Type.Method，指標接收者去掉 *）
func funcDisplayName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	typ := fd.Recv.List[0].Type
	if star, ok := typ.(*ast.StarExpr); ok {
		typ = star.X
	}
	if ident, ok := typ.(*ast.Ident); ok {
		return ident.Name + "." + fd.Name.Name
	}
	return fd.Name.Name
}

// 註：itoa 沿用同套件 model_audit_write_guard_test.go 的既有 helper（守衛檔慣例：
// 不為單一格式化引入 strconv），故本檔不重複定義。
