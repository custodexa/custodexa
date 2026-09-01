package moduleboundary

// 資料邊界閘門的**登記表**（Phase B 任務 6.0a）。
//
// 掃描器與守衛在 module_data_boundary_guard_test.go；本檔只放「人審過的事實」，
// 使登記與判定分離——改登記表不必動掃描邏輯，反之亦然。

// tableOwner 每張表的所屬模組。
//
// 判準＝「誰定義該表的業務語義、誰負責它的不變式」，不是「誰碰得最多」。
// 未登記的表被掃到即紅——新表出現時必須有人回答「它屬於哪個模組」。
var tableOwner = map[string]string{
	// asset
	"assets":                   "asset",
	"asset_groups":             "asset",
	"asset_nodes":              "asset",
	"asset_accounts":           "asset",
	"asset_host_keys":          "asset",
	"asset_account_audits":     "asset",
	"asset_changes":            "asset",
	"change_secret_plans":      "asset",
	"change_secret_records":    "asset",
	"change_secret_candidates": "asset",
	// identity
	"users":                    "identity",
	"roles":                    "identity",
	"user_roles":               "identity",
	"user_groups":              "identity",
	"user_group_members":       "identity",
	"password_histories":       "identity",
	"refresh_tokens":           "identity",
	"oidc_providers":           "identity",
	"oidc_flow_states":         "identity",
	"oidc_login_tickets":       "identity",
	"user_external_identities": "identity",
	"ldap_directories":         "identity",
	// authz
	"asset_authorizations":     "authz",
	"access_requests":          "authz",
	"access_request_approvals": "authz",
	"access_reviews":           "authz",
	"approver_scopes":          "authz",
	// audit
	"audit_logs":            "audit",
	// 證據包非同步匯出 job（受理、打包、
	// 下載授權皆在 audit 模組）
	"audit_export_jobs":     "audit",
	"command_alerts":        "audit",
	"alert_rules":           "audit",
	"notification_channels": "audit",
	"session_commands":      "audit",
	"audit_failure_events":  "audit",
	"daily_review_logs":     "audit",
	"integrity_baselines":   "audit",
	// auditor-workbench：保留期水位（每個保留類別清到哪個時刻、是否部分清除）。
	// 產生與消費皆在 audit 的 retention 路徑，故屬 audit；未登記所有者時，
	// 跨模組判定對這張表整個失效——任何模組讀寫它都不會被看見
	"audit_retention_watermarks": "audit",
	// audit-checkpoint-chain：檢查點鏈本體屬 audit（封章／驗證／修剪皆在 audit 模組）
	"audit_checkpoints": "audit",
	// audit-checkpoint-chain 第 6 組：鏈修剪記錄（殘鏈的新起點錨定），
	// 與檢查點同屬 audit（產生於 retention 的鏈修剪路徑）
	"audit_checkpoint_trims": "audit",
	// 兩層自動驗證的營運狀態（單列）。
	// 產生與消費皆在 audit 的鏈驗證編排路徑，故屬 audit。
	// **明示為營運狀態而非證據**：本表不在鏈的覆蓋範圍內（鏈只覆蓋 audit_logs）
	"audit_chain_verify_states": "audit",
	"syslog_settings":           "audit",
	// 來源限定功能：帳號 × 來源位址的已見基準。產生（建線點與登入點的
	// 交易內 upsert）與消費（位址候選查詢）皆在 audit 模組，故屬 audit；
	// 它是告警的判定依據，與 command_alerts 同家
	"user_source_ips": "audit",
	// keyvault
	"data_keys":           "keyvault",
	"export_signing_keys": "keyvault",
	// audit-checkpoint-chain：檢查點簽章鑰為 keyvault 自有表（私鑰材料只在 keyvault 內解包），
	// audit 側只透過 CheckpointSigningService 的方法簽／驗，不直接碰本表
	"checkpoint_signing_keys": "keyvault",
	// policy
	"security_policies":     "policy",
	"transmission_consents": "policy",
	// session
	"sessions":         "session",
	"snippets":         "session",
	"clipboard_events": "session",
	// offsite（evidence-offsite-storage）：離機儲存的保管帳冊與設定世代表。
	//
	// **不是第八個模組**——`internal/offsite` 是基礎設施包（形態比照
	// internal/recorder、pkg/crypto/kms），沒有自己的業務主體；它是其他模組
	// 物件的保管帳冊。所有者標籤是自由字串、守衛只核對表存在，故此登記可過。
	//
	// 登記在此的**實質效果**正是要的方向：`session`／`audit` 模組若直接 gorm 或
	// SQL 碰這兩張表，evaluateDataBoundary 立即判 NewCrossings 紅——模組只能經
	// `offsite.Ledger` 的方法取物件，帳冊的不變式（狀態機、唯一鍵、租約、世代歸屬）
	// 因此集中在一個包。
	//
	// **守衛看不見的那一半**：`internal/offsite` 本身不在資料邊界掃描面內，
	// 它對這兩張表以外任何表的存取都不會被掃到。補償＝包內自守衛
	// `internal/offsite/table_ownership_guard_test.go`（沿 keyvault 先例）：
	// AST 斷言本包非測試檔的 gorm 鏈與 SQL 字面量只碰這兩張表，`audit_logs`
	// 不直寫（走注入的 CustodyJournal）
	"offsite_objects":  "offsite",
	"offsite_profiles": "offsite",
	// infra（不屬任何業務模組，見 infraTables）
	"schema_migrations":  "infra",
	"information_schema": "infra",
	"sqlite_master":      "infra",
}

// nonModelTables 不由 `internal/model` 型別定義、但確實存在的表（GORM many2many join 表）。
// 用於 `tableOwner` 的「登記→現實」核對，使登記表不得憑空放進不存在的表。
var nonModelTables = map[string]bool{
	"user_roles":         true,
	"user_group_members": true,
}

// infraTables 不屬於任何業務模組的基礎設施表／系統目錄。
// 歸屬為 "infra"：模組碰它們仍算跨界（須具名登記），但登記的理由是遷移或方言探測，
// 不是「讀了別人的業務資料」——兩類混在一起會讓真正的業務越界被稀釋。
var infraTables = map[string]bool{
	"schema_migrations":  true, // 手寫遷移的執行 marker
	"information_schema": true, // postgres 系統目錄
	"sqlite_master":      true, // sqlite 系統目錄
}

// ---- 6.0a／6.0b：跨模組資料存取基線登記 ----

// crossModuleAccess 一筆「某模組直接讀／寫他模組的表」的具名登記。
type crossModuleAccess struct {
	Module string // 存取方模組
	Table  string // 被存取的表（他模組所有）
	Kind   string // "read" 或 "write"
	// Invisible＝本掃描器看不見（動態表名等），故不納入「登記項是否仍存在」的核對。
	// 標 true 者必須在 Reason 指名「由誰守衛」，否則等於白名單免死金牌。
	Invisible bool
	Reason    string
}

// crossModuleDataAccessBaseline 現況基線（開閘當時的全數登記）。
//
// **ratchet 方向：只准縮不准增。** 新增未登記的跨模組存取即紅；本表列了但現實中
// 已不存在者亦紅（逼人在移除時顯式更新，而非讓白名單越留越寬）。
//
// **本表不是許可證**：它記錄的是「重構開閘當下已經存在的債」，每一列都是
// 「model 不拆」與共用 `*gorm.DB` 造成的既有繞道，而非設計意圖。
// 此處只負責讓它不再增加。
var crossModuleDataAccessBaseline = []crossModuleAccess{
	// ---- asset → authz：**7.4 已收口，故此處無列**（ratchet 縮 2 列）----
	// `asset_group_service.go` 原在自己的交易內 Delete `asset_authorizations`
	// 與 `approver_scopes`；7.4 改為經 tx-taking 窄 port
	// `RevokeByAssetGroup(tx,id)` 由 authz 寫入，asset 不再直接碰他模組的表。
	// **誠實界定（本閘門看不見的那一半）**：交易句柄仍然被交出去，
	// 掃描器只看得到「authz 寫 authz 自己的表」。這條路徑改由
	// `cmd/server/tx_taking_whitelist_test.go` 的具名白名單承擔——
	// **ratchet 的數字變小不等於耦合消失**，不得如此解讀。

	// ---- identity → authz／audit ----
	{Module: "identity", Table: "asset_authorizations", Kind: "read",
		Reason: "刪使用者群組前查該群組既有授權筆數（user_group_service.go 的 AuthorizationCount，供刪除確認 UI）。純讀，未收口——7.4 只收交易級聯的寫入面。"},
	// identity 的兩條交易級聯寫入（asset_authorizations／approver_scopes）同樣於 7.4
	// 收口為 `RevokeByUserGroup(tx,id)`／`RevokeByUser(tx,id)`，故此處無列；
	// 誠實界定同上。
	{Module: "identity", Table: "audit_logs", Kind: "write",
		Reason: "登入成功／失敗與外部登入嘗試的審計直寫（auth_service.go、external_login_attempt_audit.go）。manifest 已登記為 AsyncSink 目標；搬包時改走 sink。"},

	// ---- identity → 基礎設施表 ----
	{Module: "identity", Table: "schema_migrations", Kind: "read",
		Reason: "LDAP env seed 的一次性 marker 讀取（ldap_seed_migration.go）：判斷本次啟動是否已跑過 seed。"},
	{Module: "identity", Table: "schema_migrations", Kind: "write",
		Reason: "同上，seed 成功後寫入 marker。marker 與 seed 必須同交易，故不經他人代寫。"},
	{Module: "identity", Table: "information_schema", Kind: "read",
		Reason: "postgres 系統目錄：seed 前探測欄位是否存在（跨版本相容）。非業務表。"},
	{Module: "identity", Table: "sqlite_master", Kind: "read",
		Reason: "sqlite 系統目錄：同上的方言分支。非業務表。"},

	// ---- authz → asset／identity（授權判定需要主體與客體的顯示欄與範圍）----
	{Module: "authz", Table: "assets", Kind: "read",
		Reason: "授權／申請單解析：以 JOIN／Preload 帶出資產名稱、協議與停用狀態。收口之後仍為讀取型耦合。"},
	{Module: "authz", Table: "asset_groups", Kind: "read",
		Reason: "審核者範圍與複審清單以資產群組為單位展開。"},
	{Module: "authz", Table: "users", Kind: "read",
		Reason: "申請人／審核者的顯示名與狀態；有效權限解析需知使用者是否停用。"},
	{Module: "authz", Table: "user_groups", Kind: "read",
		Reason: "群組型授權主體的展開。"},
	{Module: "authz", Table: "roles", Kind: "read",
		Reason: "審核者資格判定讀角色（判準的爭點所在）。"},
	{Module: "authz", Table: "user_roles", Kind: "read",
		Reason: "同上的 many2many join 表。"},
	{Module: "authz", Table: "user_group_members", Kind: "read",
		Reason: "群組即資格：審核者資格與授權主體展開皆以「使用者屬哪些群組」為子查詢。" +
			"**新增登記，但不是新增的存取**——這段 SQL 原本住在 `middleware/approver_guard.go` " +
			"與 `internal/repository`，兩處都不在任何模組的歸屬範圍內，掃描器從來看不到它；" +
			"7.1／7.7 把它們搬進 authz 之後才第一次進入掃描面。"},
	{Module: "authz", Table: "asset_nodes", Kind: "read",
		Reason: "節點含子樹的授權涵蓋判定：遞迴 CTE 自資產回溯掛載節點與祖先。" +
			"**新增登記，但不是新增的存取**——它原本住在 `internal/repository/" +
			"asset_authorization_repository.go`（不屬任何模組）；且在早期的掃描器下，" +
			"這段 SQL 常數超過 72 字元而被 `go/constant.Value.String()` 截斷，" +
			"表名整段自掃描面消失（改用 `constant.StringVal` 後修復，見 guard 檔內註解）。"},

	// ---- session → asset／identity／audit ----
	{Module: "session", Table: "assets", Kind: "read",
		Reason: "會話清單與自助連線視圖帶出資產顯示欄。"},
	{Module: "session", Table: "users", Kind: "read",
		Reason: "會話與錄影清單帶出使用者顯示名。"},
	{Module: "session", Table: "audit_logs", Kind: "write",
		Reason: "錄影失效報告的審計直寫（recording_failure_report.go）。**搬包時未改走 sink**：" +
			"它是 manifest 的 AP-54，與另外 34 個 AsyncSink 點同屬一次分派、迄今仍直寫；" +
			"那次搬檔是零行為變更，單獨收口這一點會改變失敗處置語義（現況 log-and-continue）。"},

	// ---- audit → asset／identity／session（顯示欄與匯出解析）----
	{Module: "audit", Table: "assets", Kind: "read",
		Reason: "指令告警與指令流清單 LEFT JOIN 補資產名。"},
	{Module: "audit", Table: "users", Kind: "read",
		Reason: "同上，補使用者名。"},
	{Module: "audit", Table: "sessions", Kind: "read",
		Reason: "審計匯出解析「有錄影的會話」（audit_export_service.go）。auditor-workbench 起另有時間軸聚合以 sessions 為主體解析面（clipboard_events 無主體欄，須 JOIN 回 sessions 取 user_id／asset_id）。"},
	{Module: "audit", Table: "clipboard_events", Kind: "read",
		Reason: "**auditor-workbench 新增的一筆資料層債，非既有債**（timeline_service.go 的 fetchClipboard／countSource；" +
			"audit_export_report.go 的報告事實列與 audit_export_clipboard.go 的" +
			"證據包內容段亦讀本表——匯出的範圍條件同樣須在 SQL 內表達，償還方向同下）。" +
			"時間軸把六類事件合併成單一 keyset 游標序，取窗條件（時間＋主體＋游標）與 LIMIT 必須在 SQL 內表達；" +
			"走 session 模組的既有清單介面會退化成「各類先各取一頁再於記憶體合併」，" +
			"分頁邊界即失真（某一類事件會整批消失或重複）。" +
			"**償還方向**：session 側提供一個帶游標與主體條件的剪貼簿讀取窄介面，audit 改呼叫它；" +
			"在那之前本列即這筆債的可見登記，ratchet 只准縮不准增。"},

	// ---- policy → asset／identity／audit ----
	{Module: "policy", Table: "assets", Kind: "read",
		Reason: "傳輸通道清冊與存取政策判定需讀資產的協議與傳輸設定。"},
	{Module: "policy", Table: "users", Kind: "read",
		Reason: "傳輸同意記錄帶出使用者顯示名。"},
	{Module: "policy", Table: "syslog_settings", Kind: "read",
		Reason: "傳輸清冊呈現 syslog 轉發是否啟用（「通道清冊」已反轉為窄介面，這一處讀的是設定表本身）。"},
	{Module: "policy", Table: "audit_logs", Kind: "write",
		Reason: "傳輸同意的審計直寫（transmission_consent_service.go）。manifest 已登記；後續改走 sink。"},

	// ---- keyvault → audit（KEK 退休監控）----
	{Module: "keyvault", Table: "audit_logs", Kind: "read",
		Reason: "KEK 退休監控以審計列數判斷降級期間的活動量（key_manager_cleanup.go）。"},

	// ---- keyvault → identity：**6.0d 已移除，故此處無列**（ratchet 縮的第一筆實績）----
	// `VerifyInitialAdminCredential` 原以 Preload("Roles") 讀 users／roles／user_roles
	// 並在 keyvault 包內做 admin 判定；6.0d 移交
	// `internal/service/initial_admin_verifier.go`（identity）後，roles／user_roles
	// 兩列已由本表刪除——刪除前守衛以「登記項已不存在」實跑轉紅，證明這條方向會擋。
	// **誠實界定**：`keyvault→users`(read) 仍在本表，來源是信封重加密的動態掃描
	// （下方 Invisible 列），不是 6.0d 移走的那條路徑。

	// ---- keyvault 的信封重加密：掃描器看不見的動態表名（由 keyvault 自己的守衛承擔）----
	{Module: "keyvault", Table: "assets", Kind: "write", Invisible: true,
		Reason: "信封重加密／AAD 遷移的動態 UPDATE。表名一律取自 envelopeMigrationTargets，由 internal/modules/keyvault/table_ownership_guard_test.go 的 TestKeyvaultDynamicTableNamesComeFromRegistry 與 TestKeyvaultCrossModuleWriteAllowlistMatchesRegistry 雙向守衛。"},
	{Module: "keyvault", Table: "asset_accounts", Kind: "write", Invisible: true,
		Reason: "同上（帳號密碼／私鑰兩欄）。"},
	{Module: "keyvault", Table: "change_secret_candidates", Kind: "write", Invisible: true,
		Reason: "同上（未驗證候選憑證的密碼／私鑰兩欄）。"},
	{Module: "keyvault", Table: "users", Kind: "write", Invisible: true,
		Reason: "同上（MFA TOTP secret 欄）。"},
	{Module: "keyvault", Table: "oidc_providers", Kind: "write", Invisible: true,
		Reason: "同上（OIDC client secret 欄）。"},
	{Module: "keyvault", Table: "ldap_directories", Kind: "write", Invisible: true,
		Reason: "同上（LDAP bind 密碼欄）。"},
	{Module: "keyvault", Table: "notification_channels", Kind: "write", Invisible: true,
		Reason: "同上（通知通道 url／secret 兩欄）。"},
	{Module: "keyvault", Table: "clipboard_events", Kind: "write", Invisible: true,
		Reason: "同上（剪貼簿留存內容欄 content_enc）。"},
	{Module: "keyvault", Table: "assets", Kind: "read", Invisible: true,
		Reason: "AAD 殘留哨兵與重加密前的掃描讀取，來源同上。"},
	{Module: "keyvault", Table: "asset_accounts", Kind: "read", Invisible: true,
		Reason: "同上。"},
	{Module: "keyvault", Table: "change_secret_candidates", Kind: "read", Invisible: true,
		Reason: "同上。"},
	{Module: "keyvault", Table: "users", Kind: "read", Invisible: true,
		Reason: "同上。"},
	{Module: "keyvault", Table: "oidc_providers", Kind: "read", Invisible: true,
		Reason: "同上。"},
	{Module: "keyvault", Table: "ldap_directories", Kind: "read", Invisible: true,
		Reason: "同上。"},
	{Module: "keyvault", Table: "notification_channels", Kind: "read", Invisible: true,
		Reason: "同上。"},
	{Module: "keyvault", Table: "clipboard_events", Kind: "read", Invisible: true,
		Reason: "同上。"},
	// ---- session 的剪貼簿加密轉換遷移 ----
	{Module: "session", Table: "information_schema", Kind: "read",
		Reason: "postgres 系統目錄：post-unseal 轉換前探測 clipboard_events 的 content 欄是否存在（冪等閘，沿 ldapSeedTableExists 慣例）。非業務表。"},
	{Module: "session", Table: "sqlite_master", Kind: "read",
		Reason: "sqlite 系統目錄：同上的方言分支。非業務表。"},
}
