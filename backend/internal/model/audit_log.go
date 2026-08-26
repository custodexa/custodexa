package model

import (
	"sync"
	"time"

	"gorm.io/gorm"
)

// AuditAction 審計操作類型
type AuditAction string

const (
	ActionCreate  AuditAction = "create"
	ActionRead    AuditAction = "read"
	ActionUpdate  AuditAction = "update"
	ActionDelete  AuditAction = "delete"
	ActionExecute AuditAction = "execute"
	ActionLogin   AuditAction = "login"
	ActionLogout  AuditAction = "logout"
	// ActionUnlock 管理員手動解鎖帳號
	ActionUnlock AuditAction = "unlock"
	// ActionPasswordNoncompliant 登入時偵測現行密碼不符政策：
	// Details 記違規類別（apierror 碼），不含任何密碼材料。varchar(20) 內
	ActionPasswordNoncompliant AuditAction = "pw_noncompliant"
	// ActionRecordingFailed session 錄影失敗：
	// 失效事件表同機制去重，逐 session 可追溯靠本審計列
	ActionRecordingFailed AuditAction = "recording_failed"
	// ActionNewSourceIP 帳號自從未見過的來源位址完成 web 登入：只留審計標記、
	// 不進告警表（登入無會話可綁；且登入與建線各響一次會違反「同位址不重響」）。
	// 與基準表的插入同交易寫入，失敗整筆回滾、下次登入再補。varchar(20) 內
	ActionNewSourceIP AuditAction = "new_source_ip"

	// SFTP 檔案操作
	ActionFileList     AuditAction = "file_list"
	ActionFileUpload   AuditAction = "file_upload"
	ActionFileDownload AuditAction = "file_download"
	ActionFileMkdir    AuditAction = "file_mkdir"
	ActionFileDelete   AuditAction = "file_delete"

	// 申請核准流狀態轉移：全動作入審計，
	// 由 service 於轉移成立時直接記錄（expire 無 HTTP 請求，中介層蓋不到）
	ActionApprove AuditAction = "approve"
	ActionReject  AuditAction = "reject"
	ActionCancel  AuditAction = "cancel"
	ActionExpire  AuditAction = "expire"
	ActionRevoke  AuditAction = "revoke" // 臨時授權提前撤銷
	ActionReview  AuditAction = "review" // 破窗事後補審
)

// AuditResource 審計資源類型
type AuditResource string

const (
	ResourceAsset   AuditResource = "asset"
	ResourceSession AuditResource = "session"
	// ResourceRecording 錄影相關動作（涵蓋單會話錄影端點）。
	//
	// **resource_id 語義分裂，且刻意如此**：
	//   - `/sessions/:id/recording{,/download,/stream,/token}` ⇒ **連線 id**
	//     （範圍鍵；取的是「這一場連線的錄影」，錄影列 id 不是查詢對象）
	//   - `/recordings/stats|stream` ⇒ **nil**（無 :id）
	// 兩者皆非「錄影列 id」，故本分類 SHALL NOT 作為樞紐型別
	//（`GET /audit-logs/resource/:resource/:id` 要求各型的 :id 指向該型自身
	// 實體 id）；它是 ResourceSession 的子資源，見 AuditHubSubResources。
	//
	// 為何獨立於 session：回傳的是終端畫面錄影**本體**，取走它與看一眼連線
	// 詳情在稽核上是兩件事，須能以 resource 欄直接篩出（PCI 10.2.1.3）
	ResourceRecording AuditResource = "recording"
	ResourceUser      AuditResource = "user"
	ResourceAuth      AuditResource = "auth"
	ResourceFile      AuditResource = "file"
	// ResourceSecurityPolicy 安全政策變更（PCI 10.2.2；action=update，
	// Details 記 key 與舊值→新值。Action 欄為 varchar(20)，
	// 故以 resource 區分而非 design 原稿的長 action 名）
	ResourceSecurityPolicy AuditResource = "security_policy"
	// ResourceCommandAlert 告警審閱處置（audit-workflows，PCI 10.4.1）
	ResourceCommandAlert AuditResource = "command_alert"
	// ResourceAuditExport 稽核證據匯出（audit-workflows，PCI 10.5.1）
	ResourceAuditExport AuditResource = "audit_export"
	// ResourceAccessReview 週期性存取複審（audit-workflows，PCI 7.2.4）
	ResourceAccessReview AuditResource = "access_review"
	// ResourceRetention 保留政策到期清除（PCI 10.5.1；
	// action=delete，Details 記資料類型/時間範圍/筆數/是否部分完成）
	ResourceRetention AuditResource = "retention"
	// ResourceDailyReview 每日審閱簽核（PCI 10.4.1）
	ResourceDailyReview AuditResource = "daily_review"
	// ResourceSyslogSetting syslog 轉發設定變更（PCI 10.3.3）
	ResourceSyslogSetting AuditResource = "syslog_setting"
	// ResourceAuditLog 操作日誌本身的存取（PCI 10.2.1.3：
	// 對審計日誌的讀取須可辨識，不得落入 default 分類）
	ResourceAuditLog AuditResource = "audit_log"
	// ResourceUserGroup 使用者群組（授權主體分組；
	// 刪群組連動撤授權時 Details 記 group_name 與 revoked_authorizations 筆數）
	ResourceUserGroup AuditResource = "user_group"
	// ResourceCommand 指令流查詢（同 10.2.1.3）。
	//
	// **resource_id 語義分裂**：
	// 跨會話 `/commands` ⇒ nil；單會話 `/sessions/:id/commands` ⇒ **連線 id**
	//（範圍鍵）。回傳的是被監控者輸入的**指令原文**，故與錄影同屬取證動作；
	// 改判之前，單會話端點歸 session，形成「跨會話查詢是敏感的、單會話查詢反而
	// 不是」的不對稱。同 ResourceRecording，本分類是 session 的子資源而非樞紐型
	ResourceCommand AuditResource = "command"
	// ResourceKeyManagement 金鑰管理：遷移、
	// 換鑰、清冊讀取等動作的審計分類
	ResourceKeyManagement AuditResource = "key_management"
	// ResourceTransmission 傳輸安全：同意立據、
	// 閘門拒絕、LDAP 登入偏離、清冊讀取/匯出的審計分類（varchar(20) 內）
	ResourceTransmission AuditResource = "transmission"
	// ResourceAccessRequest 連線申請單：
	// create/approve/reject/cancel/expire 全動作＋admin 政策豁免連線標記
	ResourceAccessRequest AuditResource = "access_request"
	// ResourceApproverScope 審核範圍分配（admin only）
	ResourceApproverScope AuditResource = "approver_scope"
	// ResourceChangeSecretPlan 改密計畫（auditor-workbench 訂正）：原本落入
	// `extractResource` 的 default asset 分支，使審計列 resource=asset 而 resource_id
	// 是**計畫 id**。資產樞紐照此查會撈到同號資產的假事件，故獨立分類。
	// 值長 18，在 resource 欄 varchar(20) 內
	ResourceChangeSecretPlan AuditResource = "change_secret_plan"
	// ResourceAuthorization 授權變更（同上訂正）：原 default asset ＋ resource_id
	// 為**授權列 id**
	ResourceAuthorization AuditResource = "authorization"
	// ResourceAuditTimeline 稽核調查工作台的聚合讀取（auditor-workbench；
	// PCI 10.2.1.3「誰查了什麼」）：不得落入 default asset 分類，且列入
	// auditSensitiveResources 以另記查詢條件摘要
	ResourceAuditTimeline AuditResource = "audit_timeline"
	// ResourceClipboardEvent 剪貼簿證物讀取（PCI 10.2.1.3）。
	//
	// 路徑 `/sessions/:id/clipboard-events` 的首個可辨識段是 `sessions`，
	// 訂正前 `extractResource` 因而回傳 session——**不是 default asset 的誤歸**
	// （resource_id 確為連線 id、session 樞紐成立），但「取走 64KB 剪貼簿明文」
	// 與「看了一眼連線詳情」在 resource 欄上無從分辨，只剩不可索引的 path 散文
	// 可資區隔。取證動作必須能以 resource 直接篩出，故獨立分類。
	//
	// **resource_id 語義**：本分類下 resource_id 是**連線 id**（範圍鍵），
	// 非剪貼簿事件列 id——查詢對象是「某場連線的全部剪貼簿事件」而非單一事件。
	// 為免此語義只存在於註解，同一筆審計列的 Details 另記 session_id。
	// 值長 15，在 resource 欄 varchar(20) 內
	ResourceClipboardEvent AuditResource = "clipboard_event"

	// ── A 類新分類（10 個）──
	//
	// 十族的共通處境：常數從未存在，`extractResource` 因而整族落兜底。兜底舊為
	// `asset`，於是帶 `:id` 的那些（alert-rules/:id、asset-groups/:id*、
	// notification-channels/:id*、oidc-providers/:id、snippets/:id）被
	// `resource == ResourceAsset && resource_id != nil` 無條件推導出 asset_id，
	// 在**同號資產**的時間軸上長出假事件。分類即止血。
	//
	// 每個常數的註解須寫明其 resource_id 指向哪種實體——(resource, resource_id)
	// 一旦不同源，寫出的就是形式合法、語義虛假的元組。

	// ResourceAuditCheckpoint 審計檢查點鏈（audit-checkpoint-chain）：
	// `/audit-checkpoints{,/public-key,/verify}` 皆無 `:id`，**resource_id 恆為 nil**。
	// 入 auditSensitiveResources——讀取審計資料本身須可辨識（PCI 10.2.1.3），
	// 且 `/verify` 帶 seq_from／seq_to，查詢範圍摘要非空。值長 16（varchar(20) 內，
	// 本 change 最長的新值）
	ResourceAuditCheckpoint AuditResource = "audit_checkpoint"
	// ResourceAuditFailure 審計失效事件讀取：
	// `/audit-failures` 無 `:id`，**resource_id 恆為 nil**。同入敏感讀取集合
	ResourceAuditFailure AuditResource = "audit_failure"
	// ResourceAuditIntegrity 審計完整性驗證（audit-integrity）：
	// `/audit-integrity/verify` 無 `:id`，**resource_id 恆為 nil**。同入敏感讀取集合——
	// 「誰在什麼範圍上驗了鏈」是稽核事實，不是設定變更
	ResourceAuditIntegrity AuditResource = "audit_integrity"
	// ResourceAlertRule 指令告警規則（command-alert）：`:id` 指向**規則列 id**。
	// 與 ResourceCommandAlert（告警的審閱處置）不同——前者是規則設定，後者是事件處置
	ResourceAlertRule AuditResource = "alert_rule"
	// ResourceNotifyChannel 告警通知通道設定：`:id` 指向**通道列 id**。
	// **刻意縮寫**：`notification_channel` 恰為 20 字元，貼齊 resource 欄 varchar(20)
	// 上限而零餘裕（同 ResourceSecurityPolicy 的取捨）；`notify_channel` 14 字
	ResourceNotifyChannel AuditResource = "notify_channel"
	// ResourceOIDCProvider OIDC 身分提供者設定：`:id` 指向**提供者列 id**。
	// 註：`/auth/oidc/:id/begin`／`/auth/oidc/callback` 是登入流程端點、鏈中無認證
	// 中介層（審計中介層必然早退），不由本分類涵蓋
	ResourceOIDCProvider AuditResource = "oidc_provider"
	// ResourceLDAPDirectory LDAP 目錄設定（單例）：`/ldap-directory{,/test}` 無 `:id`，
	// **resource_id 恆為 nil**
	ResourceLDAPDirectory AuditResource = "ldap_directory"
	// ResourceAssetGroup 資產分組：`:id` 指向**分組列 id**，**不是資產 id**——
	// 這正是兜底落 asset 時最危險的一族（分組 7 的改名會顯示成資產 7 的事件）
	ResourceAssetGroup AuditResource = "asset_group"
	// ResourceSnippet 指令片段（快捷指令範本）：`:id` 指向**片段列 id**
	ResourceSnippet AuditResource = "snippet"
	// ResourceRole 角色定義讀取（`GET /roles`）：無 `:id`，**resource_id 恆為 nil**。
	// 與 ResourceUser 分開——角色是授權模型的一部分，不是使用者實體
	ResourceRole AuditResource = "role"
	// ResourceInstanceGuard 單實例守衛：
	// 三個系統事件（overridden／lost／regained，`action=execute`，系統主體）與
	// 管理者限定端點 `GET /instance-guard` 的讀取列。無 `:id`，resource_id 恆 nil。
	// 值長 14（varchar(20) 內）
	ResourceInstanceGuard AuditResource = "instance_guard"

	// ResourceUnclassified 分類器的**兜底哨兵**。
	//
	// **兜底 SHALL NOT 落在任何有真實查詢面的類別上。** 舊兜底是 `asset`，
	// 動機只是「避免空值」（任何非空字串都滿足它），代價卻是三重：
	//  1. 把假列注入一個真實的查詢結果集（`idx_audit_resource` 會忠實撈出）；
	//  2. 由 `resource == ResourceAsset && resource_id != nil` 推導出**假 asset_id**，
	//     使遺漏升級為假事件；
	//  3. 使失敗不可觀測——誤歸列與正確列在查詢結果裡無從分辨。
	//
	// 換成專屬哨兵後，漏分類變成**可計數、可篩選、可告警**的數字
	//（`SELECT count(*) WHERE resource='unclassified'`），且 asset_id 推導對它自然失效。
	//
	// **resource_id 語義：未定義。** 哨兵不是實體類別，其 resource_id 只是
	// `c.Param("id")` 的機械產物，SHALL NOT 用於任何樞紐查詢。
	//
	// **邊界**：哨兵治理的是「已註冊但未分類」。404／405 的 `c.FullPath()` 為空字串、
	// 分類亦為哨兵，但那類請求無 userID，中介層早退不寫列。值長 12
	ResourceUnclassified AuditResource = "unclassified"
)

// AuditHubSubResources 樞紐查詢的子資源涵蓋。
//
// 稽核調查的入口是「這場連線發生過什麼」，而不是「clipboard_event 這個分類裡有什麼」。
// 把取證動作獨立分類（ResourceClipboardEvent）使 resource 欄可直接篩出取證，
// 但同時讓連線樞紐 `GET /audit-logs/resource/session/:id` 撈不到它們——查一場連線
// 卻看不到「誰在這場連線裡取走了剪貼簿內容」，比分不出兩者更糟。故樞紐查詢
// 涵蓋子資源。
//
// **入列的唯一判準是 id 空間相同**：clipboard_event 的 resource_id 是**連線 id**
//（範圍鍵，見 ResourceClipboardEvent），與樞紐鍵同一空間，故以連線 id 展開查詢
// 只會撈到該連線自己的事件。id 空間不同者 SHALL NOT 入列——例如
// ResourceChangeSecretPlan 的 resource_id 是計畫 id，展開會把別的實體的事件掛到
// 樞紐上（產生假事件，比遺漏更糟，正是這條判準要根除的缺陷）。
//
// **判準的放寬**：recording 與
// command 兩分類**同時**涵蓋單會話端點（resource_id＝連線 id）與跨會話端點
//（`/recordings/stats`、`/commands`，無 :id 故 resource_id 恆為 **nil**）。
// 故入列判準自「該分類的 resource_id 恆與樞紐同 id 空間」放寬為
// 「**非 nil 時**恆與樞紐同 id 空間」。此放寬安全：展開查詢是
// `resource IN (...) AND resource_id = ?`，nil 不匹配任何樞紐 id，跨會話列
// 不可能被撈進任何一場連線的樞紐。**放寬僅及於 nil**——非 nil 而屬別的 id
// 空間者（如 change_secret_plan）仍然禁止入列。
var AuditHubSubResources = map[AuditResource][]AuditResource{
	// 一場連線的調查須答得出：誰取走了它的剪貼簿明文、錄影本體、指令原文。
	// 三者的取證動作各自獨立分類後，若不在此展開就會從連線樞紐消失
	ResourceSession: {ResourceClipboardEvent, ResourceRecording, ResourceCommand},
}

// AuditReasonTokenExpired 認證中介層拒絕列的**審計側**原因碼：token 曾經有效但已到期。
//
// **只存在於審計，不出現在任何對外回應**：對外一律維持 `AUTH_TOKEN_INVALID`——
// 讓外部能區分「這張 token 曾經有效」與「這張是偽造的」等於開出一個憑證存在性的
// 探測面（比照 `/connect` 拒絕原因的處置）。
//
// **為何要區分**：例行的 access token 到期（每 15 分鐘一次、前端自動 refresh）是正常
// 流量，若與「無憑證」「簽章無效」一起計入每日覆核的登入失敗數，PCI 10.4.1 的覆核
// 數字會被正常流量淹沒而失去訊號——那正是本 change 要修的東西。
//
// 常數放 model 而非 middleware：寫入側（`middleware/auth.go`）與計數側
// （`modules/audit/daily_review_service.go`）都要用它，兩份副本一旦分歧，計數會
// 靜默地回到「全部計入」而沒有任何測試轉紅。
const AuditReasonTokenExpired = "AUTH_TOKEN_EXPIRED"

// AuditStatus 審計狀態
type AuditStatus string

const (
	StatusSuccess AuditStatus = "success"
	StatusFailure AuditStatus = "failure"
	StatusDenied  AuditStatus = "denied"
)

// AuditLog 審計日誌模型
type AuditLog struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `gorm:"index:idx_audit_created_at;index:idx_audit_asset_created,priority:2;index:idx_audit_user_created,priority:2" json:"created_at"`
	UpdatedAt time.Time      `json:"-"` // 審計日誌不應被更新
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// 核心欄位
	Action     AuditAction   `gorm:"type:varchar(20);not null;index:idx_audit_action_status" json:"action"`
	Resource   AuditResource `gorm:"type:varchar(20);not null;index:idx_audit_resource" json:"resource"`
	ResourceID *uint         `gorm:"index:idx_audit_resource" json:"resource_id,omitempty"` // 可選，指向具體資源
	Status     AuditStatus   `gorm:"type:varchar(20);not null;index:idx_audit_action_status" json:"status"`

	// AssetID 資產主體鍵（auditor-workbench）：稽核工作台的資產樞紐**只認本欄**，
	// SHALL NOT 以 (resource, resource_id) 冒充——`extractResource` 的 default 分支
	// 曾使 change-secret-plans／authorizations 的列 resource=asset 而 resource_id
	// 是計畫 id／授權列 id，直接查會把別的實體的事件掛到這台資產上（產生假事件，
	// 比遺漏更糟）。故主體在**寫入期**釘在來源列上，與 sessions／session_commands／
	// command_alerts 既有的 user_id＋asset_id 冗餘慣例一致。
	//
	// 指標型（可為 NULL）：非資產類動作留空，不得用 0 冒充「無資產」——0 在整數欄
	// 上與「id 為 0 的資產」無法區分，且會讓 partial index 失去意義。
	// 開發階段不做向下相容：不回填歷史列。
	AssetID *uint `gorm:"index:idx_audit_asset_created,priority:1" json:"asset_id,omitempty"`

	// 使用者資訊
	UserID   uint   `gorm:"not null;index:idx_audit_user_created,priority:1" json:"user_id"`
	Username string `gorm:"type:varchar(100);not null" json:"username"` // 反正規化，避免 JOIN

	// 請求資訊
	Method   string `gorm:"type:varchar(10)" json:"method"`                              // HTTP Method (GET, POST, etc.)
	Path     string `gorm:"type:varchar(500)" json:"path"`                               // Request path
	ClientIP string `gorm:"type:varchar(50);index:idx_audit_client_ip" json:"client_ip"` // 支援 IPv6

	// 性能指標
	StatusCode int `json:"status_code,omitempty"` // HTTP status code
	Duration   int `json:"duration_ms,omitempty"` // 響應時間（毫秒）

	// 詳細資訊（JSON 格式）
	RequestBody string `gorm:"type:text" json:"request_body,omitempty"` // 脫敏後的請求內容
	ErrorMsg    string `gorm:"type:text" json:"error_msg,omitempty"`    // 錯誤訊息（如有）
	Details     string `gorm:"type:text" json:"details,omitempty"`      // 變更詳情（用於 GORM Hooks 記錄 before/after）

	// 追蹤 ID（用於關聯多個操作）
	RequestID string `gorm:"type:varchar(100);index:idx_audit_request_id" json:"request_id,omitempty"`

	// IdempotencyUUID 冪等鍵：
	// 封印期 journal 的 at-least-once 回灌以此去重——重複回灌不產生重複列。
	// 個別事件列用 journal 的確定性事件 ID，合成聚合列用
	// (journal_uuid, 起始 seq, 結束 seq) 導出的確定性 ID。
	//
	// **必須是可為 NULL 的指標**：一般審計列不帶此鍵，若用空字串則唯一索引
	// 會讓第二筆一般審計列直接寫入失敗。多個 NULL 在 Postgres 與 SQLite 的
	// 唯一索引下皆允許並存，正是此欄需要的語義。
	IdempotencyUUID *string `gorm:"type:varchar(64);uniqueIndex:idx_audit_idempotency" json:"-"`

	// IntegrityHMAC 逐列完整性驗證碼（PCI 10.3.4 補償控制）：
	// HMAC-SHA256(關鍵欄位序列化, 伺服器完整性密鑰) 的 hex。功能上線前的
	// 歷史列為空字串，驗證端點將其獨立計數、不視為竄改
	IntegrityHMAC string `gorm:"type:varchar(64)" json:"-"`

	// KeyVersion 蓋章鑰版本：0＝legacy 派生鑰
	// （遷移時快照凍結為 audit_integrity v0，此後 JWT_SECRET 輪替不影響驗章），
	// >=1 為系統生成的版本化鑰。驗證按列取對應版本鑰。
	// DB 欄 default 0 由 migration 落（既有列回填）；Go 結構不帶 default tag
	//（GORM default 觸發 RETURNING 破壞 sqlmock），寫入端由 Stamp 顯式設值
	KeyVersion int `json:"-"`
}

// TableName 指定表名
func (AuditLog) TableName() string {
	return "audit_logs"
}

// 註冊式建立 hook：audit_logs 有多條
// **入庫**路徑（middleware 批次、asset GORM hook、file_tap、k8s cp），完整性
// HMAC 與 syslog 轉發必須覆蓋全部——service 層不能被 model import（循環
// 依賴），由 main 啟動時注入。未註冊（單測）時為 no-op。
// 「入庫」而非「寫入」是誠實邊界 R2：檔案降級與佇列滿載丟棄的事件不進 DB，
// 本 hook 對它們不會被呼叫，宣稱覆蓋「全部寫入路徑」即為過度宣稱
var (
	auditCreateHookMu sync.RWMutex
	auditStampHook    func(*AuditLog) // BeforeCreate：填 IntegrityHMAC
	auditPublishHook  func(*AuditLog) // AfterCreate：tee 入 syslog 轉發
)

// SetAuditCreateHooks 註冊 audit_logs 建立時的完整性與轉發 hook（main 注入）
func SetAuditCreateHooks(stamp, publish func(*AuditLog)) {
	auditCreateHookMu.Lock()
	defer auditCreateHookMu.Unlock()
	auditStampHook = stamp
	auditPublishHook = publish
}

func getAuditCreateHooks() (stamp, publish func(*AuditLog)) {
	auditCreateHookMu.RLock()
	defer auditCreateHookMu.RUnlock()
	return auditStampHook, auditPublishHook
}

// BeforeCreate 補 CreatedAt＋計算完整性 HMAC。CreatedAt 必須在此處定值——
// HMAC 涵蓋時戳，若留給 GORM 在 hook 之後填值，重算必不符
func (a *AuditLog) BeforeCreate(tx *gorm.DB) error {
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now()
	}
	// 欄位長度收口。順序有兩個硬約束：
	//  1. 必須在**蓋章之前**——HMAC 涵蓋這些欄位，先蓋後截即存值與章不符。
	//  2. 必須在 model 層而非各寫入端——這裡是全部入庫路徑的唯一匯流點，
	//     逐寫入端補「記得截斷」與逐 handler 補審計是同一種必漏的模式。
	// 不收口的後果不只是這一列寫不進去：多列 INSERT 是單一語句，一列違約
	// 全批回滾，一個零憑證的超長路徑請求即可把同批的真實攻擊記錄一起沖掉
	//（見 audit_log_bounds.go 檔頭）
	BoundAuditLogFields(a)
	if stamp, _ := getAuditCreateHooks(); stamp != nil {
		stamp(a)
	}
	return nil
}

// AfterCreate 寫入成功後 tee 入 syslog（PCI 10.3.3）。掛在 model hook 使
// 全部**入庫**路徑一致轉發（未入庫的降級事件不在此列，R2）；交易回滾的極端情形會多轉發一筆（寧多勿漏）
func (a *AuditLog) AfterCreate(tx *gorm.DB) error {
	if _, publish := getAuditCreateHooks(); publish != nil {
		publish(a)
	}
	return nil
}

// BeforeUpdate 禁止更新審計日誌（審計日誌應該是不可變的）
func (a *AuditLog) BeforeUpdate(tx *gorm.DB) error {
	// 審計日誌創建後不應被修改
	return gorm.ErrInvalidValue
}

// BeforeDelete 禁止經 ORM 刪除審計日誌（PCI 10.3.2）：
// model 帶 DeletedAt 軟刪欄，無此守衛時 DB.Delete() 仍可軟刪。
// 保留政策到期清除走 service 層 retention 的原生 SQL 專用路徑，不經此 hook。
// 殘餘風險：Session(SkipHooks:true) 可繞過本守衛——全庫非測試碼零使用，
// 新增 audit 相關碼時不得引入 SkipHooks
func (a *AuditLog) BeforeDelete(tx *gorm.DB) error {
	return gorm.ErrInvalidValue
}
