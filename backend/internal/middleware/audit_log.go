package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/sourceip"
)

// auditLogOption 審計中介層的內部可調項。
//
// **刻意用未匯出型別**：這些旋鈕（時鐘、限流參數）只為 middleware 包內的測試存在，
// 產品呼叫端一律 `AuditLogMiddleware(svc)` 不帶選項。匯出它們等於邀請生產程式碼
// 去調整匿名列的有界門檻，而那是 spec 釘住的安全參數
type auditLogOption func(*anonRejectionAuditor)

// withAnonRejectionParams 覆寫匿名列的有界參數（測試用）
func withAnonRejectionParams(p anonRejectionParams) auditLogOption {
	return func(a *anonRejectionAuditor) { a.params = anonRejectionDefaults(p) }
}

// withAnonRejectionClock 覆寫時鐘（測試用：限流測試不得依賴真實時間 sleep）
func withAnonRejectionClock(now func() time.Time) auditLogOption {
	return func(a *anonRejectionAuditor) { a.now = now }
}

// withTrustedProxyDecision 覆寫可信代理判定（測試用）
func withTrustedProxyDecision(trust bool) auditLogOption {
	return func(a *anonRejectionAuditor) { a.trustProxy = trust }
}

// AuditLogMiddleware 審計日誌中間件
func AuditLogMiddleware(auditService *audit.AuditLogService, opts ...auditLogOption) gin.HandlerFunc {
	// 匿名拒絕留痕器。**建在閉包外**：令牌桶與
	// 聚合表必須跨請求存續，建在請求內等於每個請求都拿到滿額度＝無界
	anon := newAnonRejectionAuditor(anonRejectionParams{},
		config.LoadSeal().TrustedProxyConfigured(), auditService)
	for _, opt := range opts {
		opt(anon)
	}

	return func(c *gin.Context) {
		// 記錄開始時間
		start := time.Now()

		// 生成 Request ID（用於追蹤）
		requestID := uuid.New().String()
		c.Set("request_id", requestID)

		// 讀取 request body（需要處理 body 只能讀一次的問題）
		var bodyBytes []byte
		var bodyData map[string]interface{}

		if c.Request.Method != "GET" && c.Request.Method != "DELETE" {
			// 讀取 body
			bodyBytes, _ = io.ReadAll(c.Request.Body)
			// 恢復 body，讓後續 handler 能讀取
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

			// 解析 JSON（忽略錯誤，可能不是 JSON）
			if len(bodyBytes) > 0 {
				json.Unmarshal(bodyBytes, &bodyData)
			}
		}

		// 執行請求
		c.Next()

		// 提取用戶資訊
		userID, userIDExists := c.Get("userID") // 修復：與 AuthMiddleware 一致（駝峰式）
		username, usernameExists := c.Get("username")

		// 沒有身分時的兩條路。
		//
		// 這個分支是審計中介層**唯一**的整筆跳過條件，也就是「拒絕路徑零留痕」這個
		// 系統性破口的所在：認證中介層的每個 401 出口都在還沒設過 userID 時 abort，
		// 於是 171 條受保護路由的拒絕全部靜默消失。修在這裡一次涵蓋全部，且新增
		// 端點自動涵蓋——逐 handler 補要改 171 處而且必漏。
		//
		// **只補「認證中介層判的拒絕」**：標記由 `abortUnauthenticated` 留下。
		// 沒有標記的無身分請求（/health 探針、/auth/login 自己留痕的密碼錯誤、
		// WebSocket 閘的 handler 自解析路徑）維持原本的跳過——無差別補寫會與那些
		// 路徑既有的留痕重複計數
		if !userIDExists || !usernameExists {
			if code, rejected := c.Get(authRejectionContextKey); rejected {
				reason, _ := code.(string)
				anon.record(c, reason, requestID, time.Since(start))
				return
			}
			log.Printf("[Audit] 跳過審計：%s (userID存在=%v, username存在=%v)",
				c.Request.URL.Path, userIDExists, usernameExists)
			return
		}

		log.Printf("[Audit] 記錄操作：%s %s (用戶: %s)",
			c.Request.Method, c.Request.URL.Path, username)

		// 解析 action 和 resource
		action, resource, resourceID := parseRoute(c)

		// handler 覆寫審計 resource/resource_id：
		// 身分綁定自助端點（如 PATCH /auth/me）路由層歸 resource=auth 且無 :id，
		// 端點覆寫為 resource=user, resource_id=當前使用者，避免模糊審計
		if v, exists := c.Get("audit_resource"); exists {
			if r, ok := v.(model.AuditResource); ok {
				resource = r
			}
		}
		if v, exists := c.Get("audit_resource_id"); exists {
			if idv, ok := v.(uint); ok {
				resourceID = &idv
			}
		}

		// 資產主體鍵（auditor-workbench）。兩條來源，順序不可倒置：
		//  1. 路由推導——resource 已是 asset 且帶 :id，此時 resource_id **就是**
		//     asset id。這條在 extractResource 訂正（change-secret-plans／
		//     authorizations 各自獨立分類）之後才成立；訂正前 default 分支會讓
		//     計畫 id／授權列 id 被當成 asset id 灌進來，正是要消滅的假事件。
		//  2. handler 覆寫——路由層看不出資產的端點（如 /change-secret-plans/:id/run
		//     的目標資產、/authorizations 的被授權資產）由 handler 顯式 Set。
		// handler 覆寫後行，故永遠勝過路由推導
		var assetID *uint
		if resource == model.ResourceAsset && resourceID != nil {
			id := *resourceID
			assetID = &id
		}
		if v, exists := c.Get("audit_asset_id"); exists {
			if idv, ok := v.(uint); ok && idv != 0 {
				assetID = &idv
			}
		}

		// 確定狀態
		status := determineStatus(c.Writer.Status())

		// 脫敏敏感欄位
		maskedBody := ""
		if bodyData != nil {
			masked := audit.MaskSensitiveFields(bodyData)
			if data, err := json.Marshal(masked); err == nil {
				maskedBody = string(data)
			}
		}

		// 提取錯誤訊息
		errorMsg := ""
		if c.Writer.Status() >= 400 {
			// 嘗試從 c.Errors 獲取錯誤
			if len(c.Errors) > 0 {
				errorMsg = c.Errors.String()
			}
		}

		// 審計資源的讀取記查詢條件摘要（PCI 10.2.1.3）
		details := ""
		if c.Request.Method == "GET" && auditSensitiveResources[resource] {
			summary := map[string]string{}
			if query := c.Request.URL.RawQuery; query != "" {
				// **憑證值不得進 details**（access log 憑證遮蔽的同型缺口）。
				// raw query 整串直寫時，走 query string 的憑證——rtoken、
				// connect_token、`token`（monitor／share WS 帶的是長效登入 JWT）、
				// password、OIDC 的 code／state／binding——會逐字入庫。這裡比
				// access log 嚴重一級：access log 會輪替、會過期，而 audit_logs
				// 受檢查點鏈保護，寫進去就刪不掉（刪了鏈驗證即失敗），等於把憑證
				// 明文**永久封存在不可篡改的紀錄**裡。
				//
				// 遮的是值不是鍵，且**只遮憑證**：稽核仍須答得出「他用什麼條件
				// 查的」——時間範圍（start_time／from／to）、對象（subject／
				// subject_id／user_id／q）、類別（types／resource）全部原樣保留。
				// 語彙與 access log 同一份（accesslog.go），不另立第二套；
				// 憑證與個資的取捨差異見該檔檔頭「兩個遮蔽面」。
				summary["query"] = MaskCredentialQuery(query)
			}
			// 會話內取證的查詢條件在**路徑**（:id＝連線 id）而非 query string：
			// 只讀 RawQuery 會讓摘要恆空，「他取走了哪一場連線的證物」在 details
			// 上答不出來，且這些分類的 resource_id 是範圍鍵而非事件列 id（見
			// model.ResourceClipboardEvent），故此處把範圍顯式寫進摘要。
			//
			// recording／command 同時涵蓋跨會話端點（/recordings/stats、
			// /commands），那些路徑無 :id，`c.Param("id")` 回空字串而不寫鍵——
			// 摘要退化為只有 query 一鍵，與其他敏感資源同形
			switch resource {
			case model.ResourceClipboardEvent, model.ResourceRecording, model.ResourceCommand:
				if sessionID := c.Param("id"); sessionID != "" {
					summary["session_id"] = sessionID
				}
			}
			if len(summary) > 0 {
				if data, err := json.Marshal(summary); err == nil {
					details = string(data)
				}
			}
		}

		// handler 注入的補充審計標記（admin 政策豁免等），
		// 與查詢摘要合併——豁免連線必須在該筆日誌帶獨立可篩標記（決議 3）
		if v, exists := c.Get("audit_details"); exists {
			merged := map[string]interface{}{}
			if details != "" {
				json.Unmarshal([]byte(details), &merged)
			}
			if extra, ok := v.(map[string]string); ok {
				for k, val := range extra {
					merged[k] = val
				}
			}
			if len(merged) > 0 {
				if data, err := json.Marshal(merged); err == nil {
					details = string(data)
				}
			}
		}

		// 創建審計日誌條目
		entry := &audit.AuditLogEntry{
			UserID:     userID.(uint),
			Username:   username.(string),
			Action:     action,
			Resource:   resource,
			ResourceID: resourceID,
			AssetID:    assetID,
			Status:     status,
			Method:     c.Request.Method,
			Path:       c.Request.URL.Path,
			// 來源位址走全庫唯一取法：本行是覆蓋面
			// 最大的一處——**所有已認證請求的審計列都由它寫**。原本的 c.ClientIP()
			// 在未設 TRUSTED_PROXIES 時採信任意轉送標頭，任何持有有效帳號者送一個
			// X-Forwarded-For，就能把自己**全部操作**的來源位址寫成任選的值。
			// trustProxy 取自匿名留痕器持有的同一份判定（建在閉包外、讀一次），
			// 使同一個中介層的具名列與匿名列不可能出現不同的採信策略
			ClientIP:    sourceip.From(c, anon.trustProxy),
			StatusCode:  c.Writer.Status(),
			Duration:    time.Since(start),
			RequestBody: maskedBody,
			ErrorMsg:    errorMsg,
			RequestID:   requestID,
			Details:     details,
		}

		// 異步記錄（不阻塞主請求）
		auditService.Log(entry)
	}
}

// parseRoute 從路由解析 action, resource, resource_id
func parseRoute(c *gin.Context) (model.AuditAction, model.AuditResource, *uint) {
	method := c.Request.Method
	path := c.FullPath() // 例如: /api/v1/assets/:id

	// 提取 resource（從路徑中獲取）
	resource := extractResource(path)

	// 根據 HTTP 方法確定 action
	var action model.AuditAction
	switch method {
	case "POST":
		action = model.ActionCreate
	case "GET":
		action = model.ActionRead
	case "PUT", "PATCH":
		action = model.ActionUpdate
	case "DELETE":
		action = model.ActionDelete
	default:
		action = model.ActionExecute
	}

	// 特殊路由處理
	if strings.Contains(path, "/login") {
		action = model.ActionLogin
		resource = model.ResourceAuth
	} else if strings.Contains(path, "/logout") {
		action = model.ActionLogout
		resource = model.ResourceAuth
	} else if strings.Contains(path, "/terminate") {
		action = model.ActionDelete // Terminate 視為 Delete
	} else if strings.Contains(path, "/test") {
		action = model.ActionExecute // Test 視為 Execute
	} else if strings.HasSuffix(path, "/approve") {
		// HasSuffix 而非 Contains：/approver-scopes 亦含 "/approve"
		// 子字串，Contains 會把範圍 CRUD 全誤判為 approve，破壞範圍配置稽核可信度
		action = model.ActionApprove // 申請核准
	} else if strings.HasSuffix(path, "/reject") {
		action = model.ActionReject
	} else if strings.HasSuffix(path, "/cancel") {
		action = model.ActionCancel
	} else if strings.HasSuffix(path, "/revoke") {
		action = model.ActionRevoke // 臨時授權提前撤銷
	} else if strings.HasSuffix(path, "/review") {
		// HasSuffix：GET /reviews/pending 不含此結尾，不受影響
		action = model.ActionReview // 破窗事後補審
	} else if strings.HasSuffix(path, "/source-policy/check") {
		// 允許來源網段的判定端點是**唯讀試算**：它拿一份尚未儲存的清單草稿問
		// 「這個位址進不進得來」，不寫任何狀態。上面的動詞推導卻把它記成
		// create＋user，於是表單每問一次就在操作日誌長出一列「建立使用者」的
		// 假事件（2026-08-26 實測 6 分鐘 13 列、details 全空），稽核讀到的是
		// 有人反覆建帳號——與真正的建帳號在動作與資源兩欄上完全同形。
		//
		// 動詞推導在這裡失準的原因是 POST 同時承載「新增一個實體」與「送一份
		// 輸入去算」兩種語義，只有路徑分得出來，故在此顯式訂正為讀取。
		// 「查了什麼」由 handler 經 audit_details 補上（形狀而非明文，見該處註解）。
		action = model.ActionRead
	}

	// 提取 resource_id（從 path params）
	var resourceID *uint
	if idParam := c.Param("id"); idParam != "" {
		// 嘗試轉換為 uint
		var id uint
		if _, err := fmt.Sscanf(idParam, "%d", &id); err == nil {
			resourceID = &id
		}
	}

	return action, resource, resourceID
}

// extractResource 從路徑提取資源名稱
func extractResource(path string) model.AuditResource {
	// 路徑示例: /api/v1/assets/:id
	// 提取 "assets"
	parts := strings.Split(path, "/")

	// 會話內子資源的優先判定（涵蓋剪貼簿、錄影與指令）：
	// 下方主迴圈依**路徑序**命中，`/sessions/:id/clipboard-events`、
	// `/sessions/:id/recording/download`、`/sessions/:id/commands` 都會先撞上
	// `sessions` 而歸 session。那不是 default asset 的誤歸（resource_id 確為連線
	// id、session 樞紐成立），但它讓「取走證物本體」與「看一眼連線詳情」在
	// resource 欄同形，稽核只剩不可索引的 path 散文可資區隔，無法以資源分類
	// 篩出取證動作（PCI 10.2.1.3）。
	//
	// 判準：**若這個回應被外洩，洩的是系統的設定與中繼資料，
	// 還是被監控者產生的原始材料本體？**是後者即須專屬分類——剪貼簿明文、
	// 終端畫面錄影、被監控者輸入的指令原文三者皆是。
	//
	// 容器身分不因此遺失：resource_id 仍是連線 id，Details 另記 session_id，
	// 且連線樞紐以 model.AuditHubSubResources 展開涵蓋這三類
	for _, part := range parts {
		switch part {
		case "clipboard-events":
			return model.ResourceClipboardEvent
		// `recording` 是**單數**段（`/sessions/:id/recording{,/download,/stream,/token}`），
		// 與主迴圈的跨會話 `recordings`（`/recordings/stats|stream`）不同段；
		// 兩者共用 ResourceRecording，resource_id 的語義差異見 model 常數註解
		case "recording":
			return model.ResourceRecording
		// 跨會話 `/commands` 原本由主迴圈命中，一併前移：兩處同分類，
		// 前移後單會話 `/sessions/:id/commands` 不再被容器段 `sessions` 吃掉
		case "commands":
			return model.ResourceCommand
		}
	}

	for _, part := range parts {
		switch part {
		case "assets":
			return model.ResourceAsset
		case "sessions":
			return model.ResourceSession
		// /my/connections* 自助端點操作的是 session（列表/自助終止），
		// 不得落入 default asset 分類
		case "connections":
			return model.ResourceSession
		case "recordings":
			return model.ResourceRecording
		case "users":
			return model.ResourceUser
		case "auth", "login", "logout":
			return model.ResourceAuth
		// 審計資源映射（PCI 10.2.1.3）：對審計日誌的
		// 存取須可辨識，不得落入 default asset 分類。
		// 注：`commands` 已上移至前置特判迴圈（跨會話與單會話同歸 command），
		// 留在此處會是永不可達的死規則
		case "audit-logs":
			return model.ResourceAuditLog
		case "command-alerts":
			return model.ResourceCommandAlert
		case "security-policies":
			return model.ResourceSecurityPolicy
		case "audit-export":
			return model.ResourceAuditExport
		// 輪替證據報告：`:id` 指向**排程列**，不是資產或工作單。
		// 段名 `rotation-report` 與 `audit-export` 不同段，兩者的 resource_id
		// 語義不同，故不共用分類
		case "rotation-report":
			return model.ResourceRotationReport
		case "daily-reviews":
			return model.ResourceDailyReview
		case "syslog-settings":
			return model.ResourceSyslogSetting
		case "keys":
			return model.ResourceKeyManagement
		// 申請核准流：申請單與審核範圍不得落入
		// default asset 分類；狀態轉移的語義動作（approve/reject/cancel/expire）
		// 由 service 直接記錄，此處僅涵蓋路由層 create/read
		case "access-requests":
			return model.ResourceAccessRequest
		case "approver-scopes":
			return model.ResourceApproverScope
		// 改密計畫與授權（auditor-workbench 訂正）：兩者原本落入
		// default asset 分支，使審計列 resource=asset 而 resource_id 是
		// **計畫 id／授權列 id**。資產樞紐若以 (resource, resource_id) 查，
		// 查資產 130 會撈到「改密計畫 130」與「授權列 130」——那是
		// **產生假事件**（把別的實體的事件掛到這台機器上），比遺漏更糟
		case "change-secret-plans":
			return model.ResourceChangeSecretPlan
		case "authorizations":
			return model.ResourceAuthorization
		// 改密候選憑證：與計畫同源的誤歸（resource_id 是候選 id），
		// 併入改密分類而非另立——它是改密流程的一環，且 resource 欄
		// 只有 varchar(20)，"change_secret_candidate" 放不下
		case "change-secret-candidates":
			return model.ResourceChangeSecretPlan
		// 稽核工作台的聚合讀取（同 PCI 10.2.1.3：對審計資料的讀取須可辨識）
		case "timeline", "subjects":
			return model.ResourceAuditTimeline
		// ── 以下四族為後續接線補上的分類 ──
		// 四者的常數皆早已存在、只是從未接上分類器，於是全族落 default asset。
		// 帶 `:id` 的那些（access-reviews/:id、user-groups/:id*）後果不只是分類
		// 不精確：上方 assetID 推導由 `resource == ResourceAsset && resource_id != nil`
		// 無條件成立，複審單 id／群組 id 因此被寫進 asset_id，在稽核工作台的
		// **同號資產**時間軸上長出假事件。接線即止血。
		//
		// 週期性存取複審（audit-workflows）：`:id` 指向複審單
		case "access-reviews":
			return model.ResourceAccessReview
		// 使用者群組：`:id` 指向群組，
		// `/user-groups/:id/members`、`/user-groups/:id/authorization-count` 同族
		case "user-groups":
			return model.ResourceUserGroup
		// 傳輸安全：清冊與同意立據同歸一類——
		// 兩者是同一份政策的兩面（現況與立據），且皆無 `:id`
		case "transmission-inventory", "transmission-consents":
			return model.ResourceTransmission
		// 連線票證簽發：票證本身不是獨立實體，它是「開一場連線」的前置動作，
		// 故歸 session 而非另立常數。無 `:id`，resource_id 恆 nil。
		// 註：`/connect`、`/ssh` 是票證的**兌換**端，兩者鏈中無認證中介層，
		// 審計中介層必然早退，不由此處涵蓋（另有 proxy 側產生點）
		case "connect-tokens":
			return model.ResourceSession
		// ── 以下十族為新增的分類 ──
		// 十者的常數從未存在，於是整族落兜底。帶 `:id` 的那些（alert-rules、
		// asset-groups、notification-channels、oidc-providers、snippets）在兜底
		// 為 asset 的年代把規則 id／分組 id／通道 id／提供者 id／片段 id 寫進
		// asset_id，在同號**資產**的時間軸上長出假事件。
		//
		// 三個審計端點（audit-checkpoints／audit-failures／audit-integrity）
		// 另入 auditSensitiveResources——它們是審計資料的讀取，PCI 10.2.1.3
		// 要求可辨識且記查詢範圍；其餘七族是**設定變更**而非審計資料讀取，
		// 不入敏感集合（理由逐條寫在 cmd/server 的分類登記表）。
		//
		// 審計檢查點鏈（audit-checkpoint-chain）：無 `:id`
		case "audit-checkpoints":
			return model.ResourceAuditCheckpoint
		// 審計失效事件：無 `:id`
		case "audit-failures":
			return model.ResourceAuditFailure
		// 審計完整性驗證：無 `:id`
		case "audit-integrity":
			return model.ResourceAuditIntegrity
		// 指令告警規則：`:id` 指向規則列。與 `command-alerts`（告警審閱處置）
		// 分屬設定面與處置面，故不共用 ResourceCommandAlert
		case "alert-rules":
			return model.ResourceAlertRule
		// 告警通知通道：`:id` 指向通道列。常數刻意縮寫，見 model 常數註解
		case "notification-channels":
			return model.ResourceNotifyChannel
		// OIDC 身分提供者設定：`:id` 指向提供者列。段名是 `oidc-providers`，
		// 與登入流程的 `/auth/oidc/*`（段名 `oidc`、鏈中無認證中介層）不同段
		case "oidc-providers":
			return model.ResourceOIDCProvider
		// LDAP 目錄設定（單例）：無 `:id`
		case "ldap-directory":
			return model.ResourceLDAPDirectory
		// 離機儲存管理（evidence-offsite-storage）：`:id` 分別指向帳冊列與世代列，
		// **都不是會話或資產 id**；設定變更與運維動作皆歸此族
		case "offsite-storage":
			return model.ResourceOffsiteStorage
		// 資產分組：`:id` 指向分組列，**不是資產 id**——本族是兜底落 asset 時
		// 最容易被誤讀為真事件的一族（段名 `asset-groups` 與 `assets` 不同段）
		case "asset-groups":
			return model.ResourceAssetGroup
		// 指令片段範本：`:id` 指向片段列
		case "snippets":
			return model.ResourceSnippet
		// 角色定義讀取：無 `:id`。`/users/:id/roles` 的首個可辨識段是 `users`，
		// 依路徑序仍歸 user，不受本條影響
		case "roles":
			return model.ResourceRole
		// 單實例守衛快照：管理者限定、唯讀、無 `:id`。
		// 每次呼叫一列讀取留痕是刻意的——它只在橫幅出現時由管理者取一次，不輪詢
		case "instance-guard":
			return model.ResourceInstanceGuard
		}
	}

	// 兜底＝專屬哨兵。
	//
	// **SHALL NOT 落在任何有真實查詢面的類別上。** 舊實作回 `asset`，註解自承
	// 動機只是「避免空值」——任何非空字串都滿足它，而 asset 的代價是把假列注入
	// 一個真實的查詢結果集，並經 `resource == ResourceAsset && resource_id != nil`
	// 推導出假 asset_id（遺漏因此升級為假事件）。
	//
	// 哨兵使漏分類可計數、可篩選、可告警；`cmd/server` 的路由分類守衛以
	// `maxUnclassifiedRoutes` 把這個數字釘在 0，新增端點漏分類即轉紅
	return model.ResourceUnclassified
}

// auditSensitiveResources 審計資源集合（PCI 10.2.1.3）：這些資源的 GET
// 讀取另記查詢條件摘要，使「誰查了什麼」可稽核
var auditSensitiveResources = map[model.AuditResource]bool{
	model.ResourceAuditLog:      true,
	model.ResourceCommand:       true,
	model.ResourceCommandAlert:  true,
	model.ResourceAuditExport:   true,
	model.ResourceDailyReview:   true,
	model.ResourceKeyManagement: true, // 金鑰清冊讀取入審計
	// 工作台的聚合讀取（auditor-workbench）：一次查詢即橫跨六類審計資料，
	// 「誰以什麼條件查了誰」比單頁讀取更需要留痕
	model.ResourceAuditTimeline: true,
	// 剪貼簿證物讀取：Content 是 64KB 明文欄，
	// 該端點是調查流程中「取走證物」的動作，比任何審計列表讀取更需要留痕
	model.ResourceClipboardEvent: true,
	// 錄影調閱：回傳的是終端畫面
	// 錄影本體——被監控者產生的原始材料，且可能含憑證輸入畫面。取走它與看一眼
	// 連線詳情必須分得開，且須答得出「取的是哪一場連線的錄影」（details.session_id）。
	// 註：ResourceCommand 早已在集合內（跨會話 /commands），單會話
	// /sessions/:id/commands 現已一併歸 command，取證與一般讀取因而同時可辨識
	model.ResourceRecording: true,
	// 三個審計端點分類：它們讀的是
	// **審計資料本身**（檢查點鏈、失效事件、完整性驗證），PCI 10.2.1.3 要求對審計
	// 資料的讀取可辨識且記查詢範圍。`/audit-checkpoints/verify` 帶 seq_from／seq_to、
	// `/audit-integrity/verify` 帶時間範圍，摘要因此非空。
	//
	// **同批新增的其餘七個分類刻意不入本集合**（alert_rule／notify_channel／
	// oidc_provider／ldap_directory／asset_group／snippet／role）：那些是**設定變更**，
	// 其稽核價值在「改了什麼」（由 request body 遮罩後記錄承擔），不在「以什麼條件查」。
	// 把設定面讀取一併灌進來只會稀釋本集合的訊號——本集合的語義是「對受保護材料或
	// 審計資料的讀取」，不是「重要的端點」
	model.ResourceAuditCheckpoint: true,
	model.ResourceAuditFailure:    true,
	model.ResourceAuditIntegrity:  true,
}

// determineStatus 根據 HTTP 狀態碼確定審計狀態
func determineStatus(statusCode int) model.AuditStatus {
	if statusCode >= 200 && statusCode < 300 {
		return model.StatusSuccess
	} else if statusCode == 403 {
		return model.StatusDenied
	} else {
		return model.StatusFailure
	}
}
