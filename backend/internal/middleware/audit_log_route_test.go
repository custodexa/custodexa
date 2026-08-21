package middleware

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// TestExtractResource 路徑段到審計資源的映射：/my/connections* 操作的是
// session，不得落入 default asset 分類
func TestExtractResource(t *testing.T) {
	cases := []struct {
		path string
		want model.AuditResource
	}{
		{"/api/v1/my/connections", model.ResourceSession},
		{"/api/v1/my/connections/:id/terminate", model.ResourceSession},
		{"/api/v1/sessions/:id/terminate", model.ResourceSession},
		{"/api/v1/assets/:id", model.ResourceAsset},
		{"/api/v1/access-requests/:id/approve", model.ResourceAccessRequest},
		{"/api/v1/approver-scopes", model.ResourceApproverScope},
		{"/api/v1/approver-scopes/:id", model.ResourceApproverScope},
		// 會話內子資源優先於容器段（clipboard-read-provenance）：剪貼簿證物讀取
		// 不得與一般連線讀取同歸 session，否則取證動作無法以資源欄篩出
		{"/api/v1/sessions/:id/clipboard-events", model.ResourceClipboardEvent},
		// 錄影與指令同理（audit-resource-classification-closure 批 1）：取走
		// 終端畫面錄影本體／被監控者輸入的指令原文都是取證動作
		{"/api/v1/sessions/:id/commands", model.ResourceCommand},
		{"/api/v1/sessions/:id/recording", model.ResourceRecording},
		{"/api/v1/sessions/:id/recording/download", model.ResourceRecording},
		{"/api/v1/sessions/:id/recording/stream", model.ResourceRecording},
		{"/api/v1/sessions/:id/recording/token", model.ResourceRecording},
		// 對照組一：容器本身的讀取仍歸 session——前置特判不得把整個 sessions 族吃掉
		{"/api/v1/sessions/:id", model.ResourceSession},
		{"/api/v1/sessions/:id/share", model.ResourceSession},
		// 對照組二：跨會話端點的既有分類不得漂移。`commands` 上移至前置特判、
		// `recordings`（複數段）仍由主迴圈命中，兩者結果與訂正前逐字相同
		{"/api/v1/commands", model.ResourceCommand},
		{"/api/v1/recordings/stats", model.ResourceRecording},
		// 對照組三：`recording` 是單數段特判，不得誤傷含 record 前綴的他族路徑
		{"/api/v1/daily-reviews", model.ResourceDailyReview},
		// A 類既有常數接線（audit-resource-classification-closure 批 2）：
		// 四族的常數早已存在、只是從未接上分類器，於是整族落 default asset
		{"/api/v1/access-reviews", model.ResourceAccessReview},
		{"/api/v1/access-reviews/:id", model.ResourceAccessReview},
		{"/api/v1/access-reviews/matrix", model.ResourceAccessReview},
		{"/api/v1/user-groups", model.ResourceUserGroup},
		{"/api/v1/user-groups/:id", model.ResourceUserGroup},
		{"/api/v1/user-groups/:id/members", model.ResourceUserGroup},
		// `authorization-count` 不是 `authorizations` 段，不得被授權分類吃掉
		{"/api/v1/user-groups/:id/authorization-count", model.ResourceUserGroup},
		{"/api/v1/transmission-inventory", model.ResourceTransmission},
		{"/api/v1/transmission-inventory/export", model.ResourceTransmission},
		{"/api/v1/transmission-consents", model.ResourceTransmission},
		// 票證簽發歸 session（不另立常數）
		{"/api/v1/connect-tokens", model.ResourceSession},
		// 對照組四：新增的四個路徑段不得誤傷同前綴的既有族。
		// `access-requests`／`authorizations`／`users` 都與新段共享前綴或子字串，
		// 分類器若改成前綴／子字串匹配，這三條會立刻漂移
		{"/api/v1/access-requests/mine", model.ResourceAccessRequest},
		{"/api/v1/authorizations/:id", model.ResourceAuthorization},
		{"/api/v1/users/:id/roles", model.ResourceUser},
		// A 類新分類（audit-resource-classification-closure 批 3）：十族的常數
		// 從未存在，整族落兜底；帶 `:id` 的五族在兜底為 asset 的年代注入假 asset_id
		{"/api/v1/audit-checkpoints", model.ResourceAuditCheckpoint},
		{"/api/v1/audit-checkpoints/public-key", model.ResourceAuditCheckpoint},
		{"/api/v1/audit-checkpoints/verify", model.ResourceAuditCheckpoint},
		{"/api/v1/audit-failures", model.ResourceAuditFailure},
		{"/api/v1/audit-integrity/verify", model.ResourceAuditIntegrity},
		{"/api/v1/alert-rules", model.ResourceAlertRule},
		{"/api/v1/alert-rules/:id", model.ResourceAlertRule},
		{"/api/v1/notification-channels/:id", model.ResourceNotifyChannel},
		{"/api/v1/notification-channels/:id/test", model.ResourceNotifyChannel},
		{"/api/v1/oidc-providers/:id", model.ResourceOIDCProvider},
		{"/api/v1/ldap-directory", model.ResourceLDAPDirectory},
		{"/api/v1/ldap-directory/test", model.ResourceLDAPDirectory},
		{"/api/v1/asset-groups", model.ResourceAssetGroup},
		{"/api/v1/asset-groups/:id/move", model.ResourceAssetGroup},
		{"/api/v1/asset-groups/tree", model.ResourceAssetGroup},
		{"/api/v1/snippets/:id", model.ResourceSnippet},
		{"/api/v1/roles", model.ResourceRole},
		// 對照組五：新段不得吃掉同前綴的既有族。`asset-groups` 與 `assets`、
		// `audit-*` 三族與 `audit-logs`／`audit-export`／`audit/timeline`、
		// `oidc-providers` 與登入流程的 `oidc` 段——分類器若改成前綴或子字串匹配，
		// 這五條會立刻漂移
		{"/api/v1/assets/:id/files", model.ResourceAsset},
		{"/api/v1/audit-logs/:id", model.ResourceAuditLog},
		{"/api/v1/audit-export/public-key", model.ResourceAuditExport},
		{"/api/v1/audit/timeline", model.ResourceAuditTimeline},
		{"/api/v1/command-alerts/:id/review", model.ResourceCommandAlert},
		// 兜底哨兵（批 3）：分類器不認得的路徑不再冒充 asset。
		// 這條是機制斷言而非現況斷言——上限已為 0，全部已註冊路由都有分類，
		// 但**下一條漏分類的新端點**必須落在這裡，而不是落進資產的查詢面
		{"/api/v1/no-such-segment-anywhere/:id", model.ResourceUnclassified},
	}
	for _, tc := range cases {
		if got := extractResource(tc.path); got != tc.want {
			t.Errorf("extractResource(%s) = %s, want %s", tc.path, got, tc.want)
		}
	}
}

// TestParseRoute_ApproverScopeNotApprove 審核範圍 CRUD 的審計動作不得被
// 誤判為 approve（codex 審查 #6：/approver-scopes 含 "/approve" 子字串）
func TestParseRoute_ApproverScopeNotApprove(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		method string
		route  string
		reqURL string
		want   model.AuditAction
	}{
		{"POST", "/api/v1/approver-scopes", "/api/v1/approver-scopes", model.ActionCreate},
		{"DELETE", "/api/v1/approver-scopes/:id", "/api/v1/approver-scopes/3", model.ActionDelete},
		{"GET", "/api/v1/approver-scopes", "/api/v1/approver-scopes", model.ActionRead},
		{"POST", "/api/v1/access-requests/:id/approve", "/api/v1/access-requests/5/approve", model.ActionApprove},
		{"POST", "/api/v1/access-requests/:id/reject", "/api/v1/access-requests/5/reject", model.ActionReject},
		{"POST", "/api/v1/access-requests/:id/cancel", "/api/v1/access-requests/5/cancel", model.ActionCancel},
		// break-glass-revocation：撤銷/補審動作；GET reviews/pending 不落 review
		{"POST", "/api/v1/access-requests/:id/revoke", "/api/v1/access-requests/5/revoke", model.ActionRevoke},
		{"POST", "/api/v1/access-requests/:id/review", "/api/v1/access-requests/5/review", model.ActionReview},
		{"GET", "/api/v1/access-requests/reviews/pending", "/api/v1/access-requests/reviews/pending", model.ActionRead},
		{"POST", "/api/v1/access-requests/break-glass", "/api/v1/access-requests/break-glass", model.ActionCreate},
	}
	for _, tc := range cases {
		var action model.AuditAction
		r := gin.New()
		r.Handle(tc.method, tc.route, func(c *gin.Context) {
			action, _, _ = parseRoute(c)
		})
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(tc.method, tc.reqURL, nil))
		if action != tc.want {
			t.Errorf("%s %s: action = %s, want %s", tc.method, tc.route, action, tc.want)
		}
	}
}

// TestBatch2FamiliesNoForgedAssetID A 類接線的**假 asset_id 迴歸**
// （audit-resource-classification-closure 批 2）。
//
// **釘子打在哪**：斷言打在 `audit_logs` 實列而非 `extractResource` 的回傳值，
// 因為缺陷本體是「寫進去的那一列長什麼樣」。中介層由
// `resource == ResourceAsset && resource_id != nil` 無條件推導 `asset_id`
// （`audit_log.go:134-137`），於是接線前 `PUT /api/v1/user-groups/7` 寫出的是
// `resource=asset, resource_id=7, asset_id=7`——稽核工作台的資產樞紐只認
// `asset_id`（`timeline_service.go:350-358`），第 7 號**資產**的時間軸上因此
// 長出一筆使用者群組編輯。那不是分類不精確，是假事件。
//
// 對照組（`/assets/:id`）是本測試的反假綠錨：它證明 `asset_id` 推導本身仍在
// 運作，`asset_id == nil` 的斷言不是因為機制壞掉而恆真。
func TestBatch2FamiliesNoForgedAssetID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := installClipboardAuditDB(t)

	svc := audit.NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false,
	})
	r := gin.New()
	r.Use(AuditLogMiddleware(svc))
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(9))
		c.Set("username", "auditor")
		c.Next()
	})
	ok := func(c *gin.Context) { c.JSON(200, gin.H{}) }

	cases := []struct {
		name     string
		method   string
		route    string
		reqURL   string
		want     model.AuditResource
		wantID   *uint
		wantAsst *uint // 期望的 asset_id；四族一律 nil
	}{
		// 帶 `:id` 者＝訂正前的假事件注入路由（proposal 列的 17 條中的 5 條）
		{"存取複審單讀取", "GET", "/api/v1/access-reviews/:id", "/api/v1/access-reviews/7",
			model.ResourceAccessReview, uintPtr(7), nil},
		{"群組更新", "PUT", "/api/v1/user-groups/:id", "/api/v1/user-groups/7",
			model.ResourceUserGroup, uintPtr(7), nil},
		{"群組刪除", "DELETE", "/api/v1/user-groups/:id", "/api/v1/user-groups/7",
			model.ResourceUserGroup, uintPtr(7), nil},
		{"群組成員異動", "PUT", "/api/v1/user-groups/:id/members", "/api/v1/user-groups/7/members",
			model.ResourceUserGroup, uintPtr(7), nil},
		{"群組授權計數", "GET", "/api/v1/user-groups/:id/authorization-count", "/api/v1/user-groups/7/authorization-count",
			model.ResourceUserGroup, uintPtr(7), nil},
		// 無 `:id` 者：不產生假 asset_id，但分類仍須離開 asset（否則整族在
		// 資源篩選上與資產操作同形）
		{"傳輸清冊讀取", "GET", "/api/v1/transmission-inventory", "/api/v1/transmission-inventory",
			model.ResourceTransmission, nil, nil},
		{"傳輸清冊匯出", "POST", "/api/v1/transmission-inventory/export", "/api/v1/transmission-inventory/export",
			model.ResourceTransmission, nil, nil},
		{"傳輸同意立據", "POST", "/api/v1/transmission-consents", "/api/v1/transmission-consents",
			model.ResourceTransmission, nil, nil},
		{"連線票證簽發", "POST", "/api/v1/connect-tokens", "/api/v1/connect-tokens",
			model.ResourceSession, nil, nil},
		// 反假綠對照：資產端點的 asset_id 推導必須仍然成立，
		// 否則上面九條的 `asset_id == nil` 只是機制壞掉的副作用
		{"對照組：資產更新仍填 asset_id", "PUT", "/api/v1/assets/:id", "/api/v1/assets/7",
			model.ResourceAsset, uintPtr(7), uintPtr(7)},
	}

	registered := map[string]bool{}
	for _, tc := range cases {
		if key := tc.method + " " + tc.route; !registered[key] {
			registered[key] = true
			r.Handle(tc.method, tc.route, ok)
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(tc.method, tc.reqURL, nil))
			if w.Code != 200 {
				t.Fatalf("請求應被受理（釘子須打在真正寫出審計列的請求上），得 %d", w.Code)
			}
			row := latestAuditRow(t, db)
			if row.Path != tc.reqURL {
				t.Fatalf("讀回的不是本次請求的列（path=%s，期望 %s）——連線池或排序有問題",
					row.Path, tc.reqURL)
			}
			if row.Resource != tc.want {
				t.Errorf("resource = %s, want %s（分類器是否漏了該路徑段而落兜底 asset？）",
					row.Resource, tc.want)
			}
			if !uintPtrEqual(row.ResourceID, tc.wantID) {
				t.Errorf("resource_id = %v, want %v", derefUint(row.ResourceID), derefUint(tc.wantID))
			}
			if !uintPtrEqual(row.AssetID, tc.wantAsst) {
				t.Errorf("asset_id = %v, want %v（非資產實體的 id 灌進 asset_id 即為假事件："+
					"稽核工作台的資產樞紐只認本欄，同號資產的時間軸會長出別人的操作）",
					derefUint(row.AssetID), derefUint(tc.wantAsst))
			}
		})
	}
}

// TestBatch3FamiliesAndSentinelNoForgedAssetID A 類新分類與**兜底哨兵**的假
// asset_id 迴歸（audit-resource-classification-closure 批 3）。
//
// 與批 2 的同型測試（`TestBatch2FamiliesNoForgedAssetID`）差別只在一處，
// 而那一處正是本批的重點：批 2 修的是「這五族該歸哪一類」，本批除了再修十族，
// 還把**兜底本身**換掉。故本測試多一格「分類器不認得的路徑」——它模擬的不是
// 假想威脅，而是本 change 反覆量到的現實：新端點上線時沒人碰 `extractResource`，
// 測試全綠、路由 golden 也全綠（golden 不記分類），漏是**預設值**。
// 兜底為 asset 時那條新端點會立刻在同號資產的時間軸上長出假事件；
// 兜底為哨兵後，它只是一列可計數、可篩選、可告警的 `resource=unclassified`。
//
// 對照組（`/assets/:id`）同樣是反假綠錨：證明 asset_id 推導機制仍在運作，
// 上方各格的 `asset_id == nil` 不是機制壞掉的副作用。
func TestBatch3FamiliesAndSentinelNoForgedAssetID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := installClipboardAuditDB(t)

	svc := audit.NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false,
	})
	r := gin.New()
	r.Use(AuditLogMiddleware(svc))
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(9))
		c.Set("username", "auditor")
		c.Next()
	})
	ok := func(c *gin.Context) { c.JSON(200, gin.H{}) }

	cases := []struct {
		name     string
		method   string
		route    string
		reqURL   string
		want     model.AuditResource
		wantID   *uint
		wantAsst *uint
	}{
		// 帶 `:id` 者＝訂正前的假事件注入路由（proposal 列的 17 條中的 12 條）
		{"告警規則更新", "PUT", "/api/v1/alert-rules/:id", "/api/v1/alert-rules/7",
			model.ResourceAlertRule, uintPtr(7), nil},
		{"資產分組更名", "PUT", "/api/v1/asset-groups/:id", "/api/v1/asset-groups/7",
			model.ResourceAssetGroup, uintPtr(7), nil},
		{"資產分組搬移", "PUT", "/api/v1/asset-groups/:id/move", "/api/v1/asset-groups/7/move",
			model.ResourceAssetGroup, uintPtr(7), nil},
		{"通知通道刪除", "DELETE", "/api/v1/notification-channels/:id", "/api/v1/notification-channels/7",
			model.ResourceNotifyChannel, uintPtr(7), nil},
		{"OIDC 提供者更新", "PUT", "/api/v1/oidc-providers/:id", "/api/v1/oidc-providers/7",
			model.ResourceOIDCProvider, uintPtr(7), nil},
		{"指令片段刪除", "DELETE", "/api/v1/snippets/:id", "/api/v1/snippets/7",
			model.ResourceSnippet, uintPtr(7), nil},
		// 無 `:id` 者：不產生假 asset_id，但分類仍須離開 asset
		{"檢查點鏈驗證", "GET", "/api/v1/audit-checkpoints/verify", "/api/v1/audit-checkpoints/verify?seq_from=1&seq_to=9",
			model.ResourceAuditCheckpoint, nil, nil},
		{"審計失效事件讀取", "GET", "/api/v1/audit-failures", "/api/v1/audit-failures",
			model.ResourceAuditFailure, nil, nil},
		{"完整性驗證", "GET", "/api/v1/audit-integrity/verify", "/api/v1/audit-integrity/verify",
			model.ResourceAuditIntegrity, nil, nil},
		{"LDAP 目錄設定更新", "PUT", "/api/v1/ldap-directory", "/api/v1/ldap-directory",
			model.ResourceLDAPDirectory, nil, nil},
		{"角色清單讀取", "GET", "/api/v1/roles", "/api/v1/roles",
			model.ResourceRole, nil, nil},
		// **兜底哨兵**：分類器不認得的新端點。resource 落哨兵、resource_id 照樣
		// 由 `c.Param("id")` 機械取得，但 asset_id **必須**為 nil——
		// 「遺漏」從此不再被升級為「假事件」
		{"哨兵：未分類的新端點不冒充資產", "PUT", "/api/v1/unwired-new-feature/:id", "/api/v1/unwired-new-feature/7",
			model.ResourceUnclassified, uintPtr(7), nil},
		// 反假綠對照：資產端點的 asset_id 推導必須仍然成立
		{"對照組：資產更新仍填 asset_id", "PUT", "/api/v1/assets/:id", "/api/v1/assets/7",
			model.ResourceAsset, uintPtr(7), uintPtr(7)},
	}

	registered := map[string]bool{}
	for _, tc := range cases {
		if key := tc.method + " " + tc.route; !registered[key] {
			registered[key] = true
			r.Handle(tc.method, tc.route, ok)
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(tc.method, tc.reqURL, nil))
			if w.Code != 200 {
				t.Fatalf("請求應被受理（釘子須打在真正寫出審計列的請求上），得 %d", w.Code)
			}
			row := latestAuditRow(t, db)
			if row.Resource != tc.want {
				t.Errorf("resource = %s, want %s（分類器是否漏了該路徑段，或兜底被改回真實類別？）",
					row.Resource, tc.want)
			}
			if !uintPtrEqual(row.ResourceID, tc.wantID) {
				t.Errorf("resource_id = %v, want %v", derefUint(row.ResourceID), derefUint(tc.wantID))
			}
			if !uintPtrEqual(row.AssetID, tc.wantAsst) {
				t.Errorf("asset_id = %v, want %v（非資產實體的 id 灌進 asset_id 即為假事件："+
					"稽核工作台的資產樞紐只認本欄，同號資產的時間軸會長出別人的操作）",
					derefUint(row.AssetID), derefUint(tc.wantAsst))
			}
		})
	}
}

// TestSensitiveAuditResourcesRecordQueryScope 三個審計端點分類入敏感讀取集合
// （批 3 的 3.3）：GET 須另記查詢範圍摘要，「誰以什麼條件驗了鏈」才答得出來。
//
// 對照組是同批新增、**刻意不入**集合的設定面分類（3.4）——沒有它，
// 「details 非空」可能只是因為中介層對所有 GET 都記摘要，斷言便與集合無關。
func TestSensitiveAuditResourcesRecordQueryScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := installClipboardAuditDB(t)

	svc := audit.NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false,
	})
	r := gin.New()
	r.Use(AuditLogMiddleware(svc))
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(9))
		c.Set("username", "auditor")
		c.Next()
	})
	ok := func(c *gin.Context) { c.JSON(200, gin.H{}) }

	cases := []struct {
		name        string
		route       string
		reqURL      string
		wantDetails bool
	}{
		{"檢查點鏈驗證記查詢範圍", "/api/v1/audit-checkpoints/verify",
			"/api/v1/audit-checkpoints/verify?seq_from=1&seq_to=9", true},
		{"審計失效事件讀取記查詢範圍", "/api/v1/audit-failures",
			"/api/v1/audit-failures?status=open", true},
		{"完整性驗證記查詢範圍", "/api/v1/audit-integrity/verify",
			"/api/v1/audit-integrity/verify?start=2026-08-01", true},
		// 對照組：設定面讀取不入敏感集合，故不另記摘要（3.4 的裁決）
		{"對照組：告警規則列表不記摘要", "/api/v1/alert-rules",
			"/api/v1/alert-rules?page=1", false},
		{"對照組：資產分組樹不記摘要", "/api/v1/asset-groups/tree",
			"/api/v1/asset-groups/tree?depth=2", false},
	}

	for _, tc := range cases {
		r.GET(tc.route, ok)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest("GET", tc.reqURL, nil))
			if w.Code != 200 {
				t.Fatalf("請求應被受理，得 %d", w.Code)
			}
			row := latestAuditRow(t, db)
			if got := row.Details != ""; got != tc.wantDetails {
				t.Errorf("details 非空 = %v, want %v（details=%q）——"+
					"審計資料讀取須記查詢範圍摘要，設定面讀取則否",
					got, tc.wantDetails, row.Details)
			}
			if tc.wantDetails && !strings.Contains(row.Details, "query") {
				t.Errorf("details 未含 query 鍵：%q——摘要沒有查詢條件等於形式留痕、實質失憶",
					row.Details)
			}
		})
	}
}

func uintPtr(v uint) *uint { return &v }

func uintPtrEqual(a, b *uint) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func derefUint(p *uint) any {
	if p == nil {
		return nil
	}
	return *p
}

// TestParseRoute_MyConnectionTerminate 自助終止的審計形狀：
// action=delete（terminate 視為 delete，與 admin 終止一致）、resource=session、id 可提取
func TestParseRoute_MyConnectionTerminate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var action model.AuditAction
	var resource model.AuditResource
	var resourceID *uint

	r := gin.New()
	r.POST("/api/v1/my/connections/:id/terminate", func(c *gin.Context) {
		action, resource, resourceID = parseRoute(c)
	})
	req := httptest.NewRequest("POST", "/api/v1/my/connections/42/terminate", nil)
	r.ServeHTTP(httptest.NewRecorder(), req)

	if action != model.ActionDelete {
		t.Errorf("action = %s, want delete", action)
	}
	if resource != model.ResourceSession {
		t.Errorf("resource = %s, want session", resource)
	}
	if resourceID == nil || *resourceID != 42 {
		t.Errorf("resourceID = %v, want 42", resourceID)
	}
}
