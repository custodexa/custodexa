package middleware

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"gorm.io/gorm"
)

// 會話內取證動作的留痕守衛（PCI 10.2.1.3）。
//
// **釘子打在哪**：`/sessions/:id/recording{,/download,/stream,/token}` 取走的是
// 終端畫面錄影本體，`/sessions/:id/commands` 取走的是被監控者輸入的指令原文。
// 訂正前兩族都歸 `session`——與「看了一眼連線詳情」在 resource 欄**同形**，
// 稽核要分辨「誰取走了證物」只剩不可索引的 path 散文可用。跨會話 `/commands`
// 早已是敏感資源而單會話反而不是，這個不對稱本身就是缺陷的指紋。
//
// 斷言打在 **audit_logs 實列**上（非 extractResource 的回傳值），因為缺口是
// 「寫進去的那一列長什麼樣」——分類正確但摘要恆空，一樣答不出「取的是哪一場」：
//   - resource 為專屬分類（recording／command），可直接以資源欄篩出取證動作
//   - details 非空且含 session_id，即取證的範圍鍵
//   - 與同一連線的一般讀取（resource=session）在 resource 欄分得開
//
// **突變自證**（還原一律用事前 cp 快照，禁用 git checkout）：
// 把 model.ResourceRecording 自 auditSensitiveResources 移除 → details 恆空 →
// TestRecordingRetrievalRecordsSessionScope 轉紅；
// 把 extractResource 的前置特判段刪掉 → resource 退回 session → 三個案例皆紅。

// sensitiveReadRouter 掛真的 AuditLogMiddleware ＋ 會話內取證路由。
// 路由字面與 RecordingHandler／SessionCommandHandler 的註冊一致（路徑本身由 route golden 釘）。
func sensitiveReadRouter(t *testing.T) (*gin.Engine, *gorm.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db := installClipboardAuditDB(t)

	svc := audit.NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false,
	})
	r := gin.New()
	r.Use(AuditLogMiddleware(svc))
	// 審計 middleware 只在 context 有身分時記錄；認證本身不在射程內
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(9))
		c.Set("username", "auditor")
		c.Next()
	})
	ok := func(c *gin.Context) { c.JSON(200, gin.H{}) }
	r.GET("/api/v1/sessions/:id/recording", ok)
	r.GET("/api/v1/sessions/:id/recording/download", ok)
	r.GET("/api/v1/sessions/:id/commands", ok)
	r.GET("/api/v1/sessions/:id", ok)
	// 跨會話對照：既有分類不得因前置特判而漂移
	r.GET("/api/v1/commands", ok)
	r.GET("/api/v1/recordings/stats", ok)
	return r, db
}

func sensitiveReadSummary(t *testing.T, row model.AuditLog) map[string]string {
	t.Helper()
	if row.Details == "" {
		t.Fatalf("details 為空——「他取走了哪一場連線的證物」答不出來"+
			"（分類 %s 是否已自 auditSensitiveResources 移除？）", row.Resource)
	}
	var summary map[string]string
	if err := json.Unmarshal([]byte(row.Details), &summary); err != nil {
		t.Fatalf("details 非 JSON 物件: %q (%v)", row.Details, err)
	}
	return summary
}

// TestRecordingRetrievalRecordsSessionScope 錄影調閱寫出的審計列須帶專屬資源
// 分類與含連線範圍的摘要。中繼資料與下載本體皆屬同一取證族。
func TestRecordingRetrievalRecordsSessionScope(t *testing.T) {
	r, db := sensitiveReadRouter(t)

	for _, path := range []string{
		"/api/v1/sessions/73/recording",
		"/api/v1/sessions/73/recording/download",
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 {
			t.Fatalf("%s 應成功（釘子須打在真正被受理的請求上），得 %d", path, w.Code)
		}

		row := latestAuditRow(t, db)
		if row.Resource != model.ResourceRecording {
			t.Errorf("%s: resource = %s, want %s（取走錄影本體須能以資源欄篩出，退回 session 即不可辨識）",
				path, row.Resource, model.ResourceRecording)
		}
		if row.Action != model.ActionRead {
			t.Errorf("%s: action = %s, want read", path, row.Action)
		}
		if row.ResourceID == nil || *row.ResourceID != 73 {
			t.Errorf("%s: resource_id = %v, want 73（範圍鍵＝連線 id）", path, row.ResourceID)
		}
		// resource 不再是 asset ⇒ asset_id 推導不生效（audit_log.go 的資產主體鍵）
		if row.AssetID != nil {
			t.Errorf("%s: asset_id = %v, want nil（錄影調閱的主體是連線不是資產）", path, row.AssetID)
		}
		if got := sensitiveReadSummary(t, row)["session_id"]; got != "73" {
			t.Errorf("%s: details.session_id = %q, want \"73\"（實得 details=%s）", path, got, row.Details)
		}
	}
}

// TestSessionCommandsRetrievalRecordsSessionScope 單會話指令查詢寫出的審計列。
// 訂正前它歸 session，於是「跨會話查指令是敏感的、查單一連線的指令反而不是」——
// 本案例釘住那個不對稱不得復發。
func TestSessionCommandsRetrievalRecordsSessionScope(t *testing.T) {
	r, db := sensitiveReadRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/sessions/73/commands?limit=50", nil))
	if w.Code != 200 {
		t.Fatalf("讀取應成功，得 %d", w.Code)
	}

	row := latestAuditRow(t, db)
	if row.Resource != model.ResourceCommand {
		t.Errorf("resource = %s, want %s（指令原文取證須與一般連線讀取分得開）",
			row.Resource, model.ResourceCommand)
	}
	if row.ResourceID == nil || *row.ResourceID != 73 {
		t.Errorf("resource_id = %v, want 73（範圍鍵＝連線 id）", row.ResourceID)
	}
	if row.AssetID != nil {
		t.Errorf("asset_id = %v, want nil", row.AssetID)
	}
	summary := sensitiveReadSummary(t, row)
	if summary["session_id"] != "73" {
		t.Errorf("details.session_id = %q, want \"73\"（實得 details=%s）", summary["session_id"], row.Details)
	}
	if summary["query"] != "limit=50" {
		t.Errorf("details.query = %q, want \"limit=50\"（查詢條件仍須留痕）", summary["query"])
	}
}

// TestEvidenceRetrievalDistinctFromSessionRead 同一場連線的三種讀取須在 resource
// 欄兩兩分得開——這是 B 類判準的本體：分類正確 ≠ 分類可辨識。
func TestEvidenceRetrievalDistinctFromSessionRead(t *testing.T) {
	r, db := sensitiveReadRouter(t)

	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/v1/sessions/73", nil))
	plain := latestAuditRow(t, db)
	if plain.Resource != model.ResourceSession {
		t.Fatalf("一般連線讀取 resource = %s, want session（既有行為不得漂移）", plain.Resource)
	}
	if plain.Details != "" {
		t.Errorf("一般連線讀取不應附摘要，得 details=%s", plain.Details)
	}

	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/v1/sessions/73/recording/download", nil))
	recording := latestAuditRow(t, db)
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/v1/sessions/73/commands", nil))
	commands := latestAuditRow(t, db)

	if recording.Resource == plain.Resource {
		t.Errorf("錄影調閱與一般連線讀取的 resource 同為 %s——稽核無從以資源分類辨識取證動作",
			recording.Resource)
	}
	if commands.Resource == plain.Resource {
		t.Errorf("指令查詢與一般連線讀取的 resource 同為 %s——同上", commands.Resource)
	}
	if recording.Resource == commands.Resource {
		t.Errorf("兩種取證動作的 resource 同為 %s——取的是錄影還是指令原文答不出來",
			recording.Resource)
	}
}

// TestCrossSessionEndpointsKeepNilScope 跨會話端點的既有形狀不得漂移：
// 分類不變、resource_id 恆為 nil（無 :id）、摘要退化為只有 query 一鍵。
// nil 正是 AuditHubSubResources 入列判準得以放寬的前提——nil 不匹配任何樞紐 id，
// 故跨會話列不可能被撈進某一場連線的樞紐。
func TestCrossSessionEndpointsKeepNilScope(t *testing.T) {
	cases := []struct {
		path string
		want model.AuditResource
	}{
		{"/api/v1/commands?session_id=73", model.ResourceCommand},
		{"/api/v1/recordings/stats", model.ResourceRecording},
	}
	for _, tc := range cases {
		r, db := sensitiveReadRouter(t)
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", tc.path, nil))
		row := latestAuditRow(t, db)
		if row.Resource != tc.want {
			t.Errorf("%s: resource = %s, want %s（跨會話端點的既有分類不得漂移）",
				tc.path, row.Resource, tc.want)
		}
		if row.ResourceID != nil {
			t.Errorf("%s: resource_id = %v, want nil——非 nil 會使該列被連線樞紐撈進去（假事件）",
				tc.path, *row.ResourceID)
		}
		if row.Details != "" {
			if _, ok := sensitiveReadSummary(t, row)["session_id"]; ok {
				t.Errorf("%s: 摘要不應有 session_id（該端點無 :id），實得 details=%s", tc.path, row.Details)
			}
		}
	}
}
