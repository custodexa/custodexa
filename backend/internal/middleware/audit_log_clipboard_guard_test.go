package middleware

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 剪貼簿證物讀取的留痕守衛（PCI 10.2.1.3）。
//
// **釘子打在哪**：GET /api/v1/sessions/:id/clipboard-events 取走的是
// ClipboardEvent.Content——64KB 明文欄，是調查流程中的證物。稽核歷程若只記得到
// 「某人呼叫了這個端點」而 resource 欄與一般連線讀取同形，「他取走了哪些證物」
// 就必須靠不可索引的 path 散文去撈。
//
// 本檔斷言打在 **audit_logs 實列**上（非 extractResource 的回傳值），因為缺口是
// 「寫進去的那一列長什麼樣」：
//   - resource 為專屬分類（clipboard_event），可直接以資源欄篩出取證動作
//   - details 非空且含 session_id，即「取的是哪一場連線的證物」
//
// **突變自證**：把 model.ResourceClipboardEvent 自 auditSensitiveResources 移除
// → details 恆空 → TestClipboardReadRecordsQueryScope 轉紅；
// 把 extractResource 的剪貼簿優先判定刪掉 → resource 退回 session → 同測試轉紅。

// installClipboardAuditDB 裝一個最小的 database.DB 並回傳它，供斷言讀回實列。
// 同步寫入（AsyncAuditEnabled=false）以免 worker 批次帶入時序不確定。
func installClipboardAuditDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	// sqlite :memory: 每條新連線是一個獨立的空 DB；連線池收到 1 才能讓
	// middleware 的寫入與本測試的讀回落在同一個 DB 上
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("取底層 sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.AuditLog{}); err != nil {
		t.Fatalf("migrate audit_logs: %v", err)
	}
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })
	return db
}

// clipboardAuditRouter 掛真的 AuditLogMiddleware ＋ 剪貼簿讀取路由。
// 路由字面與 ClipboardEventHandler.RegisterRoutes 一致（路徑本身由 route golden 釘）
func clipboardAuditRouter(t *testing.T) (*gin.Engine, *gorm.DB) {
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
	r.GET("/api/v1/sessions/:id/clipboard-events", func(c *gin.Context) {
		c.JSON(200, gin.H{"data": []any{}, "total": 0})
	})
	r.GET("/api/v1/sessions/:id", func(c *gin.Context) { c.JSON(200, gin.H{}) })
	// 既有敏感資源的對照：摘要組裝由單鍵 map 改為累積 map 時，這條確保
	// 既有形狀（只有 query 一鍵）未漂移
	r.GET("/api/v1/audit-logs", func(c *gin.Context) { c.JSON(200, gin.H{}) })
	return r, db
}

func latestAuditRow(t *testing.T, db *gorm.DB) model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	if err := db.Order("id DESC").Limit(1).Find(&rows).Error; err != nil {
		t.Fatalf("讀 audit_logs: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("未產生任何審計列——守衛失去觀測對象（middleware 未生效？）")
	}
	return rows[0]
}

// TestClipboardReadRecordsQueryScope 剪貼簿讀取寫出的審計列須帶專屬資源分類
// 與含查詢範圍的摘要
func TestClipboardReadRecordsQueryScope(t *testing.T) {
	r, db := clipboardAuditRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/sessions/73/clipboard-events", nil))
	if w.Code != 200 {
		t.Fatalf("讀取應成功（釘子須打在真正被受理的請求上），得 %d", w.Code)
	}

	row := latestAuditRow(t, db)
	if row.Resource != model.ResourceClipboardEvent {
		t.Errorf("resource = %s, want %s（取證動作須能以資源欄篩出，退回 session 即不可辨識）",
			row.Resource, model.ResourceClipboardEvent)
	}
	if row.Action != model.ActionRead {
		t.Errorf("action = %s, want read", row.Action)
	}
	if row.ResourceID == nil || *row.ResourceID != 73 {
		t.Errorf("resource_id = %v, want 73（範圍鍵＝連線 id）", row.ResourceID)
	}
	if row.Details == "" {
		t.Fatal("details 為空——「他取走了哪一場連線的證物」答不出來（分類是否已自 auditSensitiveResources 移除？）")
	}
	var summary map[string]string
	if err := json.Unmarshal([]byte(row.Details), &summary); err != nil {
		t.Fatalf("details 非 JSON 物件: %q (%v)", row.Details, err)
	}
	if summary["session_id"] != "73" {
		t.Errorf("details.session_id = %q, want \"73\"（實得 details=%s）", summary["session_id"], row.Details)
	}
}

// TestSensitiveResourceQuerySummaryUnchanged 既有敏感資源的摘要形狀不得因
// 剪貼簿的加入而漂移：帶 query string 時恰為 {"query": ...}，無多餘鍵
func TestSensitiveResourceQuerySummaryUnchanged(t *testing.T) {
	r, db := clipboardAuditRouter(t)

	r.ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest("GET", "/api/v1/audit-logs?user_id=3&action=read", nil))
	row := latestAuditRow(t, db)
	if row.Resource != model.ResourceAuditLog {
		t.Fatalf("resource = %s, want audit_log", row.Resource)
	}
	var summary map[string]string
	if err := json.Unmarshal([]byte(row.Details), &summary); err != nil {
		t.Fatalf("details 非 JSON 物件: %q (%v)", row.Details, err)
	}
	if len(summary) != 1 || summary["query"] != "user_id=3&action=read" {
		t.Errorf("details = %s, want 恰一鍵 {\"query\":\"user_id=3&action=read\"}", row.Details)
	}
}

// TestClipboardResourceDistinctFromSession 同一場連線的兩種讀取須在 resource 欄
// 分得開——否則「取走證物」會混在一般連線讀取裡
func TestClipboardResourceDistinctFromSession(t *testing.T) {
	r, db := clipboardAuditRouter(t)

	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/v1/sessions/73", nil))
	plain := latestAuditRow(t, db)
	if plain.Resource != model.ResourceSession {
		t.Fatalf("一般連線讀取 resource = %s, want session（既有行為不得漂移）", plain.Resource)
	}
	if plain.Details != "" {
		t.Errorf("一般連線讀取不應附摘要，得 details=%s", plain.Details)
	}

	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/v1/sessions/73/clipboard-events", nil))
	evidence := latestAuditRow(t, db)
	if evidence.Resource == plain.Resource {
		t.Errorf("剪貼簿取證與一般連線讀取的 resource 同為 %s——稽核無從以資源分類辨識取證動作",
			evidence.Resource)
	}
}
