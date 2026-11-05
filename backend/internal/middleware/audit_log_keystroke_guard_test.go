package middleware

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// 鍵盤紀錄查看的請求層留痕守衛：兩支端點歸專屬資源、POST view 記為讀取、
// 摘要只帶連線 id（查詢字串不入摘要）、回應本文不被擷取。

const keystrokeMarker = "KS_MARKER_7f3a"

func keystrokeAuditRouter(t *testing.T) (*gin.Engine, *gorm.DB) {
	t.Helper()
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
	r.GET("/api/v1/sessions/:id/keystrokes", func(c *gin.Context) { c.JSON(200, gin.H{"state": "complete"}) })
	r.POST("/api/v1/sessions/:id/keystrokes/view", func(c *gin.Context) {
		c.JSON(200, gin.H{"events": []gin.H{{"data_b64": keystrokeMarker}}})
	})
	return r, db
}

func TestKeystrokeRoutesAuditClassification(t *testing.T) {
	r, db := keystrokeAuditRouter(t)

	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/v1/sessions/73/keystrokes", nil))
	meta := latestAuditRow(t, db)
	if meta.Resource != model.ResourceKeystrokeRecord || meta.Action != model.ActionRead {
		t.Fatalf("中繼資料讀取 resource/action = %s/%s, want keystroke_record/read", meta.Resource, meta.Action)
	}

	req := httptest.NewRequest("POST", "/api/v1/sessions/73/keystrokes/view?reason=in-the-url",
		strings.NewReader(`{"reason":"調查"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(httptest.NewRecorder(), req)
	view := latestAuditRow(t, db)
	if view.Resource != model.ResourceKeystrokeRecord {
		t.Errorf("查看 resource = %s, want keystroke_record", view.Resource)
	}
	if view.Action != model.ActionRead {
		t.Errorf("查看 action = %s, want read（POST 不得記為 create）", view.Action)
	}
	if view.ResourceID == nil || *view.ResourceID != 73 {
		t.Errorf("resource_id = %v, want 73", view.ResourceID)
	}
	var summary map[string]string
	if err := json.Unmarshal([]byte(view.Details), &summary); err != nil {
		t.Fatalf("details 非 JSON 物件（長度 %d）: %v", len(view.Details), err)
	}
	if len(summary) != 1 || summary["session_id"] != "73" {
		t.Errorf("details 應恰為 {session_id:73}（查詢字串不入摘要），鍵數=%d", len(summary))
	}
	if strings.Contains(view.Details, "in-the-url") {
		t.Error("查詢字串中的理由不得被記入審計摘要")
	}
}

func TestKeystrokeResponseNotCaptured(t *testing.T) {
	r, db := keystrokeAuditRouter(t)
	req := httptest.NewRequest("POST", "/api/v1/sessions/5/keystrokes/view", strings.NewReader(`{"reason":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(httptest.NewRecorder(), req)
	var rows []model.AuditLog
	if err := db.Find(&rows).Error; err != nil || len(rows) == 0 {
		t.Fatalf("讀 audit_logs: %v rows=%d", err, len(rows))
	}
	for _, row := range rows {
		blob, _ := json.Marshal(row)
		if strings.Contains(string(blob), keystrokeMarker) {
			t.Fatal("審計列含查看回應的內容標記（回應本文不得被擷取）")
		}
	}
}

func TestExtractResourceKeystrokesBeforeSessions(t *testing.T) {
	for _, p := range []string{"/api/v1/sessions/:id/keystrokes", "/api/v1/sessions/:id/keystrokes/view"} {
		if got := extractResource(p); got != model.ResourceKeystrokeRecord {
			t.Errorf("%s -> %s, want keystroke_record", p, got)
		}
	}
}
