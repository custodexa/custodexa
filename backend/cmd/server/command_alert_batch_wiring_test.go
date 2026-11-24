package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestCommandAlertBatchReviewAssemblyWritesAudit 以正式組裝函式建 handler，批次審閱一次成功並寫出稽核列。
//
// 擋的威脅：交易內稽核落地面沒接上時批次審閱整批回滾（方向安全），但端點在正式環境恆回 500，
// 而服務層與路由層測試都自行注入、照樣全綠。
func TestCommandAlertBatchReviewAssemblyWritesAudit(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.AutoMigrate(&model.AuditLog{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`CREATE TABLE command_alerts (id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id INTEGER, rule_name TEXT NOT NULL DEFAULT 'r', session_id INTEGER NOT NULL DEFAULT 0,
		user_id INTEGER NOT NULL DEFAULT 3, asset_id INTEGER, command TEXT NOT NULL DEFAULT '',
		severity TEXT NOT NULL DEFAULT 'high', triggered_at DATETIME NOT NULL, reviewed_by INTEGER, reviewed_at DATETIME,
		disposition TEXT NOT NULL DEFAULT 'pending', note TEXT NOT NULL DEFAULT '', blocked BOOLEAN NOT NULL DEFAULT 0,
		kind TEXT NOT NULL DEFAULT 'rule', reason_code TEXT NOT NULL DEFAULT '')`).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`INSERT INTO command_alerts (user_id, triggered_at) VALUES (3, ?)`, time.Now().UTC()).Error; err != nil {
		t.Fatal(err)
	}
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })

	h := newCommandAlertHandler(db, audit.NewTxSink(), audit.NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true}))
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/v1/command-alerts/batch-review", func(c *gin.Context) {
		c.Set("userID", uint(8))
		c.Set("username", "auditor-8")
		c.Next()
	}, h.BatchReview)
	body := `{"alert_ids":[1],"disposition":"benign","note":"例行","batch_id":"5d1c0b7a-2e3f-4a5b-9c8d-7e6f5a4b3c2d","self_triggered_ack":0}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/command-alerts/batch-review", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("正式組裝的批次審閱 = %d (%s), want 200", w.Code, w.Body.String())
	}
	var n int64
	db.Model(&model.AuditLog{}).Where("resource = ? AND resource_id = 1", model.ResourceCommandAlert).Count(&n)
	if n != 1 {
		t.Fatalf("處置稽核列 %d, want 1", n)
	}

	// stage2 的正式組裝經由這個函式（不另組一份沒有注入落地面的 handler）
	src, err := os.ReadFile("stage2.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	if !strings.Contains(text, "commandAlertHandler := newCommandAlertHandler(database.DB, s.auditTxSink, s.auditService)") ||
		strings.Count(text, "api.NewCommandAlertHandler(") != 1 {
		t.Fatal("stage2.go 應以 newCommandAlertHandler 組裝告警審閱 handler，且只有一處建構")
	}
}
