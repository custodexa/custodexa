package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// summaryDeleteService 刪除回固定摘要的替身（其餘方法沿用 MockUserService）
type summaryDeleteService struct {
	MockUserService
	summary identity.DeletedUserSummary
}

func (s *summaryDeleteService) DeleteWithSummary(uint) (identity.DeletedUserSummary, error) {
	return s.summary, nil
}

// TestDeleteUserAuditCarriesTargetUsername 經真審計中介層刪除帳號：列上的操作者
// 維持原樣，details 另帶被刪帳號名與作廢的外部身分綁定數
func TestDeleteUserAuditCarriesTargetUsername(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.AuditLog{}); err != nil {
		t.Fatalf("migrate audit_logs: %v", err)
	}
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })

	gin.SetMode(gin.TestMode)
	svc := audit.NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true})
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(svc))
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(1))
		c.Set("username", "operator")
		c.Next()
	})
	h := NewUserHandler(&summaryDeleteService{summary: identity.DeletedUserSummary{
		Username: "alice", ExternalIdentitiesRevoked: 1,
	}})
	r.DELETE("/api/v1/users/:id", h.Delete)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/api/v1/users/42", nil))
	if w.Code != 200 {
		t.Fatalf("刪除應成功，得 %d：%s", w.Code, w.Body.String())
	}

	var rows []model.AuditLog
	if err := db.Find(&rows).Error; err != nil {
		t.Fatalf("讀 audit_logs: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("audit_logs 應恰一筆，得 %d", len(rows))
	}
	row := rows[0]
	if row.Username != "operator" || row.UserID != 1 {
		t.Errorf("操作者 = (%d, %q), want (1, operator)", row.UserID, row.Username)
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(row.Details), &details); err != nil {
		t.Fatalf("details 非 JSON 物件: %q (%v)", row.Details, err)
	}
	for k, want := range map[string]string{
		"event": "user_deleted", "target_username": "alice", "external_identities_revoked": "1",
	} {
		if details[k] != want {
			t.Errorf("details.%s = %q, want %q（details=%s）", k, details[k], want, row.Details)
		}
	}
}
