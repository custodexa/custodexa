package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
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

// lifecycleGuardedService 停用與刪除走帶操作者入口的替身：記下收到的操作者，回指定錯誤
type lifecycleGuardedService struct {
	MockUserService
	err      error
	statusOp *identity.Operator
	deleteOp *identity.Operator
}

func (s *lifecycleGuardedService) UpdateStatusBy(op identity.Operator, _ uint, _ bool) error {
	s.statusOp = &op
	return s.err
}

func (s *lifecycleGuardedService) DeleteWithSummaryBy(op identity.Operator, _ uint) (identity.DeletedUserSummary, error) {
	s.deleteOp = &op
	return identity.DeletedUserSummary{}, s.err
}

func newLifecycleAuditRouter(t *testing.T, svc UserServiceInterface) (*gin.Engine, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.AuditLog{}, &model.Role{}, &model.UserGroup{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.AutoMigrate(&model.UserRole{}, &model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })

	gin.SetMode(gin.TestMode)
	auditSvc := audit.NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true})
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(auditSvc))
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(7))
		c.Set("username", "ida")
		c.Next()
	})
	h := NewUserHandler(svc)
	r.DELETE("/api/v1/users/:id", h.Delete)
	r.PUT("/api/v1/users/:id/status", h.UpdateStatus)
	return r, db
}

// TestUserLifecycleProtectedRefusal 停用、啟用與刪除經帶操作者入口；關卡拒絕回 403 機器碼，
// 該次請求的審計列記失敗並帶事件與原因碼（不帶角色名）。
func TestUserLifecycleProtectedRefusal(t *testing.T) {
	cases := []struct {
		name, method, path, body, event string
	}{
		{"停用", "PUT", "/api/v1/users/42/status", `{"active":false}`, "user_disable_rejected"},
		{"啟用", "PUT", "/api/v1/users/42/status", `{"active":true}`, "user_enable_rejected"},
		{"刪除", "DELETE", "/api/v1/users/42", "", "user_delete_rejected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &lifecycleGuardedService{err: identity.ErrProtectedAccountOperation}
			r, db := newLifecycleAuditRouter(t, svc)
			w := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)

			if w.Code != 403 {
				t.Fatalf("應 403，得 %d：%s", w.Code, w.Body.String())
			}
			var resp map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("回應非 JSON: %s", w.Body.String())
			}
			if resp["code"] != "AUTH_PROTECTED_ACCOUNT_OPERATION" {
				t.Errorf("code = %v, want AUTH_PROTECTED_ACCOUNT_OPERATION（body=%s）", resp["code"], w.Body.String())
			}
			for _, leak := range []string{"super_admin", "security_admin"} {
				if strings.Contains(w.Body.String(), leak) {
					t.Errorf("拒絕回應洩漏 %q", leak)
				}
			}
			op := svc.statusOp
			if tc.method == "DELETE" {
				op = svc.deleteOp
			}
			if op == nil || op.UserID != 7 || op.Username != "ida" {
				t.Fatalf("應以請求者為操作者呼叫帶操作者入口，得 %+v", op)
			}

			var rows []model.AuditLog
			if err := db.Find(&rows).Error; err != nil {
				t.Fatalf("讀 audit_logs: %v", err)
			}
			if len(rows) != 1 {
				t.Fatalf("audit_logs 應恰一筆，得 %d", len(rows))
			}
			row := rows[0]
			if row.Status != model.StatusDenied || row.StatusCode != 403 {
				t.Errorf("審計列 status=(%s,%d)，want (denied,403)", row.Status, row.StatusCode)
			}
			var details map[string]string
			if err := json.Unmarshal([]byte(row.Details), &details); err != nil {
				t.Fatalf("details 非 JSON 物件: %q (%v)", row.Details, err)
			}
			if details["event"] != tc.event || details["deny_reason"] != "protected_account" {
				t.Errorf("details = %s，want event=%s deny_reason=protected_account", row.Details, tc.event)
			}
		})
	}

	t.Run("一般帳號的停用照常成功且不帶拒絕原因", func(t *testing.T) {
		svc := &lifecycleGuardedService{}
		r, db := newLifecycleAuditRouter(t, svc)
		w := httptest.NewRecorder()
		req := httptest.NewRequest("PUT", "/api/v1/users/42/status", strings.NewReader(`{"active":false}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("應 200，得 %d：%s", w.Code, w.Body.String())
		}
		var rows []model.AuditLog
		if err := db.Find(&rows).Error; err != nil {
			t.Fatalf("讀 audit_logs: %v", err)
		}
		if len(rows) != 1 || strings.Contains(rows[0].Details, "deny_reason") {
			t.Errorf("成功列不應帶拒絕原因：%+v", rows)
		}
	})
}
