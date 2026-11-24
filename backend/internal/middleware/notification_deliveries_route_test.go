package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/gin-gonic/gin"
)

// 投遞紀錄唯讀路由：權限同通道管理能力；無權者 403 並留下 denied 審計列。
func TestNotificationDeliveriesRouteRequiresChannelManage(t *testing.T) {
	for _, tc := range []struct {
		role string
		want int
	}{
		{"user", http.StatusForbidden},
		{"admin", http.StatusOK},
	} {
		t.Run(tc.role, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			db := installClipboardAuditDB(t)
			svc := audit.NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true})
			r := gin.New()
			r.Use(AuditLogMiddleware(svc))
			r.Use(func(c *gin.Context) {
				c.Set("userID", uint(7))
				c.Set("username", "route-test")
				SetPrincipal(c, legacyPrincipal(tc.role))
				c.Next()
			})
			reached := false
			g := r.Group("/api/v1/notification-channels")
			g.Use(EnforceRegistry())
			g.GET("/:id/deliveries", func(c *gin.Context) { reached = true; c.JSON(http.StatusOK, gin.H{"data": []any{}}) })

			var before int64
			db.Model(&model.AuditLog{}).Count(&before)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/notification-channels/1/deliveries", nil))
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d", w.Code, tc.want)
			}
			if tc.want == http.StatusForbidden {
				if reached {
					t.Fatal("無權者不得到達處理器")
				}
				var after int64
				db.Model(&model.AuditLog{}).Count(&after)
				row := latestAuditRow(t, db)
				if after != before+1 || row.Status != model.StatusDenied || row.StatusCode != http.StatusForbidden {
					t.Fatalf("應多一筆 denied 審計列: %d→%d status=%s code=%d", before, after, row.Status, row.StatusCode)
				}
			}
		})
	}
}
