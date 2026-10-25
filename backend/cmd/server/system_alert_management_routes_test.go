package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/gin-gonic/gin"
)

// 系統告警管理面的路由權限：通知通道五個端點，以及目錄與明細三個端點
// （目錄案例在 system_alert_catalog_routes_test.go 的 runSystemAlertCatalogRouteCases）。

type stubChannelService struct{ delivery *model.NotificationChannel }

func (stubChannelService) List() ([]model.NotificationChannel, error) {
	return []model.NotificationChannel{}, nil
}
func (stubChannelService) GetByID(id uint) (*model.NotificationChannel, error) {
	return &model.NotificationChannel{ID: id}, nil
}
func (s stubChannelService) GetForDelivery(id uint) (*model.NotificationChannel, error) {
	return s.delivery, nil
}
func (stubChannelService) Create(*audit.NotificationChannelRequest) (*model.NotificationChannel, error) {
	return &model.NotificationChannel{ID: 1}, nil
}
func (stubChannelService) Update(id uint, _ *audit.NotificationChannelRequest) (*model.NotificationChannel, error) {
	return &model.NotificationChannel{ID: id}, nil
}
func (stubChannelService) Delete(uint, audit.ChannelActor) error { return nil }

func principalWith(builtinKey, roleName string) *authz.Principal {
	return authz.NewPrincipal(7, authz.TokenFacts{}, []authz.Assignment{{
		RoleName: roleName, BuiltinKey: builtinKey, Via: authz.ViaDirect, Scope: model.ScopeKindGlobal,
	}})
}

// customRolePrincipal 單一全域指派的自訂角色主體，持有明確的權限集合。
func customRolePrincipal(roleName string, perms ...authz.Permission) *authz.Principal {
	return authz.NewPrincipal(7, authz.TokenFacts{}, []authz.Assignment{{
		RoleName: roleName, Via: authz.ViaDirect, Scope: model.ScopeKindGlobal,
		Permissions: perms, Custom: true,
	}})
}

// assetManagerCustomPrincipal 只持資產管理權（建立、修改、刪除、測試、檢視、節點管理）的自訂角色。
func assetManagerCustomPrincipal(t *testing.T) *authz.Principal {
	t.Helper()
	p := customRolePrincipal("asset-manager-custom",
		authz.PermAssetCreate, authz.PermAssetUpdate, authz.PermAssetDelete,
		authz.PermAssetTest, authz.PermAssetView, authz.PermAssetGroupManage)
	// 夾具自檢：確實持有資產管理權，避免退化成零能力主體而讓拒絕案例假綠。
	for _, perm := range []authz.Permission{authz.PermAssetCreate, authz.PermAssetUpdate, authz.PermAssetGroupManage} {
		if !p.Has(perm) {
			t.Fatalf("夾具應持有 %s", perm)
		}
	}
	return p
}

// channelRoutePrincipals 主體名稱 → 是否應能使用通知通道端點。
func channelRoutePrincipals(t *testing.T) map[string]struct {
	p    *authz.Principal
	want bool
} {
	return map[string]struct {
		p    *authz.Principal
		want bool
	}{
		"超管":               {principalWith(model.BuiltinSuperAdmin, model.RoleAdmin), true},
		"系統安全管理員範本":        {principalWith(model.BuiltinSecurityAdmin, "系統安全管理員"), true},
		"身分管理員範本":          {principalWith(model.BuiltinIdentityAdmin, "身分管理員"), false},
		"稽核員":              {principalWith(model.BuiltinAuditor, model.RoleAuditor), false},
		"一般使用者":            {principalWith(model.BuiltinUser, model.RoleUser), false},
		"審核者":              {principalWith(model.BuiltinApprover, model.RoleApprover), false},
		"只持資產管理權的自訂角色":     {assetManagerCustomPrincipal(t), false},
		"只持告警分級權的自訂角色":     {customRolePrincipal("alert-severity-custom", authz.PermSystemAlertManage), false},
		"被授予通道管理權的自訂角色":    {customRolePrincipal("channel-manager-custom", authz.PermNotificationChannel), true},
		"沒有任何角色指派（零角色一般人）": {authz.NewPrincipal(8, authz.TokenFacts{}, nil), false},
	}
}

func newChannelRouteEngine(t *testing.T, svc stubChannelService, principal *authz.Principal) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	h := api.NewNotificationChannelHandler(svc)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(7))
		c.Set("username", "route-test")
		middleware.SetPrincipal(c, principal)
	})
	// 與 RegisterRoutes 同一組端點與同一支登錄執行中介層；身分以測試注入取代 token 驗證。
	g := r.Group("/api/v1/notification-channels")
	g.Use(middleware.EnforceRegistry())
	g.GET("", h.List)
	g.POST("", h.Create)
	g.PUT("/:id", h.Update)
	g.DELETE("/:id", h.Delete)
	g.POST("/:id/test", h.Test)
	return r
}

var channelEndpoints = []struct{ method, path, body string }{
	{"GET", "/api/v1/notification-channels", ""},
	{"POST", "/api/v1/notification-channels", `{"name":"n","url":"https://example.test/h"}`},
	{"PUT", "/api/v1/notification-channels/3", `{"name":"n"}`},
	{"DELETE", "/api/v1/notification-channels/3", ""},
	{"POST", "/api/v1/notification-channels/3/test", ""},
}

func TestSystemAlertManagementRoutes(t *testing.T) {
	t.Run("通道五個端點登錄於通知通道權限點且不再寫死角色", func(t *testing.T) {
		for _, ep := range channelEndpoints {
			path := strings.Replace(ep.path, "/3", "/:id", 1)
			e, ok := authz.LookupRoute(ep.method, path)
			if !ok {
				t.Fatalf("%s %s 未登錄", ep.method, path)
			}
			if e.Base != authz.BasePerm || e.Perm != authz.PermNotificationChannel {
				t.Fatalf("%s %s 應登錄於通知通道權限點: %+v", ep.method, path, e)
			}
		}
		// 路由註冊本身不得再疊 RequireRole（權限判定只由登錄表執行）。
		src, err := readFileForTest("../../internal/api/notification_channel_handler.go")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(src, "RequireRole(") {
			t.Fatal("通道路由註冊不得再使用 RequireRole")
		}
	})

	t.Run("通道五個端點依主體權限放行或拒絕", func(t *testing.T) {
		receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer receiver.Close()
		svc := stubChannelService{delivery: &model.NotificationChannel{ID: 3, Type: "webhook", URL: receiver.URL}}
		for name, tc := range channelRoutePrincipals(t) {
			for _, ep := range channelEndpoints {
				r := newChannelRouteEngine(t, svc, tc.p)
				req := httptest.NewRequest(ep.method, ep.path, bytes.NewBufferString(ep.body))
				req.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				r.ServeHTTP(w, req)
				allowed := w.Code >= 200 && w.Code < 300
				if allowed != tc.want {
					t.Errorf("%s %s %s：狀態 %d，應%s", name, ep.method, ep.path, w.Code, map[bool]string{true: "放行", false: "拒絕"}[tc.want])
				}
				if !tc.want && w.Code != http.StatusForbidden {
					t.Errorf("%s %s %s：拒絕應為 403，實為 %d", name, ep.method, ep.path, w.Code)
				}
			}
		}
	})

	runSystemAlertCatalogRouteCases(t)
}

func readFileForTest(path string) (string, error) {
	b, err := os.ReadFile(path)
	return string(b), err
}
