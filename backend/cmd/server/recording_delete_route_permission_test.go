package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// TestRecordingDeleteRoutePermission 擋：刪錄影路由的權限點、拒絕形狀或其餘登錄欄位漂移，
// 只持刪錄影權限點的自訂角色被擋、只持結束連線或檢視會話者被放行，以及未登入不回 401。
func TestRecordingDeleteRoutePermission(t *testing.T) {
	const method, path = "DELETE", "/api/v1/sessions/:id/recording"
	t.Run("登錄項：BasePerm＋recording:delete，拒絕依據與其餘欄位", func(t *testing.T) {
		e, ok := authz.LookupRoute(method, path)
		if !ok {
			t.Fatal("未登錄")
		}
		if e.Base != authz.BasePerm || e.Perm != authz.PermRecordingDelete {
			t.Fatalf("登錄不符: %+v", e)
		}
		if d := authz.DecideEntry(e, customRolePrincipal("none")); d.Allowed || d.Basis != authz.DenialAllOf ||
			len(d.Required) != 1 || d.Required[0] != authz.PermRecordingDelete {
			t.Fatalf("拒絕依據不符: %+v", d)
		}
		if len(e.AnyOf) != 0 || len(e.Fields) != 0 || e.DataPlane {
			t.Fatalf("不得帶 AnyOf／Fields／DataPlane: %+v", e)
		}
	})

	engine := func(p *authz.Principal) *gin.Engine {
		gin.SetMode(gin.TestMode)
		r := gin.New()
		r.Use(func(c *gin.Context) {
			if p != nil {
				c.Set("userID", uint(7))
				c.Set("username", "route-test")
				middleware.SetPrincipal(c, p)
			}
		})
		g := r.Group("/api/v1/sessions")
		// 與 RegisterRoutes 同一支登錄執行中介層；終點以替身表示「通過路由層」
		g.DELETE("/:id/recording", middleware.EnforceRegistry(), func(c *gin.Context) { c.Status(http.StatusNoContent) })
		return r
	}
	cases := map[string]struct {
		p    *authz.Principal
		want bool
	}{
		"超級管理者":            {principalWith(model.BuiltinSuperAdmin, model.RoleAdmin), true},
		"系統安全管理員範本":        {principalWith(model.BuiltinSecurityAdmin, "系統安全管理員"), true},
		"只持刪錄影權限點的自訂角色":    {customRolePrincipal("recording-delete-custom", authz.PermRecordingDelete), true},
		"稽核員範本":            {principalWith(model.BuiltinAuditor, model.RoleAuditor), false},
		"只持結束連線與檢視會話的自訂角色": {customRolePrincipal("session-ops-custom", authz.PermSessionTerminate, authz.PermSessionView), false},
	}
	for name, tc := range cases {
		w := httptest.NewRecorder()
		engine(tc.p).ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/5/recording", nil))
		if tc.want {
			if w.Code != http.StatusNoContent {
				t.Errorf("%s 應通過路由層，得 %d %s", name, w.Code, w.Body.String())
			}
			continue
		}
		if w.Code != http.StatusForbidden {
			t.Errorf("%s 應 403，得 %d", name, w.Code)
			continue
		}
		// 能力拒絕單一形狀：本文只有 code、error，不帶權限點
		body := map[string]any{}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if _, hasErr := body["error"]; len(body) != 2 || !hasErr || body["code"] != "AUTH_PERMISSION_DENIED" {
			t.Errorf("%s 拒絕形狀不符: %s", name, w.Body.String())
		}
	}
	t.Run("未登入回 401", func(t *testing.T) {
		w := httptest.NewRecorder()
		engine(nil).ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/5/recording", nil))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("未登入應 401，得 %d", w.Code)
		}
	})
}
