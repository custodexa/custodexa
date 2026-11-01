package main

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// TestSuperAdminChainGuardsStandAlone 鏈上第二道超管守衛不經登錄閘也要自己擋住非超管：
// 三條路由各只掛守衛加一個計數處理器（不掛登錄執行點），非超管 403 單一形狀、依據為保留條件、
// 處理器計數 0；超管計數 1。登錄閘與守衛判定相同時，只經登錄閘的測試抓不到守衛被拿掉判定。
func TestSuperAdminChainGuardsStandAlone(t *testing.T) {
	legacy := legacyPermissionDeniedBody(t)

	var assignable []authz.Permission
	for _, d := range authz.Catalog() {
		if authz.IsAssignable(d.Key) {
			assignable = append(assignable, d.Key)
		}
	}
	subjects := []struct {
		name  string
		who   *authz.Principal
		super bool
	}{
		{"稽核員", principalOf(model.BuiltinAuditor, ""), false},
		{"持全部可指派權限的自訂角色", customPrincipal(assignable...), false},
		{"一般使用者", principalOf(model.BuiltinUser, ""), false},
		{"超管", principalOf(model.BuiltinSuperAdmin, ""), true},
	}
	routes := []struct {
		name, method, path, body string
		guard                    gin.HandlerFunc
	}{
		{"主機金鑰重置", "DELETE", "/api/v1/assets/1/host-key", "", api.RequireHostKeyResetSuperAdmin},
		{"主機金鑰採用", "POST", "/api/v1/assets/1/host-key/adopt", `{"fingerprint":"SHA256:x"}`, api.RequireHostKeyResetSuperAdmin},
		{"權限狀態確認", "POST", "/api/v1/audit-failures/permission-state/accept", `{"reason":"r"}`, api.RequirePermissionAcceptSuperAdmin},
	}

	for _, r := range routes {
		for _, s := range subjects {
			t.Run(r.name+"："+s.name, func(t *testing.T) {
				calls := 0
				pr := serviceProbe(s.who, r.method, r.path, r.body, func(g gin.IRoutes) {
					g.Handle(r.method, r.path, r.guard, func(c *gin.Context) {
						calls++
						c.JSON(http.StatusOK, gin.H{"ok": true})
					})
				})
				if s.super {
					assert.Equal(t, 1, calls, "超管須到達處理器")
					assert.Equal(t, http.StatusOK, pr.code)
					assert.False(t, pr.hasDeny)
					return
				}
				assert.Equal(t, 0, calls, "非超管不得到達處理器")
				assert.Equal(t, http.StatusForbidden, pr.code)
				assert.Equal(t, legacy, pr.raw, "本文須與能力拒絕樣本逐位元相同")
				require.True(t, pr.hasDeny, "依據須存入脈絡")
				assert.Equal(t, authz.DenialReserved, pr.denial.Basis)
				assert.Equal(t, []string{authz.ReservedSuperAdmin}, pr.denial.Required)
			})
		}
	}
}
