package sshproxy

import (
	"net/http"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// seedCustomRole 建一個自訂角色（明確權限集合）並指派給使用者；集合直接寫入，與生產的角色定義寫入同形。
func seedCustomRole(t *testing.T, e *observerAuditEnv, userID uint, name string, keys []authz.Permission) {
	t.Helper()
	if err := e.db.AutoMigrate(&model.RolePermission{}); err != nil {
		t.Fatalf("migrate role_permissions: %v", err)
	}
	role := model.Role{Name: name, DefinitionVersion: 1}
	if err := e.db.Create(&role).Error; err != nil {
		t.Fatalf("建立自訂角色 %s: %v", name, err)
	}
	for _, k := range keys {
		if err := e.db.Create(&model.RolePermission{RoleID: role.ID, PermissionKey: string(k)}).Error; err != nil {
			t.Fatalf("寫入權限 %s: %v", k, err)
		}
	}
	if err := e.db.Create(&model.UserRole{UserID: userID, RoleID: role.ID, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error; err != nil {
		t.Fatalf("指派自訂角色 %s: %v", name, err)
	}
}

// TestMonitorTicketGateMatchesProjection 釘住簽發端：同一份 DB 主體資料下，
// 能力投影含監看呈現點 ⇔ 實際打監看票簽發端點得 200；不放行時回應不含票。
// 角色在取主體與簽發之間不變。
func TestMonitorTicketGateMatchesProjection(t *testing.T) {
	e := setupObserverAuditEnv(t)
	r := e.ticketRouter()

	subjects := []struct {
		name  string
		setup func(t *testing.T, u *model.User)
		want  bool
	}{
		{"內建超管", func(t *testing.T, u *model.User) { grantDBRole(t, e.db, u.ID, model.RoleAdmin) }, true},
		{"稽核員", func(t *testing.T, u *model.User) { grantDBRole(t, e.db, u.ID, model.RoleAuditor) }, true},
		{"一般使用者", func(t *testing.T, u *model.User) { grantDBRole(t, e.db, u.ID, model.RoleUser) }, false},
		{"零角色", func(t *testing.T, u *model.User) {}, false},
		{"持會話檢視的自訂角色", func(t *testing.T, u *model.User) {
			seedCustomRole(t, e, u.ID, "session-viewer", []authz.Permission{authz.PermSessionView})
		}, false},
		{"勾滿可指派目錄的自訂角色", func(t *testing.T, u *model.User) {
			seedCustomRole(t, e, u.ID, "everything", authz.AssignableKeys())
		}, false},
	}
	var ok, denied int
	for _, s := range subjects {
		t.Run(s.name, func(t *testing.T) {
			u := e.seedObserver(t, "gate-"+s.name)
			clearUserRoles(t, e.db, u.ID)
			s.setup(t, u)

			p, err := e.h.AuthService.CurrentConnectPrincipal(u.ID)
			if err != nil {
				t.Fatalf("取主體: %v", err)
			}
			projected := false
			for _, k := range authz.ProjectCapabilities(p, authz.ProjectionInputs{}).Permissions {
				if k == authz.UISessionMonitor {
					projected = true
				}
			}
			code, body := postObserverTicket(r, monitorTicketPath(observerAuditSession), e.token(t, u, model.RoleAdmin))
			issued := code == http.StatusOK
			if projected != issued {
				t.Fatalf("%s：投影含監看點=%v，簽發端點回 %d（body=%v）：兩者須一致", s.name, projected, code, body)
			}
			if projected != s.want {
				t.Fatalf("%s：投影含監看點=%v，預期 %v", s.name, projected, s.want)
			}
			if issued {
				ok++
				if tok, _ := body["connect_token"].(string); tok == "" {
					t.Fatalf("%s：200 卻沒有票", s.name)
				}
			} else {
				denied++
				if code != http.StatusForbidden {
					t.Fatalf("%s：不放行應為 403，實得 %d", s.name, code)
				}
				if body["connect_token"] != nil {
					t.Fatalf("%s：403 的回應不得含票：%v", s.name, body)
				}
			}
			t.Logf("%s：投影含監看點=%v，簽發 %d", s.name, projected, code)
		})
	}
	if ok == 0 || denied == 0 {
		t.Fatalf("兩個分支都要走到：放行 %d、拒絕 %d", ok, denied)
	}
}
