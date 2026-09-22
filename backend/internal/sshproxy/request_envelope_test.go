package sshproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/connectgate"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func seedEnvelope(t *testing.T, db *gorm.DB, scope model.AccountScope) (model.AccessRequest, model.AccessRequestItem) {
	t.Helper()
	if err := db.AutoMigrate(&model.AccessRequestItem{}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Minute)
	end := now.Add(time.Hour)
	duration := 60
	u, a := uint(1), uint(1)
	req := model.AccessRequest{RequesterID: u, AssetID: a, Accounts: scope, Reason: "task", RequestedDurationMinutes: 60, Status: model.AccessRequestPending, PendingExpiresAt: end}
	if err := db.Create(&req).Error; err != nil {
		t.Fatal(err)
	}
	grant := model.AssetAuthorization{UserID: &u, AssetID: &a, Permission: model.PermissionConnect, GrantedBy: 2, Source: model.AuthorizationSourceTicket, Accounts: scope, DateStart: &now, DateExpired: &end}
	if err := db.Create(&grant).Error; err != nil {
		t.Fatal(err)
	}
	item := model.AccessRequestItem{RequestID: req.ID, RequesterID: u, AssetID: a, Accounts: scope, Status: model.AccessRequestPending}
	if err := db.Create(&item).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&item).Updates(map[string]any{"status": model.AccessRequestApproved, "approved_duration_minutes": duration, "approved_date_start": now, "decided_at": now, "authorization_id": grant.ID}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&model.AccessRequest{}).Where("id=?", req.ID).Updates(map[string]any{"status": model.AccessRequestApproved, "authorization_id": grant.ID}).Error; err != nil {
		t.Fatal(err)
	}
	return req, item
}
func TestIssueConnectTokenRequestEnvelope(t *testing.T) {
	for _, mode := range []string{"valid", "agent-missing", "scope", "asset", "window"} {
		t.Run(mode, func(t *testing.T) {
			h, db := gateFixture(t)
			gateSeedAccount(t, db, 1, "app", true)
			r, item := seedEnvelope(t, db, model.AccountScope{"app"})
			id := r.ID
			switch mode {
			case "agent-missing":
				id = 0
				db.Model(&model.User{}).Where("id=1").Updates(map[string]any{"kind": model.KindAgent, "owner_user_id": 2})
			case "scope":
				db.Model(&model.AccessRequestItem{}).Where("id=?", item.ID).Update("accounts", model.AccountScope{"ops"})
			case "asset":
				db.Model(&model.AccessRequestItem{}).Where("id=?", item.ID).Update("asset_id", 99)
			case "window":
				db.Model(&model.AccessRequestItem{}).Where("id=?", item.ID).Update("revoked_at", time.Now())
			}
			status, body, keys := gateIssueRequest(h, 1, model.RoleUser, 1, 0, fmt.Sprintf(`{"asset_id":1,"access_request_id":%d}`, id))
			if mode == "valid" {
				if status != 200 {
					t.Fatal(status, body)
				}
				grant, ok := h.ConnectTokens.RedeemConnectToken(context.Background(), body["connect_token"].(string))
				if !ok || grant.AccessRequestID != r.ID {
					t.Fatal(grant)
				}
				return
			}
			if status != 403 || body["code"] != "AUTH_REQUEST_ITEM_MISMATCH" {
				t.Fatal(status, body)
			}
			if keys["audit_details"] == nil {
				t.Fatal("missing denial dimensions", keys)
			}
			gateAssertNoSession(t, db, mode)
		})
	}
	t.Run("gate order", func(t *testing.T) {
		h, db := gateFixture(t)
		r, _ := seedEnvelope(t, db, model.AccountScope{"app"})
		st := &issueState{req: connectTokenRequest{AssetID: 1, AccessRequestID: r.ID}}
		c := gateTestContext("POST", "/connect-tokens", nil)
		names := connectgate.Names(h.issueResolvedAccountGates(c, gateIssueSubject(1), st.contractObject(), st))
		if len(names) < 2 || names[0] != "G-I10" || names[1] != "G-I16" {
			t.Fatal(names)
		}
	})
}
func TestRedeemRequestEnvelope(t *testing.T) {
	for _, via := range []string{"ssh", "db-console"} {
		for _, change := range []string{"revoked", "downscope"} {
			t.Run(via+"/"+change, func(t *testing.T) {
				h, db := gateFixture(t)
				h.AuditService = audit.NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true})
				t.Cleanup(func() { h.AuditService.Shutdown(context.Background()) })
				gateSeedAccount(t, db, 1, "app", true)
				r, item := seedEnvelope(t, db, model.AccountScope{"app"})
				status, body, _ := gateIssueRequest(h, 1, model.RoleUser, 1, 0, fmt.Sprintf(`{"asset_id":1,"access_request_id":%d}`, r.ID))
				if status != 200 {
					t.Fatal(status, body)
				}
				if via == "db-console" {
					db.Model(&model.Asset{}).Where("id=1").Update("protocol", model.ProtocolMySQL)
				}
				if change == "revoked" {
					db.Model(&model.AccessRequestItem{}).Where("id=?", item.ID).Update("revoked_at", time.Now())
				} else {
					db.Model(&model.AccessRequestItem{}).Where("id=?", item.ID).Update("accounts", model.AccountScope{"ops"})
				}
				token := body["connect_token"].(string)
				if via == "ssh" {
					status, body = gateRedeemSSH(h, token, "80", "24")
				} else {
					gin.SetMode(gin.TestMode)
					router := gin.New()
					router.GET("/db-console", h.HandleDBConsole)
					w := httptest.NewRecorder()
					router.ServeHTTP(w, httptest.NewRequest("GET", "/db-console?connect_token="+token, nil))
					status = w.Code
					json.Unmarshal(w.Body.Bytes(), &body)
				}
				if status != 403 || body["code"] != "AUTH_REQUEST_ITEM_MISMATCH" {
					t.Fatal(status, body)
				}
				var denial model.AuditLog
				if err := db.Where("status=?", model.StatusDenied).Last(&denial).Error; err != nil {
					t.Fatal(err)
				}
				var facts map[string]any
				if err := json.Unmarshal([]byte(denial.Details), &facts); err != nil {
					t.Fatal(err)
				}
				wantDimension := "scope"
				if change == "revoked" {
					wantDimension = "window"
				}
				if denial.AssetID == nil || *denial.AssetID != 1 || facts["request_item_dimension"] != wantDimension || facts["access_request_id"] != float64(r.ID) {
					t.Fatal("denial lost target/dimension", denial.AssetID, facts)
				}
				gateAssertNoSession(t, db, via)
				if _, ok := h.ConnectTokens.RedeemConnectToken(context.Background(), token); ok {
					t.Fatal("token reusable")
				}
			})
		}
	}
}
func TestTicketScopeNotWidenedByOtherGrant(t *testing.T) {
	h, db := gateFixture(t)
	gateSeedAccount(t, db, 1, "root", true)
	older, _ := seedEnvelope(t, db, model.AccountScope{"@ALL"})
	newer, newItem := seedEnvelope(t, db, model.AccountScope{"app"})
	db.Model(&model.AccessRequestItem{}).Where("id=?", newItem.ID).Update("decided_at", time.Now())
	// Remove standing connect. The old broad *ticket* remains active, exactly as in Spike 4 B3.
	db.Where("user_id=1 AND source<>?", model.AuthorizationSourceTicket).Delete(&model.AssetAuthorization{})
	for _, request := range []uint{newer.ID, 0} {
		token, err := h.ConnectTokens.IssueConnectToken(context.Background(), proxy.ConnectGrant{UserID: 1, AssetID: 1, AccessRequestID: request})
		if err != nil {
			t.Fatal(err)
		}
		status, body := gateRedeemSSH(h, token, "80", "24")
		if status != 403 {
			t.Fatal("drill bypass", status, body)
		}
		t.Logf("drill old_request=%d new_request=%d root redemption HTTP %d code=%v", older.ID, newer.ID, status, body["code"])
	}
	gateAssertNoSession(t, db, "drill")
}
