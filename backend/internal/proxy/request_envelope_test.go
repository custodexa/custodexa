package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

func TestRedeemRequestEnvelopeGraphics(t *testing.T) {
	for _, mode := range []string{"revoked", "downscope", "agent-missing"} {
		t.Run(mode, func(t *testing.T) {
			h, db := setupGraphicsRedeemTest(t)
			gateSeedGuacAccount(t, db, "app", true)
			if err := db.AutoMigrate(&model.AccessRequestItem{}); err != nil {
				t.Fatal(err)
			}
			start := time.Now().Add(-time.Minute)
			end := time.Now().Add(time.Hour)
			u, a := uint(1), uint(1)
			req := model.AccessRequest{RequesterID: u, AssetID: a, Reason: "work", RequestedDurationMinutes: 60, Status: model.AccessRequestPending, PendingExpiresAt: end}
			if err := db.Create(&req).Error; err != nil {
				t.Fatal(err)
			}
			grant := model.AssetAuthorization{UserID: &u, AssetID: &a, Permission: model.PermissionConnect, GrantedBy: 2, Source: model.AuthorizationSourceTicket, Accounts: model.AccountScope{"app"}, DateStart: &start, DateExpired: &end}
			if err := db.Create(&grant).Error; err != nil {
				t.Fatal(err)
			}
			item := model.AccessRequestItem{RequestID: req.ID, RequesterID: 1, AssetID: 1, Status: model.AccessRequestPending, Accounts: model.AccountScope{"app"}}
			if err := db.Create(&item).Error; err != nil {
				t.Fatal(err)
			}
			db.Model(&item).Updates(map[string]any{"status": model.AccessRequestApproved, "approved_duration_minutes": 60, "approved_date_start": start, "authorization_id": grant.ID})
			requestID := req.ID
			if mode == "agent-missing" {
				requestID = 0
				db.Model(&model.User{}).Where("id=1").Updates(map[string]any{"kind": model.KindAgent, "owner_user_id": 2})
			}
			token, err := h.ConnectTokens.IssueConnectToken(context.Background(), ConnectGrant{UserID: 1, AssetID: 1, AccessRequestID: requestID})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "revoked" {
				db.Model(&item).Update("revoked_at", time.Now())
			} else if mode == "downscope" {
				db.Model(&item).Update("accounts", model.AccountScope{"ops"})
			}
			status, body := gateRedeemGuac(h, token, "")
			if status != 403 || body["code"] != "AUTH_REQUEST_ITEM_MISMATCH" {
				t.Fatal(status, body)
			}
			gateGuacAssertNoSession(t, db, mode)
			if _, ok := h.ConnectTokens.RedeemConnectToken(context.Background(), token); ok {
				t.Fatal("token reusable")
			}
		})
	}
}
