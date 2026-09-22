package authz

import (
	"errors"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

func TestMatchRequestItem(t *testing.T) {
	for _, dimension := range []string{"valid", "asset", "principal", "scope", "before", "after", "revoked", "closed", "deleted-ticket", "assisted-visibility"} {
		t.Run(dimension, func(t *testing.T) {
			s, db, r, agent := twoPendingItems(t)
			if dimension == "assisted-visibility" {
				human := uint(1)
				db.Model(&model.AccessRequest{}).Where("id=?", r.ID).Updates(map[string]any{"requester_id": human, "executor_user_id": agent})
			}
			r, err := s.Approve(2, true, r.ID, DecideInput{})
			if err != nil {
				t.Fatal(err)
			}
			request, user, asset, name, at := r.ID, agent, uint(1), "app", time.Now()
			want := error(nil)
			switch dimension {
			case "asset":
				asset = 3
				want = ErrRequestItemAsset
			case "principal":
				user = 1
				want = ErrRequestItemAsset
			case "scope":
				name = "root"
				want = ErrRequestItemScope
			case "before":
				at = r.Items[0].ApprovedDateStart.Add(-time.Second)
				want = ErrRequestItemWindow
			case "after":
				at = r.Items[0].ApprovedDateStart.Add(time.Hour)
				want = ErrRequestItemWindow
			case "revoked":
				_, err = s.RevokeItem(2, true, "reviewer", r.ID, r.Items[0].ID, "done")
				if err != nil {
					t.Fatal(err)
				}
				want = ErrRequestItemWindow
			case "closed":
				db.Model(&model.AccessRequest{}).Where("id=?", r.ID).Update("closed_at", at)
				want = ErrRequestItemWindow
			case "deleted-ticket":
				db.Delete(&model.AssetAuthorization{}, *r.Items[0].AuthorizationID)
				want = ErrRequestItemWindow
			case "assisted-visibility":
				db.Where("user_id=1 AND asset_id=1").Delete(&model.AssetAuthorization{})
				want = ErrRequestItemAsset
			}
			item, err := NewAssetAuthorizationService(db).MatchRequestItem(request, user, asset, name, at)
			if !errors.Is(err, want) || want == nil && item == nil {
				t.Fatal(dimension, item, err)
			}
		})
	}
}
func TestAccountScopeTicketIsolation(t *testing.T) {
	for _, mode := range []string{"other-source-all", "two-tickets", "tie", "standing-preserved"} {
		t.Run(mode, func(t *testing.T) {
			s, _, db, _ := setupItemRequestEnv(t)
			// Human @ALL -> app historical tasks, no standing connect: exact drill shape.
			old, err := s.Submit(1, "human", model.RoleUser, SubmitAccessRequestInput{AssetID: 2, Reason: "older", DurationMinutes: 60})
			if err != nil {
				t.Fatal(err)
			}
			newer, err := s.Submit(1, "human", model.RoleUser, itemInput(2))
			if err != nil {
				t.Fatal(err)
			}
			if mode == "other-source-all" {
				db.Delete(&model.AssetAuthorization{}, *old.AuthorizationID)
			}
			if mode == "tie" {
				db.Model(&model.AccessRequestItem{}).Where("id=?", old.Items[0].ID).Update("decided_at", newer.Items[0].DecidedAt)
			}
			if mode == "standing-preserved" {
				u, a := uint(1), uint(2)
				db.Create(&model.AssetAuthorization{UserID: &u, AssetID: &a, Permission: model.PermissionConnect, GrantedBy: 3, Accounts: model.AccountScope{"@ALL"}})
			}
			svc := NewAssetAuthorizationService(db)
			scope, err := svc.EffectiveConnectAccountScope(userCtx(), 1, 2)
			if err != nil {
				t.Fatal(err)
			}
			if !scope.Allows("app") || scope.Allows("root") != (mode == "standing-preserved") {
				t.Fatal(mode, scope)
			}
			if mode == "two-tickets" {
				if _, err := svc.MatchRequestItem(old.ID, 1, 2, "root", time.Now()); err != nil {
					t.Fatal("explicit older task should remain usable", err)
				}
			}
		})
	}
}
func TestApproveItemsRollbackGrantFailure(t *testing.T) {
	s, db, r, _ := twoPendingItems(t)
	db.Callback().Create().Before("gorm:create").Register("fail_second_item_ticket", func(tx *gorm.DB) {
		if grant, ok := tx.Statement.Dest.(*model.AssetAuthorization); ok && grant.AssetID != nil && *grant.AssetID == 2 {
			tx.AddError(errors.New("injected ticket failure"))
		}
	})
	if _, err := s.Approve(2, true, r.ID, DecideInput{}); err == nil {
		t.Fatal("failure accepted")
	}
	got, err := s.reload(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range got.Items {
		if item.Status != model.AccessRequestPending || item.AuthorizationID != nil {
			t.Fatal("partial decision committed", item)
		}
	}
	var n int64
	db.Model(&model.AssetAuthorization{}).Where("source=?", model.AuthorizationSourceTicket).Count(&n)
	if n != 0 {
		t.Fatal("partial grant committed", n)
	}
}
