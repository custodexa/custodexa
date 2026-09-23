package authz

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"gorm.io/gorm"
)

func twoPendingItems(t *testing.T) (*AccessRequestService, *gorm.DB, *model.AccessRequest, uint) {
	t.Helper()
	s, _, db, agent := setupItemRequestEnv(t)
	if err := db.Model(&model.Asset{}).Where("id=2").Update("access_policy", model.AccessPolicyApproval).Error; err != nil {
		t.Fatal(err)
	}
	names := []string{"app"}
	req, err := s.Submit(agent, "agent", model.RoleUser, SubmitAccessRequestInput{Items: []ItemInput{{1, &names}, {2, &names}}, Reason: "work", DurationMinutes: 60})
	if err != nil {
		t.Fatal(err)
	}
	return s, db, req, agent
}
func TestApproveItemsIndependentQuorum(t *testing.T) {
	s, db, req, _ := twoPendingItems(t)
	if _, err := s.policies.Update(policy.PolicyAccessRequestMinApprovals, "2", "admin"); err != nil {
		t.Fatal(err)
	}
	for _, item := range req.Items {
		partial, err := s.Approve(2, true, req.ID, DecideInput{ItemID: item.ID})
		if err != nil {
			t.Fatal(err)
		}
		if partial.Status != model.AccessRequestPending {
			t.Fatal(partial.Status)
		}
		if _, err = s.Approve(2, true, req.ID, DecideInput{ItemID: item.ID}); !errors.Is(err, ErrAlreadyApprovedByActor) {
			t.Fatal(err)
		}
		if _, err = s.Approve(3, true, req.ID, DecideInput{ItemID: item.ID}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.reload(req.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.AccessRequestApproved || got.AuthorizationID == nil || *got.AuthorizationID != *got.Items[0].AuthorizationID {
		t.Fatal(got)
	}
	var n int64
	db.Model(&model.AccessRequestApproval{}).Where("request_id=?", req.ID).Count(&n)
	if n != 4 {
		t.Fatal("cross-item vote contamination", n)
	}
	db.Model(&model.AssetAuthorization{}).Where("source=?", model.AuthorizationSourceTicket).Count(&n)
	if n != 2 {
		t.Fatal("each approved item must have one ticket", n)
	}
}
func TestApproveItemDownscope(t *testing.T) {
	s, _, db, _ := setupItemRequestEnv(t)
	req, err := s.Submit(1, "human", model.RoleUser, SubmitAccessRequestInput{AssetID: 1, Reason: "work", DurationMinutes: 60})
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"app"}
	duration := 15
	start := time.Now().Add(time.Hour)
	got, err := s.Approve(2, false, req.ID, DecideInput{ItemID: req.Items[0].ID, Accounts: &names, DurationMinutes: &duration, DateStart: &start})
	if err != nil {
		t.Fatal(err)
	}
	var grant model.AssetAuthorization
	if err := db.First(&grant, *got.Items[0].AuthorizationID).Error; err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(grant.Accounts, model.AccountScope{"app"}) || grant.DateExpired.Sub(*grant.DateStart) != 15*time.Minute || !grant.DateStart.Equal(start) {
		t.Fatal(grant)
	}
	t.Run("remove one pending item", func(t *testing.T) {
		s, _, r, _ := twoPendingItems(t)
		got, e := s.Approve(2, true, r.ID, DecideInput{Items: []ItemDecision{{ItemID: r.Items[0].ID, Remove: true}, {ItemID: r.Items[1].ID}}})
		if e != nil {
			t.Fatal(e)
		}
		if got.Items[0].Status != model.AccessRequestRejected || got.Items[1].Status != model.AccessRequestApproved {
			t.Fatal(got.Items)
		}
	})
}
func TestApproveItemUpscopeRejected(t *testing.T) {
	for _, shape := range []string{"all", "extra", "empty", "duration", "earlier", "foreign-item"} {
		t.Run(shape, func(t *testing.T) {
			s, db, r, _ := twoPendingItems(t)
			names := []string{"@ALL"}
			in := DecideInput{ItemID: r.Items[0].ID, Accounts: &names}
			switch shape {
			case "extra":
				names = []string{"app", "root"}
			case "empty":
				names = []string{}
			case "duration":
				v := 61
				in = DecideInput{ItemID: r.Items[0].ID, DurationMinutes: &v}
			case "earlier":
				v := time.Now().Add(-time.Hour)
				in = DecideInput{ItemID: r.Items[0].ID, DateStart: &v}
			case "foreign-item":
				in = DecideInput{ItemID: 99999}
			}
			_, err := s.Approve(2, true, r.ID, in)
			if err == nil {
				t.Fatal("upscope accepted")
			}
			got, e := s.reload(r.ID)
			if e != nil {
				t.Fatal(e)
			}
			if got.Items[0].Status != model.AccessRequestPending || !reflect.DeepEqual(got.Items[0].Accounts, r.Items[0].Accounts) {
				t.Fatal("item mutated")
			}
			var n int64
			db.Model(&model.AccessRequestApproval{}).Where("request_id=?", r.ID).Count(&n)
			if n != 0 {
				t.Fatal("failed decision leaked vote")
			}
		})
	}
}
func TestRejectSingleItem(t *testing.T) {
	s, _, r, _ := twoPendingItems(t)
	got, err := s.RejectItem(2, true, r.ID, r.Items[0].ID, "not needed")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.AccessRequestPending || got.Items[1].Status != model.AccessRequestPending {
		t.Fatal(got)
	}
	got, err = s.Approve(2, true, r.ID, DecideInput{ItemID: r.Items[1].ID})
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.AccessRequestApproved || got.Items[0].Status != model.AccessRequestRejected {
		t.Fatal(got)
	}
}
func TestItemPolicySnapshot(t *testing.T) {
	s, _, db, agent := setupItemRequestEnv(t)
	auto, err := s.Submit(agent, "agent", model.RoleUser, itemInput(3))
	if err != nil {
		t.Fatal(err)
	}
	manual, err := s.Submit(agent, "agent", model.RoleUser, itemInput(1))
	if err != nil {
		t.Fatal(err)
	}
	manual, err = s.Approve(2, true, manual.ID, DecideInput{})
	if err != nil {
		t.Fatal(err)
	}
	var a, m map[string]any
	json.Unmarshal([]byte(auto.Items[0].PolicySnapshot), &a)
	json.Unmarshal([]byte(manual.Items[0].PolicySnapshot), &m)
	if a["auto_basis"] != "open" || m["required_approvals"] != float64(1) || m["segment"] != "approval" {
		t.Fatal(a, m)
	}
	s.policies.Update(policy.PolicyAccessRequestMinApprovals, "2", "admin")
	db.Model(&model.Asset{}).Where("id IN ?", []uint{1, 3}).Update("access_policy", model.AccessPolicyReason)
	for _, req := range []*model.AccessRequest{auto, manual} {
		got, e := s.reload(req.ID)
		if e != nil || got.Items[0].PolicySnapshot != req.Items[0].PolicySnapshot {
			t.Fatal("snapshot rewritten", got, e)
		}
	}
}
func TestAgentCannotDecide(t *testing.T) {
	s, _, r, agent := twoPendingItems(t)
	for _, admin := range []bool{false, true} {
		if _, err := s.Approve(agent, admin, r.ID, DecideInput{}); !errors.Is(err, ErrAgentCannotDecide) {
			t.Fatal(err)
		}
		if _, err := s.Reject(agent, admin, r.ID, "no"); !errors.Is(err, ErrAgentCannotDecide) {
			t.Fatal(err)
		}
	}
}

type itemTerminations struct {
	assets   []uint
	users    []uint
	requests []uint
}

func (f *itemTerminations) TerminateByUserAsset(u, a uint, _ string) (int, error) {
	f.users = append(f.users, u)
	f.assets = append(f.assets, a)
	return 1, nil
}
func (f *itemTerminations) TerminateByUserAssetWithIDs(u, a uint, r string) ([]uint, error) {
	f.TerminateByUserAsset(u, a, r)
	return []uint{100 + a}, nil
}
func (f *itemTerminations) TerminateByAccessRequest(id uint, _ string) ([]uint, error) {
	f.requests = append(f.requests, id)
	return []uint{900 + id}, nil
}
func TestRevokeItemOnly(t *testing.T) {
	s, db, r, _ := twoPendingItems(t)
	r, err := s.Approve(2, true, r.ID, DecideInput{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.RevokeItem(2, false, "reviewer", r.ID, r.Items[0].ID, "done")
	if err != nil {
		t.Fatal(err)
	}
	if got.RevokedAt != nil || got.ClosedAt != nil || got.Items[0].RevokedBy == nil || got.Items[0].RevokeNote != "done" || got.Items[1].Status != model.AccessRequestApproved {
		t.Fatal(got)
	}
	var n int64
	db.Model(&model.AssetAuthorization{}).Where("id=?", *r.Items[1].AuthorizationID).Count(&n)
	if n != 1 {
		t.Fatal("other item revoked")
	}
	if _, err := s.RevokeItem(2, false, "reviewer", r.ID, r.Items[0].ID, "again"); !errors.Is(err, ErrTicketNotActive) {
		t.Fatal(err)
	}
}
func TestRequestClosedAt(t *testing.T) {
	for _, mode := range []string{"revoke-last", "all-expire", "preserve"} {
		t.Run(mode, func(t *testing.T) {
			s, db, r, _ := twoPendingItems(t)
			r, err := s.Approve(2, true, r.ID, DecideInput{})
			if err != nil {
				t.Fatal(err)
			}
			f := &itemTerminations{}
			s.SetSessionService(f)
			var first time.Time
			if mode == "preserve" {
				first = time.Now().Add(-time.Hour)
				db.Model(&model.AccessRequest{}).Where("id=?", r.ID).Update("closed_at", first)
			}
			if mode == "revoke-last" {
				if _, err = s.RevokeItem(2, false, "reviewer", r.ID, r.Items[0].ID, "done"); err != nil {
					t.Fatal(err)
				}
				got, _ := s.reload(r.ID)
				if got.ClosedAt != nil {
					t.Fatal("closed early")
				}
				_, err = s.RevokeItem(2, false, "reviewer", r.ID, r.Items[1].ID, "done")
			} else {
				_, err = s.ExpireOverdue(time.Now().Add(2 * time.Hour))
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := s.reload(r.ID)
			if err != nil || got.ClosedAt == nil {
				t.Fatal(got, err)
			}
			if mode == "preserve" {
				if !got.ClosedAt.Equal(first) {
					t.Fatal("closed_at overwritten")
				}
			} else if !reflect.DeepEqual(f.requests, []uint{r.ID}) {
				t.Fatal("task session termination not called", f.requests)
			}
			original := *got.ClosedAt
			s.ExpireApprovedItems(time.Now().Add(3 * time.Hour))
			got, _ = s.reload(r.ID)
			if !got.ClosedAt.Equal(original) {
				t.Fatal("second trigger changed close time")
			}
		})
	}
}
func TestRevokeTerminatesAgentSessions(t *testing.T) {
	s, db, r, agent := twoPendingItems(t)
	s.policies.Update(policy.PolicyAccessRevokeDisconnect, "false", "admin")
	r, err := s.Approve(2, true, r.ID, DecideInput{})
	if err != nil {
		t.Fatal(err)
	}
	f := &itemTerminations{}
	s.SetSessionService(f)
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })
	s.audit = audit.NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true})
	t.Cleanup(func() { s.audit.Shutdown(context.Background()) })
	if _, err = s.RevokeItem(2, false, "reviewer", r.ID, r.Items[0].ID, "done"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.assets, []uint{1}) || !reflect.DeepEqual(f.users, []uint{agent}) {
		t.Fatal(f)
	}
	var row model.AuditLog
	if err := db.Where("action=?", model.ActionRevoke).Last(&row).Error; err != nil {
		t.Fatal(err)
	}
	var details map[string]any
	if err := json.Unmarshal([]byte(row.Details), &details); err != nil {
		t.Fatal(err)
	}
	ids, ok := details["terminated_session_ids"].([]any)
	if !ok || len(ids) != 1 || ids[0] != float64(101) {
		t.Fatal(details)
	}
}

func TestRevokeItemOnlyWholeMixedTask(t *testing.T) {
	s, _, r, _ := twoPendingItems(t)
	if _, err := s.Approve(2, true, r.ID, DecideInput{ItemID: r.Items[0].ID}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Revoke(2, true, "reviewer", r.ID, "end entire task")
	if err != nil {
		t.Fatal(err)
	}
	if got.ClosedAt == nil || got.RevokedAt == nil || got.Status != model.AccessRequestApproved {
		t.Fatal(got)
	}
	for _, item := range got.Items {
		if item.Status != model.AccessRequestItemRevoked {
			t.Fatal("pending sibling survived whole revoke", item)
		}
	}
	if _, err := s.Approve(2, true, r.ID, DecideInput{ItemID: r.Items[1].ID}); !errors.Is(err, ErrAccessRequestConflict) {
		t.Fatal("whole revoke revived", err)
	}
}

// An approval overwrites item.Accounts, so without the snapshot the record can no longer
// show what was asked for. @ALL is written explicitly, never as a JSON null.
func TestRequestedAccountsPreservedInSnapshot(t *testing.T) {
	t.Run("narrowed approval keeps the wide request", func(t *testing.T) {
		s, _, _, _ := setupItemRequestEnv(t)
		req, err := s.Submit(1, "human", model.RoleUser, SubmitAccessRequestInput{AssetID: 1, Reason: "work", DurationMinutes: 60})
		if err != nil {
			t.Fatal(err)
		}
		names := []string{"app"}
		got, err := s.Approve(2, false, req.ID, DecideInput{ItemID: req.Items[0].ID, Accounts: &names})
		if err != nil {
			t.Fatal(err)
		}
		item := got.Items[0]
		if !reflect.DeepEqual(item.Accounts, model.AccountScope{"app"}) {
			t.Fatal("granted scope", item.Accounts)
		}
		item.FillRequestedAccounts()
		if item.RequestedAccounts == nil || !reflect.DeepEqual(*item.RequestedAccounts, model.AccountScope{model.AccountScopeAll}) {
			t.Fatal("requested scope lost", item.PolicySnapshot)
		}
	})
	t.Run("automatic approval preserves it too", func(t *testing.T) {
		s, _, _, agent := setupItemRequestEnv(t)
		auto, err := s.Submit(agent, "agent", model.RoleUser, itemInput(3))
		if err != nil {
			t.Fatal(err)
		}
		if !auto.AutoApproved {
			t.Fatal("fixture is not an automatic approval")
		}
		item := auto.Items[0]
		item.FillRequestedAccounts()
		if item.RequestedAccounts == nil || !reflect.DeepEqual(*item.RequestedAccounts, model.AccountScope{"app"}) {
			t.Fatal("requested scope lost", item.PolicySnapshot)
		}
	})
	t.Run("a snapshot without the key stays null", func(t *testing.T) {
		item := model.AccessRequestItem{PolicySnapshot: `{"segment":"open"}`}
		item.FillRequestedAccounts()
		if item.RequestedAccounts != nil {
			t.Fatal("invented a requested scope", item.RequestedAccounts)
		}
	})
}
