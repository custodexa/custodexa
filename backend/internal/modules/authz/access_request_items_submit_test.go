package authz

import (
	"context"
	"errors"
	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"gorm.io/gorm"
	"strings"
	"testing"
	"time"
)

func setupItemRequestEnv(t *testing.T) (*AccessRequestService, *policy.SecurityPolicyService, *gorm.DB, uint) {
	t.Helper()
	s, p, db := setupAccessRequestEnv(t)
	seedRequestFixture(t, db)
	s.SetAccountPresenceSource(func(db *gorm.DB, id uint, name string) (bool, error) {
		var n int64
		err := db.Table("asset_accounts").Where("asset_id=? AND username=? AND deleted_at IS NULL", id, name).Count(&n).Error
		return n > 0, err
	})
	if err := db.AutoMigrate(&model.AccessRequestItem{}, &model.AssetAccount{}, &model.Credential{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`CREATE UNIQUE INDEX access_request_items_pending_unique ON access_request_items(requester_id,asset_id) WHERE status='pending' AND deleted_at IS NULL`).Error; err != nil {
		t.Fatal(err)
	}
	owner := uint(1)
	agent := model.User{Username: "task-agent", Password: "!", Kind: model.KindAgent, OwnerUserID: &owner, Active: true}
	if err := db.Create(&agent).Error; err != nil {
		t.Fatal(err)
	}
	for _, id := range []uint{1, 2, 3} {
		a := id
		if err := db.Create(&model.AssetAuthorization{UserID: &agent.ID, AssetID: &a, Permission: model.PermissionView, GrantedBy: 1}).Error; err != nil {
			t.Fatal(err)
		}
		c := model.Credential{Username: "app", Scope: model.CredentialScopeDedicated, SecretType: "password", ProtocolFamily: model.ProtocolFamilySSH}
		if err := db.Create(&c).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Create(&model.AssetAccount{AssetID: id, CredentialID: c.ID, Username: "app"}).Error; err != nil {
			t.Fatal(err)
		}
	}
	return s, p, db, agent.ID
}
func itemInput(asset uint) SubmitAccessRequestInput {
	names := []string{"app"}
	return SubmitAccessRequestInput{AssetID: asset, Accounts: &names, Reason: "maintenance", DurationMinutes: 60}
}
func TestSubmitAccessRequestItems(t *testing.T) {
	t.Run("legacy mirrors one item", func(t *testing.T) {
		s, _, _, _ := setupItemRequestEnv(t)
		r, e := s.Submit(1, "human", model.RoleUser, itemInput(1))
		if e != nil {
			t.Fatal(e)
		}
		if len(r.Items) != 1 || r.Items[0].AssetID != r.AssetID || !r.Items[0].Accounts.Contains("app") {
			t.Fatal(r)
		}
	})
	t.Run("mixed items independent", func(t *testing.T) {
		s, _, db, agent := setupItemRequestEnv(t)
		in := itemInput(1)
		in.Items = []ItemInput{{1, in.Accounts}, {3, in.Accounts}}
		in.AssetID = 0
		in.Accounts = nil
		r, e := s.Submit(agent, "agent", model.RoleUser, in)
		if e != nil {
			t.Fatal(e)
		}
		if len(r.Items) != 2 || r.Status != model.AccessRequestPending || r.Items[0].Status != model.AccessRequestPending || r.Items[1].Status != model.AccessRequestApproved || r.AuthorizationID != nil {
			t.Fatal(r)
		}
		var grants int64
		db.Model(&model.AssetAuthorization{}).Where("source='ticket' AND user_id=? AND asset_id=3", agent).Count(&grants)
		if grants != 1 {
			t.Fatal(grants)
		}
	})
	t.Run("exclusive shapes and bounds", func(t *testing.T) {
		for _, in := range []SubmitAccessRequestInput{{AssetID: 1, Items: []ItemInput{{AssetID: 2}}}, {Items: []ItemInput{}}, {Items: []ItemInput{{AssetID: 1}, {AssetID: 1}}}, {Items: make([]ItemInput, 21)}} {
			s, _, db, _ := setupItemRequestEnv(t)
			_, e := s.Submit(1, "human", model.RoleUser, in)
			if !errors.Is(e, ErrRequestItemsShape) {
				t.Fatal(e)
			}
			var n int64
			db.Model(&model.AccessRequest{}).Count(&n)
			if n != 0 {
				t.Fatal(n)
			}
		}
	})
}
func TestSubmitAccessRequestSegment(t *testing.T) {
	for _, mode := range []string{"autonomous", "assisted", "human"} {
		t.Run(mode, func(t *testing.T) {
			s, _, db, agent := setupItemRequestEnv(t)
			id := uint(1)
			in := itemInput(3)
			if mode == "autonomous" {
				id = agent
			}
			if mode == "assisted" {
				in.ExecutorUserID = &agent
			}
			r, e := s.Submit(id, "actor", model.RoleUser, in)
			if mode == "human" {
				if !errors.Is(e, ErrPolicyOpenNoRequest) {
					t.Fatal(e)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if r.Status != model.AccessRequestApproved || len(r.Items) != 1 || r.Items[0].Status != model.AccessRequestApproved || !r.AutoApproved {
				t.Fatal(r)
			}
			var auth model.AssetAuthorization
			if e := db.First(&auth, *r.AuthorizationID).Error; e != nil {
				t.Fatal(e)
			}
			if auth.UserID == nil || *auth.UserID != agent || !auth.Accounts.Contains("app") {
				t.Fatal(auth)
			}
			if !strings.Contains(r.Items[0].PolicySnapshot, `"auto_basis":"open"`) {
				t.Fatal(r.Items)
			}
		})
	}
}
func TestSubmitRejectsAccountNotOnAsset(t *testing.T) {
	s, _, db, _ := setupItemRequestEnv(t)
	in := itemInput(1)
	names := []string{"app", "absent"}
	in.Accounts = &names
	_, e := s.Submit(1, "human", model.RoleUser, in)
	if !errors.Is(e, ErrAccountNotOnAsset) {
		t.Fatal(e)
	}
	var n int64
	db.Model(&model.AccessRequest{}).Count(&n)
	if n != 0 {
		t.Fatal(n)
	}
}
func TestAgentItemRequiresAccounts(t *testing.T) {
	for _, mode := range []string{"autonomous", "assisted", "human"} {
		for _, shape := range []string{"omitted", "all", "empty", "blank"} {
			if mode == "human" && (shape == "empty" || shape == "blank") {
				continue
			}
			t.Run(mode+"/"+shape, func(t *testing.T) {
				s, _, db, agent := setupItemRequestEnv(t)
				in := itemInput(1)
				in.Accounts = nil
				if shape != "omitted" {
					names := []string{}
					if shape == "all" {
						names = []string{"@ALL"}
					}
					if shape == "blank" {
						names = []string{"  "}
					}
					in.Accounts = &names
				}
				id := uint(1)
				if mode == "autonomous" {
					id = agent
				}
				if mode == "assisted" {
					in.ExecutorUserID = &agent
				}
				r, e := s.Submit(id, "actor", model.RoleUser, in)
				if mode == "human" {
					if e != nil || !r.Accounts.IsAll() {
						t.Fatal(r, e)
					}
				} else {
					if !errors.Is(e, ErrAgentAccountsRequired) {
						t.Fatal(e)
					}
					var n int64
					if err := db.Model(&model.AccessRequest{}).Count(&n).Error; err != nil || n != 0 {
						t.Fatal("rejected input created envelope", n, err)
					}
				}
			})
		}
	}
}
func TestSubmitExecutorVisibilityIntersection(t *testing.T) {
	for _, side := range []string{"requester", "executor", "inactive", "human_executor", "revoked_after_approval"} {
		t.Run(side, func(t *testing.T) {
			s, _, db, agent := setupItemRequestEnv(t)
			in := itemInput(3)
			in.ExecutorUserID = &agent
			if side == "inactive" {
				db.Model(&model.User{}).Where("id=?", agent).Update("active", false)
			}
			if side == "human_executor" {
				id := uint(4)
				in.ExecutorUserID = &id
			}
			if side == "requester" || side == "executor" {
				id := uint(1)
				if side == "executor" {
					id = agent
				}
				db.Where("user_id=? AND asset_id=3", id).Delete(&model.AssetAuthorization{})
			}
			r, e := s.Submit(1, "human", model.RoleUser, in)
			switch side {
			case "inactive", "human_executor":
				if !errors.Is(e, ErrExecutorNotAgent) {
					t.Fatal(e)
				}
			case "requester", "executor":
				if !errors.Is(e, ErrAccessRequestNotFound) {
					t.Fatal(e)
				}
			default:
				if e != nil {
					t.Fatal(e)
				}
				if r.Items[0].Status != model.AccessRequestApproved {
					t.Fatal(r)
				}
				db.Where("user_id=1 AND asset_id=3 AND source <> 'ticket'").Delete(&model.AssetAuthorization{})
				visible, e := s.RequestItemVisible(r.RequesterID, r.ExecutorUserID, 3)
				if e != nil || visible {
					t.Fatal("approved-time snapshot rescued revoked requester", visible, e)
				}
			}
		})
	}
}
func TestSubmitDuplicatePendingItem(t *testing.T) {
	s, _, db, _ := setupItemRequestEnv(t)
	in := itemInput(2)
	in.Items = []ItemInput{{2, in.Accounts}, {1, in.Accounts}}
	in.AssetID = 0
	in.Accounts = nil
	first, e := s.Submit(1, "human", model.RoleUser, in)
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.Submit(1, "human", model.RoleUser, itemInput(1))
	var duplicate *DuplicatePendingItemError
	if !errors.As(e, &duplicate) || duplicate.RequestID != first.ID || duplicate.ItemID != first.Items[1].ID {
		t.Fatal(e)
	}
	var n int64
	db.Model(&model.AccessRequest{}).Count(&n)
	if n != 1 {
		t.Fatal("failed envelope leaked", n)
	}
}
func TestAgentRequestRateLimit(t *testing.T) {
	for _, dimension := range []string{"hour", "pending", "human"} {
		t.Run(dimension, func(t *testing.T) {
			s, p, db, agent := setupItemRequestEnv(t)
			key := policy.PolicyAgentRequestRatePerHour
			if dimension == "pending" {
				key = policy.PolicyAgentRequestPendingMax
			}
			if _, e := p.Update(key, "1", "admin"); e != nil {
				t.Fatal(e)
			}
			previousDB := database.DB
			database.DB = db
			t.Cleanup(func() { database.DB = previousDB })
			s.audit = audit.NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true})
			t.Cleanup(func() { _ = s.audit.Shutdown(context.Background()) })
			id := agent
			if dimension == "human" {
				id = 1
			}
			if _, e := s.Submit(id, "actor", model.RoleUser, itemInput(1)); e != nil {
				t.Fatal(e)
			}
			quotaQueries := 0
			if dimension == "human" {
				db.Callback().Query().After("gorm:query").Register("quota_read_counter", func(tx *gorm.DB) {
					q := tx.Statement.SQL.String()
					if strings.Contains(q, "count(*)") && strings.Contains(q, "access_requests") {
						quotaQueries++
					}
				})
			}
			r, e := s.Submit(id, "actor", model.RoleUser, itemInput(2))
			if dimension == "human" {
				if e != nil || r == nil || quotaQueries != 0 {
					t.Fatal("human quota regression", e, quotaQueries)
				}
				return
			}
			var rate *AgentRequestRateError
			if !errors.As(e, &rate) || rate.Count != 1 || rate.Limit != 1 || rate.Dimension != dimension {
				t.Fatal(e)
			}
			var requests, logs int64
			db.Model(&model.AccessRequest{}).Count(&requests)
			db.Model(&model.AuditLog{}).Where("status=? AND details LIKE ?", model.StatusDenied, "%RULE_AGENT_REQUEST_RATE%").Count(&logs)
			if requests != 1 || logs != 1 {
				t.Fatal("limit bypass or missing audit", requests, logs)
			}
			if dimension == "hour" {
				db.Model(&model.AccessRequest{}).Where("requester_id=?", agent).Update("created_at", time.Now().Add(-2*time.Hour))
			} else {
				db.Model(&model.AccessRequest{}).Where("requester_id=?", agent).Update("status", model.AccessRequestRejected)
			}
			if _, e := s.Submit(agent, "actor", model.RoleUser, itemInput(2)); e != nil {
				t.Fatal("released capacity not observed", e)
			}
		})
	}
}
