package authz

import (
	"errors"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"gorm.io/gorm"
)

func setThreshold(t *testing.T, p *policy.SecurityPolicyService, n string) {
	t.Helper()
	if _, err := p.Update(policy.PolicyAccessRequestMinApprovals, n, "admin"); err != nil {
		t.Fatal(err)
	}
}

// revokeStanding 撤掉使用者對資產的全部直授授權列（模擬常設連線權被撤）。
func revokeStanding(t *testing.T, db *gorm.DB, userID, assetID uint) {
	t.Helper()
	if err := db.Where("user_id = ? AND asset_id = ? AND source <> ?", userID, assetID, model.AuthorizationSourceTicket).Delete(&model.AssetAuthorization{}).Error; err != nil {
		t.Fatal(err)
	}
}

// 核准時於交易內逐票重判申請資格：門檻 2 的第一票也要被擋。
func TestApproveRechecksStandingConnect(t *testing.T) {
	named := []string{"app"}
	check := func(t *testing.T, s *AccessRequestService, db *gorm.DB, req *model.AccessRequest, executor uint) {
		t.Helper()
		var votes int64
		db.Model(&model.AccessRequestApproval{}).Where("request_id = ?", req.ID).Count(&votes)
		var item model.AccessRequestItem
		db.Where("request_id = ?", req.ID).First(&item)
		if votes != 0 || item.Status != model.AccessRequestPending {
			t.Fatalf("precondition: votes=%d item=%s", votes, item.Status)
		}
		_, err := s.Approve(2, false, req.ID, DecideInput{})
		if !errors.Is(err, ErrRequestConnectRequired) {
			t.Fatalf("want ErrRequestConnectRequired, got %v", err)
		}
		db.Model(&model.AccessRequestApproval{}).Where("request_id = ?", req.ID).Count(&votes)
		if votes != 0 {
			t.Errorf("votes = %d, want 0", votes)
		}
		for _, id := range []uint{1, 4, executor} {
			if id != 0 && len(ticketRows(t, db, id)) != 0 {
				t.Errorf("user %d holds tickets", id)
			}
		}
		if _, err := s.Reject(2, false, req.ID, "no longer eligible"); err != nil {
			t.Fatalf("reject must stay available: %v", err)
		}
	}
	t.Run("requester revoked after submit", func(t *testing.T) {
		s, p, db, _ := setupItemRequestEnv(t)
		setThreshold(t, p, "2")
		setStanding(t, db, 1, 1)
		req, err := s.Submit(1, "requester", false, humanInput(1))
		if err != nil {
			t.Fatal(err)
		}
		revokeStanding(t, db, 1, 1)
		check(t, s, db, req, 0)
	})
	t.Run("assisted executor revoked after submit", func(t *testing.T) {
		s, p, db, agent := setupItemRequestEnv(t)
		setThreshold(t, p, "2")
		setStanding(t, db, 4, 1)
		setStanding(t, db, agent, 1)
		req, err := s.Submit(4, "requester2", false, SubmitAccessRequestInput{AssetID: 1, Accounts: &named, Reason: "task", DurationMinutes: 60, ExecutorUserID: &agent})
		if err != nil {
			t.Fatal(err)
		}
		revokeStanding(t, db, agent, 1)
		check(t, s, db, req, agent)
	})
	t.Run("existing pending request without standing connect", func(t *testing.T) {
		s, p, db, _ := setupItemRequestEnv(t)
		setThreshold(t, p, "2")
		setViewOnly(t, db, 1, 1)
		req := model.AccessRequest{RequesterID: 1, AssetID: 1, Reason: "legacy", RequestedDurationMinutes: 60, Status: model.AccessRequestPending,
			PendingExpiresAt: time.Now().Add(time.Hour), Kind: model.AccessRequestKindNormal}
		if err := db.Create(&req).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Create(&model.AccessRequestItem{RequestID: req.ID, RequesterID: 1, AssetID: 1, Status: model.AccessRequestPending}).Error; err != nil {
			t.Fatal(err)
		}
		check(t, s, db, &req, 0)
	})
}

// 回歸：仍持有常設連線權時，核准照常記票。
func TestApproveStillWorksWithStandingConnect(t *testing.T) {
	s, _, db, _ := setupItemRequestEnv(t)
	setStanding(t, db, 1, 1)
	req, err := s.Submit(1, "requester", false, humanInput(1))
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Approve(2, false, req.ID, DecideInput{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.AccessRequestApproved || len(ticketRows(t, db, 1)) != 1 {
		t.Fatalf("status=%s tickets=%d", got.Status, len(ticketRows(t, db, 1)))
	}
}

// 送單交易內重判：交易外檢查之後、交易內重判之前撤權，申請被擋下。
func TestSubmitRecheckInTx(t *testing.T) {
	run := func(t *testing.T, s *AccessRequestService, db *gorm.DB, revoke func(tx *gorm.DB), in func() (*model.AccessRequest, error)) {
		t.Helper()
		fired := 0
		restore := SetLockOrderHookForTest(func(point string, tx *gorm.DB, ids ...uint) {
			if point != "request_submit_before_recheck" {
				return
			}
			fired++
			revoke(tx)
		})
		defer restore()
		_, err := in()
		if fired != 1 {
			t.Fatalf("precondition: hook fired %d times, want 1", fired)
		}
		if !errors.Is(err, ErrRequestConnectRequired) {
			t.Fatalf("want ErrRequestConnectRequired, got %v", err)
		}
		assertNothingCreated(t, db)
	}
	t.Run("assisted requester revoked, executor still holds", func(t *testing.T) {
		s, _, db, agent := setupItemRequestEnv(t)
		setStanding(t, db, 4, 2)
		setStanding(t, db, agent, 2)
		names := []string{"app"}
		run(t, s, db, func(tx *gorm.DB) {
			tx.Unscoped().Where("user_id = ? AND asset_id = ?", 4, 2).Delete(&model.AssetAuthorization{})
		}, func() (*model.AccessRequest, error) {
			return s.Submit(4, "requester2", false, SubmitAccessRequestInput{AssetID: 2, Accounts: &names, Reason: "task", DurationMinutes: 60, ExecutorUserID: &agent})
		})
	})
	t.Run("self-run reason segment last grant revoked", func(t *testing.T) {
		s, _, db, _ := setupItemRequestEnv(t)
		setStanding(t, db, 1, 2)
		run(t, s, db, func(tx *gorm.DB) {
			tx.Unscoped().Where("user_id = ? AND asset_id = ?", 1, 2).Delete(&model.AssetAuthorization{})
		}, func() (*model.AccessRequest, error) {
			return s.Submit(1, "requester", false, humanInput(2))
		})
	})
}

// 資產列表：沒有常設連線權且無在途單者不標示可申請狀態；有在途單者仍標 pending。
func TestConnectStatesViewOnlyNoRequestState(t *testing.T) {
	for _, breakGlass := range []bool{false, true} {
		name := "break-glass off"
		if breakGlass {
			name = "break-glass on"
		}
		t.Run(name, func(t *testing.T) {
			s, p, db, _ := setupItemRequestEnv(t)
			if breakGlass {
				enableBreakGlass(t, p)
			}
			setViewOnly(t, db, 1, 1)
			setViewOnly(t, db, 1, 2)
			load := func() []*AuthorizedAssetDTO {
				out := []*AuthorizedAssetDTO{}
				for aid := uint(1); aid <= 2; aid++ {
					var asset model.Asset
					db.First(&asset, aid)
					out = append(out, &AuthorizedAssetDTO{Asset: asset, Permission: model.PermissionView})
				}
				return out
			}
			dtos := load()
			if err := s.AnnotateConnectStates(1, dtos); err != nil {
				t.Fatal(err)
			}
			for i, d := range dtos {
				if d.AccessState != "" || d.PendingRequestID != nil || d.BreakGlassAvailable {
					t.Errorf("asset %d view-only state = %q pending=%v breakglass=%v, want empty", i+1, d.AccessState, d.PendingRequestID, d.BreakGlassAvailable)
				}
			}
			// 升級前遺留的在途單：仍要看得到，才撤得回
			legacy := model.AccessRequest{RequesterID: 1, AssetID: 1, Reason: "legacy", RequestedDurationMinutes: 60, Status: model.AccessRequestPending,
				PendingExpiresAt: time.Now().Add(time.Hour), Kind: model.AccessRequestKindNormal}
			if err := db.Create(&legacy).Error; err != nil {
				t.Fatal(err)
			}
			dtos = load()
			if err := s.AnnotateConnectStates(1, dtos); err != nil {
				t.Fatal(err)
			}
			if dtos[0].AccessState != policy.AccessStatePending || dtos[0].PendingRequestID == nil || *dtos[0].PendingRequestID != legacy.ID {
				t.Errorf("legacy pending state = %q id=%v", dtos[0].AccessState, dtos[0].PendingRequestID)
			}
			if dtos[1].AccessState != "" {
				t.Errorf("asset 2 state = %q, want empty", dtos[1].AccessState)
			}
		})
	}
}
