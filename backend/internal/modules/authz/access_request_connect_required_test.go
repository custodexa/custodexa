package authz

import (
	"errors"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

func humanInput(assetID uint, accounts ...string) SubmitAccessRequestInput {
	in := SubmitAccessRequestInput{AssetID: assetID, Reason: "maintenance", DurationMinutes: 60}
	if len(accounts) > 0 {
		a := accounts
		in.Accounts = &a
	}
	return in
}

// assertNothingCreated 被拒的申請不得留下申請單、項或任何臨時授權。
func assertNothingCreated(t *testing.T, db *gorm.DB) {
	t.Helper()
	if n := countRows(t, db, &model.AccessRequest{}); n != 0 {
		t.Errorf("access_requests = %d, want 0", n)
	}
	if n := countRows(t, db, &model.AccessRequestItem{}); n != 0 {
		t.Errorf("access_request_items = %d, want 0", n)
	}
	var tickets int64
	db.Model(&model.AssetAuthorization{}).Where("source = ?", model.AuthorizationSourceTicket).Count(&tickets)
	if tickets != 0 {
		t.Errorf("ticket grants = %d, want 0", tickets)
	}
}

func requireNoStanding(t *testing.T, s *AccessRequestService, userID, assetID uint) {
	t.Helper()
	got, err := s.authzRepo.StandingConnectAssetIDs(userID, []uint{assetID}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got[assetID] {
		t.Fatalf("precondition: user %d unexpectedly holds standing connect on asset %d", userID, assetID)
	}
}

func requireVisible(t *testing.T, s *AccessRequestService, userID, assetID uint) {
	t.Helper()
	ok, err := s.RequestItemVisible(userID, nil, assetID)
	if err != nil || !ok {
		t.Fatalf("precondition: asset %d not visible to user %d (err=%v)", assetID, userID, err)
	}
}

// 只持 view 的使用者不得對 reason 或 approval 段位資產提出申請。
func TestSubmitConnectRequired_ViewOnly(t *testing.T) {
	for _, tc := range []struct {
		name  string
		asset uint
	}{{"reason segment", 2}, {"approval segment", 1}} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, db, _ := setupItemRequestEnv(t)
			setViewOnly(t, db, 1, tc.asset)
			requireNoStanding(t, s, 1, tc.asset)
			requireVisible(t, s, 1, tc.asset)
			req, err := s.Submit(1, "requester", false, humanInput(tc.asset))
			if err == nil {
				for _, tk := range ticketRows(t, db, 1) {
					t.Errorf("view-only submission produced ticket accounts=%v", []string(tk.Accounts))
				}
				t.Fatalf("view-only submission accepted: request status=%s", req.Status)
			}
			if !errors.Is(err, ErrRequestConnectRequired) {
				t.Fatalf("want ErrRequestConnectRequired, got %v", err)
			}
			var typed *RequestConnectRequiredError
			if !errors.As(err, &typed) || typed.ItemIndex != 0 || typed.AssetID != tc.asset {
				t.Fatalf("details = %+v", typed)
			}
			assertNothingCreated(t, db)
		})
	}
}

// 只因審核範圍而可見者不得申請。
func TestSubmitConnectRequired_ApproverScopeVisibleOnly(t *testing.T) {
	s, _, db, _ := setupItemRequestEnv(t)
	// user 2 的審核範圍直配 asset 1，沒有任何授權列
	clearDirectGrants(t, db, 2, 1)
	requireNoStanding(t, s, 2, 1)
	requireVisible(t, s, 2, 1)
	var direct int64
	db.Model(&model.AssetAuthorization{}).Where("user_id = ? AND asset_id = ?", 2, 1).Count(&direct)
	if direct != 0 {
		t.Fatalf("precondition: user 2 has %d direct grants", direct)
	}
	if _, err := s.Submit(2, "approver", false, humanInput(1)); !errors.Is(err, ErrRequestConnectRequired) {
		t.Fatalf("want ErrRequestConnectRequired, got %v", err)
	}
	assertNothingCreated(t, db)
}

// 只持仍在時效內的臨時授權，不構成申請資格。
func TestSubmitConnectRequired_TicketOnly(t *testing.T) {
	s, _, db, _ := setupItemRequestEnv(t)
	clearDirectGrants(t, db, 1, 1)
	u, a := uint(1), uint(1)
	start, end := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	if err := db.Create(&model.AssetAuthorization{UserID: &u, AssetID: &a, Permission: model.PermissionConnect, GrantedBy: 3,
		Source: model.AuthorizationSourceTicket, DateStart: &start, DateExpired: &end}).Error; err != nil {
		t.Fatal(err)
	}
	requireNoStanding(t, s, 1, 1)
	requireVisible(t, s, 1, 1)
	if _, err := s.Submit(1, "requester", false, humanInput(1)); !errors.Is(err, ErrRequestConnectRequired) {
		t.Fatalf("want ErrRequestConnectRequired, got %v", err)
	}
	if n := countRows(t, db, &model.AccessRequest{}); n != 0 {
		t.Fatalf("access_requests = %d, want 0", n)
	}
}

// 多項申請：序號指向第一個不符的項目。
func TestSubmitConnectRequired_ItemIndex(t *testing.T) {
	s, _, db, _ := setupItemRequestEnv(t)
	setStanding(t, db, 1, 1)
	setViewOnly(t, db, 1, 2)
	requireVisible(t, s, 1, 2)
	in := SubmitAccessRequestInput{Reason: "maintenance", DurationMinutes: 60, Items: []ItemInput{{AssetID: 1}, {AssetID: 2}}}
	_, err := s.Submit(1, "requester", false, in)
	var typed *RequestConnectRequiredError
	if !errors.As(err, &typed) || typed.ItemIndex != 1 || typed.AssetID != 2 {
		t.Fatalf("want item 1 / asset 2, got err=%v typed=%+v", err, typed)
	}
	assertNothingCreated(t, db)
}

// 回歸：不可視資產維持不存在語義，判定順序可視在前（既有行為）。
func TestSubmitNotVisibleStillNotFound(t *testing.T) {
	s, _, db, _ := setupItemRequestEnv(t)
	clearDirectGrants(t, db, 1, 2)
	if _, err := s.Submit(1, "requester", false, humanInput(2)); !errors.Is(err, ErrAccessRequestNotFound) {
		t.Fatalf("want ErrAccessRequestNotFound, got %v", err)
	}
}

// 回歸：持常設連線權者照常提出申請。
func TestSubmitWithStandingConnectStillWorks(t *testing.T) {
	s, _, db, _ := setupItemRequestEnv(t)
	setStanding(t, db, 1, 1)
	req, err := s.Submit(1, "requester", false, humanInput(1))
	if err != nil {
		t.Fatal(err)
	}
	if req.Status != model.AccessRequestPending {
		t.Fatalf("status = %s", req.Status)
	}
}
