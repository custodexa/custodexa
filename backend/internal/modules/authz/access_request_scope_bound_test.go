package authz

import (
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

func firstItem(t *testing.T, db *gorm.DB, requestID uint) model.AccessRequestItem {
	t.Helper()
	var item model.AccessRequestItem
	if err := db.Where("request_id = ?", requestID).Order("id").First(&item).Error; err != nil {
		t.Fatalf("load item: %v", err)
	}
	return item
}

func requireStandingScope(t *testing.T, s *AccessRequestService, userID, assetID uint, want ...string) {
	t.Helper()
	rows, err := s.authzRepo.AccountScopesFor(userID, assetID, []model.PermissionType{model.PermissionConnect}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || !scopeIs(rows[0], want...) {
		t.Fatalf("precondition: user %d scopes on asset %d = %v, want %v", userID, assetID, rows, want)
	}
}

// reason 段位：未帶帳號範圍時，臨時授權範圍以常設範圍為上界。
func TestAutoApproveScopeBound_UnscopedRequestClampedToStanding(t *testing.T) {
	s, _, db, _ := setupItemRequestEnv(t)
	setStanding(t, db, 1, 2, "app")
	requireStandingScope(t, s, 1, 2, "app")
	req, err := s.Submit(1, "requester", false, humanInput(2))
	if err != nil {
		t.Fatal(err)
	}
	if req.Status != model.AccessRequestApproved {
		t.Fatalf("precondition: status = %s, want approved", req.Status)
	}
	tickets := ticketRows(t, db, 1)
	if len(tickets) != 1 {
		t.Fatalf("tickets = %d, want 1", len(tickets))
	}
	if !scopeIs(tickets[0].Accounts, "app") {
		t.Fatalf("ticket accounts = %v, want [app]", []string(tickets[0].Accounts))
	}
}

// reason 段位：具名帳號超出常設範圍的項改走人工審核，不產生臨時授權。
func TestAutoApproveScopeBound_NamedOutsideBecomesPending(t *testing.T) {
	s, _, db, _ := setupItemRequestEnv(t)
	addAssetAccount(t, db, 2, "root")
	setStanding(t, db, 1, 2, "app")
	requireStandingScope(t, s, 1, 2, "app")
	req, err := s.Submit(1, "requester", false, humanInput(2, "root"))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	item := firstItem(t, db, req.ID)
	if item.Status != model.AccessRequestPending || req.Status != model.AccessRequestPending {
		t.Fatalf("request/item status = %s/%s, want pending/pending", req.Status, item.Status)
	}
	if n := len(ticketRows(t, db, 1)); n != 0 {
		t.Fatalf("tickets = %d, want 0", n)
	}
}

// agent 於 open 段位：具名帳號超出常設範圍轉人工審核。
func TestAutoApproveScopeBound_AgentOpenSegmentOutsideBecomesPending(t *testing.T) {
	s, _, db, agent := setupItemRequestEnv(t)
	addAssetAccount(t, db, 3, "deploy")
	addAssetAccount(t, db, 3, "root")
	setStanding(t, db, agent, 3, "deploy")
	requireStandingScope(t, s, agent, 3, "deploy")
	names := []string{"root"}
	req, err := s.Submit(agent, "agent", false, SubmitAccessRequestInput{AssetID: 3, Accounts: &names, Reason: "task", DurationMinutes: 60})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	item := firstItem(t, db, req.ID)
	if item.Status != model.AccessRequestPending {
		t.Fatalf("item status = %s, want pending", item.Status)
	}
	if n := len(ticketRows(t, db, agent)); n != 0 {
		t.Fatalf("tickets = %d, want 0", n)
	}
}

// 輔助模式：上界以執行者的常設範圍計，不看申請人。
func TestAutoApproveScopeBound_AssistedUsesExecutorBound(t *testing.T) {
	s, _, db, agent := setupItemRequestEnv(t)
	addAssetAccount(t, db, 3, "deploy")
	addAssetAccount(t, db, 3, "root")
	setStanding(t, db, 1, 3)
	setStanding(t, db, agent, 3, "deploy")
	requireStandingScope(t, s, agent, 3, "deploy")
	names := []string{"root"}
	req, err := s.Submit(1, "requester", false, SubmitAccessRequestInput{AssetID: 3, Accounts: &names, Reason: "task", DurationMinutes: 60, ExecutorUserID: &agent})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if item := firstItem(t, db, req.ID); item.Status != model.AccessRequestPending {
		t.Fatalf("item status = %s, want pending", item.Status)
	}
	if n := len(ticketRows(t, db, agent)); n != 0 {
		t.Fatalf("executor tickets = %d, want 0", n)
	}
}

// 回歸：具名帳號全在上界內，原樣核發（既有行為）。
func TestAutoApproveWithinBoundKeepsRequestedAccounts(t *testing.T) {
	s, _, db, _ := setupItemRequestEnv(t)
	addAssetAccount(t, db, 2, "ops")
	setStanding(t, db, 1, 2, "app", "ops")
	req, err := s.Submit(1, "requester", false, humanInput(2, "ops"))
	if err != nil {
		t.Fatal(err)
	}
	if req.Status != model.AccessRequestApproved {
		t.Fatalf("status = %s", req.Status)
	}
	tickets := ticketRows(t, db, 1)
	if len(tickets) != 1 || !scopeIs(tickets[0].Accounts, "ops") {
		t.Fatalf("tickets = %+v", tickets)
	}
}

// 回歸：常設為全部帳號者行為不變。
func TestAutoApproveStandingAllUnchanged(t *testing.T) {
	s, _, db, _ := setupItemRequestEnv(t)
	setStanding(t, db, 1, 2)
	req, err := s.Submit(1, "requester", false, humanInput(2))
	if err != nil {
		t.Fatal(err)
	}
	if req.Status != model.AccessRequestApproved {
		t.Fatalf("status = %s", req.Status)
	}
	tickets := ticketRows(t, db, 1)
	if len(tickets) != 1 || !tickets[0].Accounts.IsAll() {
		t.Fatalf("tickets = %+v", tickets)
	}
}
