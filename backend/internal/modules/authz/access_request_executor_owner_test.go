package authz

import (
	"errors"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"gorm.io/gorm"
)

// executorOwnerEnv 人類 X（user 4）指定 agent A 為執行者，對 approval 段位的 asset 1 提出申請；
// A 的擁有者 Y（user 2）的審核範圍涵蓋 asset 1。回傳服務、DB、A、以及該申請單。
func executorOwnerEnv(t *testing.T) (*AccessRequestService, *policy.SecurityPolicyService, *gorm.DB, uint, *model.AccessRequest) {
	t.Helper()
	s, p, db, agent := setupItemRequestEnv(t)
	if err := db.Model(&model.User{}).Where("id = ?", agent).Update("owner_user_id", 2).Error; err != nil {
		t.Fatal(err)
	}
	setStanding(t, db, 4, 1)
	setStanding(t, db, agent, 1)
	names := []string{"app"}
	req, err := s.Submit(4, "requester2", false, SubmitAccessRequestInput{AssetID: 1, Accounts: &names, Reason: "task", DurationMinutes: 60, ExecutorUserID: &agent})
	if err != nil {
		t.Fatalf("precondition: submit: %v", err)
	}
	if req.Status != model.AccessRequestPending || req.ExecutorUserID == nil || *req.ExecutorUserID != agent {
		t.Fatalf("precondition: request = %+v", req)
	}
	var owner uint
	db.Model(&model.User{}).Select("owner_user_id").Where("id = ?", agent).Scan(&owner)
	if owner != 2 {
		t.Fatalf("precondition: agent owner = %d, want 2", owner)
	}
	return s, p, db, agent, req
}

// seedApprover 新增一位審核範圍涵蓋 asset 1 的使用者。
func seedApprover(t *testing.T, db *gorm.DB, name string) uint {
	t.Helper()
	u := model.User{Username: name, Email: strPtr(name + "@x"), Active: true}
	if err := db.Create(&u).Error; err != nil {
		t.Fatal(err)
	}
	a := uint(1)
	if err := db.Create(&model.ApproverScope{ApproverID: uptrScope(u.ID), AssetID: &a, GrantedBy: 3}).Error; err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func voteRows(t *testing.T, db *gorm.DB, requestID uint) int64 {
	t.Helper()
	var n int64
	db.Model(&model.AccessRequestApproval{}).Where("request_id = ?", requestID).Count(&n)
	return n
}

// 執行者 agent 的擁有者不可核准。
func TestExecutorOwnerSelfDecision_ApproveBlocked(t *testing.T) {
	s, _, db, agent, req := executorOwnerEnv(t)
	_, err := s.Approve(2, false, req.ID, DecideInput{})
	if !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("want ErrSelfApproval, got %v", err)
	}
	if n := voteRows(t, db, req.ID); n != 0 {
		t.Fatalf("votes = %d, want 0", n)
	}
	if n := len(ticketRows(t, db, agent)); n != 0 {
		t.Fatalf("tickets = %d, want 0", n)
	}
}

// 執行者 agent 的擁有者不可拒絕。
func TestExecutorOwnerSelfDecision_RejectBlocked(t *testing.T) {
	s, _, db, _, req := executorOwnerEnv(t)
	_, err := s.Reject(2, false, req.ID, "no")
	if !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("want ErrSelfApproval, got %v", err)
	}
	var got model.AccessRequest
	db.First(&got, req.ID)
	if got.Status != model.AccessRequestPending {
		t.Fatalf("status = %s, want pending", got.Status)
	}
}

// 待審列表與計數排除；其他具資格者仍看得到。
func TestExecutorOwnerSelfDecision_PendingListExcluded(t *testing.T) {
	s, _, db, _, req := executorOwnerEnv(t)
	other := seedApprover(t, db, "approver-other")
	list, err := s.ListPending(other, false, time.Now())
	if err != nil || len(list) != 1 || list[0].ID != req.ID {
		t.Fatalf("precondition: other approver list = %d err=%v", len(list), err)
	}
	if n, err := s.PendingCount(other, false, time.Now()); err != nil || n != 1 {
		t.Fatalf("precondition: other approver count = %d err=%v", n, err)
	}
	list, err = s.ListPending(2, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range list {
		if r.ID == req.ID {
			t.Fatalf("owner of executor sees request %d in pending list", req.ID)
		}
	}
	if n, err := s.PendingCount(2, false, time.Now()); err != nil || n != 0 {
		t.Fatalf("owner pending count = %d err=%v, want 0", n, err)
	}
}

// 擁有關係變更後投下的舊票不計入門檻。
func TestExecutorOwnerSelfDecision_StaleVoteNotCounted(t *testing.T) {
	s, p, db, agent, req := executorOwnerEnv(t)
	if _, err := p.Update(policy.PolicyAccessRequestMinApprovals, "2", "admin"); err != nil {
		t.Fatal(err)
	}
	z := seedApprover(t, db, "approver-z")
	got, err := s.Approve(z, false, req.ID, DecideInput{})
	if err != nil {
		t.Fatalf("precondition: first vote: %v", err)
	}
	if got.Status != model.AccessRequestPending || voteRows(t, db, req.ID) != 1 {
		t.Fatalf("precondition: status=%s votes=%d", got.Status, voteRows(t, db, req.ID))
	}
	// 升級 fixture：直接寫資料把 A 的擁有者改為 Z（不走轉移 API）
	if err := db.Model(&model.User{}).Where("id = ?", agent).Update("owner_user_id", z).Error; err != nil {
		t.Fatal(err)
	}
	var owner uint
	db.Model(&model.User{}).Select("owner_user_id").Where("id = ?", agent).Scan(&owner)
	if owner != z || voteRows(t, db, req.ID) != 1 {
		t.Fatalf("precondition: owner=%d votes=%d", owner, voteRows(t, db, req.ID))
	}
	got, err = s.Approve(3, true, req.ID, DecideInput{})
	if err != nil {
		t.Fatalf("second vote: %v", err)
	}
	if got.Status != model.AccessRequestPending {
		t.Fatalf("status = %s, want pending (1/2)", got.Status)
	}
	if n := len(ticketRows(t, db, agent)); n != 0 {
		t.Fatalf("tickets = %d, want 0", n)
	}
	if n := voteRows(t, db, req.ID); n != 2 {
		t.Fatalf("votes rows = %d, want 2 (stale vote kept for audit)", n)
	}
}

// 擁有者轉移受執行者側有效核准票阻擋。
func TestExecutorOwnerSelfDecision_TransferBlockedByExecutorSideVote(t *testing.T) {
	s, p, db, agent, req := executorOwnerEnv(t)
	if _, err := p.Update(policy.PolicyAccessRequestMinApprovals, "2", "admin"); err != nil {
		t.Fatal(err)
	}
	// 轉移守衛解析新擁有者主體需要角色表
	if err := db.AutoMigrate(&model.Role{}, &model.RolePermission{}, &model.UserGroupMember{},
		&model.UserGroupRole{}, &model.RoleBindingNode{}); err != nil {
		t.Fatal(err)
	}
	z := seedApprover(t, db, "approver-z")
	if _, err := s.Approve(z, false, req.ID, DecideInput{}); err != nil {
		t.Fatalf("precondition: vote: %v", err)
	}
	if voteRows(t, db, req.ID) != 1 {
		t.Fatal("precondition: vote row missing")
	}
	err := (SelfGrantGuard{}).CheckOwnerTransfer(db, agent, z)
	if !errors.Is(err, ErrAgentOwnerTransferSelfGrant) {
		t.Fatalf("want ErrAgentOwnerTransferSelfGrant, got %v", err)
	}
}

// 回歸：送單端不因擁有關係限制委派（非擁有者合法委派）。既有行為。
func TestExecutorOwnerSelfDecision_NonOwnerDelegationStillAllowed(t *testing.T) {
	s, _, db, agent := setupItemRequestEnv(t)
	setStanding(t, db, 4, 1)
	setStanding(t, db, agent, 1)
	names := []string{"app"}
	if _, err := s.Submit(4, "requester2", false, SubmitAccessRequestInput{AssetID: 1, Accounts: &names, Reason: "task", DurationMinutes: 60, ExecutorUserID: &agent}); err != nil {
		t.Fatal(err)
	}
}
