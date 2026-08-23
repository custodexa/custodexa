package authz

import (
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
)

// TestBreakGlassReviewStaysPendingWithNoApprover 審核資格收斂後，
// 系統可能進入「無人可補審」狀態（唯一的 admin 不再是有效審核者）。此時破窗單
// **必須維持 `pending_review`、持續逾期告警、不得自動結案**——若逾期掃描順手把
// 單結掉，破窗使用就會在無人審視的情況下靜默消失，等同放棄事後補審這道控制。
//
// 這是該次收斂唯一「行為變更製造出新常態」的地方，故以測試釘住其安全側行為。
func TestBreakGlassReviewStaysPendingWithNoApprover(t *testing.T) {
	svc, policies, db := setupAccessRequestEnv(t)
	seedRequestFixture(t, db)
	grantConnect(t, db, 1, 1)
	enableBreakGlass(t, policies)

	req, err := svc.BreakGlass(1, "requester", model.RoleUser, 1, "半夜事故")
	if err != nil {
		t.Fatalf("break glass: %v", err)
	}
	if req.ReviewStatus != model.BreakGlassReviewPending {
		t.Fatalf("破窗單初始 review_status = %s, want pending_review", req.ReviewStatus)
	}

	// 造出「零有效審核者」：清空全部審核範圍與 approver 角色關聯
	if err := db.Exec("DELETE FROM approver_scopes").Error; err != nil {
		t.Fatalf("clear scopes: %v", err)
	}

	// 僅具 admin 者已無法補審（service 端資格＝範圍命中；handler 一律傳 isAdmin=false，
	// 見 api 的 TestApproverRouteGate_AdminOnlyDenied）
	if _, err := svc.Review(3, false, req.ID, model.BreakGlassDispositionConfirmed, "x"); err == nil {
		t.Fatal("零範圍下非 admin 身分補審應被拒（ErrNotEligibleApprover）")
	}

	// 逾期掃描：發告警但不結案
	if _, err := policies.Update(policy.PolicyBreakGlassReviewTimeoutHours, "1", "admin"); err != nil {
		t.Fatalf("set timeout: %v", err)
	}
	base := time.Now()
	notified, err := svc.NotifyOverdueReviews(base.Add(2 * time.Hour))
	if err != nil {
		t.Fatalf("overdue sweep: %v", err)
	}
	if notified != 1 {
		t.Fatalf("逾期告警筆數 = %d, want 1（無人可補審時仍須持續升級）", notified)
	}

	// **持續升級才是保底**：舊實作以布林防重，同一單只響一次
	// 就永久靜默——一封信被漏看，破窗單即沉沒，避免死鎖所賴的補償控制形同
	// 不存在。以下三次掃描釘住「節流內不重發、跨節流窗必重發」兩側。
	quiet, err := svc.NotifyOverdueReviews(base.Add(3 * time.Hour))
	if err != nil {
		t.Fatalf("overdue sweep (throttled): %v", err)
	}
	if quiet != 0 {
		t.Fatalf("節流窗內重掃告警筆數 = %d, want 0（不得對同一單連續轟炸）", quiet)
	}

	again, err := svc.NotifyOverdueReviews(base.Add(48 * time.Hour))
	if err != nil {
		t.Fatalf("overdue sweep (second window): %v", err)
	}
	if again != 1 {
		t.Fatalf("跨節流窗後告警筆數 = %d, want 1（逾期告警必須週期重發，否則不構成可見性保底）", again)
	}

	third, err := svc.NotifyOverdueReviews(base.Add(30 * 24 * time.Hour))
	if err != nil {
		t.Fatalf("overdue sweep (third window): %v", err)
	}
	if third != 1 {
		t.Fatalf("第三輪告警筆數 = %d, want 1（重發不得隨次數衰減）", third)
	}

	var after model.AccessRequest
	if err := db.First(&after, req.ID).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if after.ReviewStatus != model.BreakGlassReviewPending {
		t.Fatalf("逾期掃描後 review_status = %s, want 仍為 pending_review（不得自動結案）", after.ReviewStatus)
	}
	if after.Status != model.AccessRequestApproved {
		t.Fatalf("破窗單狀態 = %s, want approved（逾期不改狀態機終態）", after.Status)
	}
}
