package authz

import (
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 定向通知收件人判定的模組內測試。收件人集合、端點守門與頁面可達的完整 fixture 在
// internal/api/targeted_recipients_test.go（要經真的路由）；這裡驗：
//   - 判定接受呼叫端的連線句柄（V2-03）：在連線池為 1 的 SQLite 上，於已開啟的交易內以交易句柄呼叫不會等待自己；
//   - 送出前重驗的結論分成「仍需要」「事情已了結」「人不對了」三種（V2-02 的判法：看收件人的權限是否還在）。

// setupTargetedAuthzEnv singleConn 為真時把連線池收為 1（驗交易句柄）；破窗流程在交易內另以連線池
// 檢查還原世代，那一格沿用既有破窗測試的連線設定。
func setupTargetedAuthzEnv(t *testing.T, singleConn bool) (*AccessRequestService, *gorm.DB) {
	t.Helper()
	svc, policies, db := setupAccessRequestEnv(t)
	if singleConn {
		sqlDB, err := db.DB()
		if err != nil {
			t.Fatal(err)
		}
		sqlDB.SetMaxOpenConns(1)
	}
	if err := db.AutoMigrate(&model.Role{}, &model.UserGroupMember{}); err != nil {
		t.Fatal(err)
	}
	seedRequestFixture(t, db)
	role := model.Role{Name: model.RoleApprover}
	if err := db.Create(&role).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.UserRole{UserID: 2, RoleID: role.ID, ScopeKind: model.ScopeKindGlobal}).Error; err != nil {
		t.Fatal(err)
	}
	enableBreakGlass(t, policies)
	return svc, db
}

// TestTargetedRecipientsAcceptTxHandle (f) 判定在呼叫端給的交易句柄上執行，5 秒內完成。
func TestTargetedRecipientsAcceptTxHandle(t *testing.T) {
	svc, db := setupTargetedAuthzEnv(t, true)
	req := submitBasic(t, svc, 1, 1)
	done := make(chan []uint, 1)
	errc := make(chan error, 1)
	go func() {
		var got []uint
		err := db.Transaction(func(tx *gorm.DB) error {
			var err error
			got, err = svc.TargetedAccessRequestRecipients(tx, req.ID, time.Now())
			if err != nil {
				return err
			}
			if _, err = svc.TargetedAccessRequestVerdict(tx, req.ID, 2, time.Now()); err != nil {
				return err
			}
			if _, err = svc.TargetedBreakGlassRecipients(tx, req.ID); err != nil {
				return err
			}
			_, err = TargetedAccessRequestAwaiting(tx, req.ID, time.Now())
			return err
		})
		if err != nil {
			errc <- err
			return
		}
		done <- got
	}()
	select {
	case got := <-done:
		if len(got) != 1 || got[0] != 2 {
			t.Errorf("收件人 = %v，want [2]", got)
		}
	case err := <-errc:
		t.Fatalf("交易內判定失敗: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("在連線池為 1 的 SQLite 上，交易內以交易句柄呼叫判定沒有在 5 秒內完成（判定改用了服務自己的連線）")
	}
}

// TestTargetedAccessRequestVerdict 送出前重驗的三種結論。
func TestTargetedAccessRequestVerdict(t *testing.T) {
	svc, db := setupTargetedAuthzEnv(t, true)
	req := submitBasic(t, svc, 1, 1)
	verdict := func() RecipientVerdict {
		v, err := svc.TargetedAccessRequestVerdict(db, req.ID, 2, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if v := verdict(); v != RecipientNeeded {
		t.Fatalf("待審時 = %v，want 仍需要", v)
	}
	if ok, _ := TargetedAccessRequestAwaiting(db, req.ID, time.Now()); !ok {
		t.Error("待審的單 Awaiting 為假")
	}
	// 他投完票：權限仍在，事情對他已了結
	var item model.AccessRequestItem
	if err := db.Where("request_id = ?", req.ID).First(&item).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.AccessRequestApproval{RequestID: req.ID, ItemID: &item.ID, ApproverID: 2}).Error; err != nil {
		t.Fatal(err)
	}
	if v := verdict(); v != RecipientResolved {
		t.Errorf("投完票後 = %v，want 事情已了結", v)
	}
	if err := db.Where("approver_id = 2").Delete(&model.AccessRequestApproval{}).Error; err != nil {
		t.Fatal(err)
	}
	// 單已被核准：事情已了結
	if err := db.Model(&model.AccessRequest{}).Where("id = ?", req.ID).Update("status", model.AccessRequestApproved).Error; err != nil {
		t.Fatal(err)
	}
	if v := verdict(); v != RecipientResolved {
		t.Errorf("單已核准 = %v，want 事情已了結", v)
	}
	if ok, _ := TargetedAccessRequestAwaiting(db, req.ID, time.Now()); ok {
		t.Error("已核准的單 Awaiting 為真")
	}
	if err := db.Model(&model.AccessRequest{}).Where("id = ?", req.ID).Update("status", model.AccessRequestPending).Error; err != nil {
		t.Fatal(err)
	}
	// 範圍被移除：人不對了
	if err := db.Where("approver_id = 2").Delete(&model.ApproverScope{}).Error; err != nil {
		t.Fatal(err)
	}
	if v := verdict(); v != RecipientIneligible {
		t.Errorf("範圍被移除 = %v，want 不具資格", v)
	}
	a1 := uint(1)
	if err := db.Create(&model.ApproverScope{ApproverID: uptrScope(2), AssetID: &a1, GrantedBy: 3}).Error; err != nil {
		t.Fatal(err)
	}
	if v := verdict(); v != RecipientNeeded {
		t.Fatalf("範圍恢復後 = %v，want 仍需要", v)
	}
	// 帳號停用、刪除：人不對了
	if err := db.Model(&model.User{}).Where("id = 2").Update("active", false).Error; err != nil {
		t.Fatal(err)
	}
	if v := verdict(); v != RecipientIneligible {
		t.Errorf("停用 = %v，want 不具資格", v)
	}
	if err := db.Model(&model.User{}).Where("id = 2").Update("active", true).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Delete(&model.User{}, 2).Error; err != nil {
		t.Fatal(err)
	}
	if v := verdict(); v != RecipientIneligible {
		t.Errorf("刪除 = %v，want 不具資格", v)
	}
}

// TestTargetedBreakGlassVerdict 破窗：建單即自動核准、補審待補審時仍需要；補審完成後事情已了結。
func TestTargetedBreakGlassVerdict(t *testing.T) {
	svc, db := setupTargetedAuthzEnv(t, false)
	bg, err := svc.BreakGlass(1, "requester", false, 1, "incident")
	if err != nil {
		t.Fatalf("BreakGlass: %v", err)
	}
	if v, err := svc.TargetedBreakGlassVerdict(db, bg.ID, 2); err != nil || v != RecipientNeeded {
		t.Fatalf("待補審 = %v（%v），want 仍需要", v, err)
	}
	if ok, _ := TargetedBreakGlassAwaiting(db, bg.ID); !ok {
		t.Error("待補審的破窗單 Awaiting 為假")
	}
	if err := db.Model(&model.AccessRequest{}).Where("id = ?", bg.ID).Update("review_status", model.BreakGlassReviewReviewed).Error; err != nil {
		t.Fatal(err)
	}
	if v, _ := svc.TargetedBreakGlassVerdict(db, bg.ID, 2); v != RecipientResolved {
		t.Errorf("已補審 = %v，want 事情已了結", v)
	}
	if ok, _ := TargetedBreakGlassAwaiting(db, bg.ID); ok {
		t.Error("已補審的破窗單 Awaiting 為真")
	}
	if v, _ := svc.TargetedBreakGlassVerdict(db, bg.ID, 1); v != RecipientIneligible {
		t.Errorf("破窗人本人（不是有效審核者）= %v，want 不具資格", v)
	}
}
