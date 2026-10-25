package authz

import (
	"context"
	"errors"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 非規則建立者只能縮小帳號範圍（安全審查 B-03）。
//
// 擁有者轉移守衛以 granted_by 判定「新擁有者曾替此 agent 授權」。若非建立者可以擴大
// 他人建立的規則，granted_by 就不再代表「誰主張了這個範圍」，先擴大再轉移即繞過。
// 修法不加沿革欄，而是維持不變式「有效規則的帳號範圍 ⊆ granted_by 主張的範圍」：
// 非超管且非建立者只能縮小，擴大須由建立者或超管執行（或刪除後以自己名義重建，
// 此時 granted_by 即為本人，轉移守衛照常命中）。
//
// 突變自檢：把 UpdateAccountScope 交易內的 guardAccountScopeWiden 拿掉，前兩案轉紅。

func accountsOf(t *testing.T, db *gorm.DB, id uint) model.AccountScope {
	t.Helper()
	var row model.AssetAuthorization
	if err := db.First(&row, id).Error; err != nil {
		t.Fatal(err)
	}
	return row.Accounts
}

func TestAccountScopeWidenByNonGranter(t *testing.T) {
	svc, db := selfGuardEnv(t)
	if err := db.AutoMigrate(&model.ApproverScope{}, &model.AccessRequest{}, &model.AccessRequestItem{}, &model.AccessRequestApproval{},
		&model.Role{}, &model.RolePermission{}, &model.UserRole{}, &model.UserGroupRole{}, &model.RoleBindingNode{}); err != nil {
		t.Fatal(err)
	}
	asset, agent := uint(1), uint(6) // agent 6 屬 user 2
	// 建立者 3（非超管、非 agent 擁有者）建一筆窄範圍規則
	scope := []string{"app"}
	row, err := svc.Grant(operatorCtx(3), GrantSpec{UserID: &agent, AssetID: &asset,
		Permission: model.PermissionConnect, GrantedBy: 3, Accounts: &scope})
	if err != nil {
		t.Fatalf("建立者建規則: %v", err)
	}

	t.Run("非建立者擴大到 @ALL 被拒且範圍不變", func(t *testing.T) {
		_, err := svc.UpdateAccountScope(operatorCtx(1), row.ID, &[]string{"@ALL"})
		if !errors.Is(err, ErrAccountScopeWidenRestricted) {
			t.Fatalf("應回 ErrAccountScopeWidenRestricted，實得 %v", err)
		}
		if got := accountsOf(t, db, row.ID); len(got) != 1 || got[0] != "app" {
			t.Fatalf("被拒後範圍不得改變: %v", got)
		}
	})

	t.Run("非建立者加入新帳號名被拒且 granted_by 不變", func(t *testing.T) {
		_, err := svc.UpdateAccountScope(operatorCtx(1), row.ID, &[]string{"app", "db"})
		if !errors.Is(err, ErrAccountScopeWidenRestricted) {
			t.Fatalf("應回 ErrAccountScopeWidenRestricted，實得 %v", err)
		}
		var cur model.AssetAuthorization
		if err := db.First(&cur, row.ID).Error; err != nil {
			t.Fatal(err)
		}
		if cur.GrantedBy != 3 {
			t.Fatalf("granted_by 不得被改寫: %d", cur.GrantedBy)
		}
	})

	t.Run("建立者擴大成功；非建立者縮小成功", func(t *testing.T) {
		if _, err := svc.UpdateAccountScope(operatorCtx(3), row.ID, &[]string{"app", "db"}); err != nil {
			t.Fatalf("建立者擴大: %v", err)
		}
		if _, err := svc.UpdateAccountScope(operatorCtx(1), row.ID, &[]string{"db"}); err != nil {
			t.Fatalf("非建立者縮小: %v", err)
		}
		if got := accountsOf(t, db, row.ID); len(got) != 1 || got[0] != "db" {
			t.Fatalf("縮小後範圍: %v", got)
		}
		// 縮小過的人想擴回去同樣被拒：縮小不取得主張權
		if _, err := svc.UpdateAccountScope(operatorCtx(1), row.ID, &[]string{"app", "db"}); !errors.Is(err, ErrAccountScopeWidenRestricted) {
			t.Fatalf("非建立者擴回去應被拒: %v", err)
		}
	})

	t.Run("超管擴大成功", func(t *testing.T) {
		if _, err := svc.UpdateAccountScope(superAdminOperatorCtx(2), row.ID, &[]string{"@ALL"}); err != nil {
			t.Fatalf("超管擴大: %v", err)
		}
		if !accountsOf(t, db, row.ID).IsAll() {
			t.Fatal("超管擴大後應為 @ALL")
		}
	})

	t.Run("從未擴大過的操作者接手 agent 不被守衛擋：範圍仍是建立者與超管主張的", func(t *testing.T) {
		if err := (SelfGrantGuard{}).CheckOwnerTransfer(db, agent, 1); err != nil {
			t.Fatalf("1 未主張任何範圍，轉移不應被擋: %v", err)
		}
		if err := (SelfGrantGuard{}).CheckOwnerTransfer(db, agent, 3); !errors.Is(err, ErrAgentOwnerTransferSelfGrant) {
			t.Fatalf("建立者 3 接手應被擋: %v", err)
		}
	})

	t.Run("脈絡無主體時 fail-close", func(t *testing.T) {
		if _, err := svc.UpdateAccountScope(context.Background(), row.ID, &[]string{"app"}); !errors.Is(err, ErrOperatorUnknown) {
			t.Fatalf("無主體應回 ErrOperatorUnknown: %v", err)
		}
	})
}
