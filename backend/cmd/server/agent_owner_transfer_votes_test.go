package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 擁有者轉移守衛的兩個補強，走真 UserService.Update（安全審查 B-03、B-04）：
// - B-03：非建立者不得擴大他人建立的規則，所以「先擴大再接手 agent」在第一步就被擋；
// - B-04：新擁有者對該 agent 尚有效的核准票（待審或已核准且票證未到期）同樣擋轉移。
//
// 突變自檢：把 CheckOwnerTransfer 的核准票查詢拿掉，「待審票擋轉移」轉紅；
// 把 UpdateAccountScope 的 guardAccountScopeWiden 拿掉，「擴大被拒」轉紅。

func managePrincipalCtx(userID uint) context.Context {
	p := authz.NewPrincipal(userID, authz.TokenFacts{}, []authz.Assignment{{
		RoleName: "authz-manager-custom", Via: authz.ViaDirect, Scope: model.ScopeKindGlobal,
		Permissions: []authz.Permission{authz.PermAuthorizationManage}, Custom: true,
	}})
	return authz.ContextWithPrincipal(context.Background(), p)
}

func TestAgentOwnerTransferVotesAndScope(t *testing.T) {
	t.Run("先擴大他人規則再接手：擴大被拒、範圍不變、轉移後 agent 只得到他人主張的範圍", func(t *testing.T) {
		env := newOwnerTransferEnv(t)
		id := env.rule(t, otUserV, nil, model.AuthorizationSourceManual)
		if err := env.db.Model(&model.AssetAuthorization{}).Where("id = ?", id).Update("accounts", model.AccountScope{"app"}).Error; err != nil {
			t.Fatal(err)
		}
		all := []string{"@ALL"}
		if _, err := env.authz.UpdateAccountScope(managePrincipalCtx(otUserU), id, &all); !errors.Is(err, authz.ErrAccountScopeWidenRestricted) {
			t.Fatalf("非建立者擴大應被拒: %v", err)
		}
		var row model.AssetAuthorization
		if err := env.db.First(&row, id).Error; err != nil {
			t.Fatal(err)
		}
		if row.Accounts.IsAll() || row.GrantedBy != otUserV {
			t.Fatalf("被拒後範圍與建立者皆不得改變: accounts=%v granted_by=%d", row.Accounts, row.GrantedBy)
		}
		if err := env.transfer(otAgentX, otUserU); err != nil {
			t.Fatalf("U 未主張任何範圍，轉移應成功: %v", err)
		}
		if got := env.ownerOf(t, otAgentX); got != otUserU {
			t.Fatalf("owner=%d", got)
		}
	})

	t.Run("待審票擋轉移：被拒時擁有者不變、權限版本與主體狀態事件不推進；票失效後成功", func(t *testing.T) {
		env := newOwnerTransferEnv(t)
		req := model.AccessRequest{RequesterID: otAgentX, AssetID: otAsset, Reason: "nightly", RequestedDurationMinutes: 60,
			Status: model.AccessRequestPending, PendingExpiresAt: time.Now().Add(time.Hour)}
		if err := env.db.Create(&req).Error; err != nil {
			t.Fatal(err)
		}
		item := model.AccessRequestItem{RequestID: req.ID, RequesterID: otAgentX, AssetID: otAsset, Status: model.AccessRequestPending}
		if err := env.db.Create(&item).Error; err != nil {
			t.Fatal(err)
		}
		vote := model.AccessRequestApproval{RequestID: req.ID, ItemID: &item.ID, ApproverID: otUserU}
		if err := env.db.Create(&vote).Error; err != nil {
			t.Fatal(err)
		}
		ver, events, audits := env.stateSnapshot(t)
		if err := env.transfer(otAgentX, otUserU); !errors.Is(err, authz.ErrAgentOwnerTransferSelfGrant) {
			t.Fatalf("對該 agent 持待審票者接手應被拒: %v", err)
		}
		if got := env.ownerOf(t, otAgentX); got != otUserOwner {
			t.Fatalf("被拒時擁有者不得改變: %d", got)
		}
		if v, e, a := env.stateSnapshot(t); v != ver || e != events || a != audits {
			t.Fatalf("被拒時版本／事件／審計不得推進: %d/%d/%d -> %d/%d/%d", ver, events, audits, v, e, a)
		}
		if err := env.db.Model(&model.AccessRequestItem{}).Where("id = ?", item.ID).Update("status", model.AccessRequestRejected).Error; err != nil {
			t.Fatal(err)
		}
		if err := env.transfer(otAgentX, otUserU); err != nil {
			t.Fatalf("票所屬項目已拒絕後轉移應成功: %v", err)
		}
	})
}
