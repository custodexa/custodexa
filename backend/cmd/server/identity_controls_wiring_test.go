package main

import (
	"errors"
	"testing"

	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
)

// 組裝自檢：關卡、分級器與帳號身分操作關卡缺任何一件（含 typed-nil）即拒絕；
// 服務層的 RequireControls 對未注入的使用者、群組、認證服務回錯，注入後通過。
func TestRequireIdentityControls(t *testing.T) {
	tx := audit.NewTxSink()
	alerts := audit.NewSystemAlertSink(nil)
	guard := identity.NewAssignmentGuard(identity.CompatCatalog())
	grader := identity.NewGrantGrader(tx, alerts)
	ops := identity.NewProtectedAccountOps(tx, alerts)

	if err := requireIdentityControls(guard, grader, ops); err != nil {
		t.Fatalf("完整注入應通過: %v", err)
	}
	var nilGuard *identity.AssignmentGuard
	var nilGrader *identity.GrantGrader
	var nilOps *identity.ProtectedAccountOps
	if requireIdentityControls(nilGuard, grader, ops) == nil {
		t.Error("缺關卡應被拒絕")
	}
	if requireIdentityControls(guard, nilGrader, ops) == nil {
		t.Error("缺分級器應被拒絕")
	}
	if requireIdentityControls(guard, grader, nilOps) == nil {
		t.Error("缺帳號身分操作關卡應被拒絕")
	}

	users := identity.NewUserService(nil, nil)
	groups := identity.NewUserGroupService(nil, tx, nil)
	auth := &identity.AuthService{}
	for name, err := range map[string]error{"user": users.RequireControls(), "group": groups.RequireControls(), "auth": auth.RequireControls()} {
		if !errors.Is(err, identity.ErrControlsNotWired) {
			t.Errorf("%s 服務未注入應回 ErrControlsNotWired，實得 %v", name, err)
		}
	}
	users.SetAssignmentGuard(guard)
	users.SetGrantGrader(grader)
	users.SetProtectedAccountOps(ops)
	groups.SetAssignmentGuard(guard)
	groups.SetGrantGrader(grader)
	auth.SetProtectedAccountOps(ops)
	for name, err := range map[string]error{"user": users.RequireControls(), "group": groups.RequireControls(), "auth": auth.RequireControls()} {
		if err != nil {
			t.Errorf("%s 服務注入後應通過: %v", name, err)
		}
	}
	// 缺落地面的分級器不算已接線
	users.SetGrantGrader(identity.NewGrantGrader(nil, nil))
	if err := users.RequireControls(); err == nil {
		t.Error("分級器缺落地面應被拒絕")
	}
}
