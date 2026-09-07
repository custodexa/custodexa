package identity

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 外部身分（OIDC）登入時的角色指派比對。
//
// 與 login_role_state_test.go 是同一條 spec 的另一條登入路徑：提權者走 SSO 進來
// 與走密碼進來，稽核面必須看到同一件事。發版前的跨模型審查抓到 OIDC 路徑沒接
// 探針——密碼路徑的測試全綠、CHANGELOG 卻宣稱「以管理員或稽核員身分登入時比對」，
// 這裡把三個性質釘住：
//   - admin／auditor 的 OIDC 登入比對**恰好一次**，且權杖照發（不阻斷）。
//   - 已註冊 TOTP 者在**第一階段**（發 pending token 前）就比對——「即將簽發權杖」
//     的時機定義與 Login 相同，不是等 MFA 完成。
//   - 一般使用者的 OIDC 登入不比對。

// seedOIDCUserWithRole 建立外部身分帳號並配角色，回傳已 Preload Roles 的使用者
// （primaryRoleOf 看的是 Roles，未載入等於一般使用者）
func seedOIDCUserWithRole(t *testing.T, e *oidcLifecycleEnv, username, subject, roleName string,
	mfa bool) *model.User {
	t.Helper()
	var u *model.User
	if mfa {
		u = e.seedMFAIdentityUser(t, username, subject)
	} else {
		u = e.seedIdentityUser(t, username, subject, nil)
	}
	var role model.Role
	if err := e.db.Where("name = ?", roleName).First(&role).Error; err != nil {
		role = model.Role{Name: roleName}
		if err := e.db.Create(&role).Error; err != nil {
			t.Fatalf("建角色: %v", err)
		}
	}
	if err := e.db.Transaction(func(tx *gorm.DB) error {
		return model.AssignUserRole(tx, u.ID, role.ID, model.RoleOriginOIDC)
	}); err != nil {
		t.Fatalf("配角色: %v", err)
	}
	var reloaded model.User
	if err := e.db.Preload("Roles").First(&reloaded, u.ID).Error; err != nil {
		t.Fatalf("重載使用者: %v", err)
	}
	return &reloaded
}

// TestOIDCLoginRoleStateCheckedForPrivilegedRoles admin 與 auditor 走 OIDC 登入即比對，
// 且權杖照發
func TestOIDCLoginRoleStateCheckedForPrivilegedRoles(t *testing.T) {
	for _, roleName := range []string{model.RoleAdmin, model.RoleAuditor} {
		t.Run(roleName, func(t *testing.T) {
			e := setupOIDCLifecycleEnv(t)
			probe := &countingProbe{}
			e.auth.SetRoleStateProbe(probe)
			user := seedOIDCUserWithRole(t, e, "sso-"+roleName, "sub-"+roleName, roleName, false)

			resp, err := e.auth.LoginWithExternalIdentity(user, e.oidcCtxFor(user))
			if err != nil {
				t.Fatalf("OIDC 登入: %v", err)
			}
			if probe.calls != 1 {
				t.Fatalf("比對次數 = %d, want 1", probe.calls)
			}
			if resp.Token == "" {
				t.Fatal("權杖未發出：比對不得阻斷登入")
			}
		})
	}
}

// TestOIDCLoginRoleStateCheckedBeforeMFAPending 已註冊 TOTP 的管理者，第一階段
// 就比對，且 pending token 照發
func TestOIDCLoginRoleStateCheckedBeforeMFAPending(t *testing.T) {
	e := setupOIDCLifecycleEnv(t)
	probe := &countingProbe{}
	e.auth.SetRoleStateProbe(probe)
	user := seedOIDCUserWithRole(t, e, "sso-mfa-admin", "sub-mfa-admin", model.RoleAdmin, true)

	resp, err := e.auth.LoginWithExternalIdentity(user, e.oidcCtxFor(user))
	if err != nil {
		t.Fatalf("OIDC 登入: %v", err)
	}
	if !resp.MFARequired || resp.PendingToken == "" {
		t.Fatalf("已註冊 TOTP 者應進入第二階段，實得 %+v", resp)
	}
	if probe.calls != 1 {
		t.Fatalf("第一階段比對次數 = %d, want 1：「即將簽發權杖」包含 pending token", probe.calls)
	}
}

// TestOIDCLoginRoleStateSkippedForOrdinaryUser 一般使用者走 OIDC 登入不比對
func TestOIDCLoginRoleStateSkippedForOrdinaryUser(t *testing.T) {
	e := setupOIDCLifecycleEnv(t)
	probe := &countingProbe{}
	e.auth.SetRoleStateProbe(probe)
	user := seedOIDCUserWithRole(t, e, "sso-plain", "sub-plain", model.RoleUser, false)

	if _, err := e.auth.LoginWithExternalIdentity(user, e.oidcCtxFor(user)); err != nil {
		t.Fatalf("OIDC 登入: %v", err)
	}
	if probe.calls != 0 {
		t.Fatalf("一般使用者 OIDC 登入執行了 %d 次比對, want 0", probe.calls)
	}
}
