package identity

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/policy"
	"gorm.io/gorm"
)

// admin 建立本地帳號的強制改密守衛。
//
// 本組測試盯的是一個曾經漏掉的落點：建號路徑未設 must_change_password，
// 使用者可無限期沿用建號者代設的初始密碼，該帳號的操作在審計上無法與建號者區分。
// 機制（登入 gate、改密端點、前端文案）本就齊備，缺的只是建號時把旗標設上。
//
// 沿用 setupLockoutEnv 的 sqlite in-memory 環境（單 goroutine 循序讀寫，
// 無 :memory: 連線池風險）。出廠密碼政策：min_length=12、require_alnum=true。

const (
	createInitialPassword = "InitPass12345"
	createNewPassword     = "ChosenPass67890"
)

func setupCreateForceChangeEnv(t *testing.T) (*UserService, *AuthService, *policy.SecurityPolicyService, *gorm.DB) {
	t.Helper()
	auth, policies, db := setupLockoutEnv(t)
	users := NewUserService(db, authz.NewAssetAuthorizationService(db))
	users.SetSecurityPolicies(policies)
	return users, auth, policies, db
}

func createLocalUser(t *testing.T, users *UserService, username string) *model.User {
	t.Helper()
	user, err := users.Create(&CreateUserRequest{
		Username: username,
		Password: createInitialPassword,
		Email:    username + "@example.test",
	})
	if err != nil {
		t.Fatalf("Create(%s) err = %v", username, err)
	}
	return user
}

// admin 建立的本地帳號一律標記強制改密。
func TestCreateUserMarksMustChangePassword(t *testing.T) {
	users, _, _, db := setupCreateForceChangeEnv(t)

	created := createLocalUser(t, users, "carol")

	if !created.MustChangePassword {
		t.Error("Create 回傳的使用者 MustChangePassword 為 false，初始密碼將可永久沿用")
	}
	reloaded := reloadUser(t, db, created.ID)
	if !reloaded.MustChangePassword {
		t.Error("持久化後 must_change_password 為 false——旗標未寫入資料庫，登入 gate 不會攔截")
	}
	if reloaded.PasswordChangedAt != nil {
		t.Error("新建帳號的 password_changed_at 應為 NULL（密碼從未由持有人變更過）")
	}
}

// 建號強制改密不受 force_change_on_reset 政策開關影響。
// force_change_on_reset 管的是 admin 重設既有帳號密碼；建號沒有對應的正當關閉場景。
func TestCreateUserForceChangeIgnoresResetPolicy(t *testing.T) {
	users, _, policies, db := setupCreateForceChangeEnv(t)

	if _, err := policies.Update(policy.PolicyForceChangeOnReset, "false", "admin"); err != nil {
		t.Fatalf("關閉 force_change_on_reset: %v", err)
	}
	if policies.GetBool(policy.PolicyForceChangeOnReset) {
		t.Fatal("前置條件未成立：force_change_on_reset 仍為 true，本測試無法鑑別政策耦合")
	}

	created := createLocalUser(t, users, "dave")

	if !reloadUser(t, db, created.ID).MustChangePassword {
		t.Error("建號強制改密被 force_change_on_reset 政策影響——" +
			"關閉該政策後新帳號未標記強制改密，可關閉的強制等同不存在")
	}
}

// 以建號時的初始密碼首次登入：憑證通過但不發正式會話，只給改密專用 token。
func TestCreateUserFirstLoginRequiresPasswordChange(t *testing.T) {
	users, auth, _, _ := setupCreateForceChangeEnv(t)

	createLocalUser(t, users, "erin")

	resp, err := auth.Login(&LoginRequest{Username: "erin", Password: createInitialPassword})
	if err != nil {
		t.Fatalf("Login err = %v", err)
	}
	if !resp.PasswordChangeRequired {
		t.Error("首次登入未進入強制改密流程")
	}
	if resp.Token != "" {
		t.Error("強制改密前不得發放正式會話 token")
	}
	if resp.PasswordChangeReason != PasswordChangeReasonMustChange {
		t.Errorf("reason = %q, want %q", resp.PasswordChangeReason, PasswordChangeReasonMustChange)
	}
	if resp.ChangeToken == "" {
		t.Error("應附改密專用 change_token，否則使用者無路可走")
	}
}

// 完成改密後恢復正常登入：旗標清除、password_changed_at 寫入、發放正式 token。
// 這一項確認強制改密不會把新帳號卡死。
func TestCreateUserAfterChangeLoginsNormally(t *testing.T) {
	users, auth, _, db := setupCreateForceChangeEnv(t)

	created := createLocalUser(t, users, "frank")

	if err := users.SelfChangePassword(created.ID, createInitialPassword, createNewPassword); err != nil {
		t.Fatalf("SelfChangePassword err = %v", err)
	}

	reloaded := reloadUser(t, db, created.ID)
	if reloaded.MustChangePassword {
		t.Error("改密後 must_change_password 未清除，使用者會被永久卡在改密頁")
	}
	if reloaded.PasswordChangedAt == nil {
		t.Error("改密後 password_changed_at 應寫入")
	}

	resp, err := auth.Login(&LoginRequest{Username: "frank", Password: createNewPassword})
	if err != nil {
		t.Fatalf("改密後 Login err = %v", err)
	}
	if resp.PasswordChangeRequired {
		t.Error("改密後仍要求改密")
	}
	if resp.Token == "" {
		t.Error("改密後登入未取得正式會話 token")
	}
}

// 目錄與身分提供者供應的影子帳號不標記強制改密。
//
// 這兩條路徑的憑證在外部，本地沒有可改的密碼；若被誤標，登入 gate 的
// !IsExternal() 雖然仍會跳過（實害休眠），但條文與實作已經分家。
// 守衛盯的是建立當下的旗標，不是 gate 的行為——後者另有
// TestLoginGateLDAPSkipped 涵蓋。
func TestShadowAccountsNotMarkedForPasswordChange(t *testing.T) {
	t.Run("LDAP", func(t *testing.T) {
		auth, db := setupProfileEnv(t)
		if err := db.Create(&model.Role{Name: model.RoleUser}).Error; err != nil {
			t.Fatalf("seed role: %v", err)
		}

		shadow, err := auth.provisionShadowUser(&LDAPUserInfo{
			Username: "ldap-shadow", Email: "ldap-shadow@example.test", FullName: "L",
		})
		if err != nil {
			t.Fatalf("provisionShadowUser err = %v", err)
		}

		if shadow.MustChangePassword {
			t.Error("LDAP 影子帳號被標記強制改密——密碼由目錄管理，本地無密碼可改")
		}
		if reloadUser(t, db, shadow.ID).MustChangePassword {
			t.Error("持久化後 LDAP 影子帳號的 must_change_password 為 true")
		}
	})

	t.Run("OIDC", func(t *testing.T) {
		login, _, db := setupOIDCEnv(t)
		provider := jitProvider(t, db)

		shadow, err := login.provisionFromClaims(provider, oidcClaims("sub-shadow", map[string]any{
			"hd": "corp.example", "preferred_username": "oidc-shadow",
		}), &oidcAuditTrail{})
		if err != nil {
			t.Fatalf("provisionFromClaims err = %v", err)
		}

		if shadow.MustChangePassword {
			t.Error("OIDC 影子帳號被標記強制改密——憑證由身分提供者管理")
		}
		if reloadUser(t, db, shadow.ID).MustChangePassword {
			t.Error("持久化後 OIDC 影子帳號的 must_change_password 為 true")
		}
	})
}
