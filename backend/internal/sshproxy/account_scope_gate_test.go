package sshproxy

import (
	"net/http"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 授權帳號範圍強制點的閘測試（asset-multi-account D5 階段 4）。
//
// 前階段雙審指認的缺口：階段 3 只驗「帳號屬於這台資產」（客體綁定），
// 沒驗「你被授權用這個帳號」。本檔鎖住簽發點與兌換點兩處補上的判定。

// setAuthAccounts 把 user 1 的既有常設授權收緊為指定帳號範圍
func setAuthAccounts(t *testing.T, db *gorm.DB, scope model.AccountScope) {
	t.Helper()
	if err := db.Model(&model.AssetAuthorization{}).
		Where("user_id = ?", 1).Update("accounts", scope).Error; err != nil {
		t.Fatalf("set accounts scope: %v", err)
	}
}

// TestConnectTokenAccountScopeGate 簽發點帳號授權判定（D5 強制點 1／3，
// authorization-management delta Scenario「個別指定帳號」）
func TestConnectTokenAccountScopeGate(t *testing.T) {
	t.Run("範圍外帳號簽發被拒且不洩漏存在性", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		rootID := seedAccount(t, db, 1, "root", true)
		seedAccount(t, db, 1, "app", false)
		setAuthAccounts(t, db, model.AccountScope{"app"})

		code, resp := issueTokenForAccount(h, 1, model.RoleUser, 1, rootID)
		if code != http.StatusNotFound || resp["code"] != "NOTFOUND_ASSET_ACCOUNT" {
			t.Fatalf("範圍外帳號應以 404+NOTFOUND_ASSET_ACCOUNT 拒發（與不存在同碼，不洩漏存在性）: code=%d resp=%v", code, resp)
		}
		if resp["connect_token"] != nil {
			t.Fatal("拒發時不得回傳 connect_token")
		}
	})

	t.Run("範圍內帳號正常簽發", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		seedAccount(t, db, 1, "root", true)
		appID := seedAccount(t, db, 1, "app", false)
		setAuthAccounts(t, db, model.AccountScope{"app"})

		code, resp := issueTokenForAccount(h, 1, model.RoleUser, 1, appID)
		if code != http.StatusOK || resp["connect_token"] == nil {
			t.Fatalf("範圍內帳號應正常簽發: code=%d resp=%v", code, resp)
		}
	})

	// 最關鍵的一條：省略 account_id 走預設帳號，若不判定實際解析出的帳號，
	// 收緊範圍的使用者只要不填參數就能拿到預設（通常是 root）憑證，
	// 整個帳號維度形同虛設
	t.Run("省略 account_id 時仍判定實際的預設帳號", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		seedAccount(t, db, 1, "root", true) // 預設帳號＝root
		seedAccount(t, db, 1, "app", false)
		setAuthAccounts(t, db, model.AccountScope{"app"}) // 只授權 app

		code, resp := issueTokenForAccount(h, 1, model.RoleUser, 1, 0)
		if code == http.StatusOK || resp["connect_token"] != nil {
			t.Fatalf("預設帳號不在授權範圍時，省略 account_id 亦須拒發: code=%d resp=%v", code, resp)
		}
		if resp["code"] != "NOTFOUND_ASSET_ACCOUNT" {
			t.Fatalf("應與範圍外帳號同碼: code=%d resp=%v", code, resp)
		}
	})

	t.Run("@ALL 範圍維持既有行為（全帳號可簽）", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		rootID := seedAccount(t, db, 1, "root", true)
		appID := seedAccount(t, db, 1, "app", false)
		setAuthAccounts(t, db, model.AccountScope{model.AccountScopeAll})

		for _, id := range []uint{rootID, appID, 0} {
			code, resp := issueTokenForAccount(h, 1, model.RoleUser, 1, id)
			if code != http.StatusOK || resp["connect_token"] == nil {
				t.Fatalf("@ALL 應涵蓋全部帳號（accountID=%d）: code=%d resp=%v", id, code, resp)
			}
		}
	})

	t.Run("admin 不受帳號範圍限制", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		rootID := seedAccount(t, db, 1, "root", true)
		setAuthAccounts(t, db, model.AccountScope{"nonexistent"})

		code, resp := issueTokenForAccount(h, 2, model.RoleAdmin, 1, rootID)
		if code != http.StatusOK || resp["connect_token"] == nil {
			t.Fatalf("admin 應全量放行: code=%d resp=%v", code, resp)
		}
	})
}

// TestSSHRedeemAccountScopeRecheck 兌換點帳號授權複查（D5 強制點 2／3，
// authorization-management delta Scenario「帳號範圍收緊即時生效」）：
// 簽發後把帳號移出授權範圍，兌換必須即時拒絕——token 效期未到不構成放行理由
func TestSSHRedeemAccountScopeRecheck(t *testing.T) {
	t.Run("簽發後範圍收緊，兌換被拒", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		rootID := seedAccount(t, db, 1, "root", true)
		seedAccount(t, db, 1, "app", false)
		setAuthAccounts(t, db, model.AccountScope{model.AccountScopeAll})

		code, resp := issueTokenForAccount(h, 1, model.RoleUser, 1, rootID)
		if code != http.StatusOK {
			t.Fatalf("簽發應成功: code=%d resp=%v", code, resp)
		}
		token, _ := resp["connect_token"].(string)
		if token == "" {
			t.Fatalf("回應未帶 connect_token: %v", resp)
		}

		// 簽發後、兌換前把 root 移出授權範圍
		setAuthAccounts(t, db, model.AccountScope{"app"})

		rcode, rresp := redeemSSH(h, token)
		if rcode == http.StatusSwitchingProtocols || rcode == http.StatusOK {
			t.Fatalf("範圍收緊後不得建線: code=%d resp=%v", rcode, rresp)
		}
		if rcode != http.StatusForbidden || rresp["code"] != "AUTH_ASSET_CONNECT_DENIED" {
			t.Fatalf("應以 403 連線授權拒絕語義擋下: code=%d resp=%v", rcode, rresp)
		}
	})

	t.Run("授權未變動時兌換不受影響", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		appID := seedAccount(t, db, 1, "root", true)
		seedAccount(t, db, 1, "app", false)
		setAuthAccounts(t, db, model.AccountScope{"root"})

		code, resp := issueTokenForAccount(h, 1, model.RoleUser, 1, appID)
		if code != http.StatusOK {
			t.Fatalf("簽發應成功: code=%d resp=%v", code, resp)
		}
		token, _ := resp["connect_token"].(string)

		// 兌換會因無法真的撥接 SSH 而失敗，但**不得**是帳號授權相關的拒絕碼
		_, rresp := redeemSSH(h, token)
		if rresp["code"] == "AUTH_ASSET_CONNECT_DENIED" || rresp["code"] == "NOTFOUND_ASSET_ACCOUNT" {
			t.Fatalf("授權未變動時不應被帳號閘攔下: resp=%v", rresp)
		}
	})

	// 撤整筆授權（非只收緊範圍）時，既有的 CheckPermission 複查先攔下，
	// 帳號閘不改變該語義
	t.Run("整筆授權撤銷仍由既有連線授權閘攔下", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		rootID := seedAccount(t, db, 1, "root", true)

		code, resp := issueTokenForAccount(h, 1, model.RoleUser, 1, rootID)
		if code != http.StatusOK {
			t.Fatalf("簽發應成功: code=%d resp=%v", code, resp)
		}
		token, _ := resp["connect_token"].(string)

		if err := db.Where("user_id = ?", 1).Delete(&model.AssetAuthorization{}).Error; err != nil {
			t.Fatalf("revoke: %v", err)
		}
		rcode, rresp := redeemSSH(h, token)
		if rcode != http.StatusForbidden || rresp["code"] != "AUTH_ASSET_CONNECT_DENIED" {
			t.Fatalf("撤授權應 403 拒絕建線: code=%d resp=%v", rcode, rresp)
		}
	})
}
