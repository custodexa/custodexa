package proxy

import (
	"context"
	"net/http"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 圖形路徑（RDP/VNC）兌換點的帳號授權範圍複查（強制點 2／3 圖形側）。
//
// 為何非補不可：規格明列多帳號適用 ssh/rdp/vnc/mysql/postgres/redis，
// 圖形側佔其中一半，卻只有實碼沒有守衛——文字側的測試綠不代表圖形側那份
// 各自獨立的取憑證／建線程式碼也擋得住。

// setScopeForUser1 把 user 1 的常設授權收緊為指定帳號範圍
func setScopeForUser1(t *testing.T, db *gorm.DB, scope model.AccountScope) {
	t.Helper()
	if err := db.Model(&model.AssetAuthorization{}).
		Where("user_id = ?", 1).Update("accounts", scope).Error; err != nil {
		t.Fatalf("set scope: %v", err)
	}
}

// TestGuacRedeemAccountScopeRecheck 簽發後把帳號移出授權範圍，兌換即時拒絕
func TestGuacRedeemAccountScopeRecheck(t *testing.T) {
	t.Run("範圍收緊後兌換被拒", func(t *testing.T) {
		h, db := setupGraphicsRedeemTest(t)
		admin := model.AssetAccount{AssetID: 1, Username: "administrator", IsDefault: true}
		if err := db.Create(&admin).Error; err != nil {
			t.Fatalf("seed default account: %v", err)
		}
		if err := db.Create(&model.AssetAccount{AssetID: 1, Username: "operator"}).Error; err != nil {
			t.Fatalf("seed account: %v", err)
		}
		setScopeForUser1(t, db, model.AccountScope{model.AccountScopeAll})

		token, err := h.ConnectTokens.IssueConnectToken(context.Background(), ConnectGrant{UserID: 1, AssetID: 1, AccountID: admin.ID})
		if err != nil {
			t.Fatalf("issue token: %v", err)
		}
		// 簽發後、兌換前把 administrator 移出範圍
		setScopeForUser1(t, db, model.AccountScope{"operator"})

		code, resp := redeemGuac(h, token)
		if code == http.StatusSwitchingProtocols || code == http.StatusOK {
			t.Fatalf("範圍收緊後不得建線: code=%d resp=%v", code, resp)
		}
		if code != http.StatusForbidden || resp["code"] != "AUTH_ASSET_CONNECT_DENIED" {
			t.Fatalf("應以 403 連線授權拒絕語義擋下: code=%d resp=%v", code, resp)
		}
	})

	// 最關鍵的一條：grant.AccountID=0 走預設帳號，若判定的是請求參數而非實際
	// 解析出的帳號，收緊範圍的使用者只要拿不帶帳號的 grant 就能用預設憑證建線
	t.Run("預設帳號（grant 不帶 account_id）同受判定", func(t *testing.T) {
		h, db := setupGraphicsRedeemTest(t)
		if err := db.Create(&model.AssetAccount{AssetID: 1, Username: "administrator", IsDefault: true}).Error; err != nil {
			t.Fatalf("seed default account: %v", err)
		}
		if err := db.Create(&model.AssetAccount{AssetID: 1, Username: "operator"}).Error; err != nil {
			t.Fatalf("seed account: %v", err)
		}
		setScopeForUser1(t, db, model.AccountScope{"operator"}) // 預設的 administrator 出局

		token, err := h.ConnectTokens.IssueConnectToken(context.Background(), ConnectGrant{UserID: 1, AssetID: 1, AccountID: 0})
		if err != nil {
			t.Fatalf("issue token: %v", err)
		}
		code, resp := redeemGuac(h, token)
		if code != http.StatusForbidden || resp["code"] != "AUTH_ASSET_CONNECT_DENIED" {
			t.Fatalf("預設帳號不在範圍內時應拒: code=%d resp=%v", code, resp)
		}
	})

	// 既有行為零變化：@ALL（migration 回填值）下不被帳號閘攔
	t.Run("@ALL 不被帳號閘攔", func(t *testing.T) {
		h, db := setupGraphicsRedeemTest(t)
		if err := db.Create(&model.AssetAccount{AssetID: 1, Username: "administrator", IsDefault: true}).Error; err != nil {
			t.Fatalf("seed default account: %v", err)
		}
		setScopeForUser1(t, db, model.AccountScope{model.AccountScopeAll})

		token, err := h.ConnectTokens.IssueConnectToken(context.Background(), ConnectGrant{UserID: 1, AssetID: 1, AccountID: 0})
		if err != nil {
			t.Fatalf("issue token: %v", err)
		}
		_, resp := redeemGuac(h, token)
		if resp["code"] == "AUTH_ASSET_CONNECT_DENIED" || resp["code"] == "NOTFOUND_ASSET_ACCOUNT" {
			t.Fatalf("@ALL 下不應被帳號閘擋: resp=%v", resp)
		}
	})

	// 回歸：零帳號資產必須回「未設定帳號」而非「無連線權限」。
	// 兩者的修正動作完全不同（補帳號 vs 查權限），順序錯了會把管理員導向錯的地方
	t.Run("零帳號資產回 RULE_ACCOUNT_NONE_USABLE 而非授權拒絕", func(t *testing.T) {
		h, db := setupGraphicsRedeemTest(t)
		// 刻意不建任何帳號，並把範圍設為具名（此時 Allows("") 為 false）
		setScopeForUser1(t, db, model.AccountScope{"operator"})

		token, err := h.ConnectTokens.IssueConnectToken(context.Background(), ConnectGrant{UserID: 1, AssetID: 1, AccountID: 0})
		if err != nil {
			t.Fatalf("issue token: %v", err)
		}
		code, resp := redeemGuac(h, token)
		if resp["code"] != "RULE_ACCOUNT_NONE_USABLE" {
			t.Fatalf("零帳號資產應回 RULE_ACCOUNT_NONE_USABLE（與 SSH 側一致）: code=%d resp=%v", code, resp)
		}
	})

	// admin 全量短路：與文字側同語義
	t.Run("admin 不受帳號範圍限制", func(t *testing.T) {
		h, db := setupGraphicsRedeemTest(t)
		acct := model.AssetAccount{AssetID: 1, Username: "administrator", IsDefault: true}
		if err := db.Create(&acct).Error; err != nil {
			t.Fatalf("seed default account: %v", err)
		}
		// user 2 為 admin，無任何授權列
		token, err := h.ConnectTokens.IssueConnectToken(context.Background(), ConnectGrant{UserID: 2, AssetID: 1, AccountID: acct.ID})
		if err != nil {
			t.Fatalf("issue token: %v", err)
		}
		_, resp := redeemGuac(h, token)
		if resp["code"] == "AUTH_ASSET_CONNECT_DENIED" {
			t.Fatalf("admin 應全量放行: resp=%v", resp)
		}
	})
}
