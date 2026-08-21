package proxy

import (
	"context"
	"net/http"
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// TestGuacRedeemAccountDeletedAfterIssue 圖形路徑（RDP/VNC）的帳號 fail-close
// （asset-multi-account D3／connection-gating delta「帳號於簽發後被刪除」）：
// grant 所帶帳號在兌換時已不存在，一律拒絕建線，**不以預設帳號靜默替代**。
//
// 圖形路徑與文字路徑各有一份取憑證程式碼，兩邊都得有這道網——只驗其中一邊，
// 另一邊悄悄退回預設帳號時測試仍全綠。
func TestGuacRedeemAccountDeletedAfterIssue(t *testing.T) {
	h, db := setupGraphicsRedeemTest(t)

	defAcct := model.AssetAccount{AssetID: 1, Username: "administrator", IsDefault: true}
	if err := db.Create(&defAcct).Error; err != nil {
		t.Fatalf("seed default account: %v", err)
	}
	opAcct := model.AssetAccount{AssetID: 1, Username: "operator"}
	if err := db.Create(&opAcct).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}

	token, err := h.ConnectTokens.IssueConnectToken(context.Background(), ConnectGrant{UserID: 1, AssetID: 1, AccountID: opAcct.ID})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	if err := db.Delete(&model.AssetAccount{}, opAcct.ID).Error; err != nil {
		t.Fatalf("delete account: %v", err)
	}

	code, resp := redeemGuac(h, token)
	if code == http.StatusSwitchingProtocols || code == http.StatusOK {
		t.Fatalf("帳號已刪不得建線: code=%d resp=%v", code, resp)
	}
	if resp["code"] != "NOTFOUND_ASSET_ACCOUNT" {
		t.Fatalf("應以帳號不存在 fail-close（非退回預設帳號）: code=%d resp=%v", code, resp)
	}
}

// TestGuacRedeemForeignAccountRejected 跨資產 account id 注入（codex NEW high）：
// 即便 grant 直接被構造成帶他資產的帳號（繞過簽發閘），兌換點的
// (account_id, asset_id) 複合現查仍須擋下——否則注入者拿到的是目標資產的預設憑證
func TestGuacRedeemForeignAccountRejected(t *testing.T) {
	h, db := setupGraphicsRedeemTest(t)

	if err := db.Create(&model.AssetAccount{AssetID: 1, Username: "administrator", IsDefault: true}).Error; err != nil {
		t.Fatalf("seed default account: %v", err)
	}
	if err := db.Create(&model.Asset{Name: "rdp2", Protocol: "rdp", Host: "h2", Port: 3389, CreatedBy: 2}).Error; err != nil {
		t.Fatalf("seed asset2: %v", err)
	}
	foreign := model.AssetAccount{AssetID: 2, Username: "root", IsDefault: true}
	if err := db.Create(&foreign).Error; err != nil {
		t.Fatalf("seed foreign account: %v", err)
	}

	token, err := h.ConnectTokens.IssueConnectToken(context.Background(), ConnectGrant{UserID: 1, AssetID: 1, AccountID: foreign.ID})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	code, resp := redeemGuac(h, token)
	if resp["code"] != "NOTFOUND_ASSET_ACCOUNT" {
		t.Fatalf("跨資產帳號應於兌換點被拒: code=%d resp=%v", code, resp)
	}
}
