package proxy

import (
	"context"
	"net/http"
	"testing"
)

// TestGuacRedeemZeroAccountAsset 零帳號資產 fail-close（asset-multi-account 階段 2，
// codex HIGH）：帳號是憑證與 username 的權威來源，資產一筆帳號都沒有時憑證束為空——
// 把空 username＋空密碼交給 guacd 等於對 RDP／VNC 目標做匿名或免密嘗試。
// 兌換點須擋在 guacd 握手之前。
//
// fixture 沿用 setupGraphicsRedeemTest（asset1 為 active、access_policy=open、
// user1 有常設 connect grant 且未建任何帳號），故唯一被擋的理由就是沒有帳號——
// 這也同時釘住閘序：停用／授權／政策三閘之後才輪到本閘。
func TestGuacRedeemZeroAccountAsset(t *testing.T) {
	h, _ := setupGraphicsRedeemTest(t)

	token, err := h.ConnectTokens.IssueConnectToken(context.Background(), ConnectGrant{UserID: 1, AssetID: 1, AccountID: 0})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	code, resp := redeemGuac(h, token)
	if code == http.StatusSwitchingProtocols || code == http.StatusOK {
		t.Fatalf("零帳號資產不得建線: code=%d resp=%v", code, resp)
	}
	if resp["code"] != "RULE_ACCOUNT_NONE_USABLE" {
		t.Fatalf("應以「無可用帳號憑證」拒絕: code=%d resp=%v", code, resp)
	}
}
