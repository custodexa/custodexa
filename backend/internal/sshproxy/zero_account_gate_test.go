package sshproxy

import (
	"net/http"
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// TestSSHRedeemZeroAccountAsset 零帳號資產 fail-close（asset-multi-account 階段 2，
// codex HIGH）：終端入口涵蓋 SSH／K8s／DB CLI 三種目標。SSH 原本靠「無可用認證
// 方法」擋得住，但 K8s 的空 token 會走匿名 ServiceAccount、DB CLI 的空密碼可能
// 命中 trust 認證或落入互動式提示——三者統一在兌換點擋。
//
// fixture 沿用 policy gate 的 open 政策＋user1 常設 connect grant，且資產未建
// 任何帳號，故唯一被擋的理由就是沒有帳號；同時釘住閘序（停用／授權／政策在前）。
func TestSSHRedeemZeroAccountAsset(t *testing.T) {
	h, db, _ := setupPolicyGateTest(t)
	seedGateFixture(t, db)
	setGroupPolicy(t, db, 1, model.AccessPolicyOpen)

	code, resp, _ := issueToken(h, 1, model.RoleUser, 1)
	if code != http.StatusOK {
		t.Fatalf("簽發應成功（零帳號僅擋兌換建線）: code=%d resp=%v", code, resp)
	}
	token, _ := resp["connect_token"].(string)
	if token == "" {
		t.Fatalf("回應未帶 connect_token: %v", resp)
	}

	code, redeemResp := redeemSSH(h, token)
	if code == http.StatusSwitchingProtocols || code == http.StatusOK {
		t.Fatalf("零帳號資產不得建線: code=%d resp=%v", code, redeemResp)
	}
	if redeemResp["code"] != "RULE_ACCOUNT_NONE_USABLE" {
		t.Fatalf("應以「無可用帳號憑證」拒絕: code=%d resp=%v", code, redeemResp)
	}
}

// TestSSHRedeemWithAccountPassesGate 反面控制：同一 fixture 補一筆 default 帳號後，
// 兌換不再被本閘擋下（證明上面的紅不是別的閘造成的假陽性）
func TestSSHRedeemWithAccountPassesGate(t *testing.T) {
	h, db, _ := setupPolicyGateTest(t)
	seedGateFixture(t, db)
	setGroupPolicy(t, db, 1, model.AccessPolicyOpen)

	if err := db.Create(&model.AssetAccount{
		AssetID: 1, Username: "root", PasswordEnc: "", IsDefault: true,
	}).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}

	code, resp, _ := issueToken(h, 1, model.RoleUser, 1)
	if code != http.StatusOK {
		t.Fatalf("簽發應成功: code=%d resp=%v", code, resp)
	}
	token, _ := resp["connect_token"].(string)

	_, redeemResp := redeemSSH(h, token)
	if redeemResp["code"] == "RULE_ACCOUNT_NONE_USABLE" {
		t.Fatalf("有 default 帳號時不得被零帳號閘擋: %v", redeemResp)
	}
}
