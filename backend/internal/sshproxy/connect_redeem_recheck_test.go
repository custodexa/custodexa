package sshproxy

import (
	"net/http"
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// TestConnectRedeemRecheck 兌換點授權與政策重查（CPG-010，connection-gating delta）：
// connect_token 於簽發後、兌換前遭撤銷之連線授權／收緊之存取政策，SHALL 於兌換
// 即時生效（403），撤權殘窗（原以 60s TTL 為上界）歸零；授權與政策不變則正常放行。
func TestConnectRedeemRecheck(t *testing.T) {
	t.Run("簽發後撤銷連線授權，殘窗內兌換被拒", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)

		code, resp, _ := issueToken(h, 1, model.RoleUser, 1)
		if code != http.StatusOK || resp["connect_token"] == nil {
			t.Fatalf("前置：open 段位常設 connect 應正常簽發: code=%d resp=%v", code, resp)
		}
		token, _ := resp["connect_token"].(string)

		// 撤銷 user 1 對 asset 1 的常設 connect 授權（簽發後、兌換前）
		if err := db.Where("user_id = ? AND asset_id = ?", 1, 1).
			Delete(&model.AssetAuthorization{}).Error; err != nil {
			t.Fatalf("revoke authz: %v", err)
		}

		rcode, rresp := redeemSSH(h, token)
		if rcode != http.StatusForbidden {
			t.Fatalf("授權撤銷後兌換應 403（權限拒絕、不憑簽發快照放行）: code=%d resp=%v", rcode, rresp)
		}
	})

	t.Run("簽發後政策改 approval（無票），殘窗內兌換被拒", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)

		code, resp, _ := issueToken(h, 1, model.RoleUser, 1)
		if code != http.StatusOK || resp["connect_token"] == nil {
			t.Fatalf("前置簽發失敗: code=%d resp=%v", code, resp)
		}
		token, _ := resp["connect_token"].(string)

		// 存取政策於簽發後收緊為 approval（user 1 無時窗內 ticket）
		setGroupPolicy(t, db, 1, model.AccessPolicyApproval)

		rcode, rresp := redeemSSH(h, token)
		if rcode != http.StatusForbidden || rresp["reason"] != "approval_required" {
			t.Fatalf("政策收緊後兌換應 403+approval_required: code=%d resp=%v", rcode, rresp)
		}
	})

	t.Run("授權與政策不變，兌換不被重查閘誤擋", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)

		code, resp, _ := issueToken(h, 1, model.RoleUser, 1)
		if code != http.StatusOK || resp["connect_token"] == nil {
			t.Fatalf("前置簽發失敗: code=%d resp=%v", code, resp)
		}
		token, _ := resp["connect_token"].(string)

		// 授權與政策皆未變動：兌換 SHALL 通過授權/政策重查閘（後續因測試環境
		// 無真 SSH target 於連線階段失敗）。正向斷言強化（codex Finding 2）：除未被
		// 授權/政策層 403 誤擋外，同時排除假通過（200 成功/101 WS 升級），確認確實過閘
		rcode, rresp := redeemSSH(h, token)
		if rcode == http.StatusForbidden {
			t.Fatalf("授權有效不應被兌換點重查閘擋（403=被閘攔截）: code=%d resp=%v", rcode, rresp)
		}
		if rcode == http.StatusOK || rcode == http.StatusSwitchingProtocols {
			t.Fatalf("正向案應落建線階段失敗、非假通過/升級: code=%d resp=%v", rcode, rresp)
		}
	})
}
