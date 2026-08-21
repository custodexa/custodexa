package sshproxy

import (
	"net/http"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
)

// connect grant 於「停用後又重新啟用」的行為（idp-oidc-integration tasks 4.11
// 的第 (7) 個驗證點的補格）。
//
// 既有的 TestConnectRedeemGenerationRecheck 覆蓋了停用／世代推進／使用者世代推進
// 三種拒絕，以及本地 grant 不受影響；缺的是**重新啟用之後**——這正是世代維度
// 存在的理由：`enabled` 是可回復的布林，攻擊者手上那張 60 秒 TTL 的一次性 token
// 只要撐過「停用 → 重新啟用」這個窗口就會復活，而 auth_epoch 不回退才擋得住。

// TestConnectRedeemStillRejectedAfterProviderReEnabled 停用→重新啟用後，
// 停用前簽發的 connect grant 仍被拒
func TestConnectRedeemStillRejectedAfterProviderReEnabled(t *testing.T) {
	h, db := setupGenerationTest(t)
	pid := seedProvider(t, db, 0, true)
	seedAccount(t, db, 1, "root", true)

	token := mustIssueWithAuth(t, h, crypto.AuthContext{
		AuthMethod: crypto.AuthMethodOIDC, ProviderID: pid, AuthEpoch: 0,
	})

	// 停用推進世代，隨後重新啟用（enabled 復原、世代不回退）
	if err := db.Model(&model.OIDCProvider{}).Where("id = ?", pid).
		Updates(map[string]any{"enabled": false, "auth_epoch": 1}).Error; err != nil {
		t.Fatalf("停用 provider: %v", err)
	}
	if err := db.Model(&model.OIDCProvider{}).Where("id = ?", pid).
		Update("enabled", true).Error; err != nil {
		t.Fatalf("重新啟用 provider: %v", err)
	}
	var reloaded model.OIDCProvider
	if err := db.First(&reloaded, pid).Error; err != nil {
		t.Fatalf("重載 provider: %v", err)
	}
	// 前提：此刻 provider 是啟用中的，唯一擋著的只有世代——
	// 前提不成立時本測試就退化成「停用後被拒」的重複
	if !reloaded.Enabled || reloaded.AuthEpoch != 1 {
		t.Fatalf("前提不成立：enabled=%v auth_epoch=%d", reloaded.Enabled, reloaded.AuthEpoch)
	}

	code, resp := redeemSSH(h, token)
	if code != http.StatusUnauthorized || resp["code"] != "AUTH_CONNECT_TOKEN_INVALID" {
		t.Fatalf("重新啟用後舊 grant 仍須 401+AUTH_CONNECT_TOKEN_INVALID: code=%d resp=%v", code, resp)
	}
}

// TestConnectRedeemAcceptsGrantIssuedAfterReEnable 對照組：重新啟用後**新簽發**的
// grant（帶現行世代）必須通得過世代閘。
// 沒有這一格，上一個測試無法排除「重新啟用之後這條路徑就永遠不通了」
func TestConnectRedeemAcceptsGrantIssuedAfterReEnable(t *testing.T) {
	h, db := setupGenerationTest(t)
	pid := seedProvider(t, db, 0, true)
	seedAccount(t, db, 1, "root", true)

	if err := db.Model(&model.OIDCProvider{}).Where("id = ?", pid).
		Updates(map[string]any{"enabled": false, "auth_epoch": 1}).Error; err != nil {
		t.Fatalf("停用 provider: %v", err)
	}
	if err := db.Model(&model.OIDCProvider{}).Where("id = ?", pid).
		Update("enabled", true).Error; err != nil {
		t.Fatalf("重新啟用 provider: %v", err)
	}

	token := mustIssueWithAuth(t, h, crypto.AuthContext{
		AuthMethod: crypto.AuthMethodOIDC, ProviderID: pid, AuthEpoch: 1,
	})

	code, resp := redeemSSH(h, token)
	if code == http.StatusUnauthorized && resp["code"] == "AUTH_CONNECT_TOKEN_INVALID" {
		t.Fatalf("重新啟用後的新 grant 不得被世代閘攔下: code=%d resp=%v", code, resp)
	}
	// 排除假通過：正向案應落到後續建線階段失敗（資產 host 不可達），非 200/101
	if code == http.StatusOK || code == http.StatusSwitchingProtocols {
		t.Fatalf("正向案應落建線階段失敗、非假通過/升級: code=%d resp=%v", code, resp)
	}
}
