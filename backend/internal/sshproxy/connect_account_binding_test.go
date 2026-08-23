package sshproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/proxy"
	"gorm.io/gorm"
)

// issueTokenForAccount 以指定身分＋指定 account_id 呼叫簽發端點。
// accountID=0 時仍顯式送出 "account_id": 0——與完全省略欄位等價（0＝預設帳號），
// 兩種寫法都必須走預設帳號路徑
func issueTokenForAccount(h *Handler, userID uint, role string, assetID, accountID uint) (int, map[string]interface{}) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/connect-tokens", func(c *gin.Context) {
		c.Set("userID", userID)
		c.Set("role", role)
		h.HandleCreateConnectToken(c)
	})
	body, _ := json.Marshal(map[string]interface{}{"asset_id": assetID, "account_id": accountID})
	req := httptest.NewRequest("POST", "/connect-tokens", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp
}

// seedAccount 建一筆帳號並回傳其 ID
func seedAccount(t *testing.T, db *gorm.DB, assetID uint, username string, isDefault bool) uint {
	t.Helper()
	acct := model.AssetAccount{AssetID: assetID, Username: username, IsDefault: isDefault}
	if err := db.Create(&acct).Error; err != nil {
		t.Fatalf("seed account(%s): %v", username, err)
	}
	return acct.ID
}

// TestConnectTokenAccountBinding 帳號客體綁定（connection-gating
//「跨資產帳號注入被拒」）：簽發點以
// (account_id, asset_id, deleted_at IS NULL) DB 現查，不屬該資產或已刪一律拒發。
//
// 這道閘不能只靠兌換點：token 一旦簽出即代表「這組 (user, asset, account) 已驗過」，
// 讓未驗的客體進 grant 等於把 fail-close 的責任全押在單一時點上
func TestConnectTokenAccountBinding(t *testing.T) {
	t.Run("跨資產 account_id 簽發被拒", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		seedAccount(t, db, 1, "root", true)

		// asset 2 是別的資產（user 1 對它無授權），其帳號絕不可用於 asset 1
		if err := db.Create(&model.Asset{Name: "a2", Protocol: "ssh", Host: "h2", Port: 22, CreatedBy: 2}).Error; err != nil {
			t.Fatalf("seed asset2: %v", err)
		}
		foreign := seedAccount(t, db, 2, "root", true)

		code, resp := issueTokenForAccount(h, 1, model.RoleUser, 1, foreign)
		if code != http.StatusNotFound || resp["code"] != "NOTFOUND_ASSET_ACCOUNT" {
			t.Fatalf("跨資產 account_id 應以 404+NOTFOUND_ASSET_ACCOUNT 拒發: code=%d resp=%v", code, resp)
		}
		if resp["connect_token"] != nil {
			t.Fatal("拒發時不得回傳 connect_token")
		}
	})

	t.Run("已刪帳號簽發被拒", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		seedAccount(t, db, 1, "root", true)
		appID := seedAccount(t, db, 1, "app", false)

		if err := db.Delete(&model.AssetAccount{}, appID).Error; err != nil {
			t.Fatalf("delete account: %v", err)
		}

		code, resp := issueTokenForAccount(h, 1, model.RoleUser, 1, appID)
		if code != http.StatusNotFound || resp["code"] != "NOTFOUND_ASSET_ACCOUNT" {
			t.Fatalf("已刪帳號應拒發: code=%d resp=%v", code, resp)
		}
	})

	t.Run("本資產帳號正常簽發", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		seedAccount(t, db, 1, "root", true)
		appID := seedAccount(t, db, 1, "app", false)

		code, resp := issueTokenForAccount(h, 1, model.RoleUser, 1, appID)
		if code != http.StatusOK || resp["connect_token"] == nil {
			t.Fatalf("本資產帳號應正常簽發: code=%d resp=%v", code, resp)
		}
	})

	t.Run("未授權者不因 account_id 得到不同語義", func(t *testing.T) {
		// 帳號綁定閘置於授權閘之後：未授權者無論帶不帶 account_id、帶存在或
		// 不存在的 account_id，回應都必須一致，否則成為帳號存在性探測器
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		realID := seedAccount(t, db, 1, "root", true)

		// user 3（auditor）對 asset 1 無 connect 授權
		codeReal, respReal := issueTokenForAccount(h, 3, model.RoleAuditor, 1, realID)
		codeFake, respFake := issueTokenForAccount(h, 3, model.RoleAuditor, 1, 99999)
		if codeReal != codeFake || respReal["code"] != respFake["code"] {
			t.Fatalf("未授權者的回應不得因帳號是否存在而不同: real=(%d,%v) fake=(%d,%v)",
				codeReal, respReal["code"], codeFake, respFake["code"])
		}
	})
}

// TestSSHRedeemAccountDeletedAfterIssue 帳號於簽發後被刪除（connection-gating
// delta Scenario）：兌換被拒，**不以預設帳號靜默替代**。
//
// 靜默替代是最危險的失敗模式：使用者以為連的是被撤掉的 app 帳號，實際拿到的是
// 預設（往往是特權）帳號的憑證，且審計會記成另一個帳號
func TestSSHRedeemAccountDeletedAfterIssue(t *testing.T) {
	h, db, _ := setupPolicyGateTest(t)
	seedGateFixture(t, db)
	setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
	seedAccount(t, db, 1, "root", true)
	appID := seedAccount(t, db, 1, "app", false)

	code, resp := issueTokenForAccount(h, 1, model.RoleUser, 1, appID)
	if code != http.StatusOK {
		t.Fatalf("簽發應成功: code=%d resp=%v", code, resp)
	}
	token, _ := resp["connect_token"].(string)
	if token == "" {
		t.Fatalf("回應未帶 connect_token: %v", resp)
	}

	// 簽發後、兌換前刪除該帳號
	if err := db.Delete(&model.AssetAccount{}, appID).Error; err != nil {
		t.Fatalf("delete account: %v", err)
	}

	rcode, rresp := redeemSSH(h, token)
	if rcode == http.StatusSwitchingProtocols || rcode == http.StatusOK {
		t.Fatalf("帳號已刪不得建線: code=%d resp=%v", rcode, rresp)
	}
	if rresp["code"] != "NOTFOUND_ASSET_ACCOUNT" {
		t.Fatalf("應以帳號不存在 fail-close（非退回預設帳號）: code=%d resp=%v", rcode, rresp)
	}
}

// TestConnectTokenK8sRejectsAccount K8s 固定單一預設帳號：帶非預設
// account_id 時明確拒絕，不靜默忽略。忽略會讓使用者以為連的是所選帳號、
// 實際用的是預設憑證——比報錯更糟
func TestConnectTokenK8sRejectsAccount(t *testing.T) {
	h, db, _ := setupPolicyGateTest(t)
	seedGateFixture(t, db)
	setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
	if err := db.Model(&model.Asset{}).Where("id = ?", 1).
		Update("protocol", string(model.ProtocolK8s)).Error; err != nil {
		t.Fatalf("switch protocol: %v", err)
	}
	acctID := seedAccount(t, db, 1, "sa", true)

	t.Run("帶 account_id 簽發被拒", func(t *testing.T) {
		code, resp := issueTokenForAccount(h, 1, model.RoleUser, 1, acctID)
		if code != http.StatusBadRequest || resp["code"] != "RULE_ACCOUNT_K8S_DEFAULT_ONLY" {
			t.Fatalf("K8s 帶 account_id 應 400+RULE_ACCOUNT_K8S_DEFAULT_ONLY: code=%d resp=%v", code, resp)
		}
	})

	t.Run("省略 account_id 照常簽發", func(t *testing.T) {
		code, resp := issueTokenForAccount(h, 1, model.RoleUser, 1, 0)
		if code != http.StatusOK || resp["connect_token"] == nil {
			t.Fatalf("K8s 走預設帳號應照常簽發: code=%d resp=%v", code, resp)
		}
	})

	t.Run("兌換點對稱防線", func(t *testing.T) {
		// 繞過簽發閘（模擬簽發後資產協議被改為 k8s）：grant 帶帳號，兌換仍須擋
		token, err := h.ConnectTokens.IssueConnectToken(context.Background(), proxy.ConnectGrant{UserID: 1, AssetID: 1, AccountID: acctID})
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		code, resp := redeemSSH(h, token)
		if resp["code"] != "RULE_ACCOUNT_K8S_DEFAULT_ONLY" {
			t.Fatalf("兌換點應同擋: code=%d resp=%v", code, resp)
		}
	})
}
