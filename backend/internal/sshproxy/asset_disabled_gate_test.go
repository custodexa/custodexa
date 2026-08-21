package sshproxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/model"
)

// redeemSSH 以 connect_token 呼叫 WS 兌換端點（升級前的 HTTP 階段即可驗閘）
func redeemSSH(h *Handler, token string) (int, map[string]interface{}) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/ssh", h.HandleSSH)
	req := httptest.NewRequest("GET", "/ssh?connect_token="+token+"&cols=80&rows=24", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp
}

// TestAssetDisabledGate 停用資產連線硬擋（asset-list-info-layering D8／
// connection-gating delta）：簽發點於授權檢查後拒發 403+asset_disabled；
// admin 不豁免（停用是資產態非權限態）；重新啟用即恢復
func TestAssetDisabledGate(t *testing.T) {
	t.Run("停用資產：user 持常設 connect 仍 403 asset_disabled", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		if err := db.Model(&model.Asset{}).Where("id = ?", 1).
			Update("active", false).Error; err != nil {
			t.Fatalf("disable asset: %v", err)
		}

		code, resp, _ := issueToken(h, 1, model.RoleUser, 1)
		if code != http.StatusForbidden || resp["reason"] != "asset_disabled" {
			t.Fatalf("停用資產應 403+asset_disabled: code=%d resp=%v", code, resp)
		}
	})

	t.Run("停用資產：admin 不豁免同 403", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		db.Model(&model.Asset{}).Where("id = ?", 1).Update("active", false)

		code, resp, _ := issueToken(h, 2, model.RoleAdmin, 1)
		if code != http.StatusForbidden || resp["reason"] != "asset_disabled" {
			t.Fatalf("admin 對停用資產應同受 403: code=%d resp=%v", code, resp)
		}
	})

	t.Run("重新啟用後恢復簽發", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		db.Model(&model.Asset{}).Where("id = ?", 1).Update("active", false)
		db.Model(&model.Asset{}).Where("id = ?", 1).Update("active", true)

		code, resp, _ := issueToken(h, 1, model.RoleUser, 1)
		if code != http.StatusOK || resp["connect_token"] == nil {
			t.Fatalf("重新啟用後應正常簽發: code=%d resp=%v", code, resp)
		}
	})

	t.Run("停用攔截先於政策閘：approval 段位停用資產回 asset_disabled", func(t *testing.T) {
		// 閘序後半：停用硬擋位於政策閘之前——停用資產不應引導使用者
		// 走申請核准流（申請了也連不上）
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyApproval)
		db.Model(&model.Asset{}).Where("id = ?", 1).Update("active", false)

		code, resp, _ := issueToken(h, 1, model.RoleUser, 1)
		if code != http.StatusForbidden || resp["reason"] != "asset_disabled" {
			t.Fatalf("停用檢查應先於政策閘: code=%d resp=%v", code, resp)
		}
	})

	t.Run("兌換點重查：簽發後停用，殘窗內 token 兌換仍 403", func(t *testing.T) {
		// TOCTOU 殘窗：token 60s TTL 內資產被停用時，兌換點須與 AUTH-1
		//（user 側消費時重載）對稱重查 asset.Active，不得憑簽發時快照放行
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)

		code, resp, _ := issueToken(h, 1, model.RoleUser, 1)
		if code != http.StatusOK || resp["connect_token"] == nil {
			t.Fatalf("前置：啟用態應正常簽發: code=%d resp=%v", code, resp)
		}
		token, _ := resp["connect_token"].(string)
		if err := db.Model(&model.Asset{}).Where("id = ?", 1).
			Update("active", false).Error; err != nil {
			t.Fatalf("disable asset: %v", err)
		}

		rcode, rresp := redeemSSH(h, token)
		if rcode != http.StatusForbidden || rresp["reason"] != "asset_disabled" {
			t.Fatalf("停用後兌換應 403+asset_disabled: code=%d resp=%v", rcode, rresp)
		}
	})

	t.Run("未授權一般 user 對停用資產仍走權限拒絕（閘序：授權先於停用）", func(t *testing.T) {
		// 停用檢查位於授權檢查之後：未授權者先被權限擋，不因停用檢查
		// 改變回應語義（不多洩漏資產狀態）。用無任何授權的一般 user
		//（auditor/admin 在 checkPermission 屬特權放行，驗不了此閘序）
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		if err := db.Create(&model.User{Username: "u-nogrant", Email: emailPtr("n@x"), Active: true}).Error; err != nil {
			t.Fatalf("seed plain user: %v", err)
		}
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)
		db.Model(&model.Asset{}).Where("id = ?", 1).Update("active", false)

		code, resp, _ := issueToken(h, 4, model.RoleUser, 1)
		if code == http.StatusOK {
			t.Fatalf("無授權者不應簽發: resp=%v", resp)
		}
		if resp["reason"] == "asset_disabled" {
			t.Fatalf("授權檢查應先於停用檢查（不洩漏狀態）: resp=%v", resp)
		}
	})
}
