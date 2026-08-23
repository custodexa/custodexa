package proxy

import (
	"context"
	"encoding/json"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/modules/audit"
)

// setupGraphicsRedeemTest 建完整圖形兌換 fixture（role/authz/policy 齊備）：
// user1=一般 user（對 asset1 有常設 connect grant）、user2=admin（無 grant，連線資格
// 純來自 admin 短路）。供圖形路徑兌換點 role／授權／政策重查測試。
func setupGraphicsRedeemTest(t *testing.T) (*ConnectionHandler, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserGroup{}, &model.Asset{}, &model.AssetAccount{},
		&model.AssetGroup{}, &model.AssetNode{}, &model.AssetAuthorization{}, &model.AccessRequest{},
		&model.SecurityPolicy{}, &model.AuditLog{}, &model.Session{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	roles := []model.Role{{Name: model.RoleUser}, {Name: model.RoleAdmin}}
	for i := range roles {
		if err := db.Create(&roles[i]).Error; err != nil {
			t.Fatalf("seed role: %v", err)
		}
	}
	users := []model.User{
		{Username: "u1", Email: emailPtr("u1@x"), Active: true, Roles: []model.Role{roles[0]}},
		{Username: "u2", Email: emailPtr("u2@x"), Active: true, Roles: []model.Role{roles[1]}},
	}
	for i := range users {
		if err := db.Create(&users[i]).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
	}
	if err := db.Create(&model.Asset{Name: "rdp1", Protocol: "rdp", Host: "h", Port: 3389, CreatedBy: 2}).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	// 明確設 open 段位（避免空值語義歧義）
	if err := db.Model(&model.Asset{}).Where("id = ?", 1).
		Update("access_policy", model.AccessPolicyOpen).Error; err != nil {
		t.Fatalf("set policy: %v", err)
	}
	uid := uint(1)
	aid := uint(1)
	if err := db.Create(&model.AssetAuthorization{
		UserID: &uid, AssetID: &aid, Permission: model.PermissionConnect, GrantedBy: 2,
	}).Error; err != nil {
		t.Fatalf("seed grant: %v", err)
	}

	assetSvc, err := asset.NewAssetService(aesColumnCodec(t, make([]byte, 32)), "localhost", 4822, audit.NewTxSink())
	if err != nil {
		t.Fatalf("asset service: %v", err)
	}
	authzSvc := authz.NewAssetAuthorizationService(db)
	h := NewConnectionHandler("localhost", 4822, nil, assetSvc,
		identity.NewAuthService("test-secret", time.Hour), authzSvc, nil)
	h.ConnectTokens = NewConnectTokenManager()
	policies := policy.NewSecurityPolicyService(db)
	h.AccessPolicy = policy.NewAccessPolicyService(db, policies, authzSvc)
	return h, db
}

// redeemGuac 以 connect_token 兌換圖形連線，回傳狀態碼與回應體
func redeemGuac(h *ConnectionHandler, token string) (int, map[string]interface{}) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/connect", h.HandleConnect)
	req := httptest.NewRequest("GET", "/connect?connect_token="+token, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp
}

// TestGraphicsRedeemRoleAndPolicyRecheck 圖形路徑的兌換重查：圖形 WS
// 兌換點 SHALL 對授權撤銷、存取政策收緊、角色降權即時生效（403），與文字終端路徑
// 對稱；授權與政策不變則不被重查閘誤擋。撤權/降權/政策攔截皆在 guacd 握手之前。
func TestGraphicsRedeemRoleAndPolicyRecheck(t *testing.T) {
	t.Run("授權撤銷兌換被拒", func(t *testing.T) {
		h, db := setupGraphicsRedeemTest(t)
		token, err := h.ConnectTokens.IssueConnectToken(context.Background(), ConnectGrant{UserID: 1, AssetID: 1, AccountID: 0})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		if err := db.Where("user_id = ? AND asset_id = ?", 1, 1).
			Delete(&model.AssetAuthorization{}).Error; err != nil {
			t.Fatalf("revoke: %v", err)
		}
		code, resp := redeemGuac(h, token)
		if code != http.StatusForbidden {
			t.Fatalf("授權撤銷後圖形兌換應 403: code=%d resp=%v", code, resp)
		}
	})

	t.Run("存取政策收緊為 approval 兌換被拒", func(t *testing.T) {
		h, db := setupGraphicsRedeemTest(t)
		token, err := h.ConnectTokens.IssueConnectToken(context.Background(), ConnectGrant{UserID: 1, AssetID: 1, AccountID: 0})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		if err := db.Model(&model.Asset{}).Where("id = ?", 1).
			Update("access_policy", model.AccessPolicyApproval).Error; err != nil {
			t.Fatalf("tighten policy: %v", err)
		}
		code, resp := redeemGuac(h, token)
		if code != http.StatusForbidden || resp["reason"] != "approval_required" {
			t.Fatalf("政策收緊後圖形兌換應 403+approval_required: code=%d resp=%v", code, resp)
		}
	})

	t.Run("角色降權兌換被拒（admin→無角色、無授權）", func(t *testing.T) {
		h, db := setupGraphicsRedeemTest(t)
		token, err := h.ConnectTokens.IssueConnectToken(context.Background(), ConnectGrant{UserID: 2, AssetID: 1, AccountID: 0}) // user2=admin，對 asset1 無 grant（admin 短路簽出）
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		var u model.User
		if err := db.First(&u, 2).Error; err != nil {
			t.Fatalf("load user: %v", err)
		}
		if err := db.Model(&u).Association("Roles").Clear(); err != nil {
			t.Fatalf("clear roles: %v", err)
		}
		code, resp := redeemGuac(h, token)
		if code != http.StatusForbidden {
			t.Fatalf("角色降權後圖形兌換應 403（不憑簽發時 admin 快照）: code=%d resp=%v", code, resp)
		}
	})

	t.Run("授權與政策不變不被誤擋（正向斷言強化）", func(t *testing.T) {
		h, _ := setupGraphicsRedeemTest(t)
		token, err := h.ConnectTokens.IssueConnectToken(context.Background(), ConnectGrant{UserID: 1, AssetID: 1, AccountID: 0})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		// user1 授權/政策皆有效：SHALL 通過兌換重查閘，落到後續 guacd 連線階段。
		// 正向斷言強化：不止「非 403」——同時排除假通過（200 成功/
		// 101 WS 升級），確認確實過閘進入建線階段（測試環境無可達 guacd，於握手失敗）
		code, resp := redeemGuac(h, token)
		if code == http.StatusForbidden {
			t.Fatalf("有效授權不應被兌換點重查閘誤擋（403=被閘攔截）: code=%d resp=%v", code, resp)
		}
		if code == http.StatusOK || code == http.StatusSwitchingProtocols {
			t.Fatalf("正向案應落建線階段（guacd 握手失敗），非假通過/升級: code=%d resp=%v", code, resp)
		}
	})
}
