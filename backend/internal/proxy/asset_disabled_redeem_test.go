package proxy

import (
	"context"
	"encoding/json"
	"github.com/custodexa/backend/internal/modules/identity"
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

// TestGuacRedeemDisabledAsset 停用硬擋兌換點重查（圖形路徑）：token 簽發後
// 資產被停用，殘窗內兌換 /connect 須 403+asset_disabled，擋在 guacd 握手之前
// （與 sshproxy 兌換點同語義；簽發點硬擋見 sshproxy 的 TestAssetDisabledGate）
func TestGuacRedeemDisabledAsset(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Asset{}, &model.AssetAccount{}, &model.AssetGroup{},
		&model.AssetNode{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	if err := db.Create(&model.User{Username: "u", Email: emailPtr("u@x"), Active: true}).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := db.Create(&model.Asset{Name: "rdp1", Protocol: "rdp", Host: "h", Port: 3389, CreatedBy: 1}).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}

	assetSvc, err := asset.NewAssetService(aesColumnCodec(t, make([]byte, 32)), "localhost", 4822, audit.NewTxSink())
	if err != nil {
		t.Fatalf("asset service: %v", err)
	}
	h := NewConnectionHandler("localhost", 4822, nil, assetSvc,
		identity.NewAuthService("test-secret", time.Hour), nil, nil, nil)
	h.ConnectTokens = NewConnectTokenManager()

	token, err := h.ConnectTokens.IssueConnectToken(context.Background(), ConnectGrant{UserID: 1, AssetID: 1, AccountID: 0})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	// 簽發後停用（TOCTOU 殘窗）
	if err := db.Model(&model.Asset{}).Where("id = ?", 1).
		Update("active", false).Error; err != nil {
		t.Fatalf("disable asset: %v", err)
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/connect", h.HandleConnect)
	req := httptest.NewRequest("GET", "/connect?connect_token="+token, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if w.Code != http.StatusForbidden || resp["reason"] != "asset_disabled" {
		t.Fatalf("停用後兌換應 403+asset_disabled: code=%d resp=%v", w.Code, resp)
	}
}
