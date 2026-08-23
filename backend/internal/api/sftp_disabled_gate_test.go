package api

import (
	"github.com/custodexa/backend/internal/modules/authz"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestSFTPDisabledAssetReturns403 停用資產檔案端點硬擋：
// 檔案面與 connect-token 同收口——授權檢查後 403+asset_disabled，
// 拒絕發生在任何 SFTP 連線建立之前（sftpService 為 nil 仍安全通過即為證）
func TestSFTPDisabledAssetReturns403(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.UserGroup{}, &model.Asset{}, &model.AssetGroup{}, &model.AssetNode{},
		&model.AssetAuthorization{}, &model.ApproverScope{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db.Create(&model.User{Username: "u1", Email: emailPtr("u@x"), Active: true})
	db.Create(&model.Asset{Name: "a1", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1})
	uid, aid := uint(1), uint(1)
	db.Create(&model.AssetAuthorization{
		UserID: &uid, AssetID: &aid, Permission: model.PermissionConnect, GrantedBy: 1,
	})
	// 停用
	if err := db.Model(&model.Asset{}).Where("id = ?", 1).Update("active", false).Error; err != nil {
		t.Fatalf("disable: %v", err)
	}

	handler := NewSFTPHandler(nil, authz.NewAssetAuthorizationService(db), nil, newSFTPTestAuthService(t, db))

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/assets/:id/files", func(c *gin.Context) {
		c.Set("userID", uint(1))
		c.Set("role", model.RoleUser)
		handler.List(c)
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/assets/1/files?path=/tmp", nil))

	if w.Code != http.StatusForbidden {
		t.Fatalf("停用資產檔案端點應 403, got %d body=%s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); !strings.Contains(body, "asset_disabled") {
		t.Fatalf("回應應含機器可辨 asset_disabled: %s", body)
	}

	// 重新啟用後的恢復語義由簽發點測試覆蓋（TestAssetDisabledGate）；
	// 此處不再前進——通過守門後會觸及 nil sftpService（測試不建真 SFTP 連線）
}
