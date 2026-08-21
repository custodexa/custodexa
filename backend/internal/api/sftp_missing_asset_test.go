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

// setupSFTPMissingAssetEnv 檔案面守門測試環境：真 sqlite、真授權服務，
// sftpService 為 nil——所有案例都應在觸及 SFTP 連線之前就被守門擋下
func setupSFTPMissingAssetEnv(t *testing.T) (*gin.Engine, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	// Role 必備：角色現況重判（codex 階段 4 high）改以 DB 現查折疊角色，
	// query 帶入的 role 只決定「呼叫端自稱什麼」，實際判定看使用者的角色關聯——
	// 這正是「降權的前 admin 不得憑 JWT 快照放行」的機制本體
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserGroup{}, &model.Asset{}, &model.AssetGroup{}, &model.AssetNode{},
		&model.AssetAuthorization{}, &model.ApproverScope{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for _, name := range []string{model.RoleUser, model.RoleAdmin, model.RoleAuditor} {
		if err := db.Create(&model.Role{Name: name}).Error; err != nil {
			t.Fatalf("seed role: %v", err)
		}
	}

	handler := NewSFTPHandler(nil, authz.NewAssetAuthorizationService(db), nil, newSFTPTestAuthService(t, db))

	gin.SetMode(gin.TestMode)
	r := gin.New()
	// role 由 query 帶入，模擬不同角色呼叫同一端點
	r.GET("/assets/:id/files", func(c *gin.Context) {
		c.Set("userID", uint(1))
		role := c.Query("as")
		if role == "" {
			role = model.RoleUser
		}
		c.Set("role", role)
		handler.List(c)
	})
	return r, db
}

func getSFTPList(r *gin.Engine, assetID string, role string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/assets/"+assetID+"/files?path=/tmp&as="+role, nil))
	return w
}

// TestSFTPNonexistentAssetReturns404ForAdmin admin 的權限檢查短路後直達存在性/
// 停用閘：不存在的資產必須回 404「資產不存在」，而非誤導的 403「資產已停用」
// （asset-syslog-debt-cleanup D3）
func TestSFTPNonexistentAssetReturns404ForAdmin(t *testing.T) {
	r, db := setupSFTPMissingAssetEnv(t)
	db.Create(&model.User{Username: "admin1", Email: emailPtr("a@x"), Active: true,
		Roles: []model.Role{{ID: 2, Name: model.RoleAdmin}}})

	w := getSFTPList(r, "9999", model.RoleAdmin)

	if w.Code != http.StatusNotFound {
		t.Fatalf("不存在資產應回 404, got %d body=%s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); strings.Contains(body, "asset_disabled") {
		t.Fatalf("不存在資產不得回報為已停用: %s", body)
	}
}

// TestSFTPSoftDeletedAssetReturns404ForUser 刪資產是軟刪且不撤銷授權
// （asset_service.Delete），權限查詢又不 join assets，故一般使用者可通過授權檢查
// 而走到存在性閘——此路徑同樣不得把「資產已不存在」說成「已停用」
func TestSFTPSoftDeletedAssetReturns404ForUser(t *testing.T) {
	r, db := setupSFTPMissingAssetEnv(t)
	db.Create(&model.User{Username: "u1", Email: emailPtr("u@x"), Active: true})
	db.Create(&model.Asset{Name: "a1", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1})
	uid, aid := uint(1), uint(1)
	db.Create(&model.AssetAuthorization{
		UserID: &uid, AssetID: &aid, Permission: model.PermissionConnect, GrantedBy: 1,
	})
	// 軟刪資產，授權刻意保留（重現真實資料生命週期）
	if err := db.Delete(&model.Asset{}, 1).Error; err != nil {
		t.Fatalf("soft delete: %v", err)
	}

	w := getSFTPList(r, "1", model.RoleUser)

	if w.Code != http.StatusNotFound {
		t.Fatalf("軟刪資產應回 404, got %d body=%s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); strings.Contains(body, "asset_disabled") {
		t.Fatalf("軟刪資產不得回報為已停用: %s", body)
	}
}

// TestSFTPSoftDeletedAssetReturns404ForAuditor auditor 的 connect 不因角色短路
// （CPG-002），但持顯式 connect 授權時同樣會通過授權檢查走到存在性閘
func TestSFTPSoftDeletedAssetReturns404ForAuditor(t *testing.T) {
	r, db := setupSFTPMissingAssetEnv(t)
	db.Create(&model.User{Username: "aud1", Email: emailPtr("aud@x"), Active: true,
		Roles: []model.Role{{ID: 3, Name: model.RoleAuditor}}})
	db.Create(&model.Asset{Name: "a1", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1})
	uid, aid := uint(1), uint(1)
	db.Create(&model.AssetAuthorization{
		UserID: &uid, AssetID: &aid, Permission: model.PermissionConnect, GrantedBy: 1,
	})
	if err := db.Delete(&model.Asset{}, 1).Error; err != nil {
		t.Fatalf("soft delete: %v", err)
	}

	w := getSFTPList(r, "1", model.RoleAuditor)

	if w.Code != http.StatusNotFound {
		t.Fatalf("auditor 對軟刪資產應回 404, got %d body=%s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); strings.Contains(body, "asset_disabled") {
		t.Fatalf("軟刪資產不得回報為已停用: %s", body)
	}
}

// TestSFTPDisabledAssetStillReturns403ForAdmin 存在但停用的資產維持 403
// asset_disabled——本次語義區分不得把停用硬擋一併弱化（admin 不豁免）
func TestSFTPDisabledAssetStillReturns403ForAdmin(t *testing.T) {
	r, db := setupSFTPMissingAssetEnv(t)
	db.Create(&model.User{Username: "admin1", Email: emailPtr("a@x"), Active: true,
		Roles: []model.Role{{ID: 2, Name: model.RoleAdmin}}})
	db.Create(&model.Asset{Name: "a1", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1})
	if err := db.Model(&model.Asset{}).Where("id = ?", 1).Update("active", false).Error; err != nil {
		t.Fatalf("disable: %v", err)
	}

	w := getSFTPList(r, "1", model.RoleAdmin)

	if w.Code != http.StatusForbidden {
		t.Fatalf("停用資產應回 403, got %d body=%s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); !strings.Contains(body, "asset_disabled") {
		t.Fatalf("回應應含機器可辨 asset_disabled: %s", body)
	}
}
