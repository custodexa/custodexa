package api

import (
	"bytes"
	"encoding/json"
	"github.com/custodexa/backend/internal/modules/authz"
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
	"github.com/custodexa/backend/internal/modules/session"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/modules/audit"
)

// 角色快照即時重判（codex 階段 4 high）。
//
// 缺陷形狀：AuthMiddleware 不查 DB，`c.Get("role")` 拿到的是**簽發 JWT 當下**的
// 角色。三個連線強制點早已以 CurrentConnectRole 覆蓋，但檔案面（SFTP）與
// `PUT /authorizations/:id/accounts` 沒有——於是被降權／停用的前 admin 在 token
// 效期內仍能以 admin 短路存取任意帳號的檔案面，並把自己加回被移除的帳號範圍。
//
// 下列測試一律讓 c.Set("role", admin)（模擬舊 JWT 快照）而 DB 內該使用者
// **不具 admin 角色**，斷言以 DB 現況為準。

func setupRoleRecheckDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql db: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserGroup{}, &model.Asset{},
		&model.AssetGroup{}, &model.AssetNode{}, &model.AssetAccount{}, &model.AssetAuthorization{},
		&model.ApproverScope{}, &model.Session{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })
	return db
}

// TestSFTPDemotedAdminJWTRejected 降權的前 admin 持舊 JWT 存取檔案面：
// 依 DB 現況折疊為一般 user，無授權即擋
func TestSFTPDemotedAdminJWTRejected(t *testing.T) {
	db := setupRoleRecheckDB(t)
	// 使用者不掛任何角色關聯＝已被降權（primaryRoleOf 折疊為 user）
	db.Create(&model.User{Username: "ex-admin", Email: emailPtr("e@x"), Active: true})
	db.Create(&model.Asset{Name: "a1", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1, Active: true})
	db.Create(&model.AssetAccount{AssetID: 1, Username: "root", IsDefault: true})

	assetSvc, err := asset.NewAssetService(aesColumnCodec(t, make([]byte, 32)), "localhost", 4822, audit.NewTxSink())
	if err != nil {
		t.Fatalf("asset service: %v", err)
	}
	handler := NewSFTPHandler(
		session.NewSFTPService(assetSvc, asset.NewHostKeyService(db)),
		authz.NewAssetAuthorizationService(db), nil, newSFTPTestAuthService(t, db))

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/assets/:id/files", func(c *gin.Context) {
		c.Set("userID", uint(1))
		c.Set("role", model.RoleAdmin) // 舊 JWT 快照仍宣稱 admin
		handler.List(c)
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/assets/1/files?path=/tmp", nil))

	if w.Code != http.StatusNotFound {
		t.Fatalf("降權者不得憑 JWT 角色快照通過檔案面授權: code=%d body=%s", w.Code, w.Body.String())
	}
}

// TestSFTPInactiveUserRejected 停用使用者持有效 JWT：CurrentConnectRole 一併完成
// AUTH-1 可連線複查，於檔案面即時擋下（與連線面同一事實源）
func TestSFTPInactiveUserRejected(t *testing.T) {
	db := setupRoleRecheckDB(t)
	adminRole := model.Role{Name: model.RoleAdmin}
	db.Create(&adminRole)
	db.Create(&model.User{Username: "gone", Email: emailPtr("g@x"), Active: true,
		Roles: []model.Role{adminRole}})
	// 停用以顯式 Update 落庫：Active 帶 gorm default tag，Create 時的 false 零值
	// 會被 DB 預設值蓋掉（GORM 慣有陷阱），直接建立會得到一個仍啟用的使用者，
	// 測試就變成假綠
	if err := db.Model(&model.User{}).Where("id = ?", 1).Update("active", false).Error; err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	db.Create(&model.Asset{Name: "a1", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1, Active: true})

	handler := NewSFTPHandler(nil, authz.NewAssetAuthorizationService(db), nil,
		newSFTPTestAuthService(t, db))

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/assets/:id/files", func(c *gin.Context) {
		c.Set("userID", uint(1))
		c.Set("role", model.RoleAdmin)
		handler.List(c)
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/assets/1/files?path=/tmp", nil))

	if w.Code != http.StatusForbidden {
		t.Fatalf("停用使用者應被擋（403 user_inactive）: code=%d body=%s", w.Code, w.Body.String())
	}
}

// TestUpdateAccountsDemotedAdminRejected 降權的前 admin 改授權帳號範圍：
// RequireRole 讀 JWT 快照會放行，handler 內的 DB 現查必須擋下——
// 否則他可以把自己加回被移除的帳號（本端點直接改授權事實）
func TestUpdateAccountsDemotedAdminRejected(t *testing.T) {
	db := setupRoleRecheckDB(t)
	db.Create(&model.User{Username: "ex-admin", Email: emailPtr("e@x"), Active: true})
	db.Create(&model.Asset{Name: "a1", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1, Active: true})
	uid, aid := uint(1), uint(1)
	db.Create(&model.AssetAuthorization{
		UserID: &uid, AssetID: &aid, Permission: model.PermissionConnect, GrantedBy: 1,
		Accounts: model.AccountScope{"app"},
	})

	authzSvc := authz.NewAssetAuthorizationService(db)
	handler := NewAuthorizationHandler(authzSvc, nil)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	// 走真 RegisterRoutes 之外的最小掛法，但顯式注入 authService（模擬組裝期行為）
	handler.authService = identity.NewAuthService("test-secret", time.Hour)
	r.PUT("/authorizations/:id/accounts", func(c *gin.Context) {
		c.Set("userID", uint(1))
		c.Set("role", model.RoleAdmin) // 舊 JWT 快照
		handler.UpdateAccounts(c)
	})

	body, _ := json.Marshal(map[string]any{"accounts": []string{"@ALL"}})
	req := httptest.NewRequest("PUT", "/authorizations/1/accounts", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("降權者不得改授權帳號範圍: code=%d body=%s", w.Code, w.Body.String())
	}
	// 授權未被改動——沒有靜默擴張成 @ALL
	var after model.AssetAuthorization
	if err := db.First(&after, 1).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if after.Accounts.IsAll() {
		t.Fatalf("拒絕後帳號範圍不得被改動: %+v", after.Accounts)
	}
}

// TestUpdateAccountsRejectsEmptyAndMissing 空陣列／欄位省略一律拒收，
// 且既有範圍不被改動（F1 的 HTTP 層回歸守衛）
func TestUpdateAccountsRejectsEmptyAndMissing(t *testing.T) {
	db := setupRoleRecheckDB(t)
	adminRole := model.Role{Name: model.RoleAdmin}
	db.Create(&adminRole)
	db.Create(&model.User{Username: "admin1", Email: emailPtr("a@x"), Active: true,
		Roles: []model.Role{adminRole}})
	db.Create(&model.Asset{Name: "a1", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1, Active: true})
	uid, aid := uint(1), uint(1)
	db.Create(&model.AssetAuthorization{
		UserID: &uid, AssetID: &aid, Permission: model.PermissionConnect, GrantedBy: 1,
		Accounts: model.AccountScope{"app"},
	})

	handler := NewAuthorizationHandler(authz.NewAssetAuthorizationService(db), nil)
	handler.authService = identity.NewAuthService("test-secret", time.Hour)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.PUT("/authorizations/:id/accounts", func(c *gin.Context) {
		c.Set("userID", uint(1))
		c.Set("role", model.RoleAdmin)
		handler.UpdateAccounts(c)
	})

	cases := []struct {
		name     string
		body     string
		wantCode string
	}{
		{"欄位省略", `{}`, "VALIDATION_ACCOUNT_SCOPE_REQUIRED"},
		{"顯式 null", `{"accounts":null}`, "VALIDATION_ACCOUNT_SCOPE_REQUIRED"},
		{"顯式空陣列", `{"accounts":[]}`, "VALIDATION_ACCOUNT_SCOPE_INVALID"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("PUT", "/authorizations/1/accounts", bytes.NewBufferString(tc.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("應 400: code=%d body=%s", w.Code, w.Body.String())
			}
			var resp map[string]any
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			if resp["code"] != tc.wantCode {
				t.Fatalf("碼不符: got=%v want=%s", resp["code"], tc.wantCode)
			}
			// 關鍵斷言：拒收後既有範圍原封不動（絕不變成 @ALL）
			var after model.AssetAuthorization
			if err := db.First(&after, 1).Error; err != nil {
				t.Fatalf("reload: %v", err)
			}
			if after.Accounts.IsAll() {
				t.Fatalf("拒收後不得溢授為 @ALL: %+v", after.Accounts)
			}
		})
	}
}

// TestUpdateAccountsHappyPath 對照組：現況 admin ＋顯式範圍→正常更新
func TestUpdateAccountsHappyPath(t *testing.T) {
	db := setupRoleRecheckDB(t)
	adminRole := model.Role{Name: model.RoleAdmin}
	db.Create(&adminRole)
	db.Create(&model.User{Username: "admin1", Email: emailPtr("a@x"), Active: true,
		Roles: []model.Role{adminRole}})
	db.Create(&model.Asset{Name: "a1", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1, Active: true})
	uid, aid := uint(1), uint(1)
	db.Create(&model.AssetAuthorization{
		UserID: &uid, AssetID: &aid, Permission: model.PermissionConnect, GrantedBy: 1,
		Accounts: model.AccountScope{"app"},
	})

	handler := NewAuthorizationHandler(authz.NewAssetAuthorizationService(db), nil)
	handler.authService = identity.NewAuthService("test-secret", time.Hour)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.PUT("/authorizations/:id/accounts", func(c *gin.Context) {
		c.Set("userID", uint(1))
		c.Set("role", model.RoleAdmin)
		handler.UpdateAccounts(c)
	})

	body, _ := json.Marshal(map[string]any{"accounts": []string{"root", "app"}})
	req := httptest.NewRequest("PUT", "/authorizations/1/accounts", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("現況 admin 應可更新: code=%d body=%s", w.Code, w.Body.String())
	}
	var after model.AssetAuthorization
	if err := db.First(&after, 1).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if after.Accounts.IsAll() || !after.Accounts.Contains("root") || !after.Accounts.Contains("app") {
		t.Fatalf("範圍應為 [app root]: %+v", after.Accounts)
	}
}
