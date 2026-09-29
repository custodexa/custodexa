package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 產品版本號經 GET /auth/me 與登入回應的 user 物件帶給介面側欄。
//
// 版本值由組裝根注入（cmd/server 的 main.Version，與 /health 同一個變數），本檔以
// SetProductVersion 模擬注入；組裝根確實有接線由 cmd/server 的
// TestAssemblyInjectsProductVersion 釘住。

// setupMeVersionEnv 經完整 RegisterRoutes（真 AuthMiddleware＋真 JWT＋sqlite）的
// /auth/me 環境；version 為空字串時不注入（對照「未注入」的回應形狀）。
func setupMeVersionEnv(t *testing.T, version string) (*gin.Engine, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1) // :memory: 每條連線各自獨立空庫
	if err := db.AutoMigrate(
		&model.User{}, &model.Role{}, &model.UserGroup{}, &model.Asset{},
		&model.AssetAuthorization{}, &model.ApproverScope{}, &model.AuditLog{}, &model.UserRole{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	secret := "me-version-secret"
	authService := identity.NewAuthService(secret, time.Minute)
	if version != "" {
		authService.SetProductVersion(version)
	}
	r := gin.New()
	h := NewAuthHandler(authService, nil)
	h.SetSourcePolicyReader(unrestrictedSourcePolicy())
	h.RegisterRoutes(r.Group("/api/v1"), authService)

	u := &model.User{Username: "vera", FullName: "Vera Lin", Email: emailPtr("v@x"), Active: true}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	token, err := crypto.NewJWTManager(secret, time.Minute).
		GenerateToken(u.ID, u.Username, "v@x", "user", crypto.AuthContext{})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	return r, token
}

func getMeRaw(t *testing.T, r *gin.Engine, token string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /auth/me = %d：%s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return body
}

// TestMe_CarriesProductVersion 注入的版本號原樣出現在 GET /auth/me 與 PATCH /auth/me
// 的回應（兩者共用 UserInfo 的同一個組裝點）。
func TestMe_CarriesProductVersion(t *testing.T) {
	r, token := setupMeVersionEnv(t, "1.13.0")

	body := getMeRaw(t, r, token)
	if got := body["product_version"]; got != "1.13.0" {
		t.Fatalf("GET /auth/me product_version = %v，want 1.13.0", got)
	}

	w := patchMe(t, r, token, map[string]any{"local_display_name": "小林"})
	if w.Code != http.StatusOK {
		t.Fatalf("PATCH /auth/me = %d：%s", w.Code, w.Body.String())
	}
	var patched map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &patched); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := patched["product_version"]; got != "1.13.0" {
		t.Fatalf("PATCH /auth/me product_version = %v，want 1.13.0（與 GET 同形）", got)
	}
}

// TestMe_DevVersionPassedThroughUnchanged 開發建置的 "dev" 原樣轉出：
// 要不要顯示由前端判定，後端不改寫、不冒充任何已發布版本。
func TestMe_DevVersionPassedThroughUnchanged(t *testing.T) {
	r, token := setupMeVersionEnv(t, "dev")
	if got := getMeRaw(t, r, token)["product_version"]; got != "dev" {
		t.Fatalf("product_version = %v，want dev", got)
	}
}

// TestMe_OmitsProductVersionWhenNotInjected 未注入時欄位不出現（omitempty），
// 未經組裝根的建構路徑回應形狀逐字不變。
func TestMe_OmitsProductVersionWhenNotInjected(t *testing.T) {
	r, token := setupMeVersionEnv(t, "")
	body := getMeRaw(t, r, token)
	if _, ok := body["product_version"]; ok {
		t.Fatalf("未注入卻出現 product_version：%v", body["product_version"])
	}
	// 判別式：回應本身正常（否則「欄位不存在」可能只是整包回應是錯誤體）
	if body["username"] != "vera" {
		t.Fatalf("回應不是使用者資訊：%v", body)
	}
}

// TestLoginResponse_UserCarriesProductVersion 登入成功回應的 user 物件與 /auth/me 共用
// UserInfo，版本號一併帶出（登入後才讀得到，未認證面不擴大）。
func TestLoginResponse_UserCarriesProductVersion(t *testing.T) {
	e := setupRefreshCookieEnv(t)
	e.auth.SetProductVersion("1.13.0")

	w := e.post(t, "/api/v1/auth/login", e.h.Login, map[string]string{
		"username": e.user.Username, "password": refreshCookieGuardPassword,
	}, "")
	if w.Code != http.StatusOK {
		t.Fatalf("login = %d：%s", w.Code, w.Body.String())
	}
	var body struct {
		User map[string]any `json:"user"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.User == nil {
		t.Fatalf("登入回應沒有 user 物件：%s", w.Body.String())
	}
	if got := body.User["product_version"]; got != "1.13.0" {
		t.Fatalf("login user.product_version = %v，want 1.13.0", got)
	}
}
