package middleware

import (
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 憑證世代閘於認證中介層的行為（idp-oidc-integration tasks 4.11 的第 (4) 個驗證點）。
//
// 為什麼要在 middleware 這一層測：既有的 auth_test.go 完全不接 DB，
// service.VerifyCredentialGenerationByUserID 於 database.DB == nil 時直接放行
//（升級／測試建構路徑的相容分支），所以那些測試對世代閘毫無鑑別力——
// 中介層的世代比對被整段刪掉也不會轉紅。本檔接上真 sqlite 補這一格。
//
// 停用動作在此以「enabled=false ＋ auth_epoch 推進」的 DB 現況模擬：
// 「停用必然推進世代、重新啟用不回退」這條耦合由 service 層的
// TestOIDCProviderDisableAdvancesEpochAndReEnableDoesNotRollBack 保證，
// 本層要驗的是「面對這樣的 DB 現況，中介層放不放行」。

const epochGateSecret = "test-secret"

// setupEpochGateRouter 接真 DB 的 AuthMiddleware 路由
func setupEpochGateRouter(t *testing.T) (*gin.Engine, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	// 純 Go driver 的每條連線是各自獨立的空 DB
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.User{}, &model.OIDCProvider{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/protected", AuthMiddleware(identity.NewAuthService(epochGateSecret, time.Minute)),
		func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"message": "ok"}) })
	return r, db
}

func seedEpochGateUser(t *testing.T, db *gorm.DB) *model.User {
	t.Helper()
	u := &model.User{Username: "sso", Password: "x", Active: true}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return u
}

// seedEpochGateProvider provider 列；Enabled 顯式回寫（GORM 對零值欄位交由 DB default 填）
func seedEpochGateProvider(t *testing.T, db *gorm.DB, epoch int, enabled bool) uint {
	t.Helper()
	p := model.OIDCProvider{Name: "idp", Issuer: "https://idp.example", ClientID: "cid",
		AuthEpoch: epoch, Enabled: enabled}
	if err := db.Create(&p).Error; err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	if err := db.Model(&model.OIDCProvider{}).Where("id = ?", p.ID).
		Update("enabled", enabled).Error; err != nil {
		t.Fatalf("set enabled: %v", err)
	}
	return p.ID
}

func epochGateToken(t *testing.T, userID uint, authCtx crypto.AuthContext) string {
	t.Helper()
	mgr := crypto.NewJWTManager(epochGateSecret, time.Minute)
	token, err := mgr.GenerateToken(userID, "sso", "sso@example.com", "user", authCtx)
	if err != nil {
		t.Fatalf("簽發 token: %v", err)
	}
	return token
}

func getProtected(r *gin.Engine, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// TestAuthMiddlewareRejectsAccessAfterProviderDisabledAndReEnabled
// 中介層的 access token 驗證點（4.11 第 (4) 點）：停用後即時失效，
// 重新啟用亦不復活
func TestAuthMiddlewareRejectsAccessAfterProviderDisabledAndReEnabled(t *testing.T) {
	r, db := setupEpochGateRouter(t)
	user := seedEpochGateUser(t, db)
	pid := seedEpochGateProvider(t, db, 0, true)

	token := epochGateToken(t, user.ID, crypto.AuthContext{
		AuthMethod: crypto.AuthMethodOIDC, ProviderID: pid, AuthEpoch: 0, CredEpoch: 0})

	// 正向控制：停用前必須是通的，否則後面的 401 可能來自任何別的原因
	if w := getProtected(r, token); w.Code != http.StatusOK {
		t.Fatalf("停用前應放行: code=%d body=%s", w.Code, w.Body.String())
	}

	// 停用（推進世代＋enabled=false）
	if err := db.Model(&model.OIDCProvider{}).Where("id = ?", pid).
		Updates(map[string]any{"enabled": false, "auth_epoch": 1}).Error; err != nil {
		t.Fatalf("停用 provider: %v", err)
	}
	w := getProtected(r, token)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("停用後應 401: code=%d body=%s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); !strings.Contains(body, "AUTH_TOKEN_INVALID") {
		t.Errorf("回應碼應收斂為 AUTH_TOKEN_INVALID（不分述成因），實得 %s", body)
	}

	// 重新啟用：enabled 已復原，只剩世代不符擋著。僅檢查布林的實作在此會放行
	if err := db.Model(&model.OIDCProvider{}).Where("id = ?", pid).
		Update("enabled", true).Error; err != nil {
		t.Fatalf("重新啟用 provider: %v", err)
	}
	var reloaded model.OIDCProvider
	if err := db.First(&reloaded, pid).Error; err != nil {
		t.Fatalf("重載 provider: %v", err)
	}
	if !reloaded.Enabled || reloaded.AuthEpoch != 1 {
		t.Fatalf("前提不成立：enabled=%v auth_epoch=%d", reloaded.Enabled, reloaded.AuthEpoch)
	}
	if w := getProtected(r, token); w.Code != http.StatusUnauthorized {
		t.Fatalf("重新啟用後舊 access 仍須 401（世代不回退）: code=%d body=%s", w.Code, w.Body.String())
	}
}

// TestAuthMiddlewareUserEpochBumpRejectsAccess 使用者維度：解綁外部身分／改為
// 僅外部登入／停用帳號皆推進 credential_epoch，既簽 access 立即失效
func TestAuthMiddlewareUserEpochBumpRejectsAccess(t *testing.T) {
	r, db := setupEpochGateRouter(t)
	user := seedEpochGateUser(t, db)
	pid := seedEpochGateProvider(t, db, 0, true)

	token := epochGateToken(t, user.ID, crypto.AuthContext{
		AuthMethod: crypto.AuthMethodOIDC, ProviderID: pid})
	if w := getProtected(r, token); w.Code != http.StatusOK {
		t.Fatalf("推進前應放行: code=%d", w.Code)
	}

	if err := identity.BumpCredentialEpoch(db, user.ID, "test_unbind"); err != nil {
		t.Fatalf("BumpCredentialEpoch: %v", err)
	}
	if w := getProtected(r, token); w.Code != http.StatusUnauthorized {
		t.Fatalf("使用者世代推進後應 401: code=%d body=%s", w.Code, w.Body.String())
	}
}

// TestAuthMiddlewareLocalTokenImmuneToProviderRevocation 升級期相容的關鍵語義：
// 四欄零值＝本地／LDAP 登入，即使系統中存在已停用且世代已推進的 provider 也不得被牽連
func TestAuthMiddlewareLocalTokenImmuneToProviderRevocation(t *testing.T) {
	r, db := setupEpochGateRouter(t)
	user := seedEpochGateUser(t, db)
	seedEpochGateProvider(t, db, 7, false)

	token := epochGateToken(t, user.ID, crypto.AuthContext{})
	if w := getProtected(r, token); w.Code != http.StatusOK {
		t.Fatalf("本地 token 不得被 provider 失效牽連: code=%d body=%s", w.Code, w.Body.String())
	}
}
