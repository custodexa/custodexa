package api

import (
	"github.com/custodexa/backend/internal/modules/authz"
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
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/session"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/modules/audit"
)

// SFTP 檔案面的帳號授權複查（asset-multi-account D5 強制點 3／3）。
//
// 前階段 opus 審查指認的旁路：`session_id` 路徑取的是**連線當下的帳號快照**
// （D7 不可變審計欄）。若逕以該快照建線，帳號被移出授權範圍後，使用者只要
// 翻出一個舊 session id 就能無限延續檔案存取——歷史快照成為繞過現行授權的門。
// 快照只該決定「用哪個帳號」，「是否還能用」必須現查。

func setupSFTPScopeEnv(t *testing.T) (*SFTPHandler, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql db: %v", err)
	}
	sqlDB.SetMaxOpenConns(1) // :memory: 多連線＝多個獨立空庫（ff51836 教訓）
	if err := db.AutoMigrate(&model.User{}, &model.UserGroup{}, &model.Asset{}, &model.AssetGroup{},
		&model.AssetNode{}, &model.AssetAccount{}, &model.AssetAuthorization{}, &model.ApproverScope{},
		&model.Session{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	db.Create(&model.User{Username: "u1", Email: emailPtr("u@x"), Active: true})
	db.Create(&model.Asset{Name: "a1", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1, Active: true})
	for _, name := range []string{"root", "app"} {
		if err := db.Create(&model.AssetAccount{
			AssetID: 1, Username: name, IsDefault: name == "root"}).Error; err != nil {
			t.Fatalf("seed account: %v", err)
		}
	}
	uid, aid := uint(1), uint(1)
	if err := db.Create(&model.AssetAuthorization{
		UserID: &uid, AssetID: &aid, Permission: model.PermissionConnect, GrantedBy: 1,
		Accounts: model.AccountScope{"app"}, // 只授權 app，未授權預設的 root
	}).Error; err != nil {
		t.Fatalf("seed grant: %v", err)
	}

	assetSvc, err := asset.NewAssetService(aesColumnCodec(t, make([]byte, 32)), "localhost", 4822, audit.NewTxSink())
	if err != nil {
		t.Fatalf("asset service: %v", err)
	}
	// 真 SFTPService：帳號身分解析需要 assetService，nil 替身在此無法涵蓋判定路徑
	sftpSvc := session.NewSFTPService(assetSvc, asset.NewHostKeyService(db))
	handler := NewSFTPHandler(sftpSvc, authz.NewAssetAuthorizationService(db), nil, newSFTPTestAuthService(t, db))
	return handler, db
}

// newSFTPTestAuthService 角色現況重判所需的 AuthService（codex 階段 4 high）。
//
// CurrentConnectRole 走 database.DB 全域，故呼叫端必須先把它指向測試庫；
// 未指向即 nil 解參考——這正是「檔案面確實在查 DB 而非信任 JWT 快照」的證明
func newSFTPTestAuthService(t *testing.T, db *gorm.DB) *identity.AuthService {
	t.Helper()
	if database.DB != db {
		old := database.DB
		database.DB = db
		t.Cleanup(func() { database.DB = old })
	}
	return identity.NewAuthService("test-secret", time.Hour)
}

// callList 以指定 query 呼叫檔案列表端點
func callList(handler *SFTPHandler, query string) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/assets/:id/files", func(c *gin.Context) {
		c.Set("userID", uint(1))
		c.Set("role", model.RoleUser)
		handler.List(c)
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/assets/1/files?path=/tmp"+query, nil))
	return w
}

// seedSession 建一筆該使用者對該資產的歷史會話，帶帳號雙快照
func seedSession(t *testing.T, db *gorm.DB, accountID uint, username string) uint {
	t.Helper()
	assetID := uint(1)
	sess := model.Session{
		UserID: 1, AssetID: &assetID, AccountID: accountID, AccountUsername: username,
		Protocol: model.ProtocolSSH, Status: model.SessionStatusClosed,
	}
	if err := db.Create(&sess).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}
	return sess.ID
}

// TestSFTPSessionSnapshotDoesNotBypassScope 歷史會話快照不得繞過現行帳號授權：
// 以 root 建立的舊會話，在 root 被移出授權範圍後不得再用於檔案操作
func TestSFTPSessionSnapshotDoesNotBypassScope(t *testing.T) {
	handler, db := setupSFTPScopeEnv(t)
	// 舊會話以 root（account id 1）建立——當時 root 仍在授權範圍內
	sessionID := seedSession(t, db, 1, "root")

	w := callList(handler, "&session_id="+uintToStr(sessionID))
	if w.Code != http.StatusNotFound {
		t.Fatalf("root 已移出授權範圍，舊 session 不得延續檔案存取: code=%d body=%s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); !strings.Contains(body, "資產不存在") {
		t.Fatalf("應與未授權同語義（不洩漏存在性）: %s", body)
	}
}

// TestSFTPSessionSnapshotInScopeAllowed 對照組：授權範圍內帳號的會話正常通過
// 帳號閘（其後因無法真的撥接 SSH 而失敗，但**不是**被授權閘擋下）
func TestSFTPSessionSnapshotInScopeAllowed(t *testing.T) {
	handler, db := setupSFTPScopeEnv(t)
	sessionID := seedSession(t, db, 2, "app") // app 在授權範圍內

	w := callList(handler, "&session_id="+uintToStr(sessionID))
	if w.Code == http.StatusNotFound && strings.Contains(w.Body.String(), "資產不存在") {
		t.Fatalf("範圍內帳號不應被授權閘擋下: code=%d body=%s", w.Code, w.Body.String())
	}
}

// TestSFTPDefaultEntryRespectsScope 獨立入口（不帶 session_id，走預設帳號）
// 同受帳號範圍判定：預設帳號 root 不在授權範圍內即拒。
// 連線面已擋預設帳號的未授權情形，檔案面不得留一道語義較寬的門
func TestSFTPDefaultEntryRespectsScope(t *testing.T) {
	handler, _ := setupSFTPScopeEnv(t)

	w := callList(handler, "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("預設帳號不在授權範圍時獨立入口應被拒: code=%d body=%s", w.Code, w.Body.String())
	}
}

// TestSFTPAllScopeKeepsExistingBehaviour 既有行為零變化：授權為 @ALL
// （migration 回填值）時，預設帳號入口與會話入口都不被帳號閘擋下
func TestSFTPAllScopeKeepsExistingBehaviour(t *testing.T) {
	handler, db := setupSFTPScopeEnv(t)
	if err := db.Model(&model.AssetAuthorization{}).Where("user_id = ?", 1).
		Update("accounts", model.AccountScope{model.AccountScopeAll}).Error; err != nil {
		t.Fatalf("widen scope: %v", err)
	}
	sessionID := seedSession(t, db, 1, "root")

	for _, q := range []string{"", "&session_id=" + uintToStr(sessionID)} {
		w := callList(handler, q)
		if w.Code == http.StatusNotFound && strings.Contains(w.Body.String(), "資產不存在") {
			t.Fatalf("@ALL 下不應被帳號閘擋（query=%q）: code=%d body=%s", q, w.Code, w.Body.String())
		}
	}
}

func uintToStr(v uint) string {
	if v == 0 {
		return "0"
	}
	var buf []byte
	for v > 0 {
		buf = append([]byte{byte('0' + v%10)}, buf...)
		v /= 10
	}
	return string(buf)
}
