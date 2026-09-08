package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/crypto"
)

// 身分來源管理面與角色替換端點在**真路由**上的兩條性質。
//
// 兩者都刻意經完整的 RegisterRoutes（真 AuthMiddleware＋真 JWT＋真服務），
// 不用 mock：要驗的正是「掛在鏈上的東西有沒有生效」與「服務層真的沒改到那些列」，
// 而 mock 在這兩題上證明不了任何事。

// setupRoleSourceEnv 真 sqlite ＋真 UserService 的環境
func setupRoleSourceEnv(t *testing.T) (*gorm.DB, *identity.UserService) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	// UserRole 排在 User／Role 之後（GORM 對關聯表的處理會蓋掉排在它之前的宣告）
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserRole{},
		&model.AuditLog{}, &model.RefreshToken{},
		&model.GroupRoleMapping{}, &model.UserRoleMapping{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })
	return db, identity.NewUserService(db, nil)
}

// seedRoleSourceUser 建一名帳號，並依 sources 給定每個角色的來源
func seedRoleSourceUser(t *testing.T, db *gorm.DB, sources map[string]string) *model.User {
	t.Helper()
	user := &model.User{Username: "mapped-user", Password: "x", Active: true, IsLDAP: true}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	for name, source := range sources {
		role := &model.Role{Name: name}
		if err := db.Where("name = ?", name).FirstOrCreate(role, model.Role{Name: name}).Error; err != nil {
			t.Fatalf("seed role %s: %v", name, err)
		}
		if err := db.Exec(
			"INSERT INTO user_roles (user_id, role_id, source) VALUES (?, ?, ?)",
			user.ID, role.ID, source).Error; err != nil {
			t.Fatalf("seed user_role %s: %v", name, err)
		}
	}
	return user
}

// roleSourcesOf 讀出該帳號每個角色的來源
func roleSourcesOf(t *testing.T, db *gorm.DB, userID uint) map[string]string {
	t.Helper()
	type row struct {
		Name   string
		Source string
	}
	var rows []row
	if err := db.Table("user_roles").
		Select("roles.name AS name, user_roles.source AS source").
		Joins("JOIN roles ON roles.id = user_roles.role_id").
		Where("user_roles.user_id = ?", userID).Scan(&rows).Error; err != nil {
		t.Fatalf("讀取角色來源: %v", err)
	}
	out := map[string]string{}
	for _, r := range rows {
		out[r.Name] = r.Source
	}
	return out
}

// TestReplaceWithEffectiveSetKeepsSources 以**現行有效集**重送角色替換，
// 不得改變任何一列的來源（附錄 A 不變式 2）。
//
// 這是最容易犯的用法：讀取端回兩份集合，用戶端把它們併起來整包回送。
// 若那次回送把僅由映射賦予的角色升成並存（釘住）或把它刪掉，都是靜默的權限改動
// ——前者讓角色不再隨外部群組異動消失，後者當場刪光目錄給的授權。
func TestReplaceWithEffectiveSetKeepsSources(t *testing.T) {
	db, userService := setupRoleSourceEnv(t)
	user := seedRoleSourceUser(t, db, map[string]string{
		"admin":   model.RoleSourceManual,
		"auditor": model.RoleSourceMapped,
		"user":    model.RoleSourceBoth,
	})
	before := roleSourcesOf(t, db, user.ID)

	handler := &UserHandler{userService: userService}
	router := setupTestRouter()
	router.PUT("/users/:id/roles", handler.AssignRoles)

	// 有效集＝手動集聯集映射集＝三個角色全部
	body, _ := json.Marshal(map[string]any{"manual_roles": []string{"admin", "auditor", "user"}})
	req := httptest.NewRequest(http.MethodPut, "/users/1/roles", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "回應 = %s", w.Body.String())

	after := roleSourcesOf(t, db, user.ID)
	assert.Equal(t, before, after, "以現行有效集重送不得改變任何列的來源")

	// 被忽略的那一個要在揭露欄說出來（否則用戶端會以為它已被固定下來）
	var resp struct {
		Disclosures []struct {
			Code   string            `json:"code"`
			Params map[string]string `json:"params"`
		} `json:"disclosures"`
	}
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	if assert.Len(t, resp.Disclosures, 1, "僅由映射賦予的角色被忽略時要有揭露") {
		assert.Equal(t, "role.mapped_ignored", resp.Disclosures[0].Code)
		assert.Equal(t, "auditor", resp.Disclosures[0].Params["roles"])
	}

	// 世代不得被推進：這次請求什麼都沒撤除
	var epoch int64
	assert.NoError(t, db.Model(&model.User{}).Where("id = ?", user.ID).
		Select("credential_epoch").Scan(&epoch).Error)
	assert.Equal(t, int64(0), epoch, "純粹重送不得推進憑證世代")
}

// TestDiscoveryPreviewRequiresAdmin 探索預覽限管理權限。
//
// 這支端點能讓呼叫者要求系統對外發起連線，掛錯權限即等於把一支出站探測器
// 開給任何登入者。經完整 RegisterRoutes 驗鏈上的角色守門真的生效。
func TestDiscoveryPreviewRequiresAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// 世代閘現查 users（DB 未注入即 fail-close）：token 宣稱的兩個 ID 須存在
	installEpochGateDB(t, 1, 7)

	const secret = "discovery-preview-gate-secret"
	authService := identity.NewAuthService(secret, time.Minute)
	providers := identity.NewOIDCProviderService(database.DB, nil,
		&identity.OIDCEgressPolicy{}, nil, "https://bastion.example.com")
	handler := NewOIDCHandler(providers, nil, "https://bastion.example.com", nil)
	handler.SetIdentitySources(identity.NewIdentitySourceService(database.DB, audit.NewTxSink()))

	r := gin.New()
	handler.RegisterRoutes(r.Group("/api/v1"), authService)
	mgr := crypto.NewJWTManager(secret, time.Minute)

	post := func(token string) int {
		body, _ := json.Marshal(map[string]string{"issuer": "https://idp.example.com"})
		req := httptest.NewRequest(http.MethodPost,
			"/api/v1/oidc-providers/discovery-preview", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	assert.Equal(t, http.StatusUnauthorized, post(""), "未認證的請求不得到達探索預覽")

	userToken, err := mgr.GenerateToken(7, "normaluser", "u@example.com", "user", crypto.AuthContext{})
	assert.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, post(userToken), "非管理者不得到達探索預覽")

	// 對照組：管理者到得了 handler（此處的失敗來自撥不到那個 issuer，不是權限）
	adminToken, err := mgr.GenerateToken(1, "admin", "a@example.com", "admin", crypto.AuthContext{})
	assert.NoError(t, err)
	code := post(adminToken)
	assert.NotEqual(t, http.StatusForbidden, code, "管理者不應被權限擋下")
	assert.NotEqual(t, http.StatusUnauthorized, code, "管理者不應被認證擋下")
}
