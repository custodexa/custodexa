package api

import (
	"bytes"
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
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupUpdateMeEnv 經完整 RegisterRoutes（真 AuthMiddleware＋真 JWT＋sqlite）的
// PATCH /auth/me 環境。AuthService 走全域 database.DB，故置換之。
func setupUpdateMeEnv(t *testing.T) (*gin.Engine, *crypto.JWTManager, *gorm.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	assert.NoError(t, err)
	assert.NoError(t, db.AutoMigrate(
		&model.User{}, &model.Role{}, &model.UserGroup{}, &model.Asset{},
		&model.AssetAuthorization{}, &model.ApproverScope{}, &model.AuditLog{},
	))
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	secret := "update-me-secret"
	authService := identity.NewAuthService(secret, time.Minute)
	r := gin.New()
	group := r.Group("/api/v1")
	NewAuthHandler(authService, nil).RegisterRoutes(group, authService)
	return r, crypto.NewJWTManager(secret, time.Minute), db
}

func patchMe(t *testing.T, r *gin.Engine, token string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/auth/me", bytes.NewBuffer(b))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// TestUpdateMe_OnlyDisplayNameWritable 惡意 body 夾帶 full_name/email/role/username/id
// 一律被忽略，只有 local_display_name 生效（profile-display-name R1 白名單＋身分綁定）
func TestUpdateMe_OnlyDisplayNameWritable(t *testing.T) {
	r, mgr, db := setupUpdateMeEnv(t)
	u := &model.User{Username: "alice", FullName: "Alice Wang", Email: emailPtr("a@x"), Active: true}
	assert.NoError(t, db.Create(u).Error)
	token, err := mgr.GenerateToken(u.ID, u.Username, "a@x", "user", crypto.AuthContext{})
	assert.NoError(t, err)

	w := patchMe(t, r, token, map[string]interface{}{
		"local_display_name": "小王",
		"full_name":          "HACKED",
		"email":              "evil@x",
		"role":               "admin",
		"username":           "root",
		"is_ldap":            true,
		"id":                 9999,
	})
	assert.Equal(t, http.StatusOK, w.Code)

	var info identity.UserInfo
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &info))
	// 只有顯示名生效
	assert.Equal(t, "小王", info.DisplayName)
	assert.Equal(t, u.ID, info.ID, "身分綁定：更新回應必為 token 使用者本人")
	// 正式身分全未被污染
	assert.Equal(t, "Alice Wang", info.FullName)
	assert.Equal(t, "a@x", info.Email)
	assert.Equal(t, "alice", info.Username)

	// DB 落地：只有本人 local_display_name 改動，正式身分不變
	var reloaded model.User
	assert.NoError(t, db.First(&reloaded, u.ID).Error)
	assert.NotNil(t, reloaded.LocalDisplayName)
	assert.Equal(t, "小王", *reloaded.LocalDisplayName)
	assert.Equal(t, "Alice Wang", reloaded.FullName)
	assert.Equal(t, "a@x", reloaded.EmailString())
	// body 帶的 id=9999 未造出任何帳號
	var count int64
	db.Model(&model.User{}).Count(&count)
	assert.Equal(t, int64(1), count)
}

// TestUpdateMe_Clear 空字串清除為 NULL，回退 full_name
func TestUpdateMe_Clear(t *testing.T) {
	r, mgr, db := setupUpdateMeEnv(t)
	pre := "舊名"
	u := &model.User{Username: "bob", FullName: "Bob Lee", Email: emailPtr("b@x"), Active: true, LocalDisplayName: &pre}
	assert.NoError(t, db.Create(u).Error)
	token, _ := mgr.GenerateToken(u.ID, u.Username, "b@x", "user", crypto.AuthContext{})

	w := patchMe(t, r, token, map[string]interface{}{"local_display_name": ""})
	assert.Equal(t, http.StatusOK, w.Code)
	var info identity.UserInfo
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &info))
	assert.Nil(t, info.LocalDisplayName)
	assert.Equal(t, "Bob Lee", info.DisplayName)
}

// TestUpdateMe_InvalidRejected 超長/控制字元回 400
func TestUpdateMe_InvalidRejected(t *testing.T) {
	r, mgr, db := setupUpdateMeEnv(t)
	u := &model.User{Username: "carol", Email: emailPtr("c@x"), Active: true}
	assert.NoError(t, db.Create(u).Error)
	token, _ := mgr.GenerateToken(u.ID, u.Username, "c@x", "user", crypto.AuthContext{})

	w := patchMe(t, r, token, map[string]interface{}{"local_display_name": "bad\nname"})
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestUpdateMe_MissingFieldNotCleared 缺 local_display_name 欄位的 body（如惡意只帶
// full_name，或空 body）回 400，且不得意外清除既有顯示名（codex round-2 抓到的清除 bug）
func TestUpdateMe_MissingFieldNotCleared(t *testing.T) {
	r, mgr, db := setupUpdateMeEnv(t)
	pre := "既有顯示名"
	u := &model.User{Username: "dee", Email: emailPtr("d@x"), Active: true, LocalDisplayName: &pre}
	assert.NoError(t, db.Create(u).Error)
	token, _ := mgr.GenerateToken(u.ID, u.Username, "d@x", "user", crypto.AuthContext{})

	for _, body := range []map[string]interface{}{
		{"full_name": "HACKED"}, // 只帶其他欄位
		{},                      // 空 body
	} {
		w := patchMe(t, r, token, body)
		assert.Equal(t, http.StatusBadRequest, w.Code, "缺欄 body %v 應回 400", body)
	}
	// 顯示名未被清除
	var reloaded model.User
	assert.NoError(t, db.First(&reloaded, u.ID).Error)
	assert.NotNil(t, reloaded.LocalDisplayName, "缺欄 body 不得清除既有顯示名")
	assert.Equal(t, "既有顯示名", *reloaded.LocalDisplayName)
}

// TestUpdateMe_NullClears 顯式 null 清除為 NULL（回退 full_name/username）
func TestUpdateMe_NullClears(t *testing.T) {
	r, mgr, db := setupUpdateMeEnv(t)
	pre := "舊名"
	u := &model.User{Username: "eve", FullName: "Eve Wang", Email: emailPtr("e@x"), Active: true, LocalDisplayName: &pre}
	assert.NoError(t, db.Create(u).Error)
	token, _ := mgr.GenerateToken(u.ID, u.Username, "e@x", "user", crypto.AuthContext{})

	w := patchMe(t, r, token, map[string]interface{}{"local_display_name": nil})
	assert.Equal(t, http.StatusOK, w.Code)
	var info identity.UserInfo
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &info))
	assert.Nil(t, info.LocalDisplayName)
	assert.Equal(t, "Eve Wang", info.DisplayName)
}
