package api

import (
	"bytes"
	"encoding/json"
	"fmt"
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
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupAccessReviewGateEnv 經完整 RegisterRoutes（真 AuthMiddleware＋真 JWT＋真 sqlite）
// 的複審路由環境。RegisterRoutes 已無權限旗標
// 參數——守門無條件成立（原 false 分支零守門，一般登入者可讀快照甚至偽造簽核）
func setupAccessReviewGateEnv(t *testing.T) (*gin.Engine, *crypto.JWTManager, *gorm.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	assert.NoError(t, err)
	assert.NoError(t, db.AutoMigrate(
		&model.User{}, &model.UserGroup{}, &model.Asset{}, &model.AssetGroup{},
		&model.AssetAuthorization{}, &model.AccessReview{}, &model.AuditLog{},
	))

	// AuthMiddleware 的憑證世代閘走 database.DB（fail-close：未注入即一律拒）。
	// 不注入時整組測試會全數 401，且「真 AuthMiddleware」這句宣稱只剩一半為真——
	// 世代閘那一半根本沒跑到
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	// token 的三個持有者須真的存在且啟用：世代閘現查 users.credential_epoch
	for id, name := range map[uint]string{1: "admin", 2: "normaluser", 3: "auditor1"} {
		u := &model.User{Username: name, Password: "x", Active: true}
		u.ID = id
		assert.NoError(t, db.Create(u).Error)
	}

	jwtSecret := "review-gate-secret"
	authService := identity.NewAuthService(jwtSecret, time.Minute)

	r := gin.New()
	group := r.Group("/api/v1")
	NewAccessReviewHandler(authz.NewAccessReviewService(db), nil).RegisterRoutes(group, authService)

	return r, crypto.NewJWTManager(jwtSecret, time.Minute), db
}

func reviewReq(t *testing.T, r *gin.Engine, method, path, token string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var buf *bytes.Buffer
	if body != nil {
		b, _ := json.Marshal(body)
		buf = bytes.NewBuffer(b)
	} else {
		buf = bytes.NewBuffer(nil)
	}
	req := httptest.NewRequest(method, path, buf)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// TestAccessReviewGate_UserDeniedUnconditionally 一般 user 對複審全部端點 403
// （守門為無條件註冊，權限旗標已退場——
// spec「權限開關關閉仍守門」由此結構性成立）
func TestAccessReviewGate_UserDeniedUnconditionally(t *testing.T) {
	r, mgr, _ := setupAccessReviewGateEnv(t)
	userToken, err := mgr.GenerateToken(2, "normaluser", "u@example.com", "user", crypto.AuthContext{})
	assert.NoError(t, err)

	for _, path := range []string{
		"/api/v1/access-reviews",
		"/api/v1/access-reviews/matrix",
		"/api/v1/access-reviews/1",
	} {
		w := reviewReq(t, r, http.MethodGet, path, userToken, nil)
		assert.Equal(t, http.StatusForbidden, w.Code, "user 對 %s 應 403，實得 %d", path, w.Code)
	}
	w := reviewReq(t, r, http.MethodPost, "/api/v1/access-reviews", userToken, map[string]string{"note": "forged"})
	assert.Equal(t, http.StatusForbidden, w.Code, "user 不得偽造簽核")
}

// TestAccessReviewGate_AuditorReadOnlySignDenied auditor 可讀（audit:view）、不可簽核
func TestAccessReviewGate_AuditorReadOnlySignDenied(t *testing.T) {
	r, mgr, _ := setupAccessReviewGateEnv(t)
	auditorToken, err := mgr.GenerateToken(3, "auditor1", "a@example.com", "auditor", crypto.AuthContext{})
	assert.NoError(t, err)

	w := reviewReq(t, r, http.MethodGet, "/api/v1/access-reviews", auditorToken, nil)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	// 週期與逾期伺服端單源回傳
	assert.Equal(t, float64(authz.ReviewPeriodDays), resp["review_period_days"])
	assert.Contains(t, resp, "overdue")

	w = reviewReq(t, r, http.MethodPost, "/api/v1/access-reviews", auditorToken, map[string]string{"note": "x"})
	assert.Equal(t, http.StatusForbidden, w.Code, "auditor 不得簽核（限 admin）")
}

// TestAccessReviewGate_AdminSignThenDetail admin 簽核後 detail 可回看型別化矩陣
func TestAccessReviewGate_AdminSignThenDetail(t *testing.T) {
	r, mgr, db := setupAccessReviewGateEnv(t)
	adminToken, err := mgr.GenerateToken(1, "admin", "adm@example.com", "admin", crypto.AuthContext{})
	assert.NoError(t, err)

	// 造一筆授權讓矩陣非空
	u := &model.User{Username: "u1", Password: "x", Email: emailPtr("u1@t.local"), Active: true}
	assert.NoError(t, db.Create(u).Error)
	a := &model.Asset{Name: "srv", Protocol: model.ProtocolSSH, Host: "h", Port: 22}
	assert.NoError(t, db.Create(a).Error)
	uid, aid := u.ID, a.ID
	assert.NoError(t, db.Create(&model.AssetAuthorization{
		UserID: &uid, AssetID: &aid, Permission: model.PermissionConnect, GrantedBy: 1,
	}).Error)

	w := reviewReq(t, r, http.MethodPost, "/api/v1/access-reviews", adminToken, map[string]string{"note": "季度複審"})
	assert.Equal(t, http.StatusCreated, w.Code)
	var created model.AccessReview
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))

	w = reviewReq(t, r, http.MethodGet, fmt.Sprintf("/api/v1/access-reviews/%d", created.ID), adminToken, nil)
	assert.Equal(t, http.StatusOK, w.Code)
	var detail map[string]interface{}
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &detail))
	assert.Equal(t, "季度複審", detail["note"])
	matrix, ok := detail["matrix"].([]interface{})
	assert.True(t, ok, "matrix 應為陣列")
	assert.Equal(t, 1, len(matrix))

	// 不存在 404
	w = reviewReq(t, r, http.MethodGet, "/api/v1/access-reviews/9999", adminToken, nil)
	assert.Equal(t, http.StatusNotFound, w.Code)
}
