package api

import (
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
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// GET /api/v1/users/local-admin-count（oidc-ops-hygiene B10 / design D1）。
//
// 守三件事：admin 才讀得到（唯讀但仍是安全姿態的情報）、計數正確、且**與
// identity.CountLocalAdmins 逐值一致**——後者是本端點存在的全部意義：管理端
// 警示若自寫查詢，會與不變式的拒絕判準漂移（「擋你的條件」≠「告訴你的條件」）。

// setupLocalAdminCountEnv 經完整 RegisterRoutes（真 AuthMiddleware＋真 RequireRole
// ＋真 UserService＋sqlite）的環境，非 mock：一致性斷言必須打到真查詢。
func setupLocalAdminCountEnv(t *testing.T) (*gin.Engine, *crypto.JWTManager, *gorm.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	assert.NoError(t, err)
	assert.NoError(t, db.AutoMigrate(&model.User{}, &model.Role{}, &model.AuditLog{}))

	// AuthMiddleware 的憑證世代閘現查 database.DB（未注入即全數 401）
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	adminRole := &model.Role{Name: model.RoleAdmin, Description: "管理員"}
	assert.NoError(t, db.Create(adminRole).Error)

	r := gin.New()
	group := r.Group("/api/v1")
	NewUserHandler(identity.NewUserService(db, authz.NewAssetAuthorizationService(db))).RegisterRoutes(group,
		identity.NewAuthService("local-admin-count-secret", time.Minute))

	return r, crypto.NewJWTManager("local-admin-count-secret", time.Minute), db
}

// createLocalAdmin 建立一個計為「本地 admin」的帳號（啟用、有 admin 角色、
// 密碼非空、未外部化）。alter 可就地破壞其中一個條件
func createLocalAdmin(t *testing.T, db *gorm.DB, username string, alter func(*model.User)) *model.User {
	t.Helper()
	u := &model.User{
		Username:           username,
		Password:           "hashed-secret",
		Active:             true,
		ProvisioningOrigin: model.AuthSourceLocal,
	}
	if alter != nil {
		alter(u)
	}
	assert.NoError(t, db.Create(u).Error)
	var role model.Role
	assert.NoError(t, db.Where("name = ?", model.RoleAdmin).First(&role).Error)
	assert.NoError(t, db.Model(u).Association("Roles").Append(&role))
	return u
}

func getLocalAdminCount(t *testing.T, r *gin.Engine, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/local-admin-count", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// TestLocalAdminCount_AdminReadsCount admin 讀得到，且數字是「本地 admin」的定義
// （外部化／停用的 admin 不計入，證明端點不是在數 admin 角色）
func TestLocalAdminCount_AdminReadsCount(t *testing.T) {
	r, mgr, db := setupLocalAdminCountEnv(t)

	admin := createLocalAdmin(t, db, "admin", nil)
	createLocalAdmin(t, db, "admin2", nil)
	createLocalAdmin(t, db, "ssoadmin", func(u *model.User) {
		u.ExternalCredential = true
		u.ProvisioningOrigin = "oidc"
	})
	// Active 有 DB default:true，零值會被 gorm 略過 → 停用須顯式更新
	disabled := createLocalAdmin(t, db, "disabledadmin", nil)
	assert.NoError(t, db.Model(disabled).Update("active", false).Error)

	token, err := mgr.GenerateToken(admin.ID, admin.Username, "admin@example.com", "admin", crypto.AuthContext{})
	assert.NoError(t, err)

	w := getLocalAdminCount(t, r, token)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Count int64 `json:"count"`
	}
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, int64(2), resp.Count, "只有啟用且未外部化的本地 admin 計入")
}

// TestLocalAdminCount_NonAdminForbidden 非 admin 一律 403（唯讀不等於公開）
func TestLocalAdminCount_NonAdminForbidden(t *testing.T) {
	r, mgr, db := setupLocalAdminCountEnv(t)
	createLocalAdmin(t, db, "admin", nil)

	normal := &model.User{Username: "operator", Password: "x", Active: true}
	assert.NoError(t, db.Create(normal).Error)
	for _, role := range []string{"user", "auditor"} {
		token, err := mgr.GenerateToken(normal.ID, normal.Username, "u@example.com", role, crypto.AuthContext{})
		assert.NoError(t, err)
		w := getLocalAdminCount(t, r, token)
		assert.Equal(t, http.StatusForbidden, w.Code, "role=%s 應 403，實得 %d", role, w.Code)
	}
}

// TestLocalAdminCount_MatchesInvariantSource 端點回值逐值等於直接呼叫
// identity.CountLocalAdmins——單一事實源的守衛：改成自寫查詢即紅
func TestLocalAdminCount_MatchesInvariantSource(t *testing.T) {
	r, mgr, db := setupLocalAdminCountEnv(t)

	admin := createLocalAdmin(t, db, "admin", nil)
	token, err := mgr.GenerateToken(admin.ID, admin.Username, "admin@example.com", "admin", crypto.AuthContext{})
	assert.NoError(t, err)

	assertMatches := func(stage string) {
		want, err := identity.CountLocalAdmins(db)
		assert.NoError(t, err)
		w := getLocalAdminCount(t, r, token)
		assert.Equal(t, http.StatusOK, w.Code)
		var resp struct {
			Count int64 `json:"count"`
		}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, want, resp.Count, "%s：端點計數應等於 CountLocalAdmins", stage)
	}

	assertMatches("初始")

	createLocalAdmin(t, db, "admin2", nil)
	assertMatches("新增一名本地 admin")

	// 空密碼列（旗標未外部化但無法以本地密碼登入）：不變式刻意不計入，
	// 端點必須同步不計入，否則「1→0」會被誤呈現為安全的「2→1」
	createLocalAdmin(t, db, "blankpw", func(u *model.User) { u.Password = "" })
	assertMatches("空密碼 admin 不計入")
}
