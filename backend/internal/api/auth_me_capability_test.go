package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// capabilityMeEnv 經完整 RegisterRoutes（真 AuthMiddleware＋真 JWT＋sqlite＋權限模型三張新表）
// 的 /auth/me 環境。
type capabilityMeEnv struct {
	r    *gin.Engine
	auth *identity.AuthService
	db   *gorm.DB
	jwt  *crypto.JWTManager
}

func setupCapabilityMeEnv(t *testing.T) *capabilityMeEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&model.User{}, &model.Role{}, &model.UserGroup{}, &model.UserGroupMember{}, &model.Asset{},
		&model.AssetAuthorization{}, &model.ApproverScope{}, &model.AuditLog{}, &model.UserRole{},
		&model.UserGroupRole{}, &model.RoleBindingNode{}, &model.AuthzState{}, &model.AssetGroup{}))
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	secret := "me-capability-secret"
	auth := identity.NewAuthService(secret, time.Minute)
	r := gin.New()
	h := NewAuthHandler(auth, nil)
	h.SetSourcePolicyReader(unrestrictedSourcePolicy())
	h.RegisterRoutes(r.Group("/api/v1"), auth)
	return &capabilityMeEnv{r: r, auth: auth, db: db, jwt: crypto.NewJWTManager(secret, time.Minute)}
}

// seedUser 建使用者並指派內建角色（builtinKey 對應 model.Builtin*，空字串＝零角色）。
func (e *capabilityMeEnv) seedUser(t *testing.T, name, roleName, builtinKey string) (*model.User, string) {
	t.Helper()
	u := &model.User{Username: name, FullName: name + " Full", Email: emailPtr(name + "@x"), Active: true}
	require.NoError(t, e.db.Create(u).Error)
	if builtinKey != "" {
		var role model.Role
		if err := e.db.Where("name = ?", roleName).First(&role).Error; err != nil {
			k := builtinKey
			role = model.Role{Name: roleName, BuiltinKey: &k}
			require.NoError(t, e.db.Create(&role).Error)
		}
		require.NoError(t, e.db.Create(&model.UserRole{UserID: u.ID, RoleID: role.ID,
			Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
	}
	tok, err := e.jwt.GenerateToken(u.ID, u.Username, name+"@x", "user", crypto.AuthContext{})
	require.NoError(t, err)
	return u, tok
}

func (e *capabilityMeEnv) do(method, body, token string) *httptest.ResponseRecorder {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, "/api/v1/auth/me", nil)
	} else {
		req = httptest.NewRequest(method, "/api/v1/auth/me", stringsReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	e.r.ServeHTTP(w, req)
	return w
}

func decodeMap(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m), string(b))
	return m
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// legacyBody 目前使用者「加投影之前」的回應形狀：UserInfo 本體的 JSON（登入回應共用的同一型別）。
func (e *capabilityMeEnv) legacyBody(t *testing.T, uid uint) map[string]any {
	t.Helper()
	info, err := e.auth.GetUserByID(uid)
	require.NoError(t, err)
	b, err := json.Marshal(info)
	require.NoError(t, err)
	return decodeMap(t, b)
}

// TestCurrentUserLegacyFields 擋：投影欄位擴大到共用 UserInfo 或錯誤回應、舊欄位被改動或消失、
// GET／PATCH 的 source_ip 語義走樣。
func TestCurrentUserLegacyFields(t *testing.T) {
	env := setupCapabilityMeEnv(t)
	admin, adminTok := env.seedUser(t, "ada", "admin", model.BuiltinSuperAdmin)
	plain, plainTok := env.seedUser(t, "bob", "user", model.BuiltinUser)
	zero, zeroTok := env.seedUser(t, "zed", "", "")
	extra := []string{"permissions", "scope_summary"}

	t.Run("GET 成功：僅多兩欄，其餘與 UserInfo 逐一相同並保留 source_ip", func(t *testing.T) {
		for _, c := range []struct {
			name string
			u    *model.User
			tok  string
		}{{"超管", admin, adminTok}, {"一般使用者", plain, plainTok}, {"零角色", zero, zeroTok}} {
			w := env.do(http.MethodGet, "", c.tok)
			require.Equal(t, http.StatusOK, w.Code, c.name+w.Body.String())
			body := decodeMap(t, w.Body.Bytes())
			require.Contains(t, body, "permissions", c.name)
			require.Contains(t, body, "scope_summary", c.name)
			assert.IsType(t, []any{}, body["permissions"], c.name)
			assert.IsType(t, []any{}, body["scope_summary"], c.name)
			src, ok := body["source_ip"].(string)
			assert.True(t, ok && src != "", c.name+": GET 保留 source_ip")
			for _, k := range extra {
				delete(body, k)
			}
			want := env.legacyBody(t, c.u.ID)
			want["source_ip"] = src
			assert.Equal(t, want, body, c.name+": 去除新增欄後與舊形狀相同")
		}
	})

	t.Run("GET 成功：欄位集合與權限決策基準凍結的舊欄位集合相同（讀自 golden，不手寫）", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join("..", "..", "cmd", "server", "testdata", "authz-baseline", "subjects-auth-me.json"))
		require.NoError(t, err)
		var golden map[string]struct {
			Status int            `json:"status"`
			Body   map[string]any `json:"body"`
		}
		require.NoError(t, json.Unmarshal(raw, &golden))
		var frozen []string
		seen := 0
		for _, g := range golden {
			if g.Status != http.StatusOK {
				continue
			}
			seen++
			keys := sortedKeys(g.Body)
			if frozen == nil {
				frozen = keys
			}
			require.Equal(t, frozen, keys, "golden 內各主體的舊欄位集合應一致")
		}
		require.NotZero(t, seen, "golden 必須含成功回應")
		// product_version 由完整伺服器啟動時注入，這個測試環境不帶；其餘欄位一律逐一對齊。
		require.Contains(t, frozen, "product_version")
		var comparable []string
		for _, k := range frozen {
			if k != "product_version" {
				comparable = append(comparable, k)
			}
		}
		for _, c := range []struct {
			name string
			tok  string
		}{{"超管", adminTok}, {"一般使用者", plainTok}, {"零角色", zeroTok}} {
			w := env.do(http.MethodGet, "", c.tok)
			require.Equal(t, http.StatusOK, w.Code, c.name)
			body := decodeMap(t, w.Body.Bytes())
			for _, k := range extra {
				delete(body, k)
			}
			assert.Equal(t, comparable, sortedKeys(body), c.name+": 去除新增欄後，鍵集合須等於授權基準 golden")
		}
	})

	t.Run("PATCH 成功：僅多兩欄，source_ip 維持省略", func(t *testing.T) {
		w := env.do(http.MethodPatch, `{"local_display_name":"小波"}`, plainTok)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		body := decodeMap(t, w.Body.Bytes())
		require.Contains(t, body, "permissions")
		require.Contains(t, body, "scope_summary")
		assert.NotContains(t, body, "source_ip", "PATCH 原本不填來源位址")
		for _, k := range extra {
			delete(body, k)
		}
		assert.Equal(t, env.legacyBody(t, plain.ID), body)
		assert.Equal(t, "小波", body["display_name"])
	})

	t.Run("投影內容取自伺服器解析而非 token 角色", func(t *testing.T) {
		// token 宣稱 admin，資料庫只有一般使用者指派：回應不得出現管理能力
		forged, err := env.jwt.GenerateToken(plain.ID, plain.Username, "bob@x", "admin", crypto.AuthContext{})
		require.NoError(t, err)
		w := env.do(http.MethodGet, "", forged)
		require.Equal(t, http.StatusOK, w.Code)
		body := decodeMap(t, w.Body.Bytes())
		assert.ElementsMatch(t, []any{"asset:view", "ui:self-service-actions"}, body["permissions"].([]any))
		assert.NotContains(t, body["permissions"], "user:manage")

		w = env.do(http.MethodGet, "", adminTok)
		adminPerms := decodeMap(t, w.Body.Bytes())["permissions"].([]any)
		assert.Contains(t, adminPerms, "user:manage")
		assert.Contains(t, adminPerms, "ui:connect-bypass")
		assert.Contains(t, adminPerms, "ui:super-admin")
		assert.NotContains(t, adminPerms, "ui:approvals", "admin 不因管理者身分取得審核點")
	})

	t.Run("錯誤回應不多欄位", func(t *testing.T) {
		for _, c := range []struct {
			name, method, body, tok string
			code                    int
		}{
			{"GET 未認證", http.MethodGet, "", "", http.StatusUnauthorized},
			{"PATCH 缺欄", http.MethodPatch, `{}`, plainTok, http.StatusBadRequest},
			{"PATCH 型別錯誤", http.MethodPatch, `{"local_display_name":7}`, plainTok, http.StatusBadRequest},
		} {
			w := env.do(c.method, c.body, c.tok)
			assert.Equal(t, c.code, w.Code, c.name)
			body := decodeMap(t, w.Body.Bytes())
			assert.NotContains(t, body, "permissions", c.name)
			assert.NotContains(t, body, "scope_summary", c.name)
		}
		require.NoError(t, env.db.Model(&model.User{}).Where("id = ?", zero.ID).Update("active", false).Error)
		w := env.do(http.MethodPatch, `{"local_display_name":"x"}`, zeroTok)
		assert.Equal(t, http.StatusForbidden, w.Code, "停用帳號沿用原拒絕")
		assert.NotContains(t, decodeMap(t, w.Body.Bytes()), "permissions")
	})

	t.Run("共用 UserInfo 本體不含新欄位", func(t *testing.T) {
		b, err := json.Marshal(identity.UserInfo{})
		require.NoError(t, err)
		keys := sortedKeys(decodeMap(t, b))
		assert.NotContains(t, keys, "permissions")
		assert.NotContains(t, keys, "scope_summary")
		info, err := env.auth.GetUserByID(admin.ID)
		require.NoError(t, err)
		b, _ = json.Marshal(info)
		assert.NotContains(t, sortedKeys(decodeMap(t, b)), "permissions", "登入、MFA、續期、改密共用的組裝點輸出不變")
	})

	t.Run("解析失敗回原查詢失敗的錯誤，不回舊角色推估值", func(t *testing.T) {
		require.NoError(t, env.db.Exec("DROP TABLE user_group_roles").Error)
		w := env.do(http.MethodGet, "", plainTok)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		body := decodeMap(t, w.Body.Bytes())
		assert.NotContains(t, body, "permissions")
		assert.NotContains(t, body, "roles")
		// PATCH 在寫入之前就失敗：顯示名不得被改動
		w = env.do(http.MethodPatch, `{"local_display_name":"不應寫入"}`, plainTok)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		var got model.User
		require.NoError(t, env.db.First(&got, plain.ID).Error)
		require.NotNil(t, got.LocalDisplayName)
		assert.Equal(t, "小波", *got.LocalDisplayName, "解析失敗時尚未產生任何副作用")
	})
}

func stringsReader(s string) *strings.Reader { return strings.NewReader(s) }
