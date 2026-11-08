package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 檔案端點與傳輸能力查詢端點在授權判定之前套用使用者的來源網段限制：
// 清單外來源回 403 AUTH_SOURCE_NOT_ALLOWED、留 denied 審計、不觸及遠端；
// 對存在與不存在的資產回應相同。
//
// sftpService 為 nil：越過來源閘而抵達遠端呼叫階段的請求會 panic，
// 由 Recovery 轉成 500，斷言以此辨識「閘沒有擋住」。

const (
	sftpGateOutside = "10.0.0.0/8"
	sftpGateInside  = "203.0.113.0/24"
)

type sftpGateEnv struct {
	r  *gin.Engine
	db *gorm.DB
}

func setupSFTPSourceGateEnv(t *testing.T) *sftpGateEnv {
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
	if err := migrateWithAuthz(db, &model.User{}, &model.Role{}, &model.UserGroup{}, &model.Asset{}, &model.AssetGroup{}, &model.AssetNode{},
		&model.AssetAuthorization{}, &model.ApproverScope{}, &model.AuditLog{}, &model.UserRole{}, &model.UserGroupMember{},
		&model.UserGroupRole{}, &model.RoleBindingNode{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for _, name := range []string{model.RoleUser, model.RoleAdmin, model.RoleAuditor} {
		if err := db.Create(&model.Role{Name: name}).Error; err != nil {
			t.Fatalf("seed role: %v", err)
		}
	}
	prev := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = prev })

	// 使用者 1：一般使用者，對資產 1 有連線授權；使用者 2：admin
	db.Create(&model.User{Username: "u1", Email: emailPtr("u1@x"), Active: true})
	db.Create(&model.User{Username: "adm", Email: emailPtr("adm@x"), Active: true,
		Roles: []model.Role{{ID: 2, Name: model.RoleAdmin}}})
	db.Create(&model.Asset{Name: "a1", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1})
	uid, aid := uint(1), uint(1)
	db.Create(&model.AssetAuthorization{UserID: &uid, AssetID: &aid, Permission: model.PermissionConnect, GrantedBy: 1})

	auditSvc := audit.NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false,
	})
	h := NewSFTPHandler(nil, authz.NewAssetAuthorizationService(db), auditSvc, newSFTPTestAuthService(t, db))

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(gin.Recovery())
	as := func(fn gin.HandlerFunc) gin.HandlerFunc {
		return func(c *gin.Context) {
			if c.Query("as") == model.RoleAdmin {
				c.Set("userID", uint(2))
				c.Set("username", "adm")
				middleware.SetPrincipal(c, legacyPrincipal(model.RoleAdmin))
			} else {
				c.Set("userID", uint(1))
				c.Set("username", "u1")
				middleware.SetPrincipal(c, legacyPrincipal(model.RoleUser))
			}
			fn(c)
		}
	}
	r.GET("/assets/:id/files", as(h.List))
	r.GET("/assets/:id/files/download", as(h.Download))
	r.POST("/assets/:id/files/upload", as(h.Upload))
	r.POST("/assets/:id/files/mkdir", as(h.Mkdir))
	r.DELETE("/assets/:id/files", as(h.Delete))
	r.GET("/assets/:id/transfer-capabilities", as(h.TransferCapabilities))
	return &sftpGateEnv{r: r, db: db}
}

func (e *sftpGateEnv) setAllowed(t *testing.T, userID uint, raw string) {
	t.Helper()
	if err := e.db.Model(&model.User{}).Where("id = ?", userID).Update("allowed_cidrs", raw).Error; err != nil {
		t.Fatalf("set allowed_cidrs: %v", err)
	}
}

func (e *sftpGateEnv) do(method, target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.5:41000"
	w := httptest.NewRecorder()
	e.r.ServeHTTP(w, req)
	return w
}

func (e *sftpGateEnv) deniedAuditCount(action model.AuditAction) int64 {
	var n int64
	e.db.Model(&model.AuditLog{}).Where("action = ? AND status = ?", action, model.StatusDenied).Count(&n)
	return n
}

func sftpGateCode(w *httptest.ResponseRecorder) string {
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	code, _ := resp["code"].(string)
	return code
}

type sftpGateEndpoint struct {
	name   string
	method string
	path   string
	action model.AuditAction
}

func sftpGateEndpoints(assetID string) []sftpGateEndpoint {
	return []sftpGateEndpoint{
		{"list", http.MethodGet, "/assets/" + assetID + "/files?path=/tmp", model.ActionFileList},
		{"upload", http.MethodPost, "/assets/" + assetID + "/files/upload?path=/tmp/x", model.ActionFileUpload},
		{"download", http.MethodGet, "/assets/" + assetID + "/files/download?path=/tmp/x", model.ActionFileDownload},
		{"mkdir", http.MethodPost, "/assets/" + assetID + "/files/mkdir", model.ActionFileMkdir},
		{"delete", http.MethodDelete, "/assets/" + assetID + "/files?path=/tmp/x", model.ActionFileDelete},
		{"capability", http.MethodGet, "/assets/" + assetID + "/transfer-capabilities", model.ActionFileList},
	}
}

func TestSFTPSourceGate_OutsideSourceDenied(t *testing.T) {
	for _, ep := range sftpGateEndpoints("1") {
		ep := ep
		t.Run(ep.name, func(t *testing.T) {
			e := setupSFTPSourceGateEnv(t)
			e.setAllowed(t, 1, sftpGateOutside)

			w := e.do(ep.method, ep.path)

			if w.Code != http.StatusForbidden || sftpGateCode(w) != "AUTH_SOURCE_NOT_ALLOWED" {
				t.Fatalf("清單外來源應回 403 AUTH_SOURCE_NOT_ALLOWED，實得 %d code=%q（500 代表已越過閘抵達遠端呼叫階段）body=%s",
					w.Code, sftpGateCode(w), w.Body.String())
			}
			for _, leak := range []string{"203.0.113.5", "10.0.0.0"} {
				if strings.Contains(w.Body.String(), leak) {
					t.Fatalf("回應不得回顯位址與清單：%s", w.Body.String())
				}
			}
			if n := e.deniedAuditCount(ep.action); n != 1 {
				t.Fatalf("action=%s 的 denied 審計 = %d 筆，want 1", ep.action, n)
			}
		})
	}
}

// 不存在的資產：清單外來源（含 admin）回應與存在的資產相同。
func TestSFTPSourceGate_OutsideSourceNonexistentAsset(t *testing.T) {
	for _, who := range []string{model.RoleUser, model.RoleAdmin} {
		who := who
		t.Run(who, func(t *testing.T) {
			e := setupSFTPSourceGateEnv(t)
			e.setAllowed(t, 1, sftpGateOutside)
			e.setAllowed(t, 2, sftpGateOutside)

			w := e.do(http.MethodGet, "/assets/9999/files?path=/tmp&as="+who)

			if w.Code != http.StatusForbidden || sftpGateCode(w) != "AUTH_SOURCE_NOT_ALLOWED" {
				t.Fatalf("不存在資產在清單外來源應回 403 AUTH_SOURCE_NOT_ALLOWED，實得 %d code=%q", w.Code, sftpGateCode(w))
			}
		})
	}
}

// 回歸：清單內來源與無清單使用者不受影響，後續閘照舊（不存在資產回 404）。
func TestSFTPSourceGate_AllowedSourceUnaffected(t *testing.T) {
	for name, raw := range map[string]string{"inside_list": sftpGateInside, "no_list": ""} {
		raw := raw
		t.Run(name, func(t *testing.T) {
			e := setupSFTPSourceGateEnv(t)
			e.setAllowed(t, 1, raw)

			w := e.do(http.MethodGet, "/assets/9999/files?path=/tmp")

			if w.Code != http.StatusNotFound {
				t.Fatalf("放行來源後應回既有的 404，實得 %d body=%s", w.Code, w.Body.String())
			}
		})
	}
}
