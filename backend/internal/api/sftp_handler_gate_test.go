package api

import (
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/policy"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestSFTPUnauthorizedReturns404 未授權檔案端點回 404「資產不存在」語義
// 與逐資產守門一致，不洩漏資產存在性；
// 拒絕發生在任何 SFTP 連線建立之前（sftpService 為 nil 仍安全通過即為證）
func TestSFTPUnauthorizedReturns404(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.UserGroup{}, &model.Asset{}, &model.AssetGroup{}, &model.AssetNode{},
		&model.AssetAuthorization{}, &model.ApproverScope{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db.Create(&model.User{Username: "u1", Email: emailPtr("u@x"), Active: true})
	db.Create(&model.Asset{Name: "a1", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1})

	handler := NewSFTPHandler(nil, authz.NewAssetAuthorizationService(db), nil, newSFTPTestAuthService(t, db))

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/assets/:id/files", func(c *gin.Context) {
		c.Set("userID", uint(1))
		c.Set("role", model.RoleUser)
		handler.List(c)
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/assets/1/files?path=/tmp", nil))

	if w.Code != http.StatusNotFound {
		t.Fatalf("未授權應回 404（不洩漏存在性）, got %d body=%s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); !strings.Contains(body, "資產不存在") {
		t.Fatalf("回應語義應為資產不存在: %s", body)
	}
}

// TestSFTPPolicyGateBlocksStandingConnect 檔案資料面同套政策閘：
// approval 段位資產上，持常設 connect 但無有效 ticket 者，檔案端點須被擋（404），
// 不可繞過強制審核直接傳檔
func TestSFTPPolicyGateBlocksStandingConnect(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.UserGroup{}, &model.Asset{}, &model.AssetGroup{}, &model.AssetNode{},
		&model.AssetAuthorization{}, &model.ApproverScope{}, &model.AccessRequest{},
		&model.SecurityPolicy{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db.Create(&model.User{Username: "u1", Email: emailPtr("u@x"), Active: true})
	approval := model.AccessPolicyApproval
	db.Create(&model.Asset{Name: "a1", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1, AccessPolicy: &approval})
	// 常設 connect（非核准流來源）
	uid, aid := uint(1), uint(1)
	db.Create(&model.AssetAuthorization{
		UserID: &uid, AssetID: &aid, Permission: model.PermissionConnect, GrantedBy: 1,
	})

	authzSvc := authz.NewAssetAuthorizationService(db)
	handler := NewSFTPHandler(nil, authzSvc, nil, newSFTPTestAuthService(t, db))
	handler.SetAccessPolicy(policy.NewAccessPolicyService(db, policy.NewSecurityPolicyService(db), authzSvc))

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/assets/:id/files", func(c *gin.Context) {
		c.Set("userID", uint(1))
		c.Set("role", model.RoleUser)
		handler.List(c)
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/assets/1/files?path=/tmp", nil))

	// 政策閘須在任何 SFTP 連線建立前擋下（sftpService 為 nil 仍安全＝證明未觸及資料面）
	if w.Code != http.StatusNotFound {
		t.Fatalf("approval 段位常設 connect 應被政策閘擋（404）, got %d body=%s", w.Code, w.Body.String())
	}
}

// TestSFTPPolicyGateAllowsTicket approval 段位持有效 ticket 者通過政策閘
// （通過後觸及 nil sftpService 會 panic，故以 recover 確認「已通過閘、進入資料面」）
func TestSFTPPolicyGateAllowsTicket(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.UserGroup{}, &model.Asset{}, &model.AssetGroup{}, &model.AssetNode{},
		&model.AssetAuthorization{}, &model.ApproverScope{}, &model.AccessRequest{},
		&model.SecurityPolicy{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db.Create(&model.User{Username: "u1", Email: emailPtr("u@x"), Active: true})
	approval := model.AccessPolicyApproval
	db.Create(&model.Asset{Name: "a1", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1, AccessPolicy: &approval})
	uid, aid := uint(1), uint(1)
	start := time.Now().Add(-time.Minute)
	expired := time.Now().Add(time.Hour)
	db.Create(&model.AssetAuthorization{
		UserID: &uid, AssetID: &aid, Permission: model.PermissionConnect, GrantedBy: 1,
		Source: model.AuthorizationSourceTicket, DateStart: &start, DateExpired: &expired,
	})

	authzSvc := authz.NewAssetAuthorizationService(db)
	handler := NewSFTPHandler(nil, authzSvc, nil, newSFTPTestAuthService(t, db))
	handler.SetAccessPolicy(policy.NewAccessPolicyService(db, policy.NewSecurityPolicyService(db), authzSvc))

	gin.SetMode(gin.TestMode)
	r := gin.New()
	passedGate := false
	r.GET("/assets/:id/files", func(c *gin.Context) {
		defer func() {
			// 通過政策閘後觸及 nil sftpService 會 panic——捕捉即證明閘已放行
			if recover() != nil {
				passedGate = true
			}
		}()
		c.Set("userID", uint(1))
		c.Set("role", model.RoleUser)
		handler.List(c)
	})
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/assets/1/files?path=/tmp", nil))

	if !passedGate {
		t.Fatal("有效 ticket 應通過政策閘進入資料面")
	}
}
