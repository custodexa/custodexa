package sshproxy

import (
	"bytes"
	"encoding/json"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupPolicyGateTest 政策閘全鏈測試（真 SQLite）：閘的段位×身分矩陣與閘序
// 必須經 HandleCreateConnectToken 實際執行驗證——閘位置（授權後、傳輸閘前）
// 是閘序的核心語義，單測 service 驗不了順序
func setupPolicyGateTest(t *testing.T) (*Handler, *gorm.DB, *policy.SecurityPolicyService) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserGroup{}, &model.Asset{}, &model.AssetAccount{}, &model.AssetGroup{}, &model.AssetNode{},
		&model.AssetAuthorization{}, &model.AccessRequest{}, &model.SecurityPolicy{},
		&model.TransmissionConsent{}, &model.AuditLog{}, &model.AuditFailureEvent{}, &model.Session{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	assetSvc, err := asset.NewAssetService(aesColumnCodec(t, make([]byte, 32)), "localhost", 4822, audit.NewTxSink())
	if err != nil {
		t.Fatalf("asset service: %v", err)
	}
	authSvc := identity.NewAuthService("test-secret", time.Hour)
	authzSvc := authz.NewAssetAuthorizationService(db)
	h := NewHandler(assetSvc, authSvc, authzSvc, nil, nil, "", nil)
	// 錄影前置 probe 走隔離目錄（可寫→放行），不觸碰真實 recordings volume
	h.RecordingPath = t.TempDir()

	policies := policy.NewSecurityPolicyService(db)
	h.AccessPolicy = policy.NewAccessPolicyService(db, policies, authzSvc)
	// 錄影失效事件整合驗證用：各測試以自己的
	// in-memory DB 重新註冊單例
	audit.InitAuditFailure(db, policies)
	return h, db, policies
}

// seedGateFixture user 1（一般）、user 2（admin）、user 3（auditor）皆 active；
// asset 1 ∈ group 1（政策由各測試設定）。user 1 持 asset 1 常設 connect
func seedGateFixture(t *testing.T, db *gorm.DB) {
	t.Helper()
	// DB 現查角色事實源：簽發/兌換點 CurrentConnectRole
	// 折疊 DB roles 判定 admin 特權，不再靠 issueToken 的 mock role——user2 須有真實 admin
	// role 關聯、user3 須有 auditor role，否則折疊為 user、admin 特權失效
	roles := []model.Role{{Name: model.RoleUser}, {Name: model.RoleAdmin}, {Name: model.RoleAuditor}}
	for i := range roles {
		if err := db.Create(&roles[i]).Error; err != nil {
			t.Fatalf("seed role: %v", err)
		}
	}
	users := []model.User{
		{Username: "u-user", Email: emailPtr("u@x"), Active: true, Roles: []model.Role{roles[0]}},
		{Username: "u-admin", Email: emailPtr("a@x"), Active: true, Roles: []model.Role{roles[1]}},
		{Username: "u-auditor", Email: emailPtr("d@x"), Active: true, Roles: []model.Role{roles[2]}},
	}
	for i := range users {
		if err := db.Create(&users[i]).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
	}
	if err := db.Create(&model.AssetGroup{Name: "g1"}).Error; err != nil {
		t.Fatalf("seed group: %v", err)
	}
	if err := db.Create(&model.Asset{Name: "a1", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 2}).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	uid := uint(1)
	aid := uint(1)
	if err := db.Create(&model.AssetAuthorization{
		UserID: &uid, AssetID: &aid, Permission: model.PermissionConnect, GrantedBy: 2,
	}).Error; err != nil {
		t.Fatalf("seed standing grant: %v", err)
	}
}

// setGroupPolicy 對組內全部資產設定政策段位（政策掛資產；
// helper 名與呼叫點沿用，語義自「設組政策」改為「組內資產逐一設定」，
// 兩者對閘測試等價）
func setGroupPolicy(t *testing.T, db *gorm.DB, _ uint, policy string) {
	t.Helper()
	if err := db.Model(&model.Asset{}).Where("1 = 1").
		Update("access_policy", policy).Error; err != nil {
		t.Fatalf("set asset policy: %v", err)
	}
}

// grantTicket 給 user 1 建時窗內核准流臨時授權
func grantTicket(t *testing.T, db *gorm.DB, userID, assetID uint) {
	t.Helper()
	start := time.Now().Add(-time.Minute)
	expired := time.Now().Add(time.Hour)
	if err := db.Create(&model.AssetAuthorization{
		UserID: &userID, AssetID: &assetID, Permission: model.PermissionConnect,
		GrantedBy: 2, Source: model.AuthorizationSourceTicket,
		DateStart: &start, DateExpired: &expired,
	}).Error; err != nil {
		t.Fatalf("seed ticket grant: %v", err)
	}
}

// issueToken 以指定身分呼叫簽發端點，回傳狀態碼/回應體/請求後的 context keys
func issueToken(h *Handler, userID uint, role string, assetID uint) (int, map[string]interface{}, map[string]interface{}) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	var keys map[string]interface{}
	r.POST("/connect-tokens", func(c *gin.Context) {
		c.Set("userID", userID)
		c.Set("role", role)
		h.HandleCreateConnectToken(c)
		keys = c.Keys
	})
	body, _ := json.Marshal(map[string]interface{}{"asset_id": assetID})
	req := httptest.NewRequest("POST", "/connect-tokens", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp, keys
}

// TestPolicyGate_Matrix 三段位×身分矩陣
func TestPolicyGate_Matrix(t *testing.T) {
	t.Run("open：user 常設放行（現狀不變）", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyOpen)

		code, resp, _ := issueToken(h, 1, model.RoleUser, 1)
		if code != http.StatusOK || resp["connect_token"] == nil {
			t.Fatalf("open 段位常設 connect 應簽發: code=%d resp=%v", code, resp)
		}
	})

	t.Run("reason：user 常設被攔（蓋過常設）", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyReason)

		code, resp, _ := issueToken(h, 1, model.RoleUser, 1)
		if code != http.StatusForbidden || resp["reason"] != "reason_required" {
			t.Fatalf("reason 段位應 403+reason_required: code=%d resp=%v", code, resp)
		}
		if resp["max_duration_minutes"] == nil {
			t.Fatal("攔截回應應含政策時長上限")
		}
	})

	t.Run("reason：user 臨時授權放行", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyReason)
		grantTicket(t, db, 1, 1)

		code, resp, _ := issueToken(h, 1, model.RoleUser, 1)
		if code != http.StatusOK || resp["connect_token"] == nil {
			t.Fatalf("ticket 來源應放行: code=%d resp=%v", code, resp)
		}
	})

	t.Run("approval：user 常設被攔", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyApproval)

		code, resp, _ := issueToken(h, 1, model.RoleUser, 1)
		if code != http.StatusForbidden || resp["reason"] != "approval_required" {
			t.Fatalf("approval 段位應 403+approval_required: code=%d resp=%v", code, resp)
		}
	})

	t.Run("approval：user 臨時授權放行、時窗內可重複簽發", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyApproval)
		grantTicket(t, db, 1, 1)

		for i := 0; i < 2; i++ {
			code, resp, _ := issueToken(h, 1, model.RoleUser, 1)
			if code != http.StatusOK || resp["connect_token"] == nil {
				t.Fatalf("時窗內第 %d 次簽發應成功: code=%d resp=%v", i+1, code, resp)
			}
		}
	})

	t.Run("approval：admin 豁免放行＋審計標記", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyApproval)

		code, resp, keys := issueToken(h, 2, model.RoleAdmin, 1)
		if code != http.StatusOK || resp["connect_token"] == nil {
			t.Fatalf("admin 應豁免放行: code=%d resp=%v", code, resp)
		}
		details, ok := keys["audit_details"].(map[string]string)
		if !ok || details["policy_exemption"] != "admin" {
			t.Fatalf("admin 豁免必須帶審計獨立標記: keys=%v", keys)
		}
	})

	t.Run("approval：auditor 在授權閘即被擋", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyApproval)

		// auditor 稽核唯讀：connect 授權閘（早於 policy gate）即回 403，根本
		// 到不了 approval 段位——比一般 user 更早被擋。policy gate 的非 admin
		// 不豁免由上方 user case 覆蓋
		code, resp, _ := issueToken(h, 3, model.RoleAuditor, 1)
		if code != http.StatusForbidden || resp["reason"] == "approval_required" {
			t.Fatalf("auditor 應在授權閘被擋（非 approval_required）: code=%d resp=%v", code, resp)
		}
	})

	t.Run("approval：已有在途單則回應帶識別", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyApproval)
		req := model.AccessRequest{
			RequesterID: 1, AssetID: 1, Reason: "維護", RequestedDurationMinutes: 60,
			Status: model.AccessRequestPending, PendingExpiresAt: time.Now().Add(72 * time.Hour),
		}
		if err := db.Create(&req).Error; err != nil {
			t.Fatalf("seed pending request: %v", err)
		}

		code, resp, _ := issueToken(h, 1, model.RoleUser, 1)
		if code != http.StatusForbidden || resp["pending_request_id"] == nil {
			t.Fatalf("攔截回應應帶在途申請識別: code=%d resp=%v", code, resp)
		}
	})

	t.Run("到期臨時授權擋新簽發", func(t *testing.T) {
		h, db, _ := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		setGroupPolicy(t, db, 1, model.AccessPolicyApproval)
		uid, aid := uint(1), uint(1)
		start := time.Now().Add(-2 * time.Hour)
		expired := time.Now().Add(-time.Hour)
		db.Create(&model.AssetAuthorization{
			UserID: &uid, AssetID: &aid, Permission: model.PermissionConnect,
			GrantedBy: 2, Source: model.AuthorizationSourceTicket,
			DateStart: &start, DateExpired: &expired,
		})

		code, resp, _ := issueToken(h, 1, model.RoleUser, 1)
		if code != http.StatusForbidden {
			t.Fatalf("到期 ticket 不應再簽發: code=%d resp=%v", code, resp)
		}
	})
}

// TestPolicyGate_GateOrder 閘序（connection-gating delta）：授權 → 政策閘 → 傳輸閘；
// 政策攔截不觸發傳輸閘（403 非 428）、政策放行後傳輸閘照常（428）
func TestPolicyGate_GateOrder(t *testing.T) {
	setup := func(t *testing.T) (*Handler, *gorm.DB) {
		h, db, policies := setupPolicyGateTest(t)
		seedGateFixture(t, db)
		// RDP 資產（預設 security=any＋ignore-cert ⇒ 有風險項）＋通道 warn ⇒
		// 無同意時傳輸閘 428
		if err := db.Create(&model.Asset{Name: "rdp1", Protocol: "rdp", Host: "h", Port: 3389, CreatedBy: 2}).Error; err != nil {
			t.Fatalf("seed rdp asset: %v", err)
		}
		uid, aid := uint(1), uint(2)
		if err := db.Create(&model.AssetAuthorization{
			UserID: &uid, AssetID: &aid, Permission: model.PermissionConnect, GrantedBy: 2,
		}).Error; err != nil {
			t.Fatalf("seed grant: %v", err)
		}
		if _, err := policies.Update(policy.PolicyTransportRDPLevel, policy.TransportLevelWarn, "admin"); err != nil {
			t.Fatalf("set transport warn: %v", err)
		}
		h.TransmissionConsent = policy.NewTransmissionConsentService(db,
			policy.NewTransmissionPolicyService(policies, nil))
		setGroupPolicy(t, db, 1, model.AccessPolicyApproval)
		return h, db
	}

	t.Run("政策攔截不觸發傳輸閘", func(t *testing.T) {
		h, _ := setup(t)
		code, resp, _ := issueToken(h, 1, model.RoleUser, 2)
		if code != http.StatusForbidden || resp["reason"] != "approval_required" {
			t.Fatalf("應為政策閘 403 而非傳輸閘 428: code=%d resp=%v", code, resp)
		}
	})

	t.Run("政策放行後傳輸閘照常", func(t *testing.T) {
		h, db := setup(t)
		grantTicket(t, db, 1, 2)
		code, resp, _ := issueToken(h, 1, model.RoleUser, 2)
		if code != http.StatusPreconditionRequired {
			t.Fatalf("政策放行後應輪到傳輸閘 428: code=%d resp=%v", code, resp)
		}
	})
}
