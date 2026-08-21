package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 連線票證兌換遭拒必須留痕（audit-coverage-closure 批 4／connection-gating spec）。
//
// # 缺陷
//
// `GET /api/v1/connect` 的拒絕路徑原本純 HTTP 回應、零留痕。兌換失敗時 `userID`
// 從未寫進 gin context，`AuditLogMiddleware` 整筆跳過，故「反覆嘗試兌換偽造票證」
// 這類探測在稽核上完全不可見——與「沒有人試過」在資料上無從分辨。
//
// # 本檔守的四件事
//
//  1. 票證不成立（缺／偽造／過期）三種拒絕**各自**留痕，且原因在審計上**可區分**
//     ——即使對外回應刻意收斂為同一則「token 無效」（不給票證存在性探測面）。
//  2. 閘序拒絕（協議不符）留痕，且與票證類拒絕的原因可區分。
//  3. `status` 依 design D3 分流：401＝憑證不成立→`failure`；其餘＝授權拒絕→`denied`。
//     一刀切會讓兩種語義混成一團，破壞既有 403 列的可解釋性。
//  4. 閘序拒絕填 `asset_id`：「有人試圖連這台機器但被擋下」必須出現在資產樞紐上。
//
// # 突變自檢（tasks 4.6）
//
// 拿掉 `HandleConnect` 內票證分支的 `h.auditConnectDenied(...)` ⇒ 票證三格轉紅；
// 拿掉 `writeOutcome` 內的 `h.auditConnectDenied(...)` ⇒ 協議不符格轉紅。
// 兩者互不掩蓋（票證分支與閘序出口是兩個獨立呼叫點）。

type connectDenyEnv struct {
	h  *ConnectionHandler
	db *gorm.DB
}

// setupConnectDenyEnv 與 setupGraphicsRedeemTest 同構，差別是注入真的審計服務
// 並改用 SSH 協議資產（G-G10「協議不符」是本檔要走到的閘）。
//
// 審計服務刻意 `AsyncAuditEnabled: false`：同步寫入使每一次紅都是真的缺列，
// 而不是「等不到」與「根本沒寫」分不清楚。
func setupConnectDenyEnv(t *testing.T, protocol string) *connectDenyEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	// 單連線：ff51836 的「單獨跑綠、整包跑紅」防護
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserGroup{}, &model.Asset{},
		&model.AssetAccount{}, &model.AssetGroup{}, &model.AssetNode{}, &model.AssetAuthorization{},
		&model.AccessRequest{}, &model.SecurityPolicy{}, &model.AuditLog{}, &model.Session{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	roles := []model.Role{{Name: model.RoleUser}, {Name: model.RoleAdmin}}
	for i := range roles {
		if err := db.Create(&roles[i]).Error; err != nil {
			t.Fatalf("seed role: %v", err)
		}
	}
	users := []model.User{
		{Username: "u1", Email: emailPtr("u1@x"), Active: true, Roles: []model.Role{roles[0]}},
		{Username: "u2", Email: emailPtr("u2@x"), Active: true, Roles: []model.Role{roles[1]}},
	}
	for i := range users {
		if err := db.Create(&users[i]).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
	}
	if err := db.Create(&model.Asset{
		Name: "target", Protocol: model.ProtocolType(protocol), Host: "h", Port: 22, CreatedBy: 2,
	}).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	if err := db.Model(&model.Asset{}).Where("id = ?", 1).
		Update("access_policy", model.AccessPolicyOpen).Error; err != nil {
		t.Fatalf("set policy: %v", err)
	}
	uid, aid := uint(1), uint(1)
	if err := db.Create(&model.AssetAuthorization{
		UserID: &uid, AssetID: &aid, Permission: model.PermissionConnect, GrantedBy: 2,
	}).Error; err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	// 資產建立經 GORM hook 落一筆自己的審計列（AP-23）：清空後起算，
	// 使「恰好一列」指的是**兌換拒絕**的列數
	if err := db.Exec("DELETE FROM audit_logs").Error; err != nil {
		t.Fatalf("清空 seed 期審計列: %v", err)
	}

	assetSvc, err := asset.NewAssetService(aesColumnCodec(t, make([]byte, 32)), "localhost", 4822, audit.NewTxSink())
	if err != nil {
		t.Fatalf("asset service: %v", err)
	}
	authzSvc := authz.NewAssetAuthorizationService(db)
	auditService := audit.NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false,
	})
	h := NewConnectionHandler("localhost", 4822, nil, assetSvc,
		identity.NewAuthService("connect-deny-secret", time.Hour), authzSvc, auditService)
	h.ConnectTokens = NewConnectTokenManager()
	policies := policy.NewSecurityPolicyService(db)
	h.AccessPolicy = policy.NewAccessPolicyService(db, policies, authzSvc)
	return &connectDenyEnv{h: h, db: db}
}

// redeem 走與生產同構的路由（含全域真審計中介層，位置同 cmd/server/main.go）
func (e *connectDenyEnv) redeem(query string) int {
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(e.h.AuditService))
	r.GET("/api/v1/connect", e.h.HandleConnect)
	req := httptest.NewRequest("GET", "/api/v1/connect"+query, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

// onlyRow 取唯一一列審計；不是恰好一列即失敗（多列＝中介層與 handler 重複記錄）
func (e *connectDenyEnv) onlyRow(t *testing.T, why string) model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	if err := e.db.Order("id asc").Find(&rows).Error; err != nil {
		t.Fatalf("查 audit_logs: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("%s：審計列 = %d 列, want 1（0＝拒絕零留痕，>1＝重複記錄）", why, len(rows))
	}
	return rows[0]
}

// assertDenyRow 逐欄檢查一列兌換拒絕留痕
func assertDenyRow(t *testing.T, row model.AuditLog, why, wantReason string,
	wantStatus model.AuditStatus, wantHTTP int, wantAsset *uint) {
	t.Helper()
	if row.Action != model.ActionCreate || row.Resource != model.ResourceSession {
		t.Errorf("%s：action/resource = %q/%q, want %q/%q",
			why, row.Action, row.Resource, model.ActionCreate, model.ResourceSession)
	}
	if row.Status != wantStatus {
		t.Errorf("%s：status = %q, want %q（認證失敗與授權拒絕不得混為一談）",
			why, row.Status, wantStatus)
	}
	if row.StatusCode != wantHTTP {
		t.Errorf("%s：status_code = %d, want %d", why, row.StatusCode, wantHTTP)
	}
	if row.ErrorMsg != wantReason {
		t.Errorf("%s：error_msg = %q, want %q（拒絕原因不可區分即無從辨識探測行為）",
			why, row.ErrorMsg, wantReason)
	}
	if !strings.Contains(row.Details, `"reason":"`+wantReason+`"`) {
		t.Errorf("%s：details = %q 未帶 reason", why, row.Details)
	}
	if !strings.Contains(row.Details, `"via":"connect"`) {
		t.Errorf("%s：details = %q 未標記入口", why, row.Details)
	}
	if row.ClientIP == "" {
		t.Errorf("%s：client_ip 為空（來源位址是這類事件的主要證據）", why)
	}
	if row.Path != "/api/v1/connect" {
		t.Errorf("%s：path = %q, want /api/v1/connect", why, row.Path)
	}
	switch {
	case wantAsset == nil && row.AssetID != nil:
		t.Errorf("%s：asset_id = %d, want nil（票證不成立時目標未知，0 會被讀成編號 0 的資產）",
			why, *row.AssetID)
	case wantAsset != nil && (row.AssetID == nil || *row.AssetID != *wantAsset):
		t.Errorf("%s：asset_id = %v, want %d（資產樞紐上看不到被擋下的連線企圖）",
			why, row.AssetID, *wantAsset)
	}
	if row.CreatedAt.IsZero() {
		t.Errorf("%s：created_at 為零值（嘗試時間答不出來）", why)
	}
}

// --- 格 1-3：票證類拒絕，三種原因各自留痕且可區分 ---

// TestConnectTicketDenialsAreAudited 缺票／偽票／過期票三者對外是同一則回應，
// 在審計上必須分得出來——那正是「有人在探測」與「使用者慢了一步」的差別。
func TestConnectTicketDenialsAreAudited(t *testing.T) {
	t.Run("缺票證", func(t *testing.T) {
		e := setupConnectDenyEnv(t, "rdp")
		if code := e.redeem(""); code != http.StatusUnauthorized {
			t.Fatalf("缺票證狀態碼 = %d, want 401", code)
		}
		assertDenyRow(t, e.onlyRow(t, "缺票證"), "缺票證", "ticket_missing",
			model.StatusFailure, http.StatusUnauthorized, nil)
	})

	t.Run("偽造票證", func(t *testing.T) {
		e := setupConnectDenyEnv(t, "rdp")
		if code := e.redeem("?connect_token=deadbeefdeadbeefdeadbeefdeadbeef"); code != http.StatusUnauthorized {
			t.Fatalf("偽造票證狀態碼 = %d, want 401", code)
		}
		assertDenyRow(t, e.onlyRow(t, "偽造票證"), "偽造票證", string(RedeemDenyInvalid),
			model.StatusFailure, http.StatusUnauthorized, nil)
	})

	t.Run("過期票證", func(t *testing.T) {
		e := setupConnectDenyEnv(t, "rdp")
		tok, err := e.h.ConnectTokens.IssueConnectToken(context.Background(),
			ConnectGrant{UserID: 1, AssetID: 1, AccountID: 0})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		// 直接把 TTL 撥到過去（同包測試）：不睡 60 秒
		e.h.ConnectTokens.mu.Lock()
		g := e.h.ConnectTokens.grants[tok]
		g.ExpiresAt = time.Now().Add(-time.Second)
		e.h.ConnectTokens.grants[tok] = g
		e.h.ConnectTokens.mu.Unlock()

		if code := e.redeem("?connect_token=" + tok); code != http.StatusUnauthorized {
			t.Fatalf("過期票證狀態碼 = %d, want 401", code)
		}
		row := e.onlyRow(t, "過期票證")
		assertDenyRow(t, row, "過期票證", string(RedeemDenyExpired),
			model.StatusFailure, http.StatusUnauthorized, nil)
		// 判準的核心：過期與偽造不得收斂為同一個原因字串
		if row.ErrorMsg == string(RedeemDenyInvalid) {
			t.Fatalf("過期票證與偽造票證的審計原因相同（%q）：拒絕原因不可區分", row.ErrorMsg)
		}
	})
}

// --- 格 4：閘序拒絕（協議不符）---

// TestConnectProtocolMismatchDenialIsAudited SSH 已退出 guacd 圖像串流路徑，
// 以 SSH 資產兌換圖形連線會被 G-G10 擋下。這一格同時證明三件事：
// 閘序出口有留痕、拒絕原因與票證類可區分、授權拒絕記 `denied` 而非 `failure`。
func TestConnectProtocolMismatchDenialIsAudited(t *testing.T) {
	e := setupConnectDenyEnv(t, "ssh")
	tok, err := e.h.ConnectTokens.IssueConnectToken(context.Background(),
		ConnectGrant{UserID: 1, AssetID: 1, AccountID: 0})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if code := e.redeem("?connect_token=" + tok); code != http.StatusBadRequest {
		t.Fatalf("協議不符狀態碼 = %d, want 400", code)
	}
	wantAsset := uint(1)
	row := e.onlyRow(t, "協議不符")
	assertDenyRow(t, row, "協議不符", string(apierror.CodeSSHEndpointMoved),
		model.StatusDenied, http.StatusBadRequest, &wantAsset)
	if row.UserID != 1 {
		t.Errorf("協議不符：user_id = %d, want 1（票證帶得出主體時不得留空）", row.UserID)
	}
	// 與票證類拒絕的原因不同義：稽核據此分得出「票不成立」與「票成立但不准」
	if row.ErrorMsg == string(RedeemDenyInvalid) || row.ErrorMsg == string(RedeemDenyExpired) {
		t.Fatalf("協議不符被記成票證類原因（%q）", row.ErrorMsg)
	}
}
