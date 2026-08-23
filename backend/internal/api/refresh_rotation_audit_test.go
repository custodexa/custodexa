package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// refresh 憑證的**成功輪替**必須留痕（auth-session spec）。
//
// # 缺陷
//
// 修法前 `/auth/refresh` 只有失敗留痕（`respondRefreshError` → `auditRefresh`），
// 成功輪替零列。`/auth/refresh` 是公開端點、不掛 AuthMiddleware，`AuditLogMiddleware`
// 因無 userID／username 而整筆跳過，故沒有任何東西補得上這一列。
//
// 這使「憑證遭竊後被持續用於維持存取」在稽核上完全不可見——攻擊者只會製造**成功**
// 的輪替，那正是該情境唯一會留下的訊號。稽核比對同一帳號的輪替來源位址是辨識
// 「憑證正被他處使用」的主要手段，而來源位址只存在於成功列上。
//
// # 本檔守的三件事
//
//  1. 成功輪替**必然**產生一列，且答得出使用者、來源位址與輪替時間。
//  2. 成功列與失敗列可區分（`status` ＋ 事件標記），否則報表分不出「輪替了」與「被拒了」。
//  3. 來源位址逐列落地：同一憑證自兩個位址輪替時，兩列的 client_ip 不同。
//
// # 突變自檢
//
// 拿掉 `Refresh` 內的 `h.auditRefreshEvent(..., model.StatusSuccess, ...)` 一行
// ⇒ 本檔三格中的兩格轉紅（第三格是失敗列的對照格，本就不依賴成功列）。

const refreshAuditSecret = "refresh-rotation-audit-secret"

type refreshAuditEnv struct {
	h    *AuthHandler
	auth *identity.AuthService
	db   *gorm.DB
	uid  uint
}

// setupRefreshAuditEnv 真 handler ＋ 真 audit service ＋ 真 sqlite。
// `AsyncAuditEnabled: false`：同步寫入，使每一次紅都是真的缺列而非「等不到」。
func setupRefreshAuditEnv(t *testing.T) *refreshAuditEnv {
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
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.RefreshToken{},
		&model.SecurityPolicy{}, &model.PasswordHistory{}, &model.OIDCProvider{},
		&model.UserExternalIdentity{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	policies := policy.NewSecurityPolicyService(db)
	auth := identity.NewAuthService(refreshAuditSecret, 15*time.Minute)
	auth.SetSecurityPolicies(policies)

	auditService := audit.NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false,
	})
	h := NewAuthHandler(auth, auditService)

	hashed, err := bcrypt.GenerateFromPassword([]byte("R3fresh-Audit!pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	u := &model.User{Username: "refresh-subject", Password: string(hashed), Active: true}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := db.Exec("DELETE FROM audit_logs").Error; err != nil {
		t.Fatalf("清空 seed 期審計列: %v", err)
	}
	return &refreshAuditEnv{h: h, auth: auth, db: db, uid: u.ID}
}

// login 取得第一張 refresh 憑證（走真登入流程，不手工塞列）
func (e *refreshAuditEnv) login(t *testing.T) string {
	t.Helper()
	resp, err := e.auth.Login(&identity.LoginRequest{
		Username: "refresh-subject", Password: "R3fresh-Audit!pw"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if resp.RefreshToken == "" {
		t.Fatal("登入應發出 refresh 憑證")
	}
	// 登入自身的審計列（AP-07）不屬本檔標的：清空後起算
	if err := e.db.Exec("DELETE FROM audit_logs").Error; err != nil {
		t.Fatalf("清空登入期審計列: %v", err)
	}
	return resp.RefreshToken
}

// postRefresh 以指定來源位址打 /auth/refresh（掛真審計中介層，位置同生產）。
//
// 憑證以 httpOnly cookie 攜帶、輪替後的新憑證亦自 Set-Cookie 取回
// request body 與回應 body 皆已無憑證通道
func (e *refreshAuditEnv) postRefresh(t *testing.T, token, remoteAddr string) (int, string) {
	t.Helper()
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(e.h.auditService))
	r.POST("/api/v1/auth/refresh", e.h.Refresh)

	req := httptest.NewRequest("POST", "/api/v1/auth/refresh", bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: token})
	req.RemoteAddr = remoteAddr
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	next := ""
	if ck := findRefreshCookie(w); ck != nil {
		next = ck.Value
	}
	return w.Code, next
}

func (e *refreshAuditEnv) rows(t *testing.T) []model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	if err := e.db.Order("id asc").Find(&rows).Error; err != nil {
		t.Fatalf("查 audit_logs: %v", err)
	}
	return rows
}

// --- 格 1：成功輪替留痕 ---

// TestRefreshRotationSuccessWritesAuditRow 成功的輪替是「憑證遭竊後仍在被使用」
// 這條路徑唯一會留下的訊號。
func TestRefreshRotationSuccessWritesAuditRow(t *testing.T) {
	e := setupRefreshAuditEnv(t)
	tok := e.login(t)

	code, next := e.postRefresh(t, tok, "203.0.113.11:5001")
	if code != http.StatusOK || next == "" {
		t.Fatalf("輪替狀態碼 = %d（新 refresh 憑證空=%v）, want 200", code, next == "")
	}

	rows := e.rows(t)
	if len(rows) != 1 {
		t.Fatalf("成功輪替應恰好一列（handler 寫、中介層跳過），實得 %d 列", len(rows))
	}
	row := rows[0]
	if row.UserID != e.uid || row.Username != "refresh-subject" {
		t.Errorf("輪替主體 = %d/%q, want %d/refresh-subject（誰在輪替答不出來）",
			row.UserID, row.Username, e.uid)
	}
	if row.Resource != model.ResourceAuth || row.Action != model.ActionLogin {
		t.Errorf("resource/action = %q/%q, want %q/%q",
			row.Resource, row.Action, model.ResourceAuth, model.ActionLogin)
	}
	if row.Status != model.StatusSuccess {
		t.Errorf("status = %q, want %q", row.Status, model.StatusSuccess)
	}
	if row.StatusCode != http.StatusOK {
		t.Errorf("status_code = %d, want 200", row.StatusCode)
	}
	if row.ErrorMsg != "refresh_rotated" {
		t.Errorf("事件標記 = %q, want refresh_rotated（成功輪替與一般登入無從區分）", row.ErrorMsg)
	}
	if row.ClientIP != "203.0.113.11" {
		t.Errorf("client_ip = %q, want 203.0.113.11（來源位址是辨識異常他處使用的主要欄）",
			row.ClientIP)
	}
	if row.CreatedAt.IsZero() || time.Since(row.CreatedAt) > time.Minute {
		t.Errorf("created_at = %v 不像本次輪替的時刻", row.CreatedAt)
	}
}

// --- 格 2：來源位址變化可被辨識 ---

// TestRefreshRotationAuditDistinguishesSourceAddresses 稽核比對同一帳號的輪替
// 記錄時，來源位址的變化正是「憑證是否遭他處使用」的判斷依據；
// 若成功輪替不留痕，這個問題根本問不出來。
func TestRefreshRotationAuditDistinguishesSourceAddresses(t *testing.T) {
	e := setupRefreshAuditEnv(t)
	tok := e.login(t)

	code, second := e.postRefresh(t, tok, "203.0.113.11:5001")
	if code != http.StatusOK {
		t.Fatalf("第一次輪替 = %d, want 200", code)
	}
	code, _ = e.postRefresh(t, second, "198.51.100.77:6002")
	if code != http.StatusOK {
		t.Fatalf("第二次輪替 = %d, want 200", code)
	}

	rows := e.rows(t)
	if len(rows) != 2 {
		t.Fatalf("兩次輪替應各一列，實得 %d 列", len(rows))
	}
	if rows[0].ClientIP == rows[1].ClientIP {
		t.Fatalf("兩次輪替的 client_ip 相同（%q）：來源變化不可辨識", rows[0].ClientIP)
	}
	if rows[0].ClientIP != "203.0.113.11" || rows[1].ClientIP != "198.51.100.77" {
		t.Fatalf("來源位址 = %q / %q, want 203.0.113.11 / 198.51.100.77",
			rows[0].ClientIP, rows[1].ClientIP)
	}
}

// --- 格 3：成功列與失敗列可區分（反向對照）---

// TestRefreshRejectionRemainsDistinguishableFromRotation 失敗留痕是既有行為；
// 本格釘住「補上成功列之後兩者仍分得開」——否則報表把被拒與輪替混成一團，
// 修好一個缺口卻毀掉既有的可解釋性。
func TestRefreshRejectionRemainsDistinguishableFromRotation(t *testing.T) {
	e := setupRefreshAuditEnv(t)
	tok := e.login(t)

	if code, _ := e.postRefresh(t, tok, "203.0.113.11:5001"); code != http.StatusOK {
		t.Fatalf("輪替 = %d, want 200", code)
	}
	// 已輪替的舊憑證重放：家族撤銷＋失敗留痕
	if code, _ := e.postRefresh(t, tok, "203.0.113.11:5001"); code != http.StatusUnauthorized {
		t.Fatalf("舊憑證重放 = %d, want 401", code)
	}

	rows := e.rows(t)
	if len(rows) != 2 {
		t.Fatalf("一成一敗應各一列，實得 %d 列", len(rows))
	}
	if rows[0].Status != model.StatusSuccess {
		t.Errorf("第一列 status = %q, want success", rows[0].Status)
	}
	if rows[1].Status != model.StatusFailure {
		t.Errorf("第二列 status = %q, want failure（認證失敗語義不得被改寫）", rows[1].Status)
	}
	if rows[0].ErrorMsg == rows[1].ErrorMsg {
		t.Errorf("成功與失敗的事件標記相同（%q）：兩者不可區分", rows[0].ErrorMsg)
	}
}
