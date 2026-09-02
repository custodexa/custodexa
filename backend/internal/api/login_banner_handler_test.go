package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
)

// 登入前告示公開端點的形狀與副作用。

type bannerTestEnv struct {
	router  *gin.Engine
	policy  *policy.SecurityPolicyService
	db      *gorm.DB
}

// setupLoginBannerRouter 真 sqlite＋真政策服務＋真審計服務（同步寫入）。
//
// 審計服務用真的而非 nil：「本端點不產生審計列」要成立為證據，就必須有一個
// 真的會寫列的服務掛在 handler 上，否則斷言零列只是在確認 nil 不寫東西。
func setupLoginBannerRouter(t *testing.T) *bannerTestEnv {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	if err := db.AutoMigrate(&model.SecurityPolicy{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	policySvc := policy.NewSecurityPolicyService(db)
	auditSvc := audit.NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false})
	handler := NewSecurityPolicyHandler(policySvc, auditSvc)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	// 刻意不掛任何認證中介層：這正是本端點在正式路由表上的形態
	r.GET("/api/v1/auth/banner", handler.LoginBanner)
	return &bannerTestEnv{router: r, policy: policySvc, db: db}
}

func (e *bannerTestEnv) get(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/banner", nil))
	return w
}

func bannerKeys(t *testing.T, w *httptest.ResponseRecorder) []string {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("回應非 JSON: %v (body=%s)", err, w.Body.String())
	}
	keys := make([]string, 0, len(body))
	for k := range body {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (e *bannerTestEnv) auditCount(t *testing.T) int64 {
	t.Helper()
	var n int64
	if err := e.db.Model(&model.AuditLog{}).Count(&n).Error; err != nil {
		t.Fatalf("count audit_logs: %v", err)
	}
	return n
}

func TestLoginBannerUnsetReturnsDisabledOnly(t *testing.T) {
	env := setupLoginBannerRouter(t)
	w := env.get(t)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200（未認證亦須可讀）", w.Code)
	}
	if got := bannerKeys(t, w); len(got) != 1 || got[0] != "enabled" {
		t.Errorf("鍵集合 = %v, want [enabled]", got)
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body.Enabled {
		t.Error("未設定時 enabled 應為 false")
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if n := env.auditCount(t); n != 0 {
		t.Errorf("審計列數 = %d, want 0（本端點不留痕）", n)
	}
}

func TestLoginBannerSetReturnsTitleAndBodyOnly(t *testing.T) {
	env := setupLoginBannerRouter(t)
	if _, err := env.policy.UpdateBatch(map[string]string{
		policy.PolicyLoginBannerTitle: "使用告示",
		policy.PolicyLoginBannerBody:  "本系統僅供授權使用者存取。\n所有操作將被記錄與錄影。",
	}, "admin"); err != nil {
		t.Fatalf("設定告示: %v", err)
	}

	w := env.get(t)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	got := bannerKeys(t, w)
	want := []string{"body", "enabled", "title"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("鍵集合 = %v, want %v", got, want)
	}
	var body struct {
		Enabled bool   `json:"enabled"`
		Title   string `json:"title"`
		Body    string `json:"body"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.Enabled || body.Title != "使用告示" {
		t.Errorf("回應 = %+v", body)
	}
	if !strings.Contains(body.Body, "\n") {
		t.Errorf("內文換行未保留: %q", body.Body)
	}

	// 其他政策一律不得出現：本端點無認證中介層，回應等同對匿名者公開
	raw := w.Body.String()
	for _, forbidden := range []string{"lockout_max_attempts", "updated_by", "updated_at",
		"pci_value", "compliant", "deviation_count", "max_length"} {
		if strings.Contains(raw, forbidden) {
			t.Errorf("回應洩漏 %q: %s", forbidden, raw)
		}
	}
	if n := env.auditCount(t); n != 0 {
		t.Errorf("審計列數 = %d, want 0（本端點不留痕）", n)
	}
}

func TestLoginBannerTitleWithoutBodyIsUnset(t *testing.T) {
	env := setupLoginBannerRouter(t)
	if _, err := env.policy.Update(policy.PolicyLoginBannerTitle, "只有標題", "admin"); err != nil {
		t.Fatalf("設定標題: %v", err)
	}
	w := env.get(t)
	if got := bannerKeys(t, w); len(got) != 1 || got[0] != "enabled" {
		t.Errorf("鍵集合 = %v, want [enabled]（標題不單獨回）", got)
	}
	if strings.Contains(w.Body.String(), "只有標題") {
		t.Errorf("內文為空時仍回了標題: %s", w.Body.String())
	}
}

// TestAuditPolicyChangeFieldsShape 政策變更審計列的形狀依鍵型別分岔。
//
// 非文字鍵那一半是**新增的斷言**：既有測試從未釘住 `policy=k old=v new=v`
// 這個格式，於是文字鍵的分岔可以在不被任何測試發現的情況下改到非文字鍵頭上。
func TestAuditPolicyChangeFieldsShape(t *testing.T) {
	t.Run("文字鍵：全文入詳情，訊息只留鍵名", func(t *testing.T) {
		old := ""
		next := "第一行\n第二行\t含跳格"
		details, errorMsg := policyChangeAuditFields(policy.PolicyLoginBannerBody, old, next)

		if errorMsg != "policy="+policy.PolicyLoginBannerBody {
			t.Errorf("error_msg = %q, want %q", errorMsg, "policy="+policy.PolicyLoginBannerBody)
		}
		if strings.ContainsAny(errorMsg, "\n\r") {
			t.Errorf("error_msg 含換行: %q", errorMsg)
		}
		if strings.ContainsAny(details, "\n\r") {
			t.Errorf("details 應為單行 JSON（換行以逸出序列表示），實得 %q", details)
		}

		var decoded struct {
			Changes []struct {
				Field string `json:"field"`
				Old   string `json:"old"`
				New   string `json:"new"`
			} `json:"changes"`
		}
		if err := json.Unmarshal([]byte(details), &decoded); err != nil {
			t.Fatalf("details 不是合法 JSON: %v (%q)", err, details)
		}
		if len(decoded.Changes) != 1 {
			t.Fatalf("changes 長度 = %d, want 1", len(decoded.Changes))
		}
		ch := decoded.Changes[0]
		if ch.Field != policy.PolicyLoginBannerBody || ch.Old != old || ch.New != next {
			t.Errorf("changes[0] = %+v，全文未原樣保存", ch)
		}
	})

	t.Run("非文字鍵：既有單行格式不變，無詳情", func(t *testing.T) {
		details, errorMsg := policyChangeAuditFields(policy.PolicyLockoutMaxAttempts, "10", "5")
		want := "policy=" + policy.PolicyLockoutMaxAttempts + " old=10 new=5"
		if errorMsg != want {
			t.Errorf("error_msg = %q, want %q", errorMsg, want)
		}
		if details != "" {
			t.Errorf("details = %q, want 空字串（非文字鍵不改形狀）", details)
		}
	})
}
