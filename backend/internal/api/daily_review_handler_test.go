package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/gin-gonic/gin"
)

// dailyReviewFullRouter 真審計中介層＋真權限中介層＋真 handler（僅以替身取代 JWT 驗證：
// 由 X-Test-Role 指定角色）。路由表與正式註冊同一份（registerOn）
func dailyReviewFullRouter(t *testing.T) (*gin.Engine, func() int64) {
	t.Helper()
	_, db, now := setupDailyReviewRouter(t)
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })

	// 一筆已簽（10-09）
	signed := model.DailyReviewLog{ReviewDate: "2026-10-09", ReviewerID: 7, ReviewerName: "auditor-a", SnapshotJSON: "{}",
		SignedAt: now, Timezone: "Asia/Taipei", WindowStart: now, WindowEnd: now, DueAt: now,
		Coverage: model.DailyReviewCoverageFullDay, SourceStatus: model.DailyReviewSourceComplete, EnabledBasis: model.DailyReviewBasisRecorded}
	if err := db.Create(&signed).Error; err != nil {
		t.Fatal(err)
	}
	svc := audit.NewDailyReviewService(db, policy.NewSecurityPolicyService(db), nil)
	svc.SetClock(func() time.Time { return now })
	h := NewDailyReviewHandler(svc, nil)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(audit.NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true})))
	v1 := r.Group("/api/v1")
	v1.Use(func(c *gin.Context) {
		c.Set("userID", uint(9))
		c.Set("username", "tester")
		middleware.SetPrincipal(c, legacyPrincipal(c.GetHeader("X-Test-Role")))
		c.Next()
	})
	h.registerOn(v1.Group("/daily-reviews"))
	return r, func() int64 {
		var n int64
		db.Model(&model.AuditLog{}).Where("resource = ?", model.ResourceDailyReview).Count(&n)
		return n
	}
}

func serveAs(r *gin.Engine, role, method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(`{"review_date":"2026-10-10"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Role", role)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// TestDailyReviewReadEndpointsDenyWithoutAuditView 擋：新 GET 漏掛權限，或對不同日期
// 狀態給出不同回應而洩漏存在性
func TestDailyReviewReadEndpointsDenyWithoutAuditView(t *testing.T) {
	r, auditRows := dailyReviewFullRouter(t)
	reads := []string{
		"/api/v1/daily-reviews/pending",
		"/api/v1/daily-reviews/pending/count",
		"/api/v1/daily-reviews/stats",
		"/api/v1/daily-reviews/days/2026-10-09", // 已簽
		"/api/v1/daily-reviews/days/2026-10-08", // 未簽
		"/api/v1/daily-reviews/days/2026-08-01", // 範圍外
		"/api/v1/daily-reviews/days/2026-13-01", // 格式錯
	}
	var first string
	for _, p := range reads {
		w := serveAs(r, "user", http.MethodGet, p)
		if w.Code != http.StatusForbidden {
			t.Errorf("user %s = %d, want 403", p, w.Code)
		}
		if first == "" {
			first = w.Body.String()
		} else if w.Body.String() != first {
			t.Errorf("user %s 的 403 回應與其他不同：%s vs %s", p, w.Body.String(), first)
		}
	}
	if w := serveAs(r, "user", http.MethodPost, "/api/v1/daily-reviews"); w.Code != http.StatusForbidden {
		t.Errorf("user POST = %d, want 403", w.Code)
	}

	for _, p := range []string{
		"/api/v1/daily-reviews/pending",
		"/api/v1/daily-reviews/pending/count",
		"/api/v1/daily-reviews/stats?period=30d",
		"/api/v1/daily-reviews/days/2026-10-08",
	} {
		before := auditRows()
		w := serveAs(r, "auditor", http.MethodGet, p)
		if w.Code != http.StatusOK {
			t.Errorf("auditor %s = %d (%s), want 200", p, w.Code, w.Body.String())
		}
		if after := auditRows(); after != before+1 {
			t.Errorf("auditor %s 審計列 %d → %d, want +1（resource=daily_review）", p, before, after)
		}
	}
	var path string
	database.DB.Model(&model.AuditLog{}).Where("resource = ?", model.ResourceDailyReview).Order("id DESC").Limit(1).Pluck("path", &path)
	if !strings.Contains(path, "2026-10-08") {
		t.Errorf("單日明細的審計 path = %q, want 含日期", path)
	}
	if w := serveAs(r, "auditor", http.MethodGet, "/api/v1/daily-reviews/days/2026-13-01"); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "VALIDATION_DAILY_REVIEW_DATE_INVALID") {
		t.Errorf("auditor 格式錯日期 = %d %s", w.Code, w.Body.String())
	}
}

// TestDailyReviewSignErrorCodesOnWire 簽核規則錯誤在 wire 上的碼與 params
func TestDailyReviewSignErrorCodesOnWire(t *testing.T) {
	r, _, _ := setupDailyReviewRouter(t)
	cases := []struct {
		body   map[string]interface{}
		code   string
		params map[string]any
	}{
		{map[string]interface{}{"review_date": "2026-10-11"}, "RULE_DAILY_REVIEW_DAY_NOT_ENDED", nil},
		{map[string]interface{}{"review_date": "9999-12-31"}, "RULE_DAILY_REVIEW_DAY_NOT_ENDED", nil},
		{map[string]interface{}{"review_date": "2026-09-30"}, "RULE_DAILY_REVIEW_DAY_OUT_OF_SCOPE", nil},
		{map[string]interface{}{"review_date": "2026/10/10"}, "VALIDATION_DAILY_REVIEW_DATE_INVALID", nil},
		{map[string]interface{}{"note": "未帶所屬日"}, "VALIDATION_DAILY_REVIEW_DATE_INVALID", nil},
		{map[string]interface{}{"review_date": "2026-10-05"}, "VALIDATION_DAILY_REVIEW_DELAY_REASON_REQUIRED", nil},
		{map[string]interface{}{"review_date": "2026-10-10", "note": strings.Repeat("審", 501)}, "VALIDATION_DAILY_REVIEW_TEXT_TOO_LONG", map[string]any{"field": "note"}},
	}
	for _, tc := range cases {
		w := doJSON(r, "POST", "/daily-reviews", tc.body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%v = %d (%s), want 400", tc.body["review_date"], w.Code, w.Body.String())
			continue
		}
		code, params, _ := decodeEnvelope(t, w)
		if code != tc.code {
			t.Errorf("%v code = %s, want %s", tc.body["review_date"], code, tc.code)
		}
		for k, v := range tc.params {
			if params[k] != v {
				t.Errorf("%s params[%s] = %v, want %v", tc.code, k, params[k], v)
			}
		}
	}
}

// TestDailyReviewDayFarFutureOnWire 擋：單日明細收到遠未來日期時進入行事曆計算；
// 入口直接回 400 尚未結束
func TestDailyReviewDayFarFutureOnWire(t *testing.T) {
	r, _, _ := setupDailyReviewRouter(t)
	w := doJSON(r, "GET", "/daily-reviews/days/9999-12-31", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("= %d (%s), want 400", w.Code, w.Body.String())
	}
	if code, _, _ := decodeEnvelope(t, w); code != "RULE_DAILY_REVIEW_DAY_NOT_ENDED" {
		t.Fatalf("code = %s", code)
	}
}

// TestDailyReviewDayRenamesRoleAssignmentReasons 擋：每日簽核單日明細的事件列沒有經名稱換算器，
// 角色指派類原因參數以識別碼呈現。夾具列用刪除動作進入高危範圍（正式資料中這類列不在範圍內，
// 這裡驗的是明細回應與換算器的接線）。
func TestDailyReviewDayRenamesRoleAssignmentReasons(t *testing.T) {
	_, db, now := setupDailyReviewRouter(t)
	taipei, _ := time.LoadLocation("Asia/Taipei")
	row := model.AuditLog{
		CreatedAt: time.Date(2026, 10, 10, 3, 0, 0, 0, taipei), UserID: 9, Username: "tester",
		Action: model.ActionDelete, Resource: model.ResourceUserRole, Status: model.StatusSuccess,
		Details: `{"resource":"user_role","user_id":9,"role_id":3,"origin":"api","event":"role_binding_range_changed",` +
			`"range_before":[167],"range_after":"global","range_before_count":1,"range_after_count":0}`,
	}
	if err := db.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	svc := audit.NewDailyReviewService(db, policy.NewSecurityPolicyService(db), nil)
	svc.SetClock(func() time.Time { return now })
	f := &fakeReasonNames{users: map[uint64]string{9: "ops-lee"}, roles: map[uint64]string{3: "asset_admin"}}
	n, _ := newFakeNamer(f, map[uint]string{167: "SIT / ELK"})
	h := NewDailyReviewHandler(svc, n)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/daily-reviews/days/:date", h.Day)
	w := doJSON(r, "GET", "/daily-reviews/days/2026-10-10", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("= %d (%s)", w.Code, w.Body.String())
	}
	var body struct {
		Data struct {
			HighRiskOps struct {
				Items []struct {
					ReasonCode   string            `json:"reason_code"`
					ReasonParams map[string]string `json:"reason_params"`
				} `json:"items"`
			} `json:"high_risk_ops"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	items := body.Data.HighRiskOps.Items
	if len(items) != 1 {
		t.Fatalf("高危明細 %d 筆, want 1: %s", len(items), w.Body.String())
	}
	p := items[0].ReasonParams
	if items[0].ReasonCode != "event.role_binding_range_changed" || p["role"] != "asset_admin" ||
		p["target"] != "ops-lee" || p["before"] != "SIT / ELK" || p["after"] != "global" {
		t.Errorf("明細未換名: %s %v", items[0].ReasonCode, p)
	}
}
