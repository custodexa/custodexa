package api

import (
	"bytes"
	"encoding/json"
	"github.com/custodexa/backend/internal/modules/audit"
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
	"github.com/stretchr/testify/mock"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 錯誤碼參數化的 wire 契約。
//
// A 批大掃除把 err.Error() 直傳改為機器碼時丟棄了動態細節；其中三組是使用者
// 行動必需資訊（要改成多少／是不是自己漏簽／該修哪一個鍵），已改由 service 的
// typed error 具名帶出並轉為 apierror params。本檔斷言**這些值真的到得了 wire**
// ——只斷言狀態碼與 code 會讓「params 沒帶出去」全程假綠。

// decodeEnvelope 解出 apierror 信封的 code 與 params。
func decodeEnvelope(t *testing.T, w *httptest.ResponseRecorder) (string, map[string]any, string) {
	t.Helper()
	var body struct {
		Error  string         `json:"error"`
		Code   string         `json:"code"`
		Params map[string]any `json:"params"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("回應非合法 JSON: %v (body=%s)", err, w.Body.String())
	}
	return body.Code, body.Params, body.Error
}

// TestDurationExceedsPolicyParamsOnWire 申請時長超限帶出政策上限（{minutes}）。
func TestDurationExceedsPolicyParamsOnWire(t *testing.T) {
	reqSvc := new(MockAccessRequestService)
	reqSvc.On("Submit", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil, &authz.DurationExceedsPolicyError{MaxMinutes: 1440})
	r, _ := newAccessRequestRouter(reqSvc, nil, 5, "user", nil)

	w := doJSON(r, "POST", "/access-requests", map[string]interface{}{
		"asset_id": 3, "reason": "r", "duration_minutes": 99999,
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	code, params, errText := decodeEnvelope(t, w)
	if code != "RULE_ACCESS_REQUEST_DURATION_EXCEEDS" {
		t.Errorf("code = %q", code)
	}
	// JSON 數字解為 float64；比對數值而非型別
	if got, ok := params["minutes"].(float64); !ok || got != 1440 {
		t.Errorf("params = %v, want {minutes: 1440}", params)
	}
	if !strings.Contains(errText, "1440") {
		t.Errorf("zh fallback 未插入上限值: %q", errText)
	}
}

// setupDailyReviewRouter 每日審閱 handler 測試環境：真 sqlite＋真政策服務＋固定時鐘，
// 僅省略 JWT middleware。業務時區 Asia/Taipei、自 2026-10-01 起啟用，現在是 2026-10-11 09:00
func setupDailyReviewRouter(t *testing.T) (*gin.Engine, *gorm.DB, time.Time) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	// sqlite :memory: 每條連線是各自獨立的庫；限一條連線，否則 AutoMigrate 建的表
	// 與後續查詢可能落在不同庫上（偶發假紅）
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	if err := migrateWithAuthz(db, &model.DailyReviewLog{}, &model.AuditLog{}, &model.SecurityPolicy{},
		&model.SecurityPolicyHistory{}, &model.AuditRetentionWatermark{}, &model.Role{}, &model.UserRole{}, &model.UserGroup{}, &model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// command_alerts 生產為 timestamptz，sqlite 以 datetime 等價表手建（scan 才讀得回 time.Time）
	if err := db.Exec(`CREATE TABLE command_alerts (id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id INTEGER, rule_name TEXT NOT NULL DEFAULT 'r', session_id INTEGER NOT NULL DEFAULT 0,
		user_id INTEGER NOT NULL DEFAULT 3, asset_id INTEGER, command TEXT NOT NULL DEFAULT '',
		severity TEXT NOT NULL DEFAULT 'high', triggered_at DATETIME NOT NULL, reviewed_by INTEGER, reviewed_at DATETIME,
		disposition TEXT NOT NULL DEFAULT 'pending', note TEXT NOT NULL DEFAULT '', blocked BOOLEAN NOT NULL DEFAULT 0,
		kind TEXT NOT NULL DEFAULT 'rule', reason_code TEXT NOT NULL DEFAULT '')`).Error; err != nil {
		t.Fatalf("建表: %v", err)
	}
	taipei, _ := time.LoadLocation("Asia/Taipei")
	since := time.Date(2026, 10, 1, 0, 0, 0, 0, taipei)
	for _, h := range []model.SecurityPolicyHistory{
		{PolicyKey: policy.PolicyDailyReviewTimezone, NewValue: "Asia/Taipei", ChangedAt: since.Add(-time.Hour).UTC(), ChangedBy: "m", Source: model.PolicyHistorySourceMigrationUpgrade},
		{PolicyKey: policy.PolicyDailyReviewEnabled, OldValue: "false", NewValue: "true", ChangedAt: since.UTC(), ChangedBy: "admin", Source: model.PolicyHistorySourcePolicyUpdate},
	} {
		h := h
		if err := db.Create(&h).Error; err != nil {
			t.Fatal(err)
		}
	}
	for k, v := range map[string]string{policy.PolicyDailyReviewTimezone: "Asia/Taipei", policy.PolicyDailyReviewEnabled: "true"} {
		if err := db.Create(&model.SecurityPolicy{Key: k, Value: v, UpdatedBy: "admin", UpdatedAt: since}).Error; err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 10, 11, 9, 0, 0, 0, taipei)
	svc := audit.NewDailyReviewService(db, policy.NewSecurityPolicyService(db), nil)
	svc.SetClock(func() time.Time { return now })
	handler := NewDailyReviewHandler(svc)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/daily-reviews", func(c *gin.Context) {
		c.Set("userID", uint(9))
		c.Set("username", "auditor-b")
		handler.Sign(c)
	})
	r.GET("/daily-reviews/days/:date", handler.Day)
	return r, db, now
}

// TestDailyReviewAlreadySignedParamsOnWire 搶先簽核：409 帶出既有紀錄的所屬日、簽核者、
// 完整簽核時刻（RFC3339）與時區
func TestDailyReviewAlreadySignedParamsOnWire(t *testing.T) {
	r, db, now := setupDailyReviewRouter(t)

	signedAt := now.Add(-time.Hour).Truncate(time.Second)
	existing := model.DailyReviewLog{
		ReviewDate: "2026-10-10", ReviewerID: 7, ReviewerName: "auditor-a", SnapshotJSON: "{}",
		SignedAt: signedAt, Timezone: "Asia/Taipei", WindowStart: now, WindowEnd: now, DueAt: now,
		Coverage: model.DailyReviewCoverageFullDay, SourceStatus: model.DailyReviewSourceComplete, EnabledBasis: model.DailyReviewBasisRecorded,
	}
	if err := db.Create(&existing).Error; err != nil {
		t.Fatalf("預置既有簽核: %v", err)
	}

	w := doJSON(r, "POST", "/daily-reviews", map[string]interface{}{"review_date": "2026-10-10", "note": "n"})
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (body=%s)", w.Code, w.Body.String())
	}
	code, params, errText := decodeEnvelope(t, w)
	if code != "CONFLICT_DAILY_REVIEW_SIGNED" {
		t.Errorf("code = %q", code)
	}
	if params["signer"] != "auditor-a" || params["date"] != "2026-10-10" || params["timezone"] != "Asia/Taipei" {
		t.Errorf("params = %v", params)
	}
	got, err := time.Parse(time.RFC3339, params["signed_at"].(string))
	if err != nil || !got.Equal(signedAt) {
		t.Errorf("params[signed_at] = %v, want RFC3339 %v", params["signed_at"], signedAt)
	}
	if !strings.Contains(errText, "auditor-a") {
		t.Errorf("zh fallback 未插入簽核者: %q", errText)
	}
}

// TestDailyReviewSignIgnoresForgedSignedAt 擋：請求夾帶較早的簽核時刻即可倒填
func TestDailyReviewSignIgnoresForgedSignedAt(t *testing.T) {
	r, db, now := setupDailyReviewRouter(t)
	w := doJSON(r, "POST", "/daily-reviews", map[string]interface{}{
		"review_date": "2026-10-10", "note": "n", "signed_at": "2026-10-01T00:00:00Z",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%s)", w.Code, w.Body.String())
	}
	var stored model.DailyReviewLog
	if err := db.Where("review_date = ?", "2026-10-10").First(&stored).Error; err != nil {
		t.Fatal(err)
	}
	if !stored.SignedAt.Equal(now) {
		t.Errorf("signed_at = %v, want 伺服器受理時刻 %v（請求夾帶的值不得生效）", stored.SignedAt, now)
	}
	if stored.ReviewDate != "2026-10-10" || stored.Late {
		t.Errorf("所屬日 %s late=%v", stored.ReviewDate, stored.Late)
	}
}

// setupSecurityPolicyRouter 安全政策 handler 測試環境（真 sqlite＋真服務）。
func setupSecurityPolicyRouter(t *testing.T) *gin.Engine {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	if err := db.AutoMigrate(&model.SecurityPolicy{}, &model.SecurityPolicyHistory{}, &model.Role{}, &model.UserGroup{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.AutoMigrate(&model.UserRole{}, &model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	policySvc := policy.NewSecurityPolicyService(db)
	groupRepo := policy.NewPolicyGroupRepository(db)
	handler := NewSecurityPolicyHandler(policySvc, nil,
		policy.NewComplianceService(policySvc, groupRepo), groupRepo)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.PUT("/security-policies", func(c *gin.Context) {
		c.Set("userID", uint(1))
		c.Set("username", "admin")
		handler.Update(c)
	})
	return r
}

func putPolicies(t *testing.T, r *gin.Engine, policies map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"policies": policies})
	req := httptest.NewRequest(http.MethodPut, "/security-policies", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// TestPolicyErrorKeyOnWire 政策批次更新的兩種 400 都指名是哪一個鍵。
func TestPolicyErrorKeyOnWire(t *testing.T) {
	t.Run("未知鍵（opaque，值來自請求 body）", func(t *testing.T) {
		r := setupSecurityPolicyRouter(t)
		w := putPolicies(t, r, map[string]string{"nonexistent_key": "1"})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body=%s)", w.Code, w.Body.String())
		}
		code, params, errText := decodeEnvelope(t, w)
		if code != "VALIDATION_POLICY_UNKNOWN_KEY" {
			t.Errorf("code = %q", code)
		}
		if params["key"] != "nonexistent_key" {
			t.Errorf("params[key] = %v, want nonexistent_key", params["key"])
		}
		if !strings.Contains(errText, "nonexistent_key") {
			t.Errorf("zh fallback 未插入鍵名: %q", errText)
		}
	})

	t.Run("未知鍵含控制字元：淨化後仍送達，不整組丟棄", func(t *testing.T) {
		r := setupSecurityPolicyRouter(t)
		w := putPolicies(t, r, map[string]string{"bad\x1b[31mkey\nx": "1"})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", w.Code)
		}
		_, params, _ := decodeEnvelope(t, w)
		key, _ := params["key"].(string)
		if key != "badkey x" {
			t.Errorf("params[key] = %q, want %q（ESC 序列剝除、換行折成空白）", key, "badkey x")
		}
		if strings.Contains(w.Body.String(), "\x1b") {
			t.Error("回應仍含 ESC 逸出序列")
		}
	})

	t.Run("值不合法（enum，鍵保證出自政策表）", func(t *testing.T) {
		r := setupSecurityPolicyRouter(t)
		w := putPolicies(t, r, map[string]string{policy.PolicyLockoutMaxAttempts: "abc"})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body=%s)", w.Code, w.Body.String())
		}
		code, params, errText := decodeEnvelope(t, w)
		if code != "VALIDATION_POLICY_INVALID_VALUE" {
			t.Errorf("code = %q", code)
		}
		if params["key"] != policy.PolicyLockoutMaxAttempts {
			t.Errorf("params[key] = %v, want %s", params["key"], policy.PolicyLockoutMaxAttempts)
		}
		if !strings.Contains(errText, policy.PolicyLockoutMaxAttempts) {
			t.Errorf("zh fallback 未插入鍵名: %q", errText)
		}
		// 不合法的「值」本身不進 wire（只回鍵名，不回顯輸入）
		if strings.Contains(w.Body.String(), "abc") {
			t.Errorf("不合法的值回顯到 wire: %s", w.Body.String())
		}
	})

	t.Run("保留天數低於下限（錄影保留 3 天）", func(t *testing.T) {
		r := setupSecurityPolicyRouter(t)
		w := putPolicies(t, r, map[string]string{policy.PolicyRetentionRecordingDays: "3"})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body=%s)", w.Code, w.Body.String())
		}
		code, params, _ := decodeEnvelope(t, w)
		if code != "VALIDATION_POLICY_INVALID_VALUE" {
			t.Errorf("code = %q", code)
		}
		if params["key"] != policy.PolicyRetentionRecordingDays {
			t.Errorf("params[key] = %v, want %s", params["key"], policy.PolicyRetentionRecordingDays)
		}
	})
}

// TestPolicyInvalidTimezoneKeepsKeyParam 擋：非法時區的錯誤回應丟掉 key 參數，
// 畫面說不出是哪個設定（新鍵未進 policyKeyZhLabels 允許清單時，params 會被整組丟棄）
func TestPolicyInvalidTimezoneKeepsKeyParam(t *testing.T) {
	for _, bad := range []string{"Mars/Olympus", "Local", ""} {
		r := setupSecurityPolicyRouter(t)
		w := putPolicies(t, r, map[string]string{policy.PolicyDailyReviewTimezone: bad})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%q: status = %d, want 400 (body=%s)", bad, w.Code, w.Body.String())
		}
		code, params, _ := decodeEnvelope(t, w)
		if code != "VALIDATION_POLICY_INVALID_VALUE" {
			t.Errorf("%q: code = %q", bad, code)
		}
		if params["key"] != policy.PolicyDailyReviewTimezone {
			t.Errorf("%q: params = %v, want key=daily_review_timezone", bad, params)
		}
	}
}
