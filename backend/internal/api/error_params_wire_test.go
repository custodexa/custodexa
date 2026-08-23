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

// setupDailyReviewRouter 每日審閱 handler 測試環境：真 sqlite＋真政策服務，
// 僅省略 JWT middleware。
func setupDailyReviewRouter(t *testing.T) (*gin.Engine, *gorm.DB) {
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
	if err := db.AutoMigrate(&model.DailyReviewLog{}, &model.AuditLog{},
		&model.CommandAlert{}, &model.SecurityPolicy{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	policies := policy.NewSecurityPolicyService(db)
	if _, err := policies.Update(policy.PolicyDailyReviewEnabled, "true", "test"); err != nil {
		t.Fatalf("啟用每日審閱: %v", err)
	}
	handler := NewDailyReviewHandler(audit.NewDailyReviewService(db, policies, nil))

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/daily-reviews", func(c *gin.Context) {
		c.Set("userID", uint(9))
		c.Set("username", "auditor-b")
		handler.Sign(c)
	})
	return r, db
}

// TestDailyReviewAlreadySignedParamsOnWire 重複簽核帶出既有簽核的時刻與簽核者。
func TestDailyReviewAlreadySignedParamsOnWire(t *testing.T) {
	r, db := setupDailyReviewRouter(t)

	signedAt := time.Now()
	existing := model.DailyReviewLog{
		ReviewDate:   signedAt.Format("2006-01-02"),
		ReviewerID:   7,
		ReviewerName: "auditor-a",
		SnapshotJSON: "{}",
	}
	if err := db.Create(&existing).Error; err != nil {
		t.Fatalf("預置既有簽核: %v", err)
	}
	// CreatedAt 由 gorm 自動填；以落庫後的實際值算出預期 HH:MM
	var stored model.DailyReviewLog
	if err := db.First(&stored, existing.ID).Error; err != nil {
		t.Fatalf("讀回既有簽核: %v", err)
	}
	wantTime := stored.CreatedAt.Format("15:04")

	w := doJSON(r, "POST", "/daily-reviews", map[string]interface{}{"note": "n"})
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (body=%s)", w.Code, w.Body.String())
	}
	code, params, errText := decodeEnvelope(t, w)
	if code != "CONFLICT_DAILY_REVIEW_SIGNED" {
		t.Errorf("code = %q", code)
	}
	if params["signer"] != "auditor-a" {
		t.Errorf("params[signer] = %v, want auditor-a", params["signer"])
	}
	if params["time"] != wantTime {
		t.Errorf("params[time] = %v, want %s", params["time"], wantTime)
	}
	if !strings.Contains(errText, "auditor-a") {
		t.Errorf("zh fallback 未插入簽核者: %q", errText)
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
	if err := db.AutoMigrate(&model.SecurityPolicy{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	handler := NewSecurityPolicyHandler(policy.NewSecurityPolicyService(db), nil)

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
}
