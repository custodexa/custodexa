package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/audit"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockAlertRuleService AlertRuleService 的 mock
type MockAlertRuleService struct {
	mock.Mock
}

func (m *MockAlertRuleService) List() ([]model.AlertRule, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.AlertRule), args.Error(1)
}

func (m *MockAlertRuleService) Create(req *audit.AlertRuleRequest) (*model.AlertRule, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.AlertRule), args.Error(1)
}

func (m *MockAlertRuleService) Update(id uint, req *audit.AlertRuleRequest) (*model.AlertRule, error) {
	args := m.Called(id, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.AlertRule), args.Error(1)
}

func (m *MockAlertRuleService) Delete(id uint) error {
	return m.Called(id).Error(0)
}

func TestAlertRuleHandler_List(t *testing.T) {
	t.Run("成功列出規則", func(t *testing.T) {
		mockService := new(MockAlertRuleService)
		mockService.On("List").Return([]model.AlertRule{
			{ID: 1, Name: "遞迴強制刪除", Pattern: `rm\s+-(rf|fr)\b`, Severity: "high", Enabled: true},
			{ID: 2, Name: "格式化檔案系統", Pattern: `\bmkfs`, Severity: "high", Enabled: false},
		}, nil)

		handler := NewAlertRuleHandler(mockService)
		router := setupTestRouter()
		router.GET("/alert-rules", handler.List)

		req := httptest.NewRequest("GET", "/alert-rules", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp struct {
			Data  []model.AlertRule `json:"data"`
			Total int               `json:"total"`
		}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, 2, resp.Total)
		assert.Equal(t, "遞迴強制刪除", resp.Data[0].Name)
		mockService.AssertExpectations(t)
	})

	t.Run("Service 層錯誤回 500", func(t *testing.T) {
		mockService := new(MockAlertRuleService)
		mockService.On("List").Return(nil, errors.New("db error"))

		handler := NewAlertRuleHandler(mockService)
		router := setupTestRouter()
		router.GET("/alert-rules", handler.List)

		req := httptest.NewRequest("GET", "/alert-rules", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		mockService.AssertExpectations(t)
	})
}

func TestAlertRuleHandler_Create(t *testing.T) {
	t.Run("成功建立回 201", func(t *testing.T) {
		mockService := new(MockAlertRuleService)
		created := &model.AlertRule{ID: 9, Name: "test", Pattern: `\btest\b`, Severity: "low", Enabled: true}
		mockService.On("Create", mock.MatchedBy(func(req *audit.AlertRuleRequest) bool {
			return req.Name == "test" && req.Pattern == `\btest\b` && req.Severity == "low"
		})).Return(created, nil)

		handler := NewAlertRuleHandler(mockService)
		router := setupTestRouter()
		router.POST("/alert-rules", handler.Create)

		body, _ := json.Marshal(map[string]interface{}{
			"name": "test", "pattern": `\btest\b`, "severity": "low",
		})
		req := httptest.NewRequest("POST", "/alert-rules", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var resp model.AlertRule
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, uint(9), resp.ID)
		mockService.AssertExpectations(t)
	})

	t.Run("無效 regex 回 400 並帶碼（碼化後不再外洩 regex 編譯器原文）", func(t *testing.T) {
		mockService := new(MockAlertRuleService)
		// service 層以 %w 包裝編譯錯誤原文；errors.Is 仍能命中 sentinel，
		// 但回應只帶固定碼＋zh fallback，不含 "missing closing" 等內部細節
		mockService.On("Create", mock.Anything).
			Return(nil, fmt.Errorf("%w: error parsing regexp: missing closing )", audit.ErrInvalidPattern))

		handler := NewAlertRuleHandler(mockService)
		router := setupTestRouter()
		router.POST("/alert-rules", handler.Create)

		body, _ := json.Marshal(map[string]interface{}{
			"name": "bad", "pattern": "rm -rf (", "severity": "high",
		})
		req := httptest.NewRequest("POST", "/alert-rules", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var resp map[string]string
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, string(apierror.CodeInvalidAlertPattern), resp["code"])
		assert.Contains(t, resp["error"], "regex pattern 無效")
		assert.NotContains(t, resp["error"], "missing closing")
		mockService.AssertExpectations(t)
	})

	// 409 而非 400：與 CONFLICT_ASSET_NAME／CONFLICT_ACCOUNT_USERNAME 同形，
	// 讓呼叫端能單憑狀態碼分流「送錯東西」與「既有資源同名」。
	// 狀態碼與碼皆以 Equal 精確斷言（非「不是 2xx」之類的鬆判定），
	// 故任一側被改動都會轉紅。
	t.Run("名稱已存在回 409 並帶碼（唯一索引違反轉譯）", func(t *testing.T) {
		mockService := new(MockAlertRuleService)
		mockService.On("Create", mock.Anything).Return(nil, audit.ErrAlertRuleNameExists)

		handler := NewAlertRuleHandler(mockService)
		router := setupTestRouter()
		router.POST("/alert-rules", handler.Create)

		body, _ := json.Marshal(map[string]interface{}{
			"name": "危險刪除", "pattern": `rm\s+-rf`, "severity": "high",
		})
		req := httptest.NewRequest("POST", "/alert-rules", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
		var resp map[string]string
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, string(apierror.CodeAlertRuleNameExists), resp["code"])
		assert.Equal(t, "告警規則名稱已存在", resp["error"])
		assertNoDBDetailInBody(t, w.Body.String())
		mockService.AssertExpectations(t)
	})

	t.Run("非法 severity 回 400", func(t *testing.T) {
		mockService := new(MockAlertRuleService)
		mockService.On("Create", mock.Anything).Return(nil, audit.ErrInvalidSeverity)

		handler := NewAlertRuleHandler(mockService)
		router := setupTestRouter()
		router.POST("/alert-rules", handler.Create)

		body, _ := json.Marshal(map[string]interface{}{
			"name": "bad", "pattern": "x", "severity": "critical",
		})
		req := httptest.NewRequest("POST", "/alert-rules", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("缺必填欄位回 400（binding 驗證）", func(t *testing.T) {
		mockService := new(MockAlertRuleService)

		handler := NewAlertRuleHandler(mockService)
		router := setupTestRouter()
		router.POST("/alert-rules", handler.Create)

		body, _ := json.Marshal(map[string]interface{}{"name": "only-name"})
		req := httptest.NewRequest("POST", "/alert-rules", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		// service 不應被觸及：binding 在 handler 層就擋下
		mockService.AssertNotCalled(t, "Create", mock.Anything)
	})
}

func TestAlertRuleHandler_Update(t *testing.T) {
	t.Run("成功更新回 200", func(t *testing.T) {
		mockService := new(MockAlertRuleService)
		updated := &model.AlertRule{ID: 3, Name: "renamed", Pattern: `\bmkfs`, Severity: "medium", Enabled: false}
		mockService.On("Update", uint(3), mock.Anything).Return(updated, nil)

		handler := NewAlertRuleHandler(mockService)
		router := setupTestRouter()
		router.PUT("/alert-rules/:id", handler.Update)

		body, _ := json.Marshal(map[string]interface{}{
			"name": "renamed", "pattern": `\bmkfs`, "severity": "medium", "enabled": false,
		})
		req := httptest.NewRequest("PUT", "/alert-rules/3", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("規則不存在回 404", func(t *testing.T) {
		mockService := new(MockAlertRuleService)
		mockService.On("Update", uint(99), mock.Anything).Return(nil, audit.ErrAlertRuleNotFound)

		handler := NewAlertRuleHandler(mockService)
		router := setupTestRouter()
		router.PUT("/alert-rules/:id", handler.Update)

		body, _ := json.Marshal(map[string]interface{}{
			"name": "x", "pattern": "x", "severity": "low",
		})
		req := httptest.NewRequest("PUT", "/alert-rules/99", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("改名撞既有規則回 409 並帶碼", func(t *testing.T) {
		mockService := new(MockAlertRuleService)
		mockService.On("Update", uint(3), mock.Anything).Return(nil, audit.ErrAlertRuleNameExists)

		handler := NewAlertRuleHandler(mockService)
		router := setupTestRouter()
		router.PUT("/alert-rules/:id", handler.Update)

		body, _ := json.Marshal(map[string]interface{}{
			"name": "規則甲", "pattern": `\bmkfs`, "severity": "medium",
		})
		req := httptest.NewRequest("PUT", "/alert-rules/3", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
		var resp map[string]string
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, string(apierror.CodeAlertRuleNameExists), resp["code"])
		assertNoDBDetailInBody(t, w.Body.String())
		mockService.AssertExpectations(t)
	})

	t.Run("無效 ID 回 400", func(t *testing.T) {
		mockService := new(MockAlertRuleService)

		handler := NewAlertRuleHandler(mockService)
		router := setupTestRouter()
		router.PUT("/alert-rules/:id", handler.Update)

		req := httptest.NewRequest("PUT", "/alert-rules/abc", bytes.NewReader([]byte("{}")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// assertNoDBDetailInBody 名稱衝突的回應必須收斂：拒絕的原因只進審計與伺服端
// 日誌，資料庫層細節（表名／索引名／SQL 動詞／驅動碼）一律不得出現在 wire 上。
func assertNoDBDetailInBody(t *testing.T, body string) {
	t.Helper()
	lower := strings.ToLower(body)
	for _, leak := range []string{
		"alert_rules", "uniq_", "unique", "constraint", "sqlstate", "23505",
		"insert into", "duplicate key",
	} {
		if strings.Contains(lower, leak) {
			t.Errorf("回應外洩資料庫層細節 %q: %s", leak, body)
		}
	}
}

func TestAlertRuleHandler_Delete(t *testing.T) {
	t.Run("成功刪除回 200", func(t *testing.T) {
		mockService := new(MockAlertRuleService)
		mockService.On("Delete", uint(5)).Return(nil)

		handler := NewAlertRuleHandler(mockService)
		router := setupTestRouter()
		router.DELETE("/alert-rules/:id", handler.Delete)

		req := httptest.NewRequest("DELETE", "/alert-rules/5", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("規則不存在回 404", func(t *testing.T) {
		mockService := new(MockAlertRuleService)
		mockService.On("Delete", uint(99)).Return(audit.ErrAlertRuleNotFound)

		handler := NewAlertRuleHandler(mockService)
		router := setupTestRouter()
		router.DELETE("/alert-rules/:id", handler.Delete)

		req := httptest.NewRequest("DELETE", "/alert-rules/99", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		mockService.AssertExpectations(t)
	})
}
