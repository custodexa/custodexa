package api

import (
	"encoding/json"
	"errors"
	"github.com/custodexa/backend/internal/modules/audit"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockCommandAlertService CommandAlertService 的 mock
type MockCommandAlertService struct {
	mock.Mock
}

func (m *MockCommandAlertService) List(filter *audit.CommandAlertFilter) (*audit.CommandAlertListResponse, error) {
	args := m.Called(filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*audit.CommandAlertListResponse), args.Error(1)
}

func (m *MockCommandAlertService) Review(alertID, reviewerID uint, disposition, note string) error {
	args := m.Called(alertID, reviewerID, disposition, note)
	return args.Error(0)
}

func emptyAlertResponse() *audit.CommandAlertListResponse {
	return &audit.CommandAlertListResponse{
		Data: []audit.CommandAlertView{}, Total: 0, Page: 1, PageSize: 20,
	}
}

func TestCommandAlertHandler_List(t *testing.T) {
	t.Run("成功返回告警列表（含 rule_name 快照欄位）", func(t *testing.T) {
		mockService := new(MockCommandAlertService)
		ruleID := uint(7)
		expected := &audit.CommandAlertListResponse{
			Data: []audit.CommandAlertView{
				{CommandAlert: model.CommandAlert{ID: 1, RuleID: &ruleID, RuleName: "遞迴強制刪除", SessionID: 5, UserID: 1,
					Command: "rm -rf /data", Severity: "high", TriggeredAt: time.Now()}, Username: "admin", AssetName: "測試 SSH"},
			},
			Total: 1, Page: 1, PageSize: 20,
		}
		mockService.On("List", mock.Anything).Return(expected, nil)

		handler := NewCommandAlertHandler(mockService)
		router := setupTestRouter()
		router.GET("/command-alerts", handler.List)

		req := httptest.NewRequest("GET", "/command-alerts", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp audit.CommandAlertListResponse
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, int64(1), resp.Total)
		assert.Equal(t, "遞迴強制刪除", resp.Data[0].RuleName)
		assert.Equal(t, "high", resp.Data[0].Severity)
		mockService.AssertExpectations(t)
	})

	t.Run("severity 過濾傳遞至 filter", func(t *testing.T) {
		mockService := new(MockCommandAlertService)
		mockService.On("List", mock.MatchedBy(func(f *audit.CommandAlertFilter) bool {
			return f.Severity == "high"
		})).Return(emptyAlertResponse(), nil)

		handler := NewCommandAlertHandler(mockService)
		router := setupTestRouter()
		router.GET("/command-alerts", handler.List)

		req := httptest.NewRequest("GET", "/command-alerts?severity=high", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("非法 severity 回 400", func(t *testing.T) {
		mockService := new(MockCommandAlertService)

		handler := NewCommandAlertHandler(mockService)
		router := setupTestRouter()
		router.GET("/command-alerts", handler.List)

		req := httptest.NewRequest("GET", "/command-alerts?severity=critical", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertNotCalled(t, "List", mock.Anything)
	})

	t.Run("user_id 與 asset_id 過濾", func(t *testing.T) {
		mockService := new(MockCommandAlertService)
		mockService.On("List", mock.MatchedBy(func(f *audit.CommandAlertFilter) bool {
			return f.UserID != nil && *f.UserID == 3 && f.AssetID != nil && *f.AssetID == 10
		})).Return(emptyAlertResponse(), nil)

		handler := NewCommandAlertHandler(mockService)
		router := setupTestRouter()
		router.GET("/command-alerts", handler.List)

		req := httptest.NewRequest("GET", "/command-alerts?user_id=3&asset_id=10", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("時間範圍過濾", func(t *testing.T) {
		mockService := new(MockCommandAlertService)
		mockService.On("List", mock.MatchedBy(func(f *audit.CommandAlertFilter) bool {
			return f.StartTime != nil && f.EndTime != nil
		})).Return(emptyAlertResponse(), nil)

		handler := NewCommandAlertHandler(mockService)
		router := setupTestRouter()
		router.GET("/command-alerts", handler.List)

		start := time.Now().Add(-time.Hour).Format(time.RFC3339)
		end := time.Now().Format(time.RFC3339)
		req := httptest.NewRequest("GET", "/command-alerts?start_time="+start+"&end_time="+end, nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("分頁參數與預設值", func(t *testing.T) {
		mockService := new(MockCommandAlertService)
		mockService.On("List", mock.MatchedBy(func(f *audit.CommandAlertFilter) bool {
			return f.Page == 2 && f.PageSize == 5
		})).Return(&audit.CommandAlertListResponse{
			Data: []audit.CommandAlertView{}, Total: 12, Page: 2, PageSize: 5,
		}, nil)

		handler := NewCommandAlertHandler(mockService)
		router := setupTestRouter()
		router.GET("/command-alerts", handler.List)

		req := httptest.NewRequest("GET", "/command-alerts?page=2&page_size=5", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp audit.CommandAlertListResponse
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, 2, resp.Page)
		assert.Equal(t, 5, resp.PageSize)
		assert.Equal(t, int64(12), resp.Total)
		mockService.AssertExpectations(t)
	})

	t.Run("無參數時使用預設分頁", func(t *testing.T) {
		mockService := new(MockCommandAlertService)
		mockService.On("List", mock.MatchedBy(func(f *audit.CommandAlertFilter) bool {
			return f.Page == 1 && f.PageSize == 20 && f.Severity == ""
		})).Return(emptyAlertResponse(), nil)

		handler := NewCommandAlertHandler(mockService)
		router := setupTestRouter()
		router.GET("/command-alerts", handler.List)

		req := httptest.NewRequest("GET", "/command-alerts", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("Service 層錯誤回 500", func(t *testing.T) {
		mockService := new(MockCommandAlertService)
		mockService.On("List", mock.Anything).Return(nil, errors.New("db error"))

		handler := NewCommandAlertHandler(mockService)
		router := setupTestRouter()
		router.GET("/command-alerts", handler.List)

		req := httptest.NewRequest("GET", "/command-alerts", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		mockService.AssertExpectations(t)
	})
}

// TestCommandAlertHandler_Review 審閱處置端點（audit-workflows）
func TestCommandAlertHandler_Review(t *testing.T) {
	t.Run("成功審閱回 200 並傳遞處置分類", func(t *testing.T) {
		mockService := new(MockCommandAlertService)
		mockService.On("Review", uint(5), mock.Anything, "escalated", "已通報").Return(nil)

		handler := NewCommandAlertHandler(mockService)
		router := setupTestRouter()
		router.POST("/command-alerts/:id/review", handler.Review)

		body := `{"disposition":"escalated","note":"已通報"}`
		req := httptest.NewRequest("POST", "/command-alerts/5/review", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("非法處置分類回 400", func(t *testing.T) {
		mockService := new(MockCommandAlertService)
		mockService.On("Review", uint(5), mock.Anything, "bogus", "").Return(audit.ErrInvalidDisposition)

		handler := NewCommandAlertHandler(mockService)
		router := setupTestRouter()
		router.POST("/command-alerts/:id/review", handler.Review)

		req := httptest.NewRequest("POST", "/command-alerts/5/review", strings.NewReader(`{"disposition":"bogus"}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("告警不存在回 404", func(t *testing.T) {
		mockService := new(MockCommandAlertService)
		mockService.On("Review", uint(999), mock.Anything, "benign", "").Return(audit.ErrAlertNotFound)

		handler := NewCommandAlertHandler(mockService)
		router := setupTestRouter()
		router.POST("/command-alerts/:id/review", handler.Review)

		req := httptest.NewRequest("POST", "/command-alerts/999/review", strings.NewReader(`{"disposition":"benign"}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("缺 disposition 回 400 不呼叫 service", func(t *testing.T) {
		mockService := new(MockCommandAlertService)

		handler := NewCommandAlertHandler(mockService)
		router := setupTestRouter()
		router.POST("/command-alerts/:id/review", handler.Review)

		req := httptest.NewRequest("POST", "/command-alerts/5/review", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertNotCalled(t, "Review", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})
}

// TestCommandAlertHandler_UnreviewedFilter 未審閱篩選傳遞至 filter
func TestCommandAlertHandler_UnreviewedFilter(t *testing.T) {
	mockService := new(MockCommandAlertService)
	mockService.On("List", mock.MatchedBy(func(f *audit.CommandAlertFilter) bool {
		return f.Unreviewed
	})).Return(emptyAlertResponse(), nil)

	handler := NewCommandAlertHandler(mockService)
	router := setupTestRouter()
	router.GET("/command-alerts", handler.List)

	req := httptest.NewRequest("GET", "/command-alerts?unreviewed=true", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockService.AssertExpectations(t)
}
