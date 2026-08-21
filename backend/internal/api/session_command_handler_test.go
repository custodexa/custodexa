package api

import (
	"encoding/json"
	"errors"
	"github.com/custodexa/backend/internal/modules/audit"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockSessionCommandService SessionCommandService 的 mock
type MockSessionCommandService struct {
	mock.Mock
}

func (m *MockSessionCommandService) ListBySession(sessionID uint) ([]model.SessionCommand, error) {
	args := m.Called(sessionID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.SessionCommand), args.Error(1)
}

func (m *MockSessionCommandService) Search(filter *audit.SessionCommandFilter) (*audit.SessionCommandListResponse, error) {
	args := m.Called(filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*audit.SessionCommandListResponse), args.Error(1)
}

// boolPtr 測試用的取址輔助（degraded 過濾為指標型：nil＝不過濾）
func boolPtr(b bool) *bool { return &b }

// TestSessionCommandHandler_ListBySession 測試單會話指令流
func TestSessionCommandHandler_ListBySession(t *testing.T) {
	t.Run("成功獲取會話指令（按 seq 順序）", func(t *testing.T) {
		mockService := new(MockSessionCommandService)

		commands := []model.SessionCommand{
			{ID: 1, SessionID: 5, UserID: 1, Command: "ls -la", Seq: 1, ExecutedAt: time.Now()},
			{ID: 2, SessionID: 5, UserID: 1, Command: "rm -rf /tmp/x", Seq: 2, ExecutedAt: time.Now()},
		}
		mockService.On("ListBySession", uint(5)).Return(commands, nil)

		handler := NewSessionCommandHandler(mockService)
		router := setupTestRouter()
		router.GET("/sessions/:id/commands", handler.ListBySession)

		req := httptest.NewRequest("GET", "/sessions/5/commands", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response struct {
			Data  []model.SessionCommand `json:"data"`
			Total int                    `json:"total"`
		}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, 2, response.Total)
		assert.Equal(t, "ls -la", response.Data[0].Command)
		assert.Equal(t, 1, response.Data[0].Seq)
		assert.Equal(t, 2, response.Data[1].Seq)

		mockService.AssertExpectations(t)
	})

	t.Run("無指令時返回空列表", func(t *testing.T) {
		mockService := new(MockSessionCommandService)
		mockService.On("ListBySession", uint(9)).Return([]model.SessionCommand{}, nil)

		handler := NewSessionCommandHandler(mockService)
		router := setupTestRouter()
		router.GET("/sessions/:id/commands", handler.ListBySession)

		req := httptest.NewRequest("GET", "/sessions/9/commands", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, float64(0), response["total"])

		mockService.AssertExpectations(t)
	})

	t.Run("無效的 Session ID", func(t *testing.T) {
		mockService := new(MockSessionCommandService)

		handler := NewSessionCommandHandler(mockService)
		router := setupTestRouter()
		router.GET("/sessions/:id/commands", handler.ListBySession)

		req := httptest.NewRequest("GET", "/sessions/invalid/commands", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "VALIDATION_INVALID_SESSION_ID", response["code"])
	})

	t.Run("Service 層錯誤", func(t *testing.T) {
		mockService := new(MockSessionCommandService)
		mockService.On("ListBySession", uint(5)).Return(nil, errors.New("database error"))

		handler := NewSessionCommandHandler(mockService)
		router := setupTestRouter()
		router.GET("/sessions/:id/commands", handler.ListBySession)

		req := httptest.NewRequest("GET", "/sessions/5/commands", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "INTERNAL_SESSION_COMMAND_QUERY", response["code"])

		mockService.AssertExpectations(t)
	})
}

// TestSessionCommandHandler_Search 測試跨會話指令搜尋
func TestSessionCommandHandler_Search(t *testing.T) {
	t.Run("帶 keyword 搜尋", func(t *testing.T) {
		mockService := new(MockSessionCommandService)

		expected := &audit.SessionCommandListResponse{
			Data: []audit.SessionCommandView{
				{SessionCommand: model.SessionCommand{ID: 2, SessionID: 5, UserID: 1, Command: "rm -rf /tmp/x", Seq: 2, ExecutedAt: time.Now()}, Username: "admin", AssetName: "ssh-a"},
				{SessionCommand: model.SessionCommand{ID: 7, SessionID: 8, UserID: 2, Command: "rm old.log", Seq: 1, ExecutedAt: time.Now()}, Username: "bob", AssetName: "ssh-b"},
			},
			Total:    2,
			Page:     1,
			PageSize: 20,
		}
		mockService.On("Search", mock.MatchedBy(func(filter *audit.SessionCommandFilter) bool {
			return filter.Keyword == "rm"
		})).Return(expected, nil)

		handler := NewSessionCommandHandler(mockService)
		router := setupTestRouter()
		router.GET("/commands", handler.Search)

		req := httptest.NewRequest("GET", "/commands?keyword=rm", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response audit.SessionCommandListResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, int64(2), response.Total)
		assert.Equal(t, 2, len(response.Data))

		mockService.AssertExpectations(t)
	})

	// degraded 過濾與 degraded_total 的接線（command-audit-altscreen-bypass）。
	//
	// **未帶 degraded 時 filter.Degraded 必須是 nil**：值型 bool 的零值是 false，
	// 會把「沒指定」靜默變成「只要有文字的列」——降級列整批消失而查詢看起來正常。
	t.Run("degraded 過濾與 degraded_total 回傳", func(t *testing.T) {
		cases := []struct {
			query string
			want  *bool
		}{
			{"", nil},
			{"&degraded=true", boolPtr(true)},
			{"&degraded=false", boolPtr(false)},
			// 無法解析時不套用（回超集而非子集，錯誤在呼叫端看得見）
			{"&degraded=maybe", nil},
		}
		for _, tc := range cases {
			mockService := new(MockSessionCommandService)
			expected := &audit.SessionCommandListResponse{
				Data: []audit.SessionCommandView{}, Total: 0, Page: 1, PageSize: 20,
				DegradedTotal: 9,
			}
			mockService.On("Search", mock.MatchedBy(func(filter *audit.SessionCommandFilter) bool {
				if tc.want == nil {
					return filter.Degraded == nil
				}
				return filter.Degraded != nil && *filter.Degraded == *tc.want
			})).Return(expected, nil)

			handler := NewSessionCommandHandler(mockService)
			router := setupTestRouter()
			router.GET("/commands", handler.Search)

			req := httptest.NewRequest("GET", "/commands?keyword=rm"+tc.query, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code, "query=%q", tc.query)

			var response audit.SessionCommandListResponse
			assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
			assert.Equal(t, int64(9), response.DegradedTotal,
				"degraded_total 未出現在回應中：誠實橫幅拿不到筆數（query=%q）", tc.query)
			mockService.AssertExpectations(t)
		}
	})

	t.Run("帶 user_id 與 asset_id 篩選", func(t *testing.T) {
		mockService := new(MockSessionCommandService)

		expected := &audit.SessionCommandListResponse{
			Data:     []audit.SessionCommandView{},
			Total:    0,
			Page:     1,
			PageSize: 20,
		}
		mockService.On("Search", mock.MatchedBy(func(filter *audit.SessionCommandFilter) bool {
			return filter.UserID != nil && *filter.UserID == 3 &&
				filter.AssetID != nil && *filter.AssetID == 10
		})).Return(expected, nil)

		handler := NewSessionCommandHandler(mockService)
		router := setupTestRouter()
		router.GET("/commands", handler.Search)

		req := httptest.NewRequest("GET", "/commands?user_id=3&asset_id=10", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("帶時間範圍篩選", func(t *testing.T) {
		mockService := new(MockSessionCommandService)

		expected := &audit.SessionCommandListResponse{
			Data:     []audit.SessionCommandView{},
			Total:    0,
			Page:     1,
			PageSize: 20,
		}
		mockService.On("Search", mock.MatchedBy(func(filter *audit.SessionCommandFilter) bool {
			return filter.StartTime != nil && filter.EndTime != nil
		})).Return(expected, nil)

		handler := NewSessionCommandHandler(mockService)
		router := setupTestRouter()
		router.GET("/commands", handler.Search)

		startTime := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
		endTime := time.Now().Format(time.RFC3339)
		req := httptest.NewRequest("GET", "/commands?start_time="+startTime+"&end_time="+endTime, nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("帶分頁參數", func(t *testing.T) {
		mockService := new(MockSessionCommandService)

		expected := &audit.SessionCommandListResponse{
			Data:     []audit.SessionCommandView{},
			Total:    50,
			Page:     3,
			PageSize: 5,
		}
		mockService.On("Search", mock.MatchedBy(func(filter *audit.SessionCommandFilter) bool {
			return filter.Page == 3 && filter.PageSize == 5
		})).Return(expected, nil)

		handler := NewSessionCommandHandler(mockService)
		router := setupTestRouter()
		router.GET("/commands", handler.Search)

		req := httptest.NewRequest("GET", "/commands?page=3&page_size=5", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response audit.SessionCommandListResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, 3, response.Page)
		assert.Equal(t, 5, response.PageSize)
		assert.Equal(t, int64(50), response.Total)

		mockService.AssertExpectations(t)
	})

	t.Run("無參數時使用預設分頁", func(t *testing.T) {
		mockService := new(MockSessionCommandService)

		expected := &audit.SessionCommandListResponse{
			Data:     []audit.SessionCommandView{},
			Total:    0,
			Page:     1,
			PageSize: 20,
		}
		mockService.On("Search", mock.MatchedBy(func(filter *audit.SessionCommandFilter) bool {
			return filter.Page == 1 && filter.PageSize == 20 && filter.Keyword == ""
		})).Return(expected, nil)

		handler := NewSessionCommandHandler(mockService)
		router := setupTestRouter()
		router.GET("/commands", handler.Search)

		req := httptest.NewRequest("GET", "/commands", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("Service 層錯誤", func(t *testing.T) {
		mockService := new(MockSessionCommandService)
		mockService.On("Search", mock.AnythingOfType("*audit.SessionCommandFilter")).
			Return(nil, errors.New("database error"))

		handler := NewSessionCommandHandler(mockService)
		router := setupTestRouter()
		router.GET("/commands", handler.Search)

		req := httptest.NewRequest("GET", "/commands", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "INTERNAL_SESSION_COMMAND_SEARCH", response["code"])

		mockService.AssertExpectations(t)
	})
}
