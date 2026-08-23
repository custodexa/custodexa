package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockSessionService SessionService 的 mock
type MockSessionService struct {
	mock.Mock
}

func (m *MockSessionService) List(filter *session.SessionFilter) (*session.SessionListResponse, error) {
	args := m.Called(filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*session.SessionListResponse), args.Error(1)
}

func (m *MockSessionService) GetByID(id uint) (*model.Session, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Session), args.Error(1)
}

func (m *MockSessionService) GetBySessionID(sessionID string) (*model.Session, error) {
	args := m.Called(sessionID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Session), args.Error(1)
}

func (m *MockSessionService) GetActiveSessions() ([]model.Session, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Session), args.Error(1)
}

func (m *MockSessionService) Terminate(id uint, reason string) error {
	args := m.Called(id, reason)
	return args.Error(0)
}

func (m *MockSessionService) GetStatistics() (map[string]interface{}, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockSessionService) Create(sess *model.Session) error {
	args := m.Called(sess)
	return args.Error(0)
}

func (m *MockSessionService) Close(id uint) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockSessionService) CloseBySessionID(sessionID string) error {
	args := m.Called(sessionID)
	return args.Error(0)
}

func (m *MockSessionService) UpdateRecording(id uint, recordingPath string, recordingSize int64) error {
	args := m.Called(id, recordingPath, recordingSize)
	return args.Error(0)
}

// TestSessionHandler_List 測試會話列表
func TestSessionHandler_List(t *testing.T) {
	t.Run("成功獲取會話列表", func(t *testing.T) {
		mockSessionService := new(MockSessionService)

		expectedResponse := &session.SessionListResponse{
			Data: []model.Session{
				{
					ID:        1,
					SessionID: "sess_1",
					Status:    model.SessionStatusActive,
					Protocol:  model.ProtocolSSH,
					UserID:    1,
					ClientIP:  "192.168.1.1",
					StartTime: time.Now(),
				},
				{
					ID:        2,
					SessionID: "sess_2",
					Status:    model.SessionStatusClosed,
					Protocol:  model.ProtocolRDP,
					UserID:    2,
					ClientIP:  "192.168.1.2",
					StartTime: time.Now(),
				},
			},
			Total:    2,
			Page:     1,
			PageSize: 20,
		}
		mockSessionService.On("List", mock.AnythingOfType("*session.SessionFilter")).
			Return(expectedResponse, nil)

		handler := NewSessionHandler(mockSessionService)
		router := setupTestRouter()
		router.GET("/sessions", handler.List)

		req := httptest.NewRequest("GET", "/sessions", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response session.SessionListResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, 2, len(response.Data))
		assert.Equal(t, int64(2), response.Total)

		mockSessionService.AssertExpectations(t)
	})

	t.Run("帶 status 篩選", func(t *testing.T) {
		mockSessionService := new(MockSessionService)

		expectedResponse := &session.SessionListResponse{
			Data: []model.Session{
				{
					ID:        1,
					SessionID: "sess_1",
					Status:    model.SessionStatusActive,
					Protocol:  model.ProtocolSSH,
					UserID:    1,
					ClientIP:  "192.168.1.1",
					StartTime: time.Now(),
				},
			},
			Total:    1,
			Page:     1,
			PageSize: 20,
		}
		mockSessionService.On("List", mock.MatchedBy(func(filter *session.SessionFilter) bool {
			return filter.Status == model.SessionStatusActive
		})).Return(expectedResponse, nil)

		handler := NewSessionHandler(mockSessionService)
		router := setupTestRouter()
		router.GET("/sessions", handler.List)

		req := httptest.NewRequest("GET", "/sessions?status=active", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response session.SessionListResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(response.Data))
		assert.Equal(t, model.SessionStatusActive, response.Data[0].Status)

		mockSessionService.AssertExpectations(t)
	})

	t.Run("帶 user_id 篩選", func(t *testing.T) {
		mockSessionService := new(MockSessionService)

		expectedResponse := &session.SessionListResponse{
			Data: []model.Session{
				{
					ID:        1,
					SessionID: "sess_1",
					Status:    model.SessionStatusActive,
					Protocol:  model.ProtocolSSH,
					UserID:    1,
					ClientIP:  "192.168.1.1",
					StartTime: time.Now(),
				},
			},
			Total:    1,
			Page:     1,
			PageSize: 20,
		}
		mockSessionService.On("List", mock.MatchedBy(func(filter *session.SessionFilter) bool {
			return filter.UserID != nil && *filter.UserID == 1
		})).Return(expectedResponse, nil)

		handler := NewSessionHandler(mockSessionService)
		router := setupTestRouter()
		router.GET("/sessions", handler.List)

		req := httptest.NewRequest("GET", "/sessions?user_id=1", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response session.SessionListResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(response.Data))
		assert.Equal(t, uint(1), response.Data[0].UserID)

		mockSessionService.AssertExpectations(t)
	})

	t.Run("帶分頁參數", func(t *testing.T) {
		mockSessionService := new(MockSessionService)

		expectedResponse := &session.SessionListResponse{
			Data:     []model.Session{},
			Total:    100,
			Page:     2,
			PageSize: 10,
		}
		mockSessionService.On("List", mock.MatchedBy(func(filter *session.SessionFilter) bool {
			return filter.Page == 2 && filter.PageSize == 10
		})).Return(expectedResponse, nil)

		handler := NewSessionHandler(mockSessionService)
		router := setupTestRouter()
		router.GET("/sessions", handler.List)

		req := httptest.NewRequest("GET", "/sessions?page=2&page_size=10", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response session.SessionListResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, 2, response.Page)
		assert.Equal(t, 10, response.PageSize)

		mockSessionService.AssertExpectations(t)
	})

	t.Run("帶 protocol 篩選", func(t *testing.T) {
		mockSessionService := new(MockSessionService)

		expectedResponse := &session.SessionListResponse{
			Data: []model.Session{
				{
					ID:        1,
					SessionID: "sess_1",
					Status:    model.SessionStatusActive,
					Protocol:  model.ProtocolSSH,
					UserID:    1,
					ClientIP:  "192.168.1.1",
					StartTime: time.Now(),
				},
			},
			Total:    1,
			Page:     1,
			PageSize: 20,
		}
		mockSessionService.On("List", mock.MatchedBy(func(filter *session.SessionFilter) bool {
			return filter.Protocol == model.ProtocolSSH
		})).Return(expectedResponse, nil)

		handler := NewSessionHandler(mockSessionService)
		router := setupTestRouter()
		router.GET("/sessions", handler.List)

		req := httptest.NewRequest("GET", "/sessions?protocol=ssh", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response session.SessionListResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(response.Data))
		assert.Equal(t, model.ProtocolSSH, response.Data[0].Protocol)

		mockSessionService.AssertExpectations(t)
	})

	t.Run("帶 asset_id 篩選", func(t *testing.T) {
		mockSessionService := new(MockSessionService)

		assetID := uint(10)
		expectedResponse := &session.SessionListResponse{
			Data: []model.Session{
				{
					ID:        1,
					SessionID: "sess_1",
					Status:    model.SessionStatusActive,
					Protocol:  model.ProtocolSSH,
					UserID:    1,
					AssetID:   &assetID,
					ClientIP:  "192.168.1.1",
					StartTime: time.Now(),
				},
			},
			Total:    1,
			Page:     1,
			PageSize: 20,
		}
		mockSessionService.On("List", mock.MatchedBy(func(filter *session.SessionFilter) bool {
			return filter.AssetID != nil && *filter.AssetID == 10
		})).Return(expectedResponse, nil)

		handler := NewSessionHandler(mockSessionService)
		router := setupTestRouter()
		router.GET("/sessions", handler.List)

		req := httptest.NewRequest("GET", "/sessions?asset_id=10", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response session.SessionListResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(response.Data))

		mockSessionService.AssertExpectations(t)
	})

	t.Run("帶時間範圍篩選", func(t *testing.T) {
		mockSessionService := new(MockSessionService)

		expectedResponse := &session.SessionListResponse{
			Data:     []model.Session{},
			Total:    0,
			Page:     1,
			PageSize: 20,
		}
		mockSessionService.On("List", mock.MatchedBy(func(filter *session.SessionFilter) bool {
			return filter.StartTime != nil && filter.EndTime != nil
		})).Return(expectedResponse, nil)

		handler := NewSessionHandler(mockSessionService)
		router := setupTestRouter()
		router.GET("/sessions", handler.List)

		startTime := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
		endTime := time.Now().Format(time.RFC3339)
		req := httptest.NewRequest("GET", "/sessions?start_time="+startTime+"&end_time="+endTime, nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		mockSessionService.AssertExpectations(t)
	})

	t.Run("Service 層錯誤", func(t *testing.T) {
		mockSessionService := new(MockSessionService)

		mockSessionService.On("List", mock.AnythingOfType("*session.SessionFilter")).
			Return(nil, errors.New("database error"))

		handler := NewSessionHandler(mockSessionService)
		router := setupTestRouter()
		router.GET("/sessions", handler.List)

		req := httptest.NewRequest("GET", "/sessions", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "INTERNAL_SESSION_ADMIN_QUERY", response["code"])

		mockSessionService.AssertExpectations(t)
	})
}

// TestSessionHandler_Get 測試獲取會話詳情
func TestSessionHandler_Get(t *testing.T) {
	t.Run("成功獲取會話詳情", func(t *testing.T) {
		mockSessionService := new(MockSessionService)

		sess := &model.Session{
			ID:        1,
			SessionID: "sess_1",
			Status:    model.SessionStatusActive,
			Protocol:  model.ProtocolSSH,
			UserID:    1,
			ClientIP:  "192.168.1.1",
			StartTime: time.Now(),
		}
		mockSessionService.On("GetByID", uint(1)).Return(sess, nil)

		handler := NewSessionHandler(mockSessionService)
		router := setupTestRouter()
		router.GET("/sessions/:id", handler.Get)

		req := httptest.NewRequest("GET", "/sessions/1", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response model.Session
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "sess_1", response.SessionID)
		assert.Equal(t, model.SessionStatusActive, response.Status)

		mockSessionService.AssertExpectations(t)
	})

	t.Run("無效的會話 ID", func(t *testing.T) {
		mockSessionService := new(MockSessionService)

		handler := NewSessionHandler(mockSessionService)
		router := setupTestRouter()
		router.GET("/sessions/:id", handler.Get)

		req := httptest.NewRequest("GET", "/sessions/invalid", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "VALIDATION_INVALID_SESSION_ID", response["code"])
	})

	t.Run("會話不存在（404）", func(t *testing.T) {
		mockSessionService := new(MockSessionService)

		mockSessionService.On("GetByID", uint(999)).Return(nil, session.ErrSessionNotFound)

		handler := NewSessionHandler(mockSessionService)
		router := setupTestRouter()
		router.GET("/sessions/:id", handler.Get)

		req := httptest.NewRequest("GET", "/sessions/999", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "NOTFOUND_SESSION", response["code"])

		mockSessionService.AssertExpectations(t)
	})

	t.Run("Service 層錯誤", func(t *testing.T) {
		mockSessionService := new(MockSessionService)

		mockSessionService.On("GetByID", uint(1)).Return(nil, errors.New("database error"))

		handler := NewSessionHandler(mockSessionService)
		router := setupTestRouter()
		router.GET("/sessions/:id", handler.Get)

		req := httptest.NewRequest("GET", "/sessions/1", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "INTERNAL_SESSION_ADMIN_QUERY", response["code"])

		mockSessionService.AssertExpectations(t)
	})
}

// TestSessionHandler_GetActive 測試獲取活動會話
func TestSessionHandler_GetActive(t *testing.T) {
	t.Run("成功獲取活動會話", func(t *testing.T) {
		mockSessionService := new(MockSessionService)

		activeSessions := []model.Session{
			{
				ID:        1,
				SessionID: "sess_1",
				Status:    model.SessionStatusActive,
				Protocol:  model.ProtocolSSH,
				UserID:    1,
				ClientIP:  "192.168.1.1",
				StartTime: time.Now(),
			},
			{
				ID:        2,
				SessionID: "sess_2",
				Status:    model.SessionStatusActive,
				Protocol:  model.ProtocolRDP,
				UserID:    2,
				ClientIP:  "192.168.1.2",
				StartTime: time.Now(),
			},
		}
		mockSessionService.On("GetActiveSessions").Return(activeSessions, nil)

		handler := NewSessionHandler(mockSessionService)
		router := setupTestRouter()
		router.GET("/sessions/active", handler.GetActive)

		req := httptest.NewRequest("GET", "/sessions/active", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response []model.Session
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, 2, len(response))
		assert.Equal(t, model.SessionStatusActive, response[0].Status)
		assert.Equal(t, model.SessionStatusActive, response[1].Status)

		mockSessionService.AssertExpectations(t)
	})

	t.Run("Service 層錯誤", func(t *testing.T) {
		mockSessionService := new(MockSessionService)

		mockSessionService.On("GetActiveSessions").
			Return(nil, errors.New("database error"))

		handler := NewSessionHandler(mockSessionService)
		router := setupTestRouter()
		router.GET("/sessions/active", handler.GetActive)

		req := httptest.NewRequest("GET", "/sessions/active", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "INTERNAL_SESSION_ACTIVE_QUERY", response["code"])

		mockSessionService.AssertExpectations(t)
	})
}

// TestSessionHandler_GetStatistics 測試獲取統計資訊
func TestSessionHandler_GetStatistics(t *testing.T) {
	t.Run("成功獲取統計資訊", func(t *testing.T) {
		mockSessionService := new(MockSessionService)

		stats := map[string]interface{}{
			"active_sessions": int64(5),
			"today_sessions":  int64(25),
			"total_sessions":  int64(150),
		}
		mockSessionService.On("GetStatistics").Return(stats, nil)

		handler := NewSessionHandler(mockSessionService)
		router := setupTestRouter()
		router.GET("/sessions/statistics", handler.GetStatistics)

		req := httptest.NewRequest("GET", "/sessions/statistics", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, float64(5), response["active_sessions"])
		assert.Equal(t, float64(25), response["today_sessions"])
		assert.Equal(t, float64(150), response["total_sessions"])

		mockSessionService.AssertExpectations(t)
	})

	t.Run("Service 層錯誤", func(t *testing.T) {
		mockSessionService := new(MockSessionService)

		mockSessionService.On("GetStatistics").
			Return(nil, errors.New("database error"))

		handler := NewSessionHandler(mockSessionService)
		router := setupTestRouter()
		router.GET("/sessions/statistics", handler.GetStatistics)

		req := httptest.NewRequest("GET", "/sessions/statistics", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "INTERNAL_SESSION_STATISTICS", response["code"])

		mockSessionService.AssertExpectations(t)
	})
}

// TestSessionHandler_Terminate 測試終止會話
func TestSessionHandler_Terminate(t *testing.T) {
	t.Run("成功終止會話（管理員權限）", func(t *testing.T) {
		mockSessionService := new(MockSessionService)

		mockSessionService.On("Terminate", uint(1), model.EndReasonAdminTerminate).Return(nil)

		handler := NewSessionHandler(mockSessionService)
		router := setupTestRouter()
		router.POST("/sessions/:id/terminate", func(c *gin.Context) {
			// 模擬認證中間件設定 role
			c.Set("role", "admin")
			handler.Terminate(c)
		})

		req := httptest.NewRequest("POST", "/sessions/1/terminate", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// 成功回應 message 中文欄已移除：前端改走自有 $t 成功文案，
		// payload 不再攜帶 UI 文案，僅驗證空物件形狀
		assert.Equal(t, "{}", w.Body.String())

		mockSessionService.AssertExpectations(t)
	})

	t.Run("無效的會話 ID", func(t *testing.T) {
		mockSessionService := new(MockSessionService)

		handler := NewSessionHandler(mockSessionService)
		router := setupTestRouter()
		router.POST("/sessions/:id/terminate", func(c *gin.Context) {
			c.Set("role", "admin")
			handler.Terminate(c)
		})

		req := httptest.NewRequest("POST", "/sessions/invalid/terminate", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "VALIDATION_INVALID_SESSION_ID", response["code"])
	})

	t.Run("會話不存在（404）", func(t *testing.T) {
		mockSessionService := new(MockSessionService)

		mockSessionService.On("Terminate", uint(999), model.EndReasonAdminTerminate).Return(session.ErrSessionNotFound)

		handler := NewSessionHandler(mockSessionService)
		router := setupTestRouter()
		router.POST("/sessions/:id/terminate", func(c *gin.Context) {
			c.Set("role", "admin")
			handler.Terminate(c)
		})

		req := httptest.NewRequest("POST", "/sessions/999/terminate", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "NOTFOUND_SESSION", response["code"])

		mockSessionService.AssertExpectations(t)
	})

	t.Run("會話已關閉", func(t *testing.T) {
		mockSessionService := new(MockSessionService)

		mockSessionService.On("Terminate", uint(1), model.EndReasonAdminTerminate).Return(session.ErrSessionAlreadyClosed)

		handler := NewSessionHandler(mockSessionService)
		router := setupTestRouter()
		router.POST("/sessions/:id/terminate", func(c *gin.Context) {
			c.Set("role", "admin")
			handler.Terminate(c)
		})

		req := httptest.NewRequest("POST", "/sessions/1/terminate", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "RULE_SESSION_CLOSED", response["code"])

		mockSessionService.AssertExpectations(t)
	})

	t.Run("未認證（無 role）", func(t *testing.T) {
		mockSessionService := new(MockSessionService)

		handler := NewSessionHandler(mockSessionService)
		router := setupTestRouter()
		router.POST("/sessions/:id/terminate", handler.Terminate)

		req := httptest.NewRequest("POST", "/sessions/1/terminate", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "AUTH_UNAUTHENTICATED", response["code"])
	})

	t.Run("權限不足（非管理員）", func(t *testing.T) {
		mockSessionService := new(MockSessionService)

		handler := NewSessionHandler(mockSessionService)
		router := setupTestRouter()
		router.POST("/sessions/:id/terminate", func(c *gin.Context) {
			c.Set("role", "user")
			handler.Terminate(c)
		})

		req := httptest.NewRequest("POST", "/sessions/1/terminate", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "AUTH_SESSION_TERMINATE_ADMIN_ONLY", response["code"])
	})

	t.Run("Service 層錯誤", func(t *testing.T) {
		mockSessionService := new(MockSessionService)

		mockSessionService.On("Terminate", uint(1), model.EndReasonAdminTerminate).
			Return(errors.New("database error"))

		handler := NewSessionHandler(mockSessionService)
		router := setupTestRouter()
		router.POST("/sessions/:id/terminate", func(c *gin.Context) {
			c.Set("role", "admin")
			handler.Terminate(c)
		})

		req := httptest.NewRequest("POST", "/sessions/1/terminate", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "INTERNAL_SESSION_TERMINATE", response["code"])

		mockSessionService.AssertExpectations(t)
	})
}
