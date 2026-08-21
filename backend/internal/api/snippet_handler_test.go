package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockSnippetService struct {
	mock.Mock
}

func (m *MockSnippetService) List(userID uint) ([]model.Snippet, error) {
	args := m.Called(userID)
	return args.Get(0).([]model.Snippet), args.Error(1)
}

func (m *MockSnippetService) Create(userID uint, req *session.SnippetRequest) (*model.Snippet, error) {
	args := m.Called(userID, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Snippet), args.Error(1)
}

func (m *MockSnippetService) Update(userID, id uint, req *session.SnippetRequest) (*model.Snippet, error) {
	args := m.Called(userID, id, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Snippet), args.Error(1)
}

func (m *MockSnippetService) Delete(userID, id uint) error {
	return m.Called(userID, id).Error(0)
}

// snippetTestRouter 以固定 userID 模擬認證 context
func snippetTestRouter(h *SnippetHandler, userID uint) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", userID)
		c.Next()
	})
	r.GET("/snippets", h.List)
	r.POST("/snippets", h.Create)
	r.PUT("/snippets/:id", h.Update)
	r.DELETE("/snippets/:id", h.Delete)
	return r
}

func TestSnippetHandler_List(t *testing.T) {
	mockSvc := new(MockSnippetService)
	mockSvc.On("List", uint(7)).Return([]model.Snippet{
		{ID: 1, UserID: 7, Name: "top", Content: "top -c"},
	}, nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/snippets", nil)
	snippetTestRouter(NewSnippetHandler(mockSvc), 7).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, float64(1), resp["total"])
	mockSvc.AssertExpectations(t)
}

func TestSnippetHandler_Create(t *testing.T) {
	t.Run("成功建立", func(t *testing.T) {
		mockSvc := new(MockSnippetService)
		mockSvc.On("Create", uint(7), mock.Anything).Return(&model.Snippet{ID: 2, UserID: 7, Name: "ll", Content: "ls -al"}, nil)

		body, _ := json.Marshal(map[string]string{"name": "ll", "content": "ls -al"})
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/snippets", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		snippetTestRouter(NewSnippetHandler(mockSvc), 7).ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("內容超長回 400", func(t *testing.T) {
		mockSvc := new(MockSnippetService)
		mockSvc.On("Create", uint(7), mock.Anything).Return(nil, session.ErrSnippetTooLong)

		body, _ := json.Marshal(map[string]string{"name": "x", "content": "y"})
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/snippets", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		snippetTestRouter(NewSnippetHandler(mockSvc), 7).ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("缺欄位回 400", func(t *testing.T) {
		mockSvc := new(MockSnippetService)
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/snippets", bytes.NewBufferString("{}"))
		req.Header.Set("Content-Type", "application/json")
		snippetTestRouter(NewSnippetHandler(mockSvc), 7).ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestSnippetHandler_Delete(t *testing.T) {
	t.Run("越權刪除他人片段回 404", func(t *testing.T) {
		mockSvc := new(MockSnippetService)
		mockSvc.On("Delete", uint(7), uint(99)).Return(session.ErrSnippetNotFound)

		w := httptest.NewRecorder()
		req := httptest.NewRequest("DELETE", "/snippets/99", nil)
		snippetTestRouter(NewSnippetHandler(mockSvc), 7).ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		var resp map[string]string
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "片段不存在", resp["error"])
	})

	t.Run("成功刪除", func(t *testing.T) {
		mockSvc := new(MockSnippetService)
		mockSvc.On("Delete", uint(7), uint(2)).Return(nil)

		w := httptest.NewRecorder()
		req := httptest.NewRequest("DELETE", "/snippets/2", nil)
		snippetTestRouter(NewSnippetHandler(mockSvc), 7).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}
