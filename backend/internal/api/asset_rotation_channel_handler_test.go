package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/modules/asset"
)

// 改密通道的兩個 sentinel 在 handler 層映射為 400 帶機器碼（未映射時會落到 default 回 500）。
func TestAssetHandlerRotationChannelErrorsAre400(t *testing.T) {
	decode := func(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
		t.Helper()
		var body map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		return body
	}

	t.Run("Create 通道不相容回 VALIDATION_ASSET_ROTATION_CHANNEL", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAssetService.On("Create", mock.Anything).Return(nil, asset.ErrInvalidRotationChannel)
		handler := NewAssetHandler(mockAssetService, new(MockAssetAuthorizationService), nil)
		router := setupTestRouter()
		router.POST("/assets", func(c *gin.Context) {
			c.Set("userID", uint(7))
			handler.Create(c)
		})
		body := `{"name":"win","host":"h","port":3389,"protocol":"mysql","username":"u","password":"p","rotation_channel":"windows_winrm"}`
		req := httptest.NewRequest("POST", "/assets", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "VALIDATION_ASSET_ROTATION_CHANNEL", decode(t, w)["code"])
	})

	t.Run("Update 通道參數不合回 VALIDATION_ASSET_ROTATION_CHANNEL_PARAMS", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAssetService.On("Update", mock.Anything, uint(1), mock.AnythingOfType("*asset.UpdateAssetRequest")).
			Return(nil, asset.ErrInvalidRotationChannelParams)
		handler := NewAssetHandler(mockAssetService, new(MockAssetAuthorizationService), nil)
		router := setupTestRouter()
		router.PUT("/assets/:id", func(c *gin.Context) {
			c.Set("userID", uint(1))
			c.Set("username", "testuser")
			handler.Update(c)
		})
		body := `{"rotation_channel":"windows_winrm","winrm_scheme":"https"}`
		req := httptest.NewRequest("PUT", "/assets/1", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "VALIDATION_ASSET_ROTATION_CHANNEL_PARAMS", decode(t, w)["code"])
	})
}
