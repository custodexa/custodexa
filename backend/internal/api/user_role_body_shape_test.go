package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/stretchr/testify/assert"
)

// TestAssignRolesRejectsLegacyBody 角色替換端點拒絕舊請求形狀。
//
// 舊形狀的單一鍵描述的是整組**有效**角色集，而端點的作用範圍已收斂為管理者
// 指派集。靜默把它當成管理者指派集，會讓未更新的用戶端一次刪光該使用者由外部
// 群組賦予的角色，而且沒有任何訊號——拒絕是唯一會被看見的處置。
//
// 反向斷言（服務層一次都不得被呼叫）是這支測試的重點：只斷言狀態碼的話，
// 「先照做再回 400」也會綠。
func TestAssignRolesRejectsLegacyBody(t *testing.T) {
	mockUserService := new(MockUserService)
	handler := newTestUserHandler(mockUserService)
	router := setupTestRouter()
	router.PUT("/users/:id/roles", handler.AssignRoles)

	body, _ := json.Marshal(map[string]any{"roles": []string{"admin", "user"}})
	req := httptest.NewRequest("PUT", "/users/1/roles", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]any
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, string(apierror.CodeRolesLegacyField), resp["code"],
		"舊請求形狀要回可辨識的機器碼，用戶端才知道該改哪裡")
	mockUserService.AssertNotCalled(t, "AssignRoles")

	// 兩個鍵同時出現一樣拒絕：新舊混送時無從得知用戶端要的是哪一種語義
	both, _ := json.Marshal(map[string]any{
		"manual_roles": []string{"admin"},
		"roles":        []string{"admin", "user"},
	})
	req2 := httptest.NewRequest("PUT", "/users/1/roles", bytes.NewBuffer(both))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusBadRequest, w2.Code)
	mockUserService.AssertNotCalled(t, "AssignRoles")
}
