package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/pkg/crypto"
)

// 共用憑證仍有掛載時刪除：409 的本文經統一錯誤出口產生，帶封套欄位（error、code），
// 既有的頂層欄位（code、assets、範圍化檢視者的範圍外台數）保留。改前本文只有 code 與 assets，沒有 error。
func TestCredentialDeleteInUseUsesUnifiedEnvelope(t *testing.T) {
	t.Run("經真實路由刪除仍有掛載的憑證", func(t *testing.T) {
		f := setupCredentialAPIEnv(t)
		r, mgr := credentialTestRouter(t, f)
		adminToken, err := mgr.GenerateToken(1, "admin", "a@example.com", model.RoleAdmin, crypto.AuthContext{})
		require.NoError(t, err)

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/credentials/%d", f.sharedID), nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		r.ServeHTTP(w, req)
		require.Equal(t, http.StatusConflict, w.Code, w.Body.String())

		var body map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		assert.Equal(t, string(apierror.CodeCredentialInUse), body["code"], "頂層機器碼保留")
		assert.NotEmpty(t, body["error"], "統一封套的 error 欄")
		assets, ok := body["assets"].([]any)
		require.True(t, ok, "頂層資產名單保留：%v", body)
		assert.Equal(t, []any{"alpha"}, assets)
		_, scoped := body["out_of_scope_asset_count"]
		assert.False(t, scoped, "全域主體不帶範圍外台數")
		assert.Len(t, body, 3, "本文只有 error、code、assets")

		var count int64
		require.NoError(t, f.db.Model(&model.Credential{}).Where("id = ?", f.sharedID).Count(&count).Error)
		assert.Equal(t, int64(1), count, "被拒的刪除不刪資料")
	})

	t.Run("範圍化檢視者：範圍外台數保留於頂層", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodDelete, "/api/v1/credentials/1", nil)
		respondCredentialError(c, apierror.CodeInternalCredentialList, &asset.CredentialInUseError{
			Assets: []string{"alpha"}, OutOfScopeAssets: 2, Scoped: true,
		})
		require.Equal(t, http.StatusConflict, w.Code)
		var body map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		assert.Equal(t, string(apierror.CodeCredentialInUse), body["code"])
		assert.NotEmpty(t, body["error"])
		assert.Equal(t, []any{"alpha"}, body["assets"])
		assert.EqualValues(t, 2, body["out_of_scope_asset_count"])
	})
}
