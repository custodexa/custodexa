package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// TestUserGroupApproverOnlyDenialShape 群組拒絕回應的形狀：鍵只有 error、code、params、details；
// details.affected_users 每筆鍵恰為 id、username；error 不帶任何內建角色名稱或顯示名。
func TestUserGroupApproverOnlyDenialShape(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPut, "/api/v1/user-groups/1/role-bindings", nil)
	err := fmt.Errorf("更新成員失敗: %w", &identity.ApproverOnlyMembersError{Count: 23,
		Users: []identity.AffectedUser{{ID: 3, Username: "sun.yh"}, {ID: 9, Username: "wu.jh"}}})
	respondUserGroupError(c, apierror.CodeInternalUserGroupUpdate, err)

	require.Equal(t, http.StatusBadRequest, w.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.ElementsMatch(t, []string{"error", "code", "params", "details"}, sortedKeys(body))
	require.Equal(t, string(apierror.CodeValidationUserGroupApproverOnlyMembers), body["code"])
	require.Equal(t, map[string]any{"count": float64(23)}, body["params"])
	details := body["details"].(map[string]any)
	require.ElementsMatch(t, []string{"affected_users"}, sortedKeys(details))
	users := details["affected_users"].([]any)
	require.Len(t, users, 2)
	for i, want := range []struct {
		id   float64
		name string
	}{{3, "sun.yh"}, {9, "wu.jh"}} {
		u := users[i].(map[string]any)
		require.ElementsMatch(t, []string{"id", "username"}, sortedKeys(u))
		require.Equal(t, want.id, u["id"])
		require.Equal(t, want.name, u["username"])
	}
	msg := body["error"].(string)
	require.Contains(t, msg, "23")
	for _, name := range builtinRoleNames(t) {
		require.NotContains(t, msg, name)
	}
}

// builtinRoleNames 內建角色的識別與三語顯示名（取自前端 locale 的 role.<key>.label）。
func builtinRoleNames(t *testing.T) []string {
	t.Helper()
	names := []string{"super_admin", "auditor", "approver", "identity_admin", "security_admin", "asset_admin", "authz_admin"}
	for _, loc := range []string{"zh-TW", "en-US", "ja-JP"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "locales", loc+".json"))
		require.NoError(t, err)
		var doc map[string]any
		require.NoError(t, json.Unmarshal(raw, &doc))
		found := 0
		var walk func(v any)
		walk = func(v any) {
			m, ok := v.(map[string]any)
			if !ok {
				return
			}
			if role, ok := m["role"].(map[string]any); ok {
				for _, key := range []string{"admin", "auditor", "approver", "user"} {
					if r, ok := role[key].(map[string]any); ok {
						if l, ok := r["label"].(string); ok && strings.TrimSpace(l) != "" {
							names = append(names, l)
							found++
						}
					}
				}
			}
			for _, child := range m {
				walk(child)
			}
		}
		walk(doc)
		require.NotZero(t, found, loc)
	}
	return names
}
