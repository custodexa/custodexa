package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/modules/identity"
)

// 共用指派關卡拒絕時，原因碼併進該次請求的審計 details（deny_reason），只有原因碼；
// 回應仍只帶機器碼。非關卡錯誤不寫 deny_reason。
func TestAssignmentDenyReasonRecordedInAuditDetails(t *testing.T) {
	gin.SetMode(gin.TestMode)
	run := func(err error, handler func(*gin.Context, error)) (*httptest.ResponseRecorder, map[string]string) {
		var details map[string]string
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Set("audit_details", map[string]string{"prior": "kept"})
			c.Next()
			if v, ok := c.Get("audit_details"); ok {
				details, _ = v.(map[string]string)
			}
		})
		r.POST("/x", func(c *gin.Context) { handler(c, err) })
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/x", nil))
		return w, details
	}
	principal := func(c *gin.Context, err error) { require.True(t, respondPrincipalError(c, err)) }

	denied := &identity.AssignmentDenial{Reason: identity.DenyReasonProtectedRole, Err: identity.ErrProtectedRoleAssignment}
	w, details := run(denied, principal)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), string(apierror.CodeAuthProtectedRoleAssignment))
	assert.NotContains(t, w.Body.String(), "deny_reason", "原因碼只進審計，不進回應")
	assert.Equal(t, map[string]string{"prior": "kept", "deny_reason": identity.DenyReasonProtectedRole}, details)

	// 群組角色指派的目錄外角色走另一個出口，同樣記原因碼
	notAssignable := &identity.AssignmentDenial{Reason: identity.DenyReasonRoleNotAssignable, Err: identity.ErrRoleNotFound}
	_, details = run(notAssignable, func(c *gin.Context, err error) {
		respondRoleBindingError(c, apierror.CodeInternalUserGroupQuery, err)
	})
	assert.Equal(t, identity.DenyReasonRoleNotAssignable, details["deny_reason"])

	// 不是關卡拒絕：不寫 deny_reason
	_, details = run(identity.ErrProtectedRoleAssignment, principal)
	assert.NotContains(t, details, "deny_reason")
	_, details = run(errors.New("other"), func(c *gin.Context, err error) { assert.False(t, respondPrincipalError(c, err)) })
	assert.NotContains(t, details, "deny_reason")
}
