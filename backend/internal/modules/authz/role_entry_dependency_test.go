package authz

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// 告警與存取複審的頁面與列表都要稽核檢視權限；缺它時缺依賴提示必須指出。
func TestBlockedScreensDeclareAuditViewDependency(t *testing.T) {
	cases := []struct {
		name  string
		perms []Permission
		id    string
	}{
		{"alert read only", []Permission{PermAlertView}, "alerts"},
		{"alert manage", []Permission{PermAlertView, PermAlertManage}, "alerts"},
		{"access review manage", []Permission{PermAccessReviewManage}, "access_reviews"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bs := BlockedScreens(c.perms)
			require.Contains(t, bs, BlockedScreen{ID: c.id, Missing: []Permission{PermAuditView}})
		})
	}
	t.Run("with audit view nothing is blocked", func(t *testing.T) {
		assert.Empty(t, BlockedScreens([]Permission{PermAlertView, PermAlertManage, PermAuditView, PermAccessReviewManage}))
	})
	t.Run("auditor template summary is unchanged", func(t *testing.T) {
		perms := TemplatePermissions(model.BuiltinAuditor)
		s := SummarizeRole(perms)
		assert.Contains(t, s.Manage, "alerts")
		assert.Contains(t, s.Available, "audit_logs")
		assert.Empty(t, BlockedScreens(perms))
		assert.Empty(t, MissingDependencies(perms))
	})
}
