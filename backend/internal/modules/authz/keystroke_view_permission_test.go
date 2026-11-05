package authz

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// TestKeystrokeViewPermission 擋：鍵盤紀錄查看權限點的群組／範圍漂移、落入範圍化範本、
// 被列為指派保護或系統安全管理員專屬，以及稽核員範本失去它。
func TestKeystrokeViewPermission(t *testing.T) {
	t.Run("目錄屬性：稽核組、稽核類、global-only、依賴 session:view", func(t *testing.T) {
		def, ok := LookupPermission("keystroke:view")
		require.True(t, ok)
		assert.Equal(t, GroupAudit, def.Group)
		assert.Equal(t, CategoryAudit, def.Category)
		assert.Equal(t, ScopeGlobalOnly, def.Scope)
		assert.Equal(t, []Permission{PermSessionView}, PermissionDependencies(PermKeystrokeView))
		assert.True(t, IsAssignable(PermKeystrokeView))
	})

	t.Run("範本：超管與稽核員含，其他內建範本不含", func(t *testing.T) {
		has := func(builtin string) bool {
			for _, k := range TemplatePermissions(builtin) {
				if k == PermKeystrokeView {
					return true
				}
			}
			return false
		}
		assert.True(t, has(model.BuiltinSuperAdmin))
		assert.True(t, has(model.BuiltinAuditor))
		for _, b := range []string{model.BuiltinUser, model.BuiltinApprover, model.BuiltinIdentityAdmin,
			model.BuiltinSecurityAdmin, model.BuiltinAssetAdmin, model.BuiltinAuthzAdmin} {
			assert.False(t, has(b), "範本 %s 不得含 keystroke:view", b)
		}
	})

	t.Run("不列入指派保護與系統安全管理員專屬（要改須是刻意變更）", func(t *testing.T) {
		for _, p := range ProtectedAssignmentPermissions() {
			assert.NotEqual(t, PermKeystrokeView, p)
		}
		for _, p := range SecurityAdminExclusivePermissions() {
			assert.NotEqual(t, PermKeystrokeView, p)
		}
	})

	t.Run("入口描述：獨立頁面入口，狀態集合含 session:view 依賴鍵", func(t *testing.T) {
		var found *EntryDescriptor
		for _, e := range EntryDescriptors() {
			if e.ID == "keystroke_investigation" {
				e := e
				found = &e
			}
		}
		require.NotNil(t, found)
		assert.Equal(t, PlacementPage, found.PlacementKind())
		require.Len(t, found.States, 2)
		assert.ElementsMatch(t, []Permission{PermSessionView, PermKeystrokeView}, found.States[1].Keys)
	})
}
