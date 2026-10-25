package authz

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// TestRecordingDeletePermission 擋：刪除錄影權限點的群組／類別／範圍漂移、被加上依賴、
// 落入不該有的範本、失去獨立能力描述，或不再參與身分＋安全的危險組合判定。
func TestRecordingDeletePermission(t *testing.T) {
	t.Run("目錄屬性：設定組、管理類、global-only、無依賴、可指派", func(t *testing.T) {
		def, ok := LookupPermission("recording:delete")
		require.True(t, ok, "目錄內必須有 recording:delete")
		assert.Equal(t, PermRecordingDelete, def.Key)
		assert.Equal(t, GroupSettings, def.Group)
		assert.Equal(t, CategoryManage, def.Category)
		assert.Equal(t, ScopeGlobalOnly, def.Scope)
		assert.Empty(t, PermissionDependencies(PermRecordingDelete), "刪錄影沒有畫面，不得要求讀取依賴")
		assert.True(t, IsAssignable(PermRecordingDelete), "自訂角色可勾選")
	})

	t.Run("範本：超管與系統安全管理員含，其他範本不含", func(t *testing.T) {
		has := func(builtin string) bool {
			for _, k := range TemplatePermissions(builtin) {
				if k == PermRecordingDelete {
					return true
				}
			}
			return false
		}
		assert.True(t, has(model.BuiltinSuperAdmin))
		assert.True(t, has(model.BuiltinSecurityAdmin))
		for _, b := range []string{model.BuiltinIdentityAdmin, model.BuiltinAuditor, model.BuiltinUser, model.BuiltinApprover} {
			assert.False(t, has(b), "範本 %s 不得含 recording:delete", b)
		}
	})

	t.Run("獨立能力描述 recording_delete 無信任提示，且仍有 role_assign", func(t *testing.T) {
		ids := map[string]CapabilityDescriptor{}
		for _, c := range CapabilityDescriptors() {
			ids[c.ID] = c
		}
		require.Contains(t, ids, "recording_delete")
		assert.Equal(t, PermRecordingDelete, ids["recording_delete"].Key)
		assert.False(t, ids["recording_delete"].TrustHint)
		require.Contains(t, ids, "role_assign")
	})

	t.Run("只持指派角色與刪錄影的自訂集合構成身分＋安全組合", func(t *testing.T) {
		p := NewPrincipal(1, TokenFacts{}, []Assignment{{
			Scope: model.ScopeKindGlobal, Custom: true,
			Permissions: []Permission{PermRoleAssign, PermRecordingDelete},
		}})
		combos := comboCodes(p, false)
		assert.Contains(t, combos, ComboIdentityWithSecurity)
		// 對照：只持指派角色時不構成
		only := NewPrincipal(2, TokenFacts{}, []Assignment{{
			Scope: model.ScopeKindGlobal, Custom: true, Permissions: []Permission{PermRoleAssign},
		}})
		assert.NotContains(t, comboCodes(only, false), ComboIdentityWithSecurity)
	})
}
