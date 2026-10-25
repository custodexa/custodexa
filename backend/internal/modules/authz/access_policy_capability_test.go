package authz

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAccessPolicyCapabilityCatalog 存取政策權限點的目錄屬性、歸屬與依賴。
func TestAccessPolicyCapabilityCatalog(t *testing.T) {
	t.Run("鍵存在且群組類別範圍如凍結表；目錄只有已逐鍵啟用的 scoped-enforced", func(t *testing.T) {
		def, ok := LookupPermission("access_policy:manage")
		require.True(t, ok)
		assert.Equal(t, GroupAuthzRule, def.Group)
		assert.Equal(t, CategoryManage, def.Category)
		assert.Equal(t, ScopeEnforced, def.Scope)
		assertScopedEnforcedOnlyEnabled(t, Catalog())
		assert.True(t, IsAssignable(PermAccessPolicyManage))
	})
	t.Run("超管解析含此鍵；兩個鎖定範本與稽核員、一般使用者不含", func(t *testing.T) {
		db := newRoleDefDB(t)
		adm := mkRole(t, db, "admin", model.BuiltinSuperAdmin)
		u := mkUser(t, db, "root")
		assignDirect(t, db, u.ID, adm.ID, model.ScopeKindGlobal)
		p, err := NewResolver(db).ResolveUser(u.ID, TokenFacts{})
		require.NoError(t, err)
		assert.True(t, p.Has(PermAccessPolicyManage))
		for _, key := range []string{model.BuiltinIdentityAdmin, model.BuiltinSecurityAdmin, model.BuiltinAuditor, model.BuiltinUser, model.BuiltinApprover} {
			assert.NotContains(t, TemplatePermissions(key), PermAccessPolicyManage, key)
		}
	})
	t.Run("descriptor 不宣告依賴（畫面資料取自覆寫清單路由）；不自動補授、無缺依賴提示", func(t *testing.T) {
		assert.Empty(t, PermissionDependencies(PermAccessPolicyManage))
		out, err := NormalizeRolePermissions([]string{"access_policy:manage"})
		require.NoError(t, err)
		assert.Equal(t, []string{"access_policy:manage"}, permStrings(out), "沒有補任何鍵")
		assert.Empty(t, MissingDependencies(out))
		assert.Empty(t, BlockedScreens(out))
		tpl := make([]Permission, 0, len(ScopedTemplateAuthorizationAdminPermissions()))
		tpl = append(tpl, ScopedTemplateAuthorizationAdminPermissions()...)
		for _, m := range MissingDependencies(tpl) {
			assert.NotEqual(t, PermAccessPolicyManage, m.Permission, "授權管理員範本的缺依賴不含存取政策權限點")
		}
		t.Logf("EVIDENCE access-policy-deps deps=%v template-missing=%v", PermissionDependencies(PermAccessPolicyManage), MissingDependencies(tpl))
	})
}

// scopedEnforcedEnabled 已逐鍵啟用範圍判定的權限點（目標解析與列表投影皆已宣告）。
// 新增一鍵須同時有目標宣告與這裡的一列；目錄出現不在此表的 scoped-enforced 即失敗。
var scopedEnforcedEnabled = map[Permission]bool{PermAssetGroupManage: true,
	PermAssetUpdate: true, PermAssetDelete: true, PermAssetTest: true, PermAssetView: true,
	PermCredentialView: true, PermCredentialCreate: true, PermCredentialUpdate: true,
	PermCredentialSetSecret: true, PermCredentialRotate: true, PermCredentialConvertScope: true,
	PermCredentialDetach: true, PermCredentialDelete: true, PermCredentialBind: true,
	PermAuthorizationManage: true, PermApproverScopeManage: true, PermAssetCreate: true,
	PermChangeSecretManage: true, PermAccountRotate: true, PermAccessPolicyManage: true}

// assertScopedEnforcedOnlyEnabled 目錄的 scoped-enforced 集合恰為已啟用表（不多也不少）。
func assertScopedEnforcedOnlyEnabled(t *testing.T, defs []PermissionDef) {
	t.Helper()
	got := map[Permission]bool{}
	for _, d := range defs {
		if d.Scope == ScopeEnforced {
			got[d.Key] = true
			assert.True(t, scopedEnforcedEnabled[d.Key], "%s：未逐鍵啟用的權限點不得為 scoped-enforced", d.Key)
		}
	}
	for k := range scopedEnforcedEnabled {
		assert.True(t, got[k], "%s：已啟用表內的權限點須為 scoped-enforced", k)
	}
}
