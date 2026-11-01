package authz

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/assert"
)

// 持有已收回鍵的自訂角色：主體能力略過它（/auth/me 的權限投影取自能力集合）；內建超管仍持有。
func TestRetiredKeyIgnoredInPrincipalCapabilities(t *testing.T) {
	custom := NewPrincipal(7, TokenFacts{}, []Assignment{{
		RoleName: "legacy-ops", Via: ViaDirect, Scope: model.ScopeKindGlobal,
		Permissions: []Permission{PermSessionTerminate, PermSessionView}, Custom: true,
	}})
	assert.False(t, custom.Has(PermSessionTerminate))
	assert.True(t, custom.Has(PermSessionView))
	assert.NotContains(t, custom.Capabilities(), PermSessionTerminate)

	super := NewPrincipal(1, TokenFacts{}, []Assignment{{
		RoleName: model.BuiltinSuperAdmin, BuiltinKey: model.BuiltinSuperAdmin, Via: ViaDirect, Scope: model.ScopeKindGlobal,
	}})
	assert.True(t, super.Has(PermSessionTerminate), "內建超管範本照常持有")
}

// 已收回的鍵：不可指派、不判無效；從未可指派的保留鍵仍判無效。
func TestRetiredAssignableKey(t *testing.T) {
	assert.False(t, IsAssignable(PermSessionTerminate))
	assert.True(t, IsRetiredAssignable(PermSessionTerminate))
	assert.False(t, IsRetiredAssignable(PermHostKeyReset))
	assert.NotContains(t, AssignableKeys(), PermSessionTerminate)
	_, ok := LookupPermission(PermSessionTerminate)
	assert.True(t, ok, "鍵仍留在目錄，超管範本與目錄摘要不變")

	state := func(keys ...string) RoleDefinitionState {
		return RoleDefinitionState{Format: RoleDefinitionStateFormat, LegacyCatalogIDs: []uint{}, BuiltinRoleIDs: []uint{},
			Roles: []RoleDefinitionStateRole{{RoleID: 100, DefinitionVersion: 1, Keys: keys}}}
	}
	assert.NoError(t, ValidateRoleDefinitionState(state("session:view", "session:terminate")))
	assert.Error(t, ValidateRoleDefinitionState(state("hostkey:reset")))
}
