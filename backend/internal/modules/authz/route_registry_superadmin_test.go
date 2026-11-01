package authz

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// 超管保留種類的判定：各類主體的放行與拒絕依據。
func TestDecideEntrySuperAdminBase(t *testing.T) {
	e := RouteEntry{Method: "POST", Path: "/zz/super-only", Base: BaseSuperAdmin}

	assignable := make([]Permission, 0)
	for _, d := range Catalog() {
		if IsAssignable(d.Key) {
			assignable = append(assignable, d.Key)
		}
	}
	builtin := func(key string) *Principal {
		return NewPrincipal(1, TokenFacts{}, []Assignment{{RoleName: key, BuiltinKey: key, Via: ViaDirect, Scope: model.ScopeKindGlobal}})
	}
	cases := []struct {
		name    string
		p       *Principal
		allowed bool
		unauth  bool
	}{
		{"未登入", nil, false, true},
		{"內建超管", builtin(model.BuiltinSuperAdmin), true, false},
		{"持全部可指派權限的自訂角色", NewPrincipal(2, TokenFacts{}, []Assignment{{
			RoleName: "all-assignable", Via: ViaDirect, Scope: model.ScopeKindGlobal, Permissions: assignable, Custom: true}}), false, false},
		{"稽核員", builtin(model.BuiltinAuditor), false, false},
		{"系統安全管理員", builtin(model.BuiltinSecurityAdmin), false, false},
		{"agent", NewPrincipal(3, TokenFacts{SubjectKind: model.KindAgent}, []Assignment{{
			RoleName: model.BuiltinSuperAdmin, BuiltinKey: model.BuiltinSuperAdmin, Via: ViaDirect, Scope: model.ScopeKindGlobal}}), false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := DecideEntry(e, c.p)
			assert.Equal(t, c.allowed, d.Allowed, "%s：放行與否", c.name)
			assert.Equal(t, c.unauth, d.Unauthenticated, "%s：未認證", c.name)
			if c.allowed || c.unauth {
				assert.Empty(t, d.Basis, c.name)
				assert.Empty(t, d.Reserved, c.name)
				return
			}
			assert.Equal(t, DenialReserved, d.Basis, "%s：拒絕依據種類", c.name)
			assert.Equal(t, ReservedSuperAdmin, d.Reserved, "%s：保留條件值", c.name)
			assert.Empty(t, d.Required, "%s：保留條件不是權限點", c.name)
		})
	}
}

// 超管保留種類的登錄項不得帶權限點、並列能力、欄位條件或資料面標記。
func TestCheckSuperAdminEntryShape(t *testing.T) {
	base := RouteEntry{Method: "PUT", Path: "/zz/super-only", Base: BaseSuperAdmin}
	require.NoError(t, checkSuperAdminEntry(base), "合法登錄")
	require.NoError(t, checkSuperAdminEntry(RouteEntry{Method: "GET", Path: "/zz/other", Base: BasePerm, Perm: PermAssetView}), "其他種類不受此檢查約束")

	with := func(f func(*RouteEntry)) RouteEntry {
		e := base
		f(&e)
		return e
	}
	bad := map[string]RouteEntry{
		"Perm":      with(func(e *RouteEntry) { e.Perm = PermAssetView }),
		"AnyOf":     with(func(e *RouteEntry) { e.AnyOf = []Permission{PermAssetView} }),
		"Fields":    with(func(e *RouteEntry) { e.Fields = []FieldCondition{{Field: "x", Perm: PermAssetView}} }),
		"DataPlane": with(func(e *RouteEntry) { e.DataPlane = true }),
	}
	for name, e := range bad {
		err := checkSuperAdminEntry(e)
		require.Error(t, err, name)
		assert.True(t, strings.Contains(err.Error(), "PUT") && strings.Contains(err.Error(), "/zz/super-only"),
			"%s：訊息須含方法與樣板，實得 %q", name, err.Error())
	}
}
