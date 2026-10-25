package authz

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// TestScopeEvaluationSameBinding 範圍判定的各入口共用同一份目錄與同一組指派。
// 目錄注入之外，同筆指派判定的子測試見 scope_decide_test.go；路由入口在同名測試下續加子測試。
func TestScopeEvaluationSameBinding(t *testing.T) {
	t.Run("sqlite_topology_write_lock", runSQLiteTopologyWriteLockCases)
	t.Run("catalogue_injection", func(t *testing.T) {
		n := model.ScopeKindNodes
		nodeAssignment := func() []Assignment {
			return []Assignment{{RoleName: "c", Via: ViaDirect, Scope: n, LiveNodeIDs: []uint{7}, Custom: true, Permissions: []Permission{PermAuditView}}}
		}
		entry := RouteEntry{Method: "GET", Path: "/x", Base: BasePerm, Perm: PermAuditView}

		// 產品目錄的 scoped-enforced 只有已逐鍵啟用者（注入對象 audit:view 不在其中）
		assertScopedEnforcedOnlyEnabled(t, Catalog())
		require.False(t, scopedEnforcedEnabled[PermAuditView])
		before, _ := LookupPermission(PermAuditView)
		require.Equal(t, ScopeReserved, before.Scope)

		keys := []Permission{PermAuditView}
		cat, err := CatalogueWithScopedEnforcedForTest(keys...)
		require.NoError(t, err)
		keys[0] = PermAssetView // 注入後改來源切片，不影響已建構的目錄

		d, ok := cat.Lookup(PermAuditView)
		require.True(t, ok)
		assert.Equal(t, ScopeEnforced, d.Scope)
		other, _ := cat.Lookup(PermAssetView)
		orig, _ := LookupPermission(PermAssetView)
		assert.Equal(t, orig, other, "來源切片改動後，其他鍵不變")

		// 套件層目錄與正式目錄不被注入改寫
		after, _ := LookupPermission(PermAuditView)
		assert.Equal(t, before, after)
		pd, _ := ProductCatalogue().Lookup(PermAuditView)
		assert.Equal(t, ScopeReserved, pd.Scope)

		// 建構錯誤：目錄外、非 scoped-reserved
		_, err = CatalogueWithScopedEnforcedForTest("no:such")
		assert.Error(t, err)
		_, err = CatalogueWithScopedEnforcedForTest(PermAlertRuleManage)
		assert.Error(t, err, "global-only 不可改標")

		// 主體建構與路由判定共用同一份目錄
		injected := NewPrincipalOn(cat, 1, TokenFacts{}, nodeAssignment())
		product := NewPrincipal(1, TokenFacts{}, nodeAssignment())
		assert.True(t, injected.Has(PermAuditView))
		assert.False(t, product.Has(PermAuditView))
		assert.True(t, DecideEntry(entry, injected).Allowed)
		assert.False(t, DecideEntry(entry, product).Allowed)

		// 解析器：自 DB 解析時目錄貫穿到主體
		db := newPrincipalDB(t)
		require.NoError(t, db.AutoMigrate(&model.RolePermission{}))
		u := mkUser(t, db, "scoped")
		role := mkCustomRole(t, db, "audit-viewer", PermAuditView)
		assignDirect(t, db, u.ID, role.ID, n)
		node := mkNode(t, db, "n1", nil)
		require.NoError(t, db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser, SubjectID: u.ID, RoleID: role.ID, NodeID: node.ID}).Error)
		pi, err := ResolveUserOnWithCatalogue(db, cat, u.ID, TokenFacts{})
		require.NoError(t, err)
		assert.True(t, pi.Has(PermAuditView))
		pp, err := ResolveUserOn(db, u.ID, TokenFacts{})
		require.NoError(t, err)
		assert.False(t, pp.Has(PermAuditView))

		// 自訂角色集合解析吃注入的目錄：目錄不含的鍵不授權
		var sub []PermissionDef
		for _, d := range Catalog() {
			if d.Key != PermAuditView {
				sub = append(sub, d)
			}
		}
		narrow := catalogueOf(sub)
		// 改來源切片，不影響已建構目錄（取第一個不是 scoped-enforced 的項，改前改後才分得出）
		k := 0
		for k < len(sub) && sub[k].Scope == ScopeEnforced {
			k++
		}
		require.Less(t, k, len(sub))
		sub[k].Scope = ScopeEnforced
		rows := []assignmentRow{{RoleID: role.ID, DefVersion: 1}}
		got, err := customPermissionsOf(db, narrow, rows)
		require.NoError(t, err)
		assert.Empty(t, got[role.ID])
		got, err = customPermissionsOf(db, cat, rows)
		require.NoError(t, err)
		assert.Equal(t, []Permission{PermAuditView}, got[role.ID])
		dd, _ := narrow.Lookup(sub[k].Key)
		assert.NotEqual(t, ScopeEnforced, dd.Scope)
	})
	runDecideSubtests(t)
	runDecideInTxSubtests(t)
	runLockOrderProbeSubtests(t)
}
