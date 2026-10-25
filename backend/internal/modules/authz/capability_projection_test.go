package authz

import (
	"sort"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCurrentUserCapabilityProjection 擋：投影與主體解析結果分家、衍生呈現點被角色或管理權兜出、
// 不生效的節點指派被表示為全域、下一請求沿用舊能力。
func TestCurrentUserCapabilityProjection(t *testing.T) {
	g, n := model.ScopeKindGlobal, model.ScopeKindNodes
	human := TokenFacts{SubjectKind: model.KindHuman}
	derivedOf := func(perms []string) []string {
		out := []string{}
		for _, p := range perms {
			if IsPresentationPoint(p) {
				out = append(out, p)
			}
		}
		return out
	}

	t.Run("有效權限排序去重且與摘要一一對應", func(t *testing.T) {
		p := NewPrincipal(1, human, []Assignment{asg(model.BuiltinSuperAdmin, g), asg(model.BuiltinAuditor, g), asg(model.BuiltinUser, g)})
		proj := ProjectCapabilities(p, ProjectionInputs{})
		assignable := []string{}
		for _, k := range proj.Permissions {
			if !IsPresentationPoint(k) {
				assignable = append(assignable, k)
			}
		}
		assert.Len(t, assignable, len(CatalogKeys()), "超管折疊後為目錄全部，聯集不重複")
		assert.True(t, sort.StringsAreSorted(proj.Permissions))
		seen := map[string]bool{}
		for _, k := range proj.Permissions {
			assert.False(t, seen[k], "重複: "+k)
			seen[k] = true
		}
		require.Len(t, proj.ScopeSummary, len(assignable))
		for i, e := range proj.ScopeSummary {
			assert.Equal(t, assignable[i], e.Permission, "摘要按權限排序且不含 ui: 點")
			assert.Equal(t, "global", e.BindingScope)
		}
	})

	t.Run("空集合回非 nil 空陣列", func(t *testing.T) {
		p := NewPrincipal(2, human, []Assignment{asg(model.BuiltinApprover, g)}) // 純審核者：能力為空
		proj := ProjectCapabilities(p, ProjectionInputs{})
		require.NotNil(t, proj.Permissions)
		require.NotNil(t, proj.ScopeSummary)
		assert.Equal(t, []string{UISelfServiceActions}, proj.Permissions, "純審核者無可指派能力，只剩原本就顯示的申請操作點")
		assert.Empty(t, proj.ScopeSummary)
		nilProj := ProjectCapabilities(nil, ProjectionInputs{IsApprover: true})
		assert.NotNil(t, nilProj.Permissions)
		assert.Empty(t, nilProj.Permissions, "沒有主體時連衍生點也不產生")
	})

	t.Run("審核點只來自既有審核資格，管理者不兜底", func(t *testing.T) {
		pureApprover := NewPrincipal(3, human, []Assignment{asg(model.BuiltinApprover, g)})
		groupApprover := NewPrincipal(4, human, nil) // 零角色但屬審核方群組：資格是外部傳入的既有值
		admin := NewPrincipal(5, human, []Assignment{asg(model.BuiltinSuperAdmin, g)})
		assert.Contains(t, ProjectCapabilities(pureApprover, ProjectionInputs{IsApprover: true}).Permissions, UIApprovals)
		assert.Contains(t, ProjectCapabilities(groupApprover, ProjectionInputs{IsApprover: true}).Permissions, UIApprovals)
		assert.NotContains(t, ProjectCapabilities(admin, ProjectionInputs{IsApprover: false}).Permissions, UIApprovals,
			"admin 持有全部權限點仍不因此取得審核點")
		assert.NotContains(t, ProjectCapabilities(pureApprover, ProjectionInputs{IsApprover: false}).Permissions, UIApprovals,
			"審核角色列存在但資格查詢為否時不帶審核點（以同次 is_approver 為準）")
	})

	t.Run("agent 入口由兩旗標決定", func(t *testing.T) {
		p := NewPrincipal(6, human, []Assignment{asg(model.BuiltinUser, g)})
		for _, c := range []struct {
			name string
			in   ProjectionInputs
			want bool
		}{
			{"皆否", ProjectionInputs{}, false},
			{"擁有 agent", ProjectionInputs{OwnsAgents: true}, true},
			{"允許自建", ProjectionInputs{CanSelfCreateAgent: true}, true},
			{"兩者皆是", ProjectionInputs{OwnsAgents: true, CanSelfCreateAgent: true}, true},
		} {
			got := ProjectCapabilities(p, c.in).Permissions
			if c.want {
				assert.Contains(t, got, UIMyAgents, c.name)
			} else {
				assert.NotContains(t, got, UIMyAgents, c.name)
			}
		}
		admin := NewPrincipal(7, human, []Assignment{asg(model.BuiltinSuperAdmin, g)})
		assert.NotContains(t, ProjectCapabilities(admin, ProjectionInputs{}).Permissions, UIMyAgents, "角色不產生 agent 入口")
	})

	t.Run("連線豁免只來自保留的超管身分", func(t *testing.T) {
		admin := NewPrincipal(8, human, []Assignment{asg(model.BuiltinSuperAdmin, g)})
		adminProj := ProjectCapabilities(admin, ProjectionInputs{})
		assert.Equal(t, []string{UIAssetsGlobal, UIConnectBypass, UISuperAdmin}, derivedOf(adminProj.Permissions))

		auditor := NewPrincipal(9, human, []Assignment{asg(model.BuiltinAuditor, g)})
		assert.Equal(t, []string{UIAssetsGlobal}, derivedOf(ProjectCapabilities(auditor, ProjectionInputs{}).Permissions),
			"稽核員有全域檢視呈現但無連線豁免")

		// 勾滿目錄全部權限點的非內建角色：不是超管、不是稽核，也不得獲得任何衍生點
		custom := NewPrincipal(10, human, []Assignment{{RoleName: "ops", Via: ViaDirect, Scope: g}})
		for _, k := range CatalogKeys() {
			custom.caps[k] = true
		}
		got := derivedOf(ProjectCapabilities(custom, ProjectionInputs{}).Permissions)
		assert.NotContains(t, got, UIConnectBypass)
		assert.NotContains(t, got, UISuperAdmin)
		assert.NotContains(t, got, UIAssetsGlobal)

		user := NewPrincipal(11, human, []Assignment{asg(model.BuiltinUser, g)})
		assert.Equal(t, []string{UISelfServiceActions}, derivedOf(ProjectCapabilities(user, ProjectionInputs{}).Permissions))
		zero := NewPrincipal(12, human, nil)
		assert.Equal(t, []string{UISelfServiceActions}, derivedOf(ProjectCapabilities(zero, ProjectionInputs{}).Permissions), "零角色視同一般使用者")
		assert.NotContains(t, adminProj.Permissions, UISelfServiceActions, "超管不顯示申請操作")
	})

	t.Run("不生效的節點指派不被投影成全域", func(t *testing.T) {
		p := NewPrincipal(13, human, []Assignment{asg(model.BuiltinSuperAdmin, n, 5, 6)})
		proj := ProjectCapabilities(p, ProjectionInputs{})
		assert.Empty(t, proj.ScopeSummary)
		assert.NotContains(t, proj.Permissions, UIConnectBypass, "節點範圍的超管指派不是保留身分")
		assert.NotContains(t, proj.Permissions, UISuperAdmin, "節點範圍的超管指派不是保留身分")
		assert.NotContains(t, proj.Permissions, string(PermUserManage))
		// 對照：同一主體另有全域一般使用者指派時，只取得該指派的能力
		mixed := NewPrincipal(14, human, []Assignment{asg(model.BuiltinSuperAdmin, n, 5), asg(model.BuiltinUser, g)})
		got := ProjectCapabilities(mixed, ProjectionInputs{})
		require.Len(t, got.ScopeSummary, 1)
		assert.Equal(t, string(PermAssetView), got.ScopeSummary[0].Permission)
	})

	t.Run("ui 點不可出現在目錄與摘要，且命名空間固定", func(t *testing.T) {
		for _, k := range CatalogKeys() {
			assert.False(t, IsPresentationPoint(string(k)), "目錄鍵不得使用 ui: 命名空間: "+string(k))
		}
		for _, k := range UIPresentationPoints() {
			assert.True(t, IsPresentationPoint(k))
			_, ok := LookupPermission(Permission(k))
			assert.False(t, ok, "呈現點不是可指派權限點: "+k)
		}
		admin := NewPrincipal(15, human, []Assignment{asg(model.BuiltinSuperAdmin, g)})
		for _, e := range ProjectCapabilities(admin, ProjectionInputs{IsApprover: true, OwnsAgents: true}).ScopeSummary {
			assert.False(t, IsPresentationPoint(e.Permission))
		}
	})

	t.Run("下一請求採新解析結果而非快取", func(t *testing.T) {
		db := newPrincipalDB(t)
		userRole := mkRole(t, db, "user", model.BuiltinUser)
		adminRole := mkRole(t, db, "admin", model.BuiltinSuperAdmin)
		u := mkUser(t, db, "carol")
		assignDirect(t, db, u.ID, userRole.ID, g)
		r := NewResolver(db)

		p1, err := r.ResolveUser(u.ID, human)
		require.NoError(t, err)
		first := ProjectCapabilities(p1, ProjectionInputs{})
		assert.Equal(t, []string{string(PermAssetView), UISelfServiceActions}, first.Permissions)

		assignDirect(t, db, u.ID, adminRole.ID, g)
		p2, err := r.ResolveUser(u.ID, human)
		require.NoError(t, err)
		second := ProjectCapabilities(p2, ProjectionInputs{})
		assert.Contains(t, second.Permissions, string(PermUserManage))
		assert.Contains(t, second.Permissions, UIConnectBypass)
		assert.NotContains(t, second.Permissions, UISelfServiceActions)

		require.NoError(t, db.Where("user_id = ? AND role_id = ?", u.ID, adminRole.ID).Delete(&model.UserRole{}).Error)
		p3, err := r.ResolveUser(u.ID, human)
		require.NoError(t, err)
		assert.Equal(t, first, ProjectCapabilities(p3, ProjectionInputs{}), "撤除後回到原集合，不殘留前次結果")
	})
}
