package authz

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// ovSubject 一個主體夾具：名稱、建立方式。
type ovSubject struct {
	name  string
	build func(e *ovEnv, fx *ovFixture) *model.User
}

// ovFixture 管理面測試用的節點與資產。
type ovFixture struct {
	nA, nA1, nB uint
	a1, a2, b1  uint
	deletedNode uint
}

func newOvFixture(e *ovEnv) *ovFixture {
	fx := &ovFixture{}
	fx.nA = e.node("ov-node-a", nil)
	fx.nA1 = e.node("ov-node-a1", &fx.nA)
	fx.nB = e.node("ov-node-b", nil)
	fx.deletedNode = e.node("ov-node-gone", nil)
	fx.a1 = e.assetOn("ov-asset-a1", fx.nA1)
	fx.a2 = e.assetOn("ov-asset-a2", fx.nA)
	fx.b1 = e.assetOn("ov-asset-b1", fx.nB)
	return fx
}

// ovSubjects 對應既有授權基準主體的形狀（匿名者沒有主體；停用與刪除的帳號不影響權限解析，
// 與其餘一般使用者同形），另加四個主體：全域自訂角色、群組節點範圍角色、節點全刪的指派、經映射的稽核員。
func ovSubjects() []ovSubject {
	roleSubject := func(name string, roles ...string) ovSubject {
		return ovSubject{name: name, build: func(e *ovEnv, _ *ovFixture) *model.User {
			u := e.user(e.uniq(name))
			for _, r := range roles {
				e.assign(u.ID, r, "")
			}
			return u
		}}
	}
	return []ovSubject{
		roleSubject("admin", model.BuiltinSuperAdmin),
		roleSubject("user", model.BuiltinUser),
		roleSubject("auditor", model.BuiltinAuditor),
		roleSubject("approver", model.BuiltinApprover),
		roleSubject("user+approver", model.BuiltinUser, model.BuiltinApprover),
		roleSubject("admin+approver", model.BuiltinSuperAdmin, model.BuiltinApprover),
		roleSubject("auditor+user", model.BuiltinAuditor, model.BuiltinUser),
		roleSubject("user-b", model.BuiltinUser),
		roleSubject("zero-role"),
		roleSubject("user-disabled", model.BuiltinUser),
		roleSubject("user-deleted-peer", model.BuiltinUser),
		{name: "agent", build: func(e *ovEnv, _ *ovFixture) *model.User {
			u := e.agent(e.uniq("agent"))
			e.assign(u.ID, model.BuiltinSuperAdmin, "") // agent 的固定能力不受角色列影響
			return u
		}},
		{name: "mapped-admin", build: func(e *ovEnv, _ *ovFixture) *model.User {
			u := e.user(e.uniq("mapped-admin"))
			e.assign(u.ID, model.BuiltinSuperAdmin, model.RoleSourceMapped)
			return u
		}},
		roleSubject("user-c", model.BuiltinUser),
		{name: "custom-global", build: func(e *ovEnv, _ *ovFixture) *model.User {
			e.custom("ov-custom-global", PermAssetView, PermAssetUpdate, PermUserManage)
			u := e.user(e.uniq("custom-global"))
			e.assign(u.ID, "ov-custom-global", "")
			return u
		}},
		{name: "group-node-role", build: func(e *ovEnv, fx *ovFixture) *model.User {
			u := e.user(e.uniq("group-node"))
			g := e.group(e.uniq("ov-group"))
			e.groupRole(g.ID, model.BuiltinAssetAdmin, fx.nA)
			e.join(g.ID, u.ID, true)
			return u
		}},
		{name: "nodes-all-deleted", build: func(e *ovEnv, fx *ovFixture) *model.User {
			u := e.user(e.uniq("gone"))
			e.assign(u.ID, model.BuiltinAssetAdmin, "", fx.deletedNode)
			require.NoError(e.t, e.db.Delete(&model.AssetGroup{}, fx.deletedNode).Error)
			return u
		}},
		{name: "mapped-auditor", build: func(e *ovEnv, _ *ovFixture) *model.User {
			u := e.user(e.uniq("mapped-auditor"))
			e.assign(u.ID, model.BuiltinAuditor, model.RoleSourceMapped)
			return u
		}},
	}
}

func ovScopeNodeIDs(sc OverviewScope) []uint {
	ids := make([]uint, 0, len(sc.Nodes))
	for _, n := range sc.Nodes {
		ids = append(ids, n.ID)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// TestPermissionOverviewMatchesResolver 權限集合與範圍逐鍵等於解析器與集合述詞。
func TestPermissionOverviewMatchesResolver(t *testing.T) {
	for _, sub := range ovSubjects() {
		sub := sub
		t.Run("主體 "+sub.name, func(t *testing.T) {
			e := newOvEnv(t)
			fx := newOvFixture(e)
			u := sub.build(e, fx)
			p := e.principalOf(u)
			got, err := e.svc.Overview(e.ctxOf(e.globalViewer()), u.ID)
			require.NoError(t, err)
			m := got.Management

			// 權限點集合逐鍵相同
			keys := make([]string, 0, len(m.Permissions))
			byKey := map[string]OverviewPermission{}
			for _, op := range m.Permissions {
				keys = append(keys, op.Permission)
				byKey[op.Permission] = op
			}
			want := make([]string, 0)
			for _, c := range p.Capabilities() {
				want = append(want, string(c))
			}
			assert.Equal(t, want, keys, "權限點集合應等於解析器的有效能力")

			// 來源表
			srcByRef := map[string]OverviewSource{}
			for _, s := range m.Sources {
				srcByRef[s.SourceRef] = s
			}
			require.Len(t, srcByRef, len(m.Sources), "source_ref 在回應內唯一")
			for _, c := range p.Capabilities() {
				op := byKey[string(c)]
				// 範圍等於 bindingOf
				global, nodes := p.bindingOf(c)
				if global {
					assert.Equal(t, OverviewScopeGlobal, op.Scopes.Kind, c)
				} else {
					assert.Equal(t, OverviewScopeNodes, op.Scopes.Kind, c)
					assert.Equal(t, nodes, ovScopeNodeIDs(op.Scopes), c)
				}
				// 與 Decide 相同：資產目標的逐資產放行等於範圍涵蓋
				if def, ok := p.cat.Lookup(c); ok && def.Scope == ScopeEnforced && (c == PermAssetView || c == PermAssetUpdate) {
					for _, a := range []uint{fx.a1, fx.a2, fx.b1} {
						res, _, err := e.e.decideOn(e.db, p, c, AssetTarget(a))
						require.NoError(t, err)
						covered := global
						if !global {
							cover, _, err := e.e.topo.AssetCoverNodes(e.db, a)
							require.NoError(t, err)
							for _, n := range cover {
								for _, s := range nodes {
									covered = covered || n == s
								}
							}
						}
						assert.Equal(t, covered, res.Outcome == ScopeAllow, "%s 對資產 %d", c, a)
					}
				}
				// 每鍵至少一個來源，且所指來源的有效權限含此鍵
				require.NotEmpty(t, op.SourceRefs, c)
				for _, ref := range op.SourceRefs {
					s, ok := srcByRef[ref]
					require.True(t, ok, "來源 %s 存在", ref)
					assert.Contains(t, s.EffectivePermissions, string(c))
				}
			}
			// 各來源的有效權限聯集等於權限點集合
			union := map[string]bool{}
			for _, s := range m.Sources {
				for _, k := range s.EffectivePermissions {
					union[k] = true
				}
			}
			assert.Len(t, union, len(want))

			// 每張卡的入口等於以該卡有效鍵呼叫 SummarizeRole
			for _, b := range m.Bindings {
				cardKeys := map[string]bool{}
				for _, ref := range b.SourceRefs {
					for _, k := range srcByRef[ref].EffectivePermissions {
						cardKeys[k] = true
					}
				}
				ks := make([]Permission, 0)
				for k := range cardKeys {
					ks = append(ks, Permission(k))
				}
				sort.Slice(ks, func(i, j int) bool { return ks[i] < ks[j] })
				sum := SummarizeRole(ks)
				assert.Equal(t, nonNil(sum.Manage), b.Entries.Manage)
				assert.Equal(t, nonNil(sum.Partial), b.Entries.Partial)
				assert.Equal(t, nonNil(sum.Read), b.Entries.Read)
				assert.Equal(t, nonNil(sum.Available), b.Entries.Available)
			}

			// 身分旗標取自已解析主體
			assert.Equal(t, p.IsSuperAdmin(), m.Identity.SuperAdmin)
			assert.Equal(t, p.IsAuditor(), m.Identity.Auditor)
			assert.Equal(t, p.IsApprover(), m.Identity.Approver)
			assert.Equal(t, u.Kind == model.KindAgent, m.Identity.Agent)
			switch sub.name {
			case "zero-role":
				assert.True(t, m.Identity.CompatDefault)
				require.NotEmpty(t, m.Permissions)
				for _, op := range m.Permissions {
					require.Len(t, op.SourceRefs, 1)
					assert.Equal(t, OverviewSourceCompatDefault, srcByRef[op.SourceRefs[0]].Kind)
				}
			case "agent":
				assert.False(t, m.Identity.SuperAdmin, "agent 不因角色列取得超管")
				for _, op := range m.Permissions {
					require.Len(t, op.SourceRefs, 1)
					assert.Equal(t, OverviewSourceAgentFixed, srcByRef[op.SourceRefs[0]].Kind)
				}
				assert.Empty(t, m.IneffectiveSources)
			case "nodes-all-deleted":
				require.Len(t, m.IneffectiveSources, 1)
				assert.Equal(t, OverviewReasonNodesAllDeleted, m.IneffectiveSources[0].Reason)
				assert.Empty(t, m.Permissions)
				assert.Empty(t, m.Sources)
			case "mapped-auditor":
				assert.True(t, m.Identity.Auditor)
			}
		})
	}
	t.Run("附加情形", ovMultiSourceCases)
}

// ovMultiSourceCases 附加情形：同角色多來源、節點指派內不支援節點範圍的鍵。
func ovMultiSourceCases(t *testing.T) {
	t.Run("同一角色直接範圍 A、經群組範圍 B 合為一張卡且範圍各自獨立", func(t *testing.T) {
		e := newOvEnv(t)
		fx := newOvFixture(e)
		u := e.user("ov-multi")
		e.assign(u.ID, model.BuiltinAssetAdmin, "", fx.nA1)
		g := e.group("ov-multi-group")
		e.groupRole(g.ID, model.BuiltinAssetAdmin, fx.nB)
		e.join(g.ID, u.ID, true)
		got := e.overview(e.globalViewer(), u).Management
		require.Len(t, got.Bindings, 1)
		require.Len(t, got.Sources, 2)
		assert.Len(t, got.Bindings[0].SourceRefs, 2)
		scopes := map[string][]uint{}
		for _, s := range got.Sources {
			scopes[s.Kind] = ovScopeNodeIDs(s.Scope)
		}
		assert.Equal(t, []uint{fx.nA1}, scopes[OverviewSourceDirect])
		assert.Equal(t, []uint{fx.nB}, scopes[OverviewSourceGroup])
		for _, op := range got.Permissions {
			if op.Permission == string(PermAssetView) {
				assert.Equal(t, OverviewScopeNodes, op.Scopes.Kind)
				assert.ElementsMatch(t, []uint{fx.nA1, fx.nB}, ovScopeNodeIDs(op.Scopes), "權限點範圍為各來源節點聯集（等於 bindingOf）")
			}
		}
	})
	t.Run("節點指派內的 global-only 鍵列為不生效且不在權限點", func(t *testing.T) {
		e := newOvEnv(t)
		fx := newOvFixture(e)
		e.custom("ov-mixed", PermAssetView, PermAssetUpdate, PermUserManage)
		u := e.user("ov-mixed-user")
		e.assign(u.ID, "ov-mixed", "", fx.nA)
		got := e.overview(e.globalViewer(), u).Management
		require.Len(t, got.Sources, 1)
		require.Equal(t, []OverviewIneffective{{Permission: string(PermUserManage), Reason: OverviewReasonNotNodeScopable}}, got.Sources[0].Ineffective)
		for _, op := range got.Permissions {
			assert.NotEqual(t, string(PermUserManage), op.Permission)
		}
		assert.NotContains(t, got.Sources[0].EffectivePermissions, string(PermUserManage))
	})
	t.Run("內建身分範本以節點範圍指派時列為需全系統", func(t *testing.T) {
		e := newOvEnv(t)
		fx := newOvFixture(e)
		u := e.user("ov-builtin-node")
		e.assign(u.ID, model.BuiltinUser, "", fx.nA)
		got := e.overview(e.globalViewer(), u).Management
		for _, s := range got.Sources {
			for _, ie := range s.Ineffective {
				assert.Contains(t, []string{OverviewReasonBuiltinRequiresGlobal, OverviewReasonNotNodeScopable}, ie.Reason)
			}
		}
	})
	t.Run("僅經使用者群組取得超管者的身分旗標為真", func(t *testing.T) {
		e := newOvEnv(t)
		newOvFixture(e)
		u := e.user("ov-group-super")
		g := e.group("ov-super-group")
		e.groupRole(g.ID, model.BuiltinSuperAdmin)
		e.join(g.ID, u.ID, true)
		got := e.overview(e.globalViewer(), u).Management
		assert.True(t, got.Identity.SuperAdmin)
		assert.False(t, got.Identity.CompatDefault)
		for _, op := range got.Permissions {
			assert.Equal(t, OverviewScopeGlobal, op.Scopes.Kind)
		}
	})
}
