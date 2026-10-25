package authz

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

var (
	wantAllow    = ScopeResult{Outcome: ScopeAllow}
	wantNoCap    = ScopeResult{Outcome: ScopeDenyCapability, Reason: ScopeReasonNoEffectiveBinding}
	wantOutScope = ScopeResult{Outcome: ScopeDenyScope, Reason: ScopeReasonOutOfScope}
)

// runDecideSubtests 同筆指派判定的子測試（掛在 TestScopeEvaluationSameBinding 之下）。
func runDecideSubtests(t *testing.T) {
	t.Run("same_binding_not_stitched", func(t *testing.T) {
		f := newDecideFixture(t)
		ev := f.evaluator(f.catView)
		// 甲指派：asset:view＋節點 n3；乙指派：asset:update（不含 view）＋節點 n4
		uid := f.user(t)
		f.bindDirect(t, uid, f.role(t, PermAssetView), f.n[3])
		f.bindDirect(t, uid, f.role(t, PermAssetUpdate), f.n[4])

		assert.Equal(t, wantAllow, f.decide(t, ev, uid, PermAssetView, AssetTarget(f.a[1])), "能力與範圍同在甲")
		assert.Equal(t, wantOutScope, f.decide(t, ev, uid, PermAssetView, AssetTarget(f.a[2])), "能力來自甲、範圍來自乙：拒絕")
		assert.Equal(t, wantOutScope, f.decide(t, ev, uid, PermAssetUpdate, AssetTarget(f.a[1])), "反向拼湊也拒絕")
		assert.Equal(t, wantAllow, f.decide(t, ev, uid, PermAssetUpdate, AssetTarget(f.a[2])))
		// 多歸屬資產 a4 掛 n2、n4：在乙的範圍內
		assert.Equal(t, wantAllow, f.decide(t, ev, uid, PermAssetUpdate, AssetTarget(f.a[4])))
		assert.Equal(t, wantOutScope, f.decide(t, ev, uid, PermAssetView, AssetTarget(f.a[4])), "view 只在甲，a4 不在 n3 子樹")
	})

	t.Run("direct_and_group_same_result", func(t *testing.T) {
		f := newDecideFixture(t)
		ev := f.evaluator(f.catView)
		role := f.role(t, PermAssetView)
		d, g := f.user(t), f.user(t)
		f.bindDirect(t, d, role, f.n[2])
		f.bindGroup(t, g, role, f.n[2])
		for name, target := range map[string]ScopeTarget{
			"a1": AssetTarget(f.a[1]), "a2": AssetTarget(f.a[2]), "a3": AssetTarget(f.a[3]), "a4": AssetTarget(f.a[4]),
			"acc1": AssetAccountTarget(f.a[1], f.acc[1]), "acc2": AssetAccountTarget(f.a[2], f.acc[2]),
			"n3": NodeTarget(f.n[3]), "n1": NodeTarget(f.n[1]), "n4": NodeTarget(f.n[4]), "none": AssetTarget(9999),
		} {
			assert.Equal(t, f.decide(t, ev, d, PermAssetView, target), f.decide(t, ev, g, PermAssetView, target), name)
		}
		assert.Equal(t, wantAllow, f.decide(t, ev, g, PermAssetView, AssetTarget(f.a[1])))
		assert.Equal(t, wantAllow, f.decide(t, ev, g, PermAssetView, NodeTarget(f.n[2])), "範圍根節點自身在範圍")
		assert.Equal(t, wantOutScope, f.decide(t, ev, g, PermAssetView, NodeTarget(f.n[1])), "祖先節點不在子樹範圍")
	})

	t.Run("partial_and_full_node_deletion", func(t *testing.T) {
		f := newDecideFixture(t)
		ev := f.evaluator(f.catView)
		partial, all, empty := f.user(t), f.user(t), f.user(t)
		f.bindDirect(t, partial, f.role(t, PermAssetView), f.n[3], f.n[5])
		f.bindDirect(t, all, f.role(t, PermAssetView), f.n[5])
		f.bindDirect(t, empty, f.role(t, PermAssetView)) // 節點範圍但沒有任何節點
		assert.Equal(t, wantAllow, f.decide(t, ev, all, PermAssetView, AssetTarget(f.a[5])))
		f.deleteNode(t, f.n[5])
		assert.Equal(t, wantAllow, f.decide(t, ev, partial, PermAssetView, AssetTarget(f.a[1])), "部分刪除：略過已刪節點，其餘生效")
		assert.Equal(t, wantNoCap, f.decide(t, ev, all, PermAssetView, AssetTarget(f.a[5])), "全刪：不生效")
		assert.Equal(t, wantNoCap, f.decide(t, ev, all, PermAssetView, AssetTarget(f.a[1])))
		assert.Equal(t, wantNoCap, f.decide(t, ev, empty, PermAssetView, AssetTarget(f.a[1])), "空集合：能力拒絕")
		// 已刪子樹不再涵蓋：刪掉 n3 後，掛在其下的資產不在 n2 範圍內
		sub := f.user(t)
		f.bindDirect(t, sub, f.role(t, PermAssetView), f.n[2])
		assert.Equal(t, wantAllow, f.decide(t, ev, sub, PermAssetView, AssetTarget(f.a[1])))
		f.deleteNode(t, f.n[3])
		assert.Equal(t, wantOutScope, f.decide(t, ev, sub, PermAssetView, AssetTarget(f.a[1])), "掛載節點已刪：已刪子樹不涵蓋")
		assert.Equal(t, wantOutScope, f.decide(t, ev, sub, PermAssetView, NodeTarget(f.n[3])))
	})

	t.Run("ungrouped_asset_global_only", func(t *testing.T) {
		f := newDecideFixture(t)
		ev := f.evaluator(f.catView)
		scoped, global := f.user(t), f.user(t)
		f.bindDirect(t, scoped, f.role(t, PermAssetView), f.n[1], f.n[4], f.n[5])
		f.global(t, global, f.role(t, PermAssetView))
		assert.Equal(t, wantOutScope, f.decide(t, ev, scoped, PermAssetView, AssetTarget(f.a[3])), "節點範圍不涵蓋未分組")
		assert.Equal(t, wantAllow, f.decide(t, ev, global, PermAssetView, AssetTarget(f.a[3])), "全域涵蓋未分組")
	})

	t.Run("scope_attribute_variants", func(t *testing.T) {
		f := newDecideFixture(t)
		uid := f.user(t)
		f.bindDirect(t, uid, f.role(t, PermAssetView), f.n[1], f.n[4])
		variant := func(attr ScopeAttr) Catalogue {
			defs := Catalog()
			for i := range defs {
				if defs[i].Key == PermAssetView {
					defs[i].Scope = attr
				}
			}
			return catalogueOf(defs)
		}
		target := AssetTarget(f.a[1])
		assert.Equal(t, wantAllow, f.decide(t, f.evaluator(variant(ScopeEnforced)), uid, PermAssetView, target))
		assert.Equal(t, wantNoCap, f.decide(t, f.evaluator(variant(ScopeReserved)), uid, PermAssetView, target), "scoped-reserved")
		assert.Equal(t, wantNoCap, f.decide(t, f.evaluator(variant(ScopeGlobalOnly)), uid, PermAssetView, target), "global-only")
		assert.Equal(t, wantAllow, f.decide(t, f.evaluator(ProductCatalogue()), uid, PermAssetView, target), "產品目錄（資產檢視已啟用範圍判定）")
	})

	t.Run("global_source_does_not_resolve", func(t *testing.T) {
		f := newDecideFixture(t)
		uid := f.user(t)
		f.global(t, uid, f.role(t, PermAssetView))
		// 有全域來源：不解析目標，不存在的 ID、未登記種類都放行；拓撲未注入也照常
		for _, ev := range []*ScopeEvaluator{f.evaluator(f.catView), NewScopeEvaluator(f.catView, nil)} {
			assert.Equal(t, wantAllow, f.decide(t, ev, uid, PermAssetView, AssetTarget(99999)))
			assert.Equal(t, wantAllow, f.decide(t, ev, uid, PermAssetView, NodeTarget(99999)))
			assert.Equal(t, wantAllow, f.decide(t, ev, uid, PermAssetView, AssetAccountTarget(99999, 99999)))
			assert.Equal(t, wantAllow, f.decide(t, ev, uid, PermAssetView, ScopeTarget{Kind: "credential", RefID: 1}))
		}
		// 全域來源加節點範圍來源：仍是全域放行
		mixed := f.user(t)
		f.global(t, mixed, f.role(t, PermAssetView))
		f.bindDirect(t, mixed, f.role(t, PermAssetView), f.n[4])
		assert.Equal(t, wantAllow, f.decide(t, f.evaluator(f.catView), mixed, PermAssetView, AssetTarget(f.a[1])))
	})

	t.Run("superadmin_and_builtin_identities", func(t *testing.T) {
		f := newDecideFixture(t)
		ev := f.evaluator(f.catView)
		su, scopedSU, zero := f.user(t), f.user(t), f.user(t)
		_ = zero
		f.global(t, su, f.builtinRole(t, model.BuiltinSuperAdmin))
		assignDirect(t, f.db, scopedSU, f.builtinRole(t, model.BuiltinSuperAdmin), model.ScopeKindNodes)
		require.NoError(t, f.db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser, SubjectID: scopedSU,
			RoleID: f.builtinRole(t, model.BuiltinSuperAdmin), NodeID: f.n[4]}).Error)
		assert.Equal(t, wantAllow, f.decide(t, ev, su, PermAssetView, AssetTarget(99999)), "超管視同全域，不解析目標")
		assert.Equal(t, wantAllow, f.decide(t, NewScopeEvaluator(f.catView, nil), su, PermAssetUpdate, NodeTarget(1)))
		assert.Equal(t, wantNoCap, f.decide(t, ev, scopedSU, PermAssetView, AssetTarget(f.a[2])), "節點範圍的超管範本列不構成超管")
		// 零指派：相容規則視同一般使用者範本（全域來源），不解析目標
		assert.Equal(t, wantAllow, f.decide(t, ev, zero, PermAssetView, AssetTarget(99999)))
		assert.Equal(t, wantNoCap, f.decide(t, ev, zero, PermAssetUpdate, AssetTarget(f.a[1])))
		// agent：固定範本，不受角色列影響
		res, err := ev.Decide(f.db, &Principal{UserID: zero, Facts: TokenFacts{SubjectKind: model.KindAgent}}, PermAssetView, AssetTarget(99999))
		require.NoError(t, err)
		assert.Equal(t, wantAllow, res)
	})

	t.Run("nil_inputs_and_unavailable_topology", func(t *testing.T) {
		f := newDecideFixture(t)
		ev := f.evaluator(f.catView)
		res, err := ev.Decide(f.db, nil, PermAssetView, AssetTarget(1))
		assert.ErrorIs(t, err, ErrScopeNilPrincipal)
		assert.Equal(t, ScopeResult{}, res, "零值結果不是放行")
		res, err = ev.Decide(nil, &Principal{UserID: 1}, PermAssetView, AssetTarget(1))
		assert.Error(t, err)
		assert.Equal(t, ScopeResult{}, res)

		uid := f.user(t)
		f.bindDirect(t, uid, f.role(t, PermAssetView), f.n[1])
		noTopo := NewScopeEvaluator(f.catView, nil)
		assert.Equal(t, ScopeResult{Outcome: ScopeDenyScope, Reason: ScopeReasonTopologyUnavailable},
			f.decide(t, noTopo, uid, PermAssetView, AssetTarget(f.a[1])), "未注入拓撲：節點範圍主體範圍拒絕")
		_, layer, err := noTopo.decideOn(f.db, mustResolve(t, f, noTopo, uid), PermAssetView, AssetTarget(f.a[1]))
		require.NoError(t, err)
		assert.Equal(t, ScopeLayerAsset, layer)

		// 未登記種類
		res = f.decide(t, ev, uid, PermAssetView, ScopeTarget{Kind: "credential", RefID: 1})
		assert.Equal(t, ScopeResult{Outcome: ScopeDenyScope, Reason: ScopeReasonResolverMissing}, res)
		_, layer, _ = ev.decideOn(f.db, mustResolve(t, f, ev, uid), PermAssetView, ScopeTarget{Kind: "credential", RefID: 1})
		assert.Equal(t, ScopeLayerTarget, layer)
	})

	t.Run("capability_denied_iff_has_false", func(t *testing.T) {
		f := newDecideFixture(t)
		build := map[string]uint{}
		add := func(label string, fn func(uid uint)) {
			uid := f.user(t)
			fn(uid)
			build[label] = uid
		}
		viewRole, updRole, bothRole := f.role(t, PermAssetView), f.role(t, PermAssetUpdate), f.role(t, PermAssetView, PermAssetUpdate, PermAuditView, PermAlertRuleManage)
		add("no_assignment", func(uint) {})
		add("global_view", func(u uint) { f.global(t, u, viewRole) })
		add("global_both", func(u uint) { f.global(t, u, bothRole) })
		add("node_view", func(u uint) { f.bindDirect(t, u, viewRole, f.n[1]) })
		add("node_both", func(u uint) { f.bindDirect(t, u, bothRole, f.n[4]) })
		add("node_stitch", func(u uint) { f.bindDirect(t, u, viewRole, f.n[3]); f.bindDirect(t, u, updRole, f.n[4]) })
		add("group_node_both", func(u uint) { f.bindGroup(t, u, bothRole, f.n[2]) })
		add("global_plus_node", func(u uint) { f.global(t, u, updRole); f.bindDirect(t, u, viewRole, f.n[1]) })
		add("node_no_nodes", func(u uint) { f.bindDirect(t, u, bothRole) })
		add("node_all_deleted", func(u uint) { f.bindDirect(t, u, bothRole, f.n[5]) })
		add("super_admin", func(u uint) { f.global(t, u, f.builtinRole(t, model.BuiltinSuperAdmin)) })
		add("auditor", func(u uint) { f.global(t, u, f.builtinRole(t, model.BuiltinAuditor)) })
		add("builtin_user_node", func(u uint) {
			r := f.builtinRole(t, model.BuiltinUser)
			assignDirect(t, f.db, u, r, model.ScopeKindNodes)
			require.NoError(t, f.db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser, SubjectID: u, RoleID: r, NodeID: f.n[1]}).Error)
		})
		f.deleteNode(t, f.n[5])
		// agent 以第二種 token 脈絡加入
		type subject struct {
			label string
			uid   uint
			facts TokenFacts
		}
		var subjects []subject
		for l, u := range build {
			subjects = append(subjects, subject{l, u, TokenFacts{}})
		}
		subjects = append(subjects, subject{"agent", build["no_assignment"], TokenFacts{SubjectKind: model.KindAgent}})

		catalogues := map[string]Catalogue{"product": ProductCatalogue(), "enforced_view_update": f.catView}
		allEnforced := func() Catalogue {
			var keys []Permission
			for _, d := range Catalog() {
				if d.Scope == ScopeReserved {
					keys = append(keys, d.Key)
				}
			}
			c, err := CatalogueWithScopedEnforcedForTest(keys...)
			require.NoError(t, err)
			return c
		}()
		catalogues["all_reserved_enforced"] = allEnforced
		targets := []ScopeTarget{AssetTarget(f.a[1]), AssetTarget(f.a[3]), AssetTarget(99999), NodeTarget(f.n[3]),
			AssetAccountTarget(f.a[2], f.acc[2]), {Kind: "credential", RefID: 1}}

		total, capDeny, allow, scopeDeny := 0, 0, 0, 0
		for cname, cat := range catalogues {
			ev := f.evaluator(cat)
			for _, s := range subjects {
				p, err := ResolveUserOnWithCatalogue(f.db, cat, s.uid, s.facts)
				require.NoError(t, err)
				for _, perm := range CatalogKeys() {
					for _, target := range targets {
						res, err := ev.Decide(f.db, &Principal{UserID: s.uid, Facts: s.facts}, perm, target)
						require.NoError(t, err)
						total++
						isCap := res.Outcome == ScopeDenyCapability
						require.Equalf(t, !p.Has(perm), isCap, "目錄 %s 主體 %s 權限 %s 目標 %v：能力拒絕 ⇔ Has 為假", cname, s.label, perm, target)
						switch res.Outcome {
						case ScopeDenyCapability:
							capDeny++
						case ScopeAllow:
							allow++
						case ScopeDenyScope:
							scopeDeny++
						default:
							t.Fatalf("非法結果 %v", res)
						}
					}
				}
			}
		}
		require.Greater(t, capDeny, 0)
		require.Greater(t, allow, 0)
		require.Greater(t, scopeDeny, 0)
		t.Logf("EVIDENCE exhaustive catalogues=%d subjects=%d perms=%d targets=%d total=%d allow=%d deny_capability=%d deny_scope=%d",
			len(catalogues), len(subjects), len(CatalogKeys()), len(targets), total, allow, capDeny, scopeDeny)
	})

	t.Run("product_catalogue_direct_node_row", func(t *testing.T) {
		f := newDecideFixture(t)
		userRole := f.builtinRole(t, model.BuiltinUser)
		withRow, rowOnly, rowSuper := f.user(t), f.user(t), f.user(t)
		globalOnly := f.user(t)
		f.global(t, withRow, userRole)
		f.global(t, globalOnly, userRole)
		// 自訂角色只放正式目錄仍為 scoped-reserved 的鍵（已逐鍵啟用的鍵會讓節點範圍列生效，不屬本案例）
		custom := f.role(t, PermCredentialManage, PermAuditView)
		for _, k := range []Permission{PermCredentialManage, PermAuditView} {
			d, _ := LookupPermission(k)
			require.Equal(t, ScopeReserved, d.Scope, "前提：%s 在正式目錄仍為 scoped-reserved", k)
		}
		f.bindDirect(t, withRow, custom, f.n[1]) // 直接寫表的節點範圍列
		f.bindDirect(t, rowOnly, custom, f.n[1])
		su := f.builtinRole(t, model.BuiltinSuperAdmin)
		assignDirect(t, f.db, rowSuper, su, model.ScopeKindNodes)
		require.NoError(t, f.db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser, SubjectID: rowSuper, RoleID: su, NodeID: f.n[1]}).Error)

		resolve := func(uid uint) *Principal {
			p, err := ResolveUserOn(f.db, uid, TokenFacts{})
			require.NoError(t, err)
			return p
		}
		assert.Equal(t, resolve(globalOnly).Capabilities(), resolve(withRow).Capabilities(), "加上節點範圍列後，能力集合與只有全域指派時相同")
		for _, uid := range []uint{rowOnly, rowSuper} {
			p := resolve(uid)
			assert.Empty(t, p.Capabilities(), "只有節點範圍列：能力為空")
			assert.False(t, p.Has(PermAssetView), "不具一般使用者範本")
			assert.False(t, p.IsSuperAdmin())
		}
		// 判定也一致：產品目錄下這些鍵仍為 scoped-reserved，節點範圍列不放行
		ev := f.evaluator(ProductCatalogue())
		assert.Equal(t, wantNoCap, f.decide(t, ev, rowOnly, PermCredentialManage, AssetTarget(f.a[1])))
		assert.Equal(t, wantNoCap, f.decide(t, ev, withRow, PermCredentialManage, AssetTarget(f.a[1])), "額外的節點範圍列不增加能力")
		assert.Equal(t, wantAllow, f.decide(t, ev, withRow, PermAssetView, AssetTarget(99999)), "全域一般使用者仍持 asset:view")
	})
}

func mustResolve(t *testing.T, f *decideFixture, ev *ScopeEvaluator, uid uint) *Principal {
	t.Helper()
	p, err := ResolveUserOnWithCatalogue(f.db, ev.cat, uid, TokenFacts{})
	require.NoError(t, err)
	return p
}

// failingTopology 讀取一律失敗的拓撲替身。
type failingTopology struct{ ScopeTopology }

var errTopologyDown = errors.New("topology down")

func (failingTopology) AssetCoverNodes(*gorm.DB, uint) ([]uint, bool, error) {
	return nil, false, errTopologyDown
}
func (failingTopology) NodeCoverNodes(*gorm.DB, uint) ([]uint, bool, error) {
	return nil, false, errTopologyDown
}
func (failingTopology) AccountAsset(*gorm.DB, uint) (uint, bool, error) {
	return 0, false, errTopologyDown
}

// runDecideResultSubtests 結果分類、原因碼與錯誤傳遞的子測試（掛在 TestScopeTargetResolvers 之下）。
func runDecideResultSubtests(t *testing.T) {
	t.Run("deleted_missing_out_of_scope_identical", func(t *testing.T) {
		f := newDecideFixture(t)
		ev := f.evaluator(f.catView)
		uid := f.user(t)
		f.bindDirect(t, uid, f.role(t, PermAssetView), f.n[1])
		// 已刪資產 a5、已刪節點 n5、不存在 ID、範圍外（a2 掛 n4、n4）：同一結構
		require.NoError(t, f.db.Delete(&model.Asset{}, f.a[5]).Error)
		f.deleteNode(t, f.n[5])
		p := mustResolve(t, f, ev, uid)
		type full struct {
			res   ScopeResult
			layer ScopeDeniedLayer
		}
		run := func(target ScopeTarget) full {
			res, layer, err := ev.decideOn(f.db, p, PermAssetView, target)
			require.NoError(t, err)
			return full{res, layer}
		}
		assetCases := []ScopeTarget{AssetTarget(f.a[5]), AssetTarget(99999), AssetTarget(f.a[2])}
		first := run(assetCases[0])
		assert.Equal(t, full{wantOutScope, ScopeLayerAsset}, first)
		for _, c := range assetCases[1:] {
			assert.Equal(t, first, run(c), "資產：已刪除、不存在、範圍外逐欄相同")
		}
		nodeCases := []ScopeTarget{NodeTarget(f.n[5]), NodeTarget(99999), NodeTarget(f.n[4])}
		firstNode := run(nodeCases[0])
		assert.Equal(t, full{wantOutScope, ScopeLayerNode}, firstNode)
		for _, c := range nodeCases[1:] {
			assert.Equal(t, firstNode, run(c), "節點：已刪除、不存在、範圍外逐欄相同")
		}
		// 帳號目標：資產不在範圍內（含已刪除、不存在）一律資產層，且與帳號是否屬於它無關
		accAsset := []ScopeTarget{
			AssetAccountTarget(f.a[5], f.acc[1]), // 已刪資產
			AssetAccountTarget(99999, f.acc[1]),  // 不存在資產
			AssetAccountTarget(f.a[2], f.acc[2]), // 範圍外資產＋帳號屬於它
			AssetAccountTarget(f.a[2], f.acc[1]), // 範圍外資產＋帳號不屬於它
			AssetAccountTarget(f.a[2], 99999),    // 範圍外資產＋帳號不存在
		}
		firstAcc := run(accAsset[0])
		assert.Equal(t, full{wantOutScope, ScopeLayerAsset}, firstAcc)
		for i, c := range accAsset[1:] {
			assert.Equal(t, firstAcc, run(c), "帳號目標資產層情形 %d 與已刪資產逐欄相同", i+1)
		}
		// 帳號層只在資產在範圍內、且帳號不存在或不屬於它
		assert.Equal(t, full{wantOutScope, ScopeLayerAccount}, run(AssetAccountTarget(f.a[1], f.acc[2])), "範圍內資產搭他資產的帳號：帳號層")
		assert.Equal(t, full{wantOutScope, ScopeLayerAccount}, run(AssetAccountTarget(f.a[1], 99999)), "範圍內資產＋帳號不存在：帳號層")
		assert.Equal(t, wantAllow, run(AssetAccountTarget(f.a[1], f.acc[1])).res)
		// 每個拒絕都能組成 ErrScopeDenied，且為同一固定字串
		err := error(NewErrScopeDenied(ScopeTargetAsset, first.layer, first.res.Reason))
		var denied *ErrScopeDenied
		require.True(t, errors.As(err, &denied))
		assert.Equal(t, "authz: scope denied", err.Error())
	})

	t.Run("read_failure_is_error_not_decision", func(t *testing.T) {
		f := newDecideFixture(t)
		uid := f.user(t)
		f.bindDirect(t, uid, f.role(t, PermAssetView), f.n[1])
		bad := NewScopeEvaluator(f.catView, failingTopology{f.topo})
		for _, target := range []ScopeTarget{AssetTarget(f.a[1]), NodeTarget(f.n[1]), AssetAccountTarget(f.a[1], f.acc[1])} {
			res, err := bad.Decide(f.db, &Principal{UserID: uid}, PermAssetView, target)
			require.Error(t, err)
			assert.ErrorIs(t, err, errTopologyDown)
			assert.Equal(t, ScopeResult{}, res, "不是放行也不是範圍拒絕")
			assert.NotEqual(t, ScopeAllow, res.Outcome)
			assert.NotEqual(t, ScopeDenyScope, res.Outcome)
			var denied *ErrScopeDenied
			assert.False(t, errors.As(err, &denied), "讀取失敗不偽裝成範圍拒絕")
		}
		// 登記的後段解析器回錯誤：同樣原樣傳出
		boom := errors.New("resolver boom")
		reg := NewScopeEvaluator(f.catView, f.topo, ScopeTargetResolverRegistration{Kind: "credential",
			Resolve: func(*gorm.DB, ScopeTopology, ScopeTarget) (ResolvedScopeTarget, error) {
				return ResolvedScopeTarget{}, boom
			}})
		res, err := reg.Decide(f.db, &Principal{UserID: uid}, PermAssetView, ScopeTarget{Kind: "credential", RefID: 1})
		assert.ErrorIs(t, err, boom)
		assert.Equal(t, ScopeResult{}, res)
		// 全域主體不碰拓撲：拓撲壞了仍放行
		g := f.user(t)
		f.global(t, g, f.role(t, PermAssetView))
		res, err = bad.Decide(f.db, &Principal{UserID: g}, PermAssetView, AssetTarget(f.a[1]))
		require.NoError(t, err)
		assert.Equal(t, wantAllow, res)
		// 主體解析失敗（連線關閉）：錯誤
		sqlDB, _ := f.db.DB()
		require.NoError(t, sqlDB.Close())
		res, err = f.evaluator(f.catView).Decide(f.db, &Principal{UserID: uid}, PermAssetView, AssetTarget(f.a[1]))
		assert.Error(t, err)
		assert.Equal(t, ScopeResult{}, res)
	})

	t.Run("result_is_name_free_and_reasons_controlled", func(t *testing.T) {
		f := newDecideFixture(t)
		ev := f.evaluator(f.catView)
		controlled := map[ScopeReason]bool{ScopeReasonNone: true, ScopeReasonNoEffectiveBinding: true, ScopeReasonOutOfScope: true,
			ScopeReasonResolverMissing: true, ScopeReasonTopologyUnavailable: true}
		uid, noCap := f.user(t), f.user(t)
		f.bindDirect(t, uid, f.role(t, PermAssetView), f.n[1])
		f.bindDirect(t, noCap, f.role(t, PermAuditView), f.n[1])
		noTopo := NewScopeEvaluator(f.catView, nil)
		var blobs []string
		for _, e := range []*ScopeEvaluator{ev, noTopo} {
			for _, target := range []ScopeTarget{AssetTarget(f.a[1]), AssetTarget(f.a[2]), AssetTarget(99999), NodeTarget(f.n[4]),
				AssetAccountTarget(f.a[1], f.acc[2]), {Kind: "credential", RefID: 1}} {
				for _, u := range []uint{uid, noCap} {
					res := f.decide(t, e, u, PermAssetView, target)
					assert.True(t, controlled[res.Reason], "原因碼 %q 不在受控集合", res.Reason)
					switch res.Outcome {
					case ScopeAllow:
						assert.Equal(t, ScopeReasonNone, res.Reason)
					case ScopeDenyCapability:
						assert.Equal(t, ScopeReasonNoEffectiveBinding, res.Reason)
					case ScopeDenyScope:
						assert.NotContains(t, []ScopeReason{ScopeReasonNone, ScopeReasonNoEffectiveBinding}, res.Reason)
					default:
						t.Fatalf("非法結果 %v", res)
					}
					b, err := json.Marshal(res)
					require.NoError(t, err)
					blobs = append(blobs, string(b))
					_, layer, _ := e.decideOn(f.db, mustResolve(t, f, e, u), PermAssetView, target)
					eb, err := json.Marshal(NewErrScopeDenied(target.Kind, layer, res.Reason))
					require.NoError(t, err)
					blobs = append(blobs, string(eb), NewErrScopeDenied(target.Kind, layer, res.Reason).Error())
				}
			}
		}
		require.NotEmpty(t, f.names)
		for _, blob := range blobs {
			assert.NotContains(t, blob, fxSecretPrefix)
			for _, n := range f.names {
				assert.NotContains(t, blob, n)
			}
		}
	})

	t.Run("no_package_state_in_evaluator_files", func(t *testing.T) {
		for _, name := range []string{"scope_evaluator.go", "scope_sources.go", "scope_result.go", "scope_target_resolvers.go"} {
			src, err := os.ReadFile(name)
			require.NoError(t, err)
			assert.NotRegexp(t, `sync\.Map|cache`, string(src), name)
		}
	})
}
