package authz

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/testgate"
)

// 範圍集合述詞的 parity 與窄介面。指派集合入口的子測試在 scope_set_assignments_test.go，
// 全部子測試在 SQLite 與 PostgreSQL（postgres 子測試）各跑一次。

// setParityExtra 在判定夾具上另建一段含已刪中間節點的子樹與已刪資產：
//
//	n6 根 ── n7（刪除）── n8；a6 掛 n8；a7 掛 n4（資產刪除）；a8 只掛 n7
type setParityExtra struct {
	n6, n7, n8 uint
	a6, a7, a8 uint
}

func addSetParityExtra(t *testing.T, f *decideFixture) setParityExtra {
	t.Helper()
	up := func(i uint) *uint { return &i }
	var x setParityExtra
	x.n6 = mkNode(t, f.db, f.uniq("n"), nil).ID
	x.n7 = mkNode(t, f.db, f.uniq("n"), up(x.n6)).ID
	x.n8 = mkNode(t, f.db, f.uniq("n"), up(x.n7)).ID
	x.a6 = mkAsset(t, f.db, f.uniq("a")).ID
	x.a7 = mkAsset(t, f.db, f.uniq("a")).ID
	x.a8 = mkAsset(t, f.db, f.uniq("a")).ID
	for _, m := range [][2]uint{{x.a6, x.n8}, {x.a7, f.n[4]}, {x.a8, x.n7}} {
		require.NoError(t, f.db.Create(&model.AssetNode{AssetID: m[0], NodeID: m[1]}).Error)
	}
	return x
}

// members 套集合後的實際列（只含未刪除列；分頁與計數前過濾的同一查詢）。
func setMembers(t *testing.T, db *gorm.DB, ev *ScopeEvaluator, set ScopeSet, kind ScopeQueryKind) map[uint]bool {
	t.Helper()
	q, col := db.Model(&model.Asset{}), "assets.id"
	if kind == ScopeQueryNode {
		q, col = db.Model(&model.AssetGroup{}), "asset_groups.id"
	}
	q, err := ev.ApplyScopeSet(db, q, set, kind)
	require.NoError(t, err)
	var ids []uint
	require.NoError(t, q.Pluck(col, &ids).Error)
	out := make(map[uint]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out
}

func setIDs(m map[uint]bool) []uint {
	out := make([]uint, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func liveIDs(t *testing.T, db *gorm.DB, kind ScopeQueryKind) []uint {
	t.Helper()
	var ids []uint
	if kind == ScopeQueryAsset {
		require.NoError(t, db.Model(&model.Asset{}).Order("id").Pluck("id", &ids).Error)
	} else {
		require.NoError(t, db.Model(&model.AssetGroup{}).Order("id").Pluck("id", &ids).Error)
	}
	return ids
}

func allReservedEnforced(t *testing.T) Catalogue {
	t.Helper()
	var keys []Permission
	for _, d := range Catalog() {
		if d.Scope == ScopeReserved {
			keys = append(keys, d.Key)
		}
	}
	c, err := CatalogueWithScopedEnforcedForTest(keys...)
	require.NoError(t, err)
	return c
}

// setParitySubject 母體中的一個主體（agent 與零指派主體共用同一使用者編號）。
type setParitySubject struct {
	label string
	uid   uint
	facts TokenFacts
}

// setParityPopulation 建立 parity 母體的主體與拓撲（含已刪節點、已刪中間節點與已刪資產），
// 回傳主體清單、額外拓撲與「不存在或已刪」的 ID（不得在任何集合內）。
func setParityPopulation(t *testing.T, f *decideFixture) ([]setParitySubject, setParityExtra, map[ScopeQueryKind][]uint) {
	t.Helper()
	x := addSetParityExtra(t, f)
	var subjects []setParitySubject
	add := func(label string, fn func(uid uint)) {
		uid := f.user(t)
		fn(uid)
		subjects = append(subjects, setParitySubject{label, uid, TokenFacts{}})
	}
	viewRole, updRole := f.role(t, PermAssetView), f.role(t, PermAssetUpdate)
	bothRole := f.role(t, PermAssetView, PermAssetUpdate, PermAuditView, PermAlertRuleManage)
	add("no_assignment", func(uint) {})
	add("global_view", func(u uint) { f.global(t, u, viewRole) })
	add("global_both", func(u uint) { f.global(t, u, bothRole) })
	add("node_view_n1", func(u uint) { f.bindDirect(t, u, viewRole, f.n[1]) })
	add("node_both_n4", func(u uint) { f.bindDirect(t, u, bothRole, f.n[4]) })
	add("node_stitch", func(u uint) { f.bindDirect(t, u, viewRole, f.n[3]); f.bindDirect(t, u, updRole, f.n[4]) })
	add("group_node_both_n2", func(u uint) { f.bindGroup(t, u, bothRole, f.n[2]) })
	add("direct_and_group_overlap", func(u uint) { f.bindDirect(t, u, viewRole, f.n[2]); f.bindGroup(t, u, viewRole, f.n[2], f.n[4]) })
	add("global_plus_node", func(u uint) { f.global(t, u, updRole); f.bindDirect(t, u, viewRole, f.n[1]) })
	add("node_no_nodes", func(u uint) { f.bindDirect(t, u, bothRole) })
	add("node_all_deleted", func(u uint) { f.bindDirect(t, u, bothRole, f.n[5]) })
	add("node_partial_deleted", func(u uint) { f.bindDirect(t, u, bothRole, f.n[5], f.n[3]) })
	add("node_above_deleted_mid", func(u uint) { f.bindDirect(t, u, bothRole, x.n6) })
	add("node_on_deleted_mid", func(u uint) { f.bindGroup(t, u, bothRole, x.n7, x.n8) })
	add("super_admin", func(u uint) { f.global(t, u, f.builtinRole(t, model.BuiltinSuperAdmin)) })
	add("auditor", func(u uint) { f.global(t, u, f.builtinRole(t, model.BuiltinAuditor)) })
	add("approver_only", func(u uint) { f.global(t, u, f.builtinRole(t, model.BuiltinApprover)) })
	add("builtin_user_node", func(u uint) {
		r := f.builtinRole(t, model.BuiltinUser)
		assignDirect(t, f.db, u, r, model.ScopeKindNodes)
		require.NoError(t, f.db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser, SubjectID: u, RoleID: r, NodeID: f.n[1]}).Error)
	})
	subjects = append(subjects, setParitySubject{"agent", subjects[0].uid, TokenFacts{SubjectKind: model.KindAgent}})
	f.deleteNode(t, f.n[5])
	f.deleteNode(t, x.n7)
	require.NoError(t, f.db.Delete(&model.Asset{}, x.a7).Error)
	absent := map[ScopeQueryKind][]uint{ // 不存在與已刪除的 ID：不在任何集合
		ScopeQueryAsset: {x.a7, 99991},
		ScopeQueryNode:  {f.n[5], x.n7, 99992},
	}
	return subjects, x, absent
}

// setParityCatalogues parity 母體的三個目錄（正式、asset:view／update 範圍化、全部保留鍵範圍化）。
func setParityCatalogues(t *testing.T, f *decideFixture) map[string]Catalogue {
	t.Helper()
	return map[string]Catalogue{
		"product": ProductCatalogue(), "enforced_view_update": f.catView, "all_reserved_enforced": allReservedEnforced(t),
	}
}

// TestScopeSetParity 在 SQLite 跑全部子測試；設了 TEST_PG_DSN 時於 postgres 子測試以獨立 schema 再跑一次
// （REQUIRE_INTEGRATION=1 而未設時轉為失敗）。
func TestScopeSetParity(t *testing.T) {
	runScopeSetParity(t, newDecideFixture)
	t.Run("postgres", func(t *testing.T) {
		dsn := testgate.Value(t, testgate.EnvPGDSN)
		runScopeSetParity(t, func(t *testing.T) *decideFixture {
			f := newDecideFixtureOn(t, newPrincipalDBPG(t, dsn))
			require.Equal(t, "postgres", f.db.Dialector.Name(), "PG 子測試不得回退 SQLite")
			return f
		})
	})
}

func runScopeSetParity(t *testing.T, newFx func(*testing.T) *decideFixture) {
	t.Run("population_exhaustive", func(t *testing.T) {
		f := newFx(t)
		subjects, x, absent := setParityPopulation(t, f)
		assets, nodes := liveIDs(t, f.db, ScopeQueryAsset), liveIDs(t, f.db, ScopeQueryNode)
		require.NotContains(t, assets, x.a7)
		require.NotContains(t, nodes, x.n7)
		require.Contains(t, assets, x.a8) // 只掛已刪節點的未刪資產仍在母體內

		catalogues := setParityCatalogues(t, f)
		total, allow, deny := 0, 0, 0
		states := map[ScopeSetState]int{}
		for cname, cat := range catalogues {
			ev := f.evaluator(cat)
			for _, s := range subjects {
				carrier := &Principal{UserID: s.uid, Facts: s.facts}
				for _, perm := range CatalogKeys() {
					set, err := ev.ScopeSetFor(f.db, carrier, perm)
					require.NoError(t, err)
					require.NotZero(t, set.State(), "集合狀態不得為零值")
					states[set.State()]++
					for _, kind := range []ScopeQueryKind{ScopeQueryAsset, ScopeQueryNode} {
						in := setMembers(t, f.db, ev, set, kind)
						pop, mk := assets, AssetTarget
						if kind == ScopeQueryNode {
							pop, mk = nodes, NodeTarget
						}
						for _, id := range absent[kind] {
							require.Falsef(t, in[id], "目錄 %s 主體 %s 權限 %s：不存在或已刪的 %s %d 不得在集合內", cname, s.label, perm, kind, id)
						}
						for _, id := range pop {
							res, err := ev.Decide(f.db, carrier, perm, mk(id))
							require.NoError(t, err)
							total++
							allowed := res.Outcome == ScopeAllow
							if allowed {
								allow++
							} else {
								deny++
							}
							require.Equalf(t, allowed, in[id], "目錄 %s 主體 %s 權限 %s %s %d：在集合內 ⇔ Decide 放行（集合 %s，判定 %v）",
								cname, s.label, perm, kind, id, set.State(), res)
						}
					}
				}
			}
		}
		require.Greater(t, allow, 0)
		require.Greater(t, deny, 0)
		require.Greater(t, states[ScopeSetConditional], 0)
		require.Greater(t, states[ScopeSetEmpty], 0)
		require.Greater(t, states[ScopeSetUnlimited], 0)
		t.Logf("EVIDENCE set-parity dialect=%s catalogues=%d subjects=%d perms=%d assets=%d nodes=%d total=%d allow=%d deny=%d sets_unlimited=%d sets_empty=%d sets_conditional=%d",
			f.db.Dialector.Name(), len(catalogues), len(subjects), len(CatalogKeys()), len(assets), len(nodes), total, allow, deny,
			states[ScopeSetUnlimited], states[ScopeSetEmpty], states[ScopeSetConditional])
	})

	t.Run("page_and_count_after_filter", func(t *testing.T) {
		f := newFx(t)
		ev := f.evaluator(f.catView)
		view := f.role(t, PermAssetView)
		u := f.user(t)
		f.bindDirect(t, u, view, f.n[2]) // n2 子樹：a1（n3）、a4（n2 與 n4）
		f.bindGroup(t, u, view, f.n[4])  // n4：a2、a4（a4 經兩個來源命中）
		carrier := &Principal{UserID: u}
		set, err := ev.ScopeSetFor(f.db, carrier, PermAssetView)
		require.NoError(t, err)
		require.Equal(t, ScopeSetConditional, set.State())

		var want []uint
		for _, id := range liveIDs(t, f.db, ScopeQueryAsset) {
			if f.decide(t, ev, u, PermAssetView, AssetTarget(id)).Outcome == ScopeAllow {
				want = append(want, id)
			}
		}
		require.Equal(t, []uint{f.a[1], f.a[2], f.a[4]}, want)

		page := func(offset, limit int) ([]uint, int64) {
			q, err := ev.ApplyScopeSet(f.db, f.db.Model(&model.Asset{}), set, ScopeQueryAsset)
			require.NoError(t, err)
			var n int64
			require.NoError(t, q.Count(&n).Error)
			q, err = ev.ApplyScopeSet(f.db, f.db.Model(&model.Asset{}), set, ScopeQueryAsset)
			require.NoError(t, err)
			var ids []uint
			require.NoError(t, q.Order("assets.id").Offset(offset).Limit(limit).Pluck("assets.id", &ids).Error)
			return ids, n
		}
		first, total := page(0, 2)
		require.Equal(t, int64(len(want)), total, "總數等於範圍內實際數（多來源命中的 a4 只計一次）")
		require.Equal(t, want[:2], first, "第一頁只含範圍內，且先過濾再分頁")
		second, _ := page(2, 2)
		require.Equal(t, want[2:], second)

		// 節點查詢同樣先過濾：n2、n3、n4
		qn, err := ev.ApplyScopeSet(f.db, f.db.Model(&model.AssetGroup{}), set, ScopeQueryNode)
		require.NoError(t, err)
		var nn int64
		require.NoError(t, qn.Count(&nn).Error)
		require.Equal(t, int64(3), nn)

		// 不限與空在分頁計數上的結果
		gu := f.user(t)
		f.global(t, gu, view)
		uset, err := ev.ScopeSetFor(f.db, &Principal{UserID: gu}, PermAssetView)
		require.NoError(t, err)
		require.Len(t, setIDs(setMembers(t, f.db, ev, uset, ScopeQueryAsset)), len(liveIDs(t, f.db, ScopeQueryAsset)))
		eset, err := ev.ScopeSetFor(f.db, &Principal{UserID: gu}, PermAuditView)
		require.NoError(t, err)
		require.Empty(t, setMembers(t, f.db, ev, eset, ScopeQueryAsset))
	})

	t.Run("unlimited_and_empty_are_typed", func(t *testing.T) {
		f := newFx(t)
		ev := f.evaluator(f.catView)
		g, none := f.user(t), f.user(t)
		f.global(t, g, f.role(t, PermAssetView))
		f.global(t, none, f.builtinRole(t, model.BuiltinApprover)) // 有指派、無能力
		uset, err := ev.ScopeSetFor(f.db, &Principal{UserID: g}, PermAssetView)
		require.NoError(t, err)
		eset, err := ev.ScopeSetFor(f.db, &Principal{UserID: none}, PermAssetView)
		require.NoError(t, err)
		require.Equal(t, ScopeSetUnlimited, uset.State())
		require.Equal(t, ScopeSetEmpty, eset.State())
		require.Equal(t, ScopeReasonNoEffectiveBinding, eset.Reason())
		require.NotEqual(t, uset, eset)
		require.NotEqual(t, ScopeSet{}, uset)
		require.NotEqual(t, ScopeSet{}, eset)
		require.Equal(t, ScopeSetState(0), ScopeSet{}.State(), "零值不是任何合法狀態")
		_, err = ev.ApplyScopeSet(f.db, f.db.Model(&model.Asset{}), ScopeSet{}, ScopeQueryAsset)
		require.Error(t, err, "零值集合不得被當成不限套用")
		_, err = ev.ApplyScopeSet(f.db, f.db.Model(&model.Asset{}), uset, ScopeQueryKind("credential"))
		require.Error(t, err, "未登記的查詢種類回錯誤")
		_, err = ev.ApplyScopeSet(f.db, nil, uset, ScopeQueryAsset)
		require.Error(t, err)
		_, err = ev.ScopeSetFor(f.db, nil, PermAssetView)
		require.ErrorIs(t, err, ErrScopeNilPrincipal)

		// 拓撲未注入：條件集合套用後為空（與 Decide 的 topology_unavailable 同結論）
		n := f.user(t)
		f.bindDirect(t, n, f.role(t, PermAssetView), f.n[1])
		noTopo := NewScopeEvaluator(f.catView, nil)
		cset, err := noTopo.ScopeSetFor(f.db, &Principal{UserID: n}, PermAssetView)
		require.NoError(t, err)
		require.Equal(t, ScopeSetConditional, cset.State())
		require.Empty(t, setMembers(t, f.db, noTopo, cset, ScopeQueryAsset))
		require.Equal(t, ScopeDenyScope, f.decide(t, noTopo, n, PermAssetView, AssetTarget(f.a[1])).Outcome)
	})

	// 變體四案
	t.Run("variant_global_view_plus_node_view", func(t *testing.T) {
		f := newFx(t)
		ev := f.evaluator(f.catView)
		u := f.user(t)
		f.global(t, u, f.builtinRole(t, model.BuiltinUser)) // 全域 asset:view（一般使用者範本）
		f.bindDirect(t, u, f.role(t, PermAssetView), f.n[2])
		carrier := &Principal{UserID: u}
		gen, err := ev.ScopeSetFor(f.db, carrier, PermAssetView)
		require.NoError(t, err)
		require.Equal(t, ScopeSetUnlimited, gen.State(), "一般三態回不限")
		v, err := ev.NodeScopeOnlySetFor(f.db, carrier, PermAssetView)
		require.NoError(t, err)
		require.Equal(t, ScopeSetConditional, v.State())
		require.Equal(t, []uint{f.a[1], f.a[4]}, setIDs(setMembers(t, f.db, ev, v, ScopeQueryAsset)), "變體只回 n2 子樹")
		require.Equal(t, []uint{f.n[2], f.n[3]}, setIDs(setMembers(t, f.db, ev, v, ScopeQueryNode)))
	})

	t.Run("variant_global_update_node_view", func(t *testing.T) {
		f := newFx(t)
		ev := f.evaluator(f.catView)
		u := f.user(t)
		f.global(t, u, f.role(t, PermAssetUpdate))
		f.bindDirect(t, u, f.role(t, PermAssetView), f.n[4])
		carrier := &Principal{UserID: u}
		upd, err := ev.ScopeSetFor(f.db, carrier, PermAssetUpdate)
		require.NoError(t, err)
		require.Equal(t, ScopeSetUnlimited, upd.State(), "動作選擇照一般三態，不因管理可視變窄")
		v, err := ev.NodeScopeOnlySetFor(f.db, carrier, PermAssetView)
		require.NoError(t, err)
		require.Equal(t, ScopeSetConditional, v.State())
		require.Equal(t, []uint{f.a[2], f.a[4]}, setIDs(setMembers(t, f.db, ev, v, ScopeQueryAsset)), "變體只回 n4 子樹")
		require.Equal(t, []uint{f.n[4]}, setIDs(setMembers(t, f.db, ev, v, ScopeQueryNode)))
		vu, err := ev.NodeScopeOnlySetFor(f.db, carrier, PermAssetUpdate)
		require.NoError(t, err)
		require.Equal(t, ScopeSetEmpty, vu.State(), "asset:update 只有全域來源：變體為空")
	})

	t.Run("variant_all_nodes_deleted_is_empty", func(t *testing.T) {
		f := newFx(t)
		ev := f.evaluator(f.catView)
		u := f.user(t)
		f.global(t, u, f.builtinRole(t, model.BuiltinUser))
		view := f.role(t, PermAssetView)
		f.bindDirect(t, u, view, f.n[5])
		f.bindGroup(t, u, view, f.n[5])
		carrier := &Principal{UserID: u}
		before, err := ev.NodeScopeOnlySetFor(f.db, carrier, PermAssetView)
		require.NoError(t, err)
		require.Equal(t, ScopeSetConditional, before.State())
		f.deleteNode(t, f.n[5])
		v, err := ev.NodeScopeOnlySetFor(f.db, carrier, PermAssetView)
		require.NoError(t, err)
		require.Equal(t, ScopeSetEmpty, v.State(), "含該鍵的節點範圍指派全刪：變體回空")
		require.NotEqual(t, ScopeSetUnlimited, v.State())
		require.NotEqual(t, ScopeSet{}, v)
		require.Empty(t, setMembers(t, f.db, ev, v, ScopeQueryAsset))
		gen, err := ev.ScopeSetFor(f.db, carrier, PermAssetView)
		require.NoError(t, err)
		require.Equal(t, ScopeSetUnlimited, gen.State(), "一般三態仍由全域來源決定")
	})

	t.Run("variant_reresolves_in_same_tx", func(t *testing.T) {
		f := newFx(t)
		ev := f.evaluator(f.catView)
		u := f.user(t)
		view := f.role(t, PermAssetView)
		f.global(t, u, f.builtinRole(t, model.BuiltinUser))
		f.bindDirect(t, u, view, f.n[4])
		carrier := &Principal{UserID: u} // 只帶 UserID；測試不另建或改寫主體
		tx := f.db.Begin()
		require.NoError(t, tx.Error)
		require.NoError(t, tx.Where("subject_kind = ? AND subject_id = ?", model.BindingSubjectUser, u).Delete(&model.RoleBindingNode{}).Error)
		v, err := ev.NodeScopeOnlySetFor(tx, carrier, PermAssetView)
		require.NoError(t, err)
		require.Equal(t, ScopeSetEmpty, v.State(), "交易內已移除節點：變體依交易內狀態")
		require.NoError(t, tx.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser, SubjectID: u, RoleID: view, NodeID: f.n[1]}).Error)
		v, err = ev.NodeScopeOnlySetFor(tx, carrier, PermAssetView)
		require.NoError(t, err)
		require.Equal(t, []uint{f.n[1], f.n[2], f.n[3]}, setIDs(setMembers(t, tx, ev, v, ScopeQueryNode)))
		require.NoError(t, tx.Rollback().Error)
		v, err = ev.NodeScopeOnlySetFor(f.db, carrier, PermAssetView)
		require.NoError(t, err)
		require.Equal(t, []uint{f.n[4]}, setIDs(setMembers(t, f.db, ev, v, ScopeQueryNode)), "回滾後回到已提交狀態")
		require.Nil(t, carrier.Assignments, "集合函式不改寫傳入的主體")
		require.Nil(t, carrier.caps)
	})

	t.Run("node_counts_dedup_and_deleted", func(t *testing.T) {
		f := newFx(t)
		ev := f.evaluator(f.catView)
		view, audit := f.role(t, PermAssetView), f.role(t, PermAuditView)
		u := f.user(t)
		f.global(t, u, f.builtinRole(t, model.BuiltinUser)) // 全域來源不計入
		f.bindDirect(t, u, view, f.n[4])
		f.bindGroup(t, u, view, f.n[4], f.n[5]) // 直接與經群組指向同一節點 n4
		f.bindDirect(t, u, audit, f.n[1])       // 不含所問的鍵；audit:view 也不是範圍化鍵
		f.deleteNode(t, f.n[5])
		carrier := &Principal{UserID: u}
		c, err := ev.ManagementScopeNodeCountsFor(f.db, carrier, []Permission{PermAssetView, PermAssetUpdate})
		require.NoError(t, err)
		require.Equal(t, ManagementScopeNodeCounts{Live: 1, Deleted: 1}, c)

		// 指派節點全刪：已刪數仍計入（不經只回未刪節點的 liveNodesOf）
		w := f.user(t)
		f.bindDirect(t, w, view, f.n[5])
		c, err = ev.ManagementScopeNodeCountsFor(f.db, &Principal{UserID: w}, []Permission{PermAssetView})
		require.NoError(t, err)
		require.Equal(t, ManagementScopeNodeCounts{Live: 0, Deleted: 1}, c)

		// 同一節點由兩個不同權限鍵的指派命中也只計一次
		upd := f.role(t, PermAssetUpdate)
		f.bindDirect(t, w, upd, f.n[5], f.n[2])
		c, err = ev.ManagementScopeNodeCountsFor(f.db, &Principal{UserID: w}, []Permission{PermAssetView, PermAssetUpdate})
		require.NoError(t, err)
		require.Equal(t, ManagementScopeNodeCounts{Live: 1, Deleted: 1}, c)

		// 目錄上不是範圍化的鍵：節點範圍指派不生效，不構成管理範圍
		c, err = f.evaluator(ProductCatalogue()).ManagementScopeNodeCountsFor(f.db, carrier, []Permission{PermAuditView})
		require.NoError(t, err)
		require.Equal(t, ManagementScopeNodeCounts{}, c)

		_, err = ev.ManagementScopeNodeCountsFor(f.db, carrier, nil)
		require.Error(t, err)
		_, err = ev.ManagementScopeNodeCountsFor(f.db, nil, []Permission{PermAssetView})
		require.ErrorIs(t, err, ErrScopeNilPrincipal)
	})

	runScopeAssignmentParity(t, newFx)
}
