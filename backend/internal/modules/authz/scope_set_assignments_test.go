package authz

import (
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 指派集合入口的 parity：實際指派原樣輸入與正式入口逐筆相同、
// 模擬指派等於實寫後的正式判定（寫入、比較、回滾，列數不變）、ViewShortcut 四類主體。
// 由 runScopeSetParity 呼叫，SQLite 與 PG 各跑一次。

// actualAssignmentSet 在 tx 內讀主體的實際指派，原樣組成指派集合。母體與正式解析相同
// （已刪角色、已刪群組的指派不列入）；範圍節點取原始綁定，含已刪與不存在的節點。
func actualAssignmentSet(t *testing.T, tx *gorm.DB, uid uint, facts TokenFacts) AssignmentSet {
	t.Helper()
	var direct []struct {
		RoleID    uint
		ScopeKind string
	}
	require.NoError(t, tx.Raw(`SELECT user_roles.role_id AS role_id, user_roles.scope_kind AS scope_kind
 FROM user_roles JOIN roles ON roles.id = user_roles.role_id AND roles.deleted_at IS NULL
 WHERE user_roles.user_id = ? ORDER BY roles.id`, uid).Scan(&direct).Error)
	var viaGroup []struct {
		GroupID   uint
		RoleID    uint
		ScopeKind string
	}
	require.NoError(t, tx.Raw(`SELECT user_group_roles.user_group_id AS group_id, user_group_roles.role_id AS role_id, user_group_roles.scope_kind AS scope_kind
 FROM user_group_members
 JOIN user_groups ON user_groups.id = user_group_members.user_group_id AND user_groups.deleted_at IS NULL
 JOIN user_group_roles ON user_group_roles.user_group_id = user_group_members.user_group_id
 JOIN roles ON roles.id = user_group_roles.role_id AND roles.deleted_at IS NULL
 WHERE user_group_members.user_id = ? ORDER BY user_group_roles.user_group_id, roles.id`, uid).Scan(&viaGroup).Error)
	rawNodes := func(kind string, subject, role uint) []uint {
		var ids []uint
		require.NoError(t, tx.Raw(`SELECT node_id FROM role_binding_nodes WHERE subject_kind = ? AND subject_id = ? AND role_id = ? ORDER BY node_id`,
			kind, subject, role).Scan(&ids).Error)
		return ids
	}
	set := AssignmentSet{SubjectKind: facts.SubjectKind}
	for _, d := range direct {
		in := AssignmentInput{BindingSubject: model.BindingSubjectUser, RoleID: d.RoleID, Scope: d.ScopeKind}
		if d.ScopeKind == model.ScopeKindNodes {
			in.NodeIDs = rawNodes(model.BindingSubjectUser, uid, d.RoleID)
		}
		set.Items = append(set.Items, in)
	}
	for _, g := range viaGroup {
		in := AssignmentInput{BindingSubject: model.BindingSubjectUserGroup, GroupID: g.GroupID, RoleID: g.RoleID, Scope: g.ScopeKind}
		if g.ScopeKind == model.ScopeKindNodes {
			in.NodeIDs = rawNodes(model.BindingSubjectUserGroup, g.GroupID, g.RoleID)
		}
		set.Items = append(set.Items, in)
	}
	return set
}

// writeAssignmentSet 把指派集合實際寫成 tx 內一位新使用者的指派（經群組者另建群組並加入），回傳使用者編號。
func writeAssignmentSet(t *testing.T, f *decideFixture, tx *gorm.DB, set AssignmentSet) uint {
	t.Helper()
	uid := mkUser(t, tx, f.uniq("sim")).ID
	for _, it := range set.Items {
		subjectKind, subjectID := model.BindingSubjectUser, uid
		if it.BindingSubject == model.BindingSubjectUserGroup {
			g := &model.UserGroup{Name: f.uniq("simg")}
			require.NoError(t, tx.Create(g).Error)
			require.NoError(t, tx.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: uid, Manual: true}).Error)
			require.NoError(t, tx.Create(&model.UserGroupRole{UserGroupID: g.ID, RoleID: it.RoleID, ScopeKind: it.Scope}).Error)
			subjectKind, subjectID = model.BindingSubjectUserGroup, g.ID
		} else {
			assignDirect(t, tx, uid, it.RoleID, it.Scope)
		}
		for _, n := range it.NodeIDs {
			require.NoError(t, tx.Create(&model.RoleBindingNode{SubjectKind: subjectKind, SubjectID: subjectID, RoleID: it.RoleID, NodeID: n}).Error)
		}
	}
	return uid
}

// tableRowCounts 全部表的列數（含軟刪列）。
func tableRowCounts(t *testing.T, db *gorm.DB) map[string]int64 {
	t.Helper()
	tables, err := db.Migrator().GetTables()
	require.NoError(t, err)
	require.NotEmpty(t, tables)
	out := make(map[string]int64, len(tables))
	for _, tb := range tables {
		var n int64
		require.NoError(t, db.Raw(fmt.Sprintf(`SELECT count(*) FROM %q`, tb)).Scan(&n).Error)
		out[tb] = n
	}
	return out
}

func rowCountsLine(m map[string]int64) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	s := ""
	for _, k := range keys {
		s += fmt.Sprintf(" %s=%d", k, m[k])
	}
	return s
}

// setSnapshot 集合的可比對樣貌：狀態、原因、套用後的資產與節點成員。
type setSnapshot struct {
	State  ScopeSetState
	Reason ScopeReason
	Assets []uint
	Nodes  []uint
}

func snapshotSet(t *testing.T, tx *gorm.DB, ev *ScopeEvaluator, set ScopeSet) setSnapshot {
	t.Helper()
	require.NotZero(t, set.State(), "集合狀態不得為零值")
	return setSnapshot{set.State(), set.Reason(),
		setIDs(setMembers(t, tx, ev, set, ScopeQueryAsset)), setIDs(setMembers(t, tx, ev, set, ScopeQueryNode))}
}

// paritySnapshot 一個主體在一個目錄下全部權限點的結果：單筆判定（每個目標）、一般三態、變體、ViewShortcut。
type paritySnapshot struct {
	Decisions map[string]ScopeResult
	General   map[Permission]setSnapshot
	Variant   map[Permission]setSnapshot
	View      bool
}

// parityTargets 判定比對的目標：實存資產與節點、不存在或已刪的 ID、帳號（含不屬該資產的帳號）。
func parityTargets(t *testing.T, f *decideFixture, tx *gorm.DB, absent map[ScopeQueryKind][]uint) []ScopeTarget {
	t.Helper()
	var out []ScopeTarget
	for _, id := range append(liveIDs(t, tx, ScopeQueryAsset), absent[ScopeQueryAsset]...) {
		out = append(out, AssetTarget(id))
	}
	for _, id := range append(liveIDs(t, tx, ScopeQueryNode), absent[ScopeQueryNode]...) {
		out = append(out, NodeTarget(id))
	}
	return append(out, AssetAccountTarget(f.a[1], f.acc[1]), AssetAccountTarget(f.a[2], f.acc[2]), AssetAccountTarget(f.a[1], f.acc[2]))
}

func targetKey(tg ScopeTarget) string {
	return fmt.Sprintf("%s/%d/%d/%d", tg.Kind, tg.AssetID, tg.AccountID, tg.NodeID)
}

// formalSnapshot 正式入口（Decide、ScopeSetFor、NodeScopeOnlySetFor、Principal.ViewShortcut）在 tx 內的結果。
func formalSnapshot(t *testing.T, tx *gorm.DB, ev *ScopeEvaluator, cat Catalogue, uid uint, facts TokenFacts, targets []ScopeTarget) paritySnapshot {
	t.Helper()
	carrier := &Principal{UserID: uid, Facts: facts}
	p, err := ResolveUserOnWithCatalogue(tx, cat, uid, facts)
	require.NoError(t, err)
	out := paritySnapshot{Decisions: map[string]ScopeResult{}, General: map[Permission]setSnapshot{}, Variant: map[Permission]setSnapshot{}, View: p.ViewShortcut()}
	for _, perm := range CatalogKeys() {
		g, err := ev.ScopeSetFor(tx, carrier, perm)
		require.NoError(t, err)
		out.General[perm] = snapshotSet(t, tx, ev, g)
		v, err := ev.NodeScopeOnlySetFor(tx, carrier, perm)
		require.NoError(t, err)
		out.Variant[perm] = snapshotSet(t, tx, ev, v)
		for _, tg := range targets {
			res, err := ev.Decide(tx, carrier, perm, tg)
			require.NoError(t, err)
			out.Decisions[string(perm)+"@"+targetKey(tg)] = res
		}
	}
	return out
}

// entrySnapshot 指派集合入口在 tx 內的結果。
func entrySnapshot(t *testing.T, tx *gorm.DB, ev *ScopeEvaluator, set AssignmentSet, targets []ScopeTarget) paritySnapshot {
	t.Helper()
	view, err := ev.ViewShortcutForAssignments(tx, set)
	require.NoError(t, err)
	out := paritySnapshot{Decisions: map[string]ScopeResult{}, General: map[Permission]setSnapshot{}, Variant: map[Permission]setSnapshot{}, View: view}
	for _, perm := range CatalogKeys() {
		g, err := ev.ScopeSetForAssignments(tx, set, perm)
		require.NoError(t, err)
		out.General[perm] = snapshotSet(t, tx, ev, g)
		v, err := ev.NodeScopeOnlySetForAssignments(tx, set, perm)
		require.NoError(t, err)
		out.Variant[perm] = snapshotSet(t, tx, ev, v)
		for _, tg := range targets {
			res, err := ev.DecideForAssignments(tx, set, perm, tg)
			require.NoError(t, err)
			out.Decisions[string(perm)+"@"+targetKey(tg)] = res
		}
	}
	return out
}

// requireSnapshotsEqual 逐筆比對（失敗訊息指出哪一筆），並累計結果分佈。
func requireSnapshotsEqual(t *testing.T, label string, want, got paritySnapshot, dist map[string]int) {
	t.Helper()
	require.Equalf(t, want.View, got.View, "%s：ViewShortcut", label)
	require.Len(t, got.Decisions, len(want.Decisions))
	for k, w := range want.Decisions {
		require.Equalf(t, w, got.Decisions[k], "%s：單筆判定 %s", label, k)
		dist[fmt.Sprintf("decide_%v/%s", w.Outcome, w.Reason)]++
	}
	for perm, w := range want.General {
		require.Equalf(t, w, got.General[perm], "%s：一般三態 %s", label, perm)
		dist["general_"+w.State.String()]++
	}
	for perm, w := range want.Variant {
		require.Equalf(t, w, got.Variant[perm], "%s：變體 %s", label, perm)
		dist["variant_"+w.State.String()]++
	}
}

func distLine(dist map[string]int) string {
	keys := make([]string, 0, len(dist))
	for k := range dist {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	s := ""
	for _, k := range keys {
		s += fmt.Sprintf(" %s=%d", k, dist[k])
	}
	return s
}

func runScopeAssignmentParity(t *testing.T, newFx func(*testing.T) *decideFixture) {
	t.Run("assignments_actual_input_parity", func(t *testing.T) {
		f := newFx(t)
		subjects, _, absent := setParityPopulation(t, f)
		targets := parityTargets(t, f, f.db, absent)
		dist := map[string]int{}
		subjectsRun, views := 0, 0
		for cname, cat := range setParityCatalogues(t, f) {
			ev := f.evaluator(cat)
			for _, s := range subjects {
				tx := f.db.Begin()
				require.NoError(t, tx.Error)
				set := actualAssignmentSet(t, tx, s.uid, s.facts)
				want := formalSnapshot(t, tx, ev, cat, s.uid, s.facts, targets)
				got := entrySnapshot(t, tx, ev, set, targets)
				requireSnapshotsEqual(t, fmt.Sprintf("目錄 %s 主體 %s（%d 筆指派）", cname, s.label, len(set.Items)), want, got, dist)
				require.NoError(t, tx.Rollback().Error)
				subjectsRun++
				if want.View {
					views++
				}
			}
		}
		require.Greater(t, dist[fmt.Sprintf("decide_%v/", ScopeAllow)], 0)
		require.Greater(t, dist["general_conditional"], 0)
		require.Greater(t, dist["variant_conditional"], 0)
		decisions := 0
		for k, n := range dist {
			if len(k) > 7 && k[:7] == "decide_" {
				decisions += n
			}
		}
		t.Logf("EVIDENCE assignment-parity dialect=%s subject_runs=%d targets=%d perms=%d decisions=%d view_shortcut_true=%d dist:%s",
			f.db.Dialector.Name(), subjectsRun, len(targets), len(CatalogKeys()), decisions, views, distLine(dist))
	})

	t.Run("assignments_simulated_equals_written", func(t *testing.T) {
		f := newFx(t)
		_, x, absent := setParityPopulation(t, f) // n5、n7 已刪
		view, upd := f.role(t, PermAssetView), f.role(t, PermAssetUpdate, PermAuditView)
		both := f.role(t, PermAssetView, PermAssetUpdate, PermAlertRuleManage)
		user := f.builtinRole(t, model.BuiltinUser)
		targets := parityTargets(t, f, f.db, absent)
		const placeholderGroup = 990001 // 模擬的群組不存在；入口不讀群組，實寫時另建群組
		sims := map[string]AssignmentSet{
			"node_with_deleted_plus_global": {Items: []AssignmentInput{
				{BindingSubject: model.BindingSubjectUser, RoleID: view, Scope: model.ScopeKindNodes, NodeIDs: []uint{f.n[2], f.n[5]}},
				{BindingSubject: model.BindingSubjectUserGroup, GroupID: placeholderGroup, RoleID: both, Scope: model.ScopeKindNodes, NodeIDs: []uint{f.n[4], x.n7, x.n8}},
				{BindingSubject: model.BindingSubjectUser, RoleID: upd, Scope: model.ScopeKindGlobal},
			}},
			"node_only_one_all_deleted": {Items: []AssignmentInput{
				{BindingSubject: model.BindingSubjectUser, RoleID: both, Scope: model.ScopeKindNodes, NodeIDs: []uint{f.n[5]}},
				{BindingSubject: model.BindingSubjectUserGroup, GroupID: placeholderGroup, RoleID: view, Scope: model.ScopeKindNodes, NodeIDs: []uint{f.n[1], x.n7}},
			}},
			"global_user_plus_node_view": {Items: []AssignmentInput{
				{BindingSubject: model.BindingSubjectUser, RoleID: user, Scope: model.ScopeKindGlobal},
				{BindingSubject: model.BindingSubjectUser, RoleID: view, Scope: model.ScopeKindNodes, NodeIDs: []uint{x.n6, f.n[5]}},
			}},
		}
		dist := map[string]int{}
		runs := 0
		for cname, cat := range setParityCatalogues(t, f) {
			ev := f.evaluator(cat)
			for sname, sim := range sims {
				before := tableRowCounts(t, f.db)
				tx := f.db.Begin()
				require.NoError(t, tx.Error)
				got := entrySnapshot(t, tx, ev, sim, targets)
				require.Equalf(t, before, tableRowCounts(t, tx), "目錄 %s 模擬 %s：呼叫入口前後所有表的列數不變", cname, sname)
				uid := writeAssignmentSet(t, f, tx, sim)
				written := actualAssignmentSet(t, tx, uid, TokenFacts{})
				require.Len(t, written.Items, len(sim.Items), "實寫後讀回的指派筆數與模擬相同")
				want := formalSnapshot(t, tx, ev, cat, uid, TokenFacts{}, targets)
				requireSnapshotsEqual(t, fmt.Sprintf("目錄 %s 模擬 %s", cname, sname), want, got, dist)
				require.NoError(t, tx.Rollback().Error)
				after := tableRowCounts(t, f.db)
				require.Equalf(t, before, after, "目錄 %s 模擬 %s：回滾後各表列數與開始前相同", cname, sname)
				runs++
				if runs == 1 {
					t.Logf("EVIDENCE simulated rowcounts_before:%s", rowCountsLine(before))
					t.Logf("EVIDENCE simulated rowcounts_after:%s", rowCountsLine(after))
				}
			}
		}
		require.Greater(t, dist["general_conditional"], 0)
		require.Greater(t, dist["variant_conditional"], 0)
		require.Greater(t, dist["variant_empty"], 0)
		t.Logf("EVIDENCE simulated-parity dialect=%s runs=%d targets=%d dist:%s", f.db.Dialector.Name(), runs, len(targets), distLine(dist))
	})

	t.Run("assignments_input_errors", func(t *testing.T) {
		f := newFx(t)
		ev := f.evaluator(f.catView)
		gone := f.role(t, PermAssetView)
		require.NoError(t, f.db.Delete(&model.Role{}, gone).Error)
		u := f.user(t)
		f.global(t, u, gone)
		p, err := ResolveUserOnWithCatalogue(f.db, f.catView, u, TokenFacts{})
		require.NoError(t, err)
		require.Empty(t, p.Assignments, "正式解析略過已刪角色的指派，故 parity 母體不含已刪角色")
		require.Empty(t, actualAssignmentSet(t, f.db, u, TokenFacts{}).Items)

		one := func(in AssignmentInput) AssignmentSet { return AssignmentSet{Items: []AssignmentInput{in}} }
		_, err = ev.DecideForAssignments(f.db, one(AssignmentInput{BindingSubject: model.BindingSubjectUser, RoleID: gone, Scope: model.ScopeKindGlobal}), PermAssetView, AssetTarget(f.a[1]))
		require.ErrorIs(t, err, ErrAssignmentRoleMissing, "已刪角色不冒充零指派")
		_, err = ev.ScopeSetForAssignments(f.db, one(AssignmentInput{BindingSubject: model.BindingSubjectUser, RoleID: 987654, Scope: model.ScopeKindGlobal}), PermAssetView)
		require.ErrorIs(t, err, ErrAssignmentRoleMissing)
		view := f.role(t, PermAssetView)
		for name, in := range map[string]AssignmentInput{
			"bad_subject":       {BindingSubject: "agent", RoleID: view, Scope: model.ScopeKindGlobal},
			"group_without_id":  {BindingSubject: model.BindingSubjectUserGroup, RoleID: view, Scope: model.ScopeKindGlobal},
			"direct_with_group": {BindingSubject: model.BindingSubjectUser, GroupID: 3, RoleID: view, Scope: model.ScopeKindGlobal},
			"bad_scope":         {BindingSubject: model.BindingSubjectUser, RoleID: view, Scope: "tenant"},
			"global_with_nodes": {BindingSubject: model.BindingSubjectUser, RoleID: view, Scope: model.ScopeKindGlobal, NodeIDs: []uint{f.n[1]}},
			"zero_role":         {BindingSubject: model.BindingSubjectUser, Scope: model.ScopeKindGlobal},
		} {
			_, err := ev.NodeScopeOnlySetForAssignments(f.db, one(in), PermAssetView)
			require.ErrorIsf(t, err, ErrAssignmentInvalid, "%s", name)
		}
		_, err = ev.ViewShortcutForAssignments(f.db, AssignmentSet{SubjectKind: "robot"})
		require.ErrorIs(t, err, ErrAssignmentInvalid)
		_, err = ev.ViewShortcutForAssignments(nil, AssignmentSet{})
		require.Error(t, err)

		// 零指派主體適用相容規則（一般使用者範本），與正式解析的零指派使用者相同
		zero := f.user(t)
		res, err := ev.DecideForAssignments(f.db, AssignmentSet{}, PermAssetView, AssetTarget(f.a[3]))
		require.NoError(t, err)
		require.Equal(t, f.decide(t, ev, zero, PermAssetView, AssetTarget(f.a[3])), res)
	})

	t.Run("view_shortcut", func(t *testing.T) {
		f := newFx(t)
		ev := f.evaluator(f.catView)
		superRole, auditorRole := f.builtinRole(t, model.BuiltinSuperAdmin), f.builtinRole(t, model.BuiltinAuditor)
		userRole, nodeRole := f.builtinRole(t, model.BuiltinUser), f.role(t, PermAssetView)
		cases := []struct {
			name  string
			setup func(uid uint)
			want  bool
		}{
			{"super_admin", func(u uint) { f.global(t, u, superRole) }, true},
			{"auditor", func(u uint) { f.global(t, u, auditorRole) }, true},
			{"user", func(u uint) { f.global(t, u, userRole) }, false},
			{"node_scope_only", func(u uint) { f.bindDirect(t, u, nodeRole, f.n[1]); f.bindGroup(t, u, auditorRole, f.n[2]) }, false},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				uid := f.user(t)
				c.setup(uid)
				tx := f.db.Begin()
				require.NoError(t, tx.Error)
				defer func() { require.NoError(t, tx.Rollback().Error) }()
				set := actualAssignmentSet(t, tx, uid, TokenFacts{})
				require.NotEmpty(t, set.Items)
				p, err := ResolveUserOnWithCatalogue(tx, f.catView, uid, TokenFacts{})
				require.NoError(t, err)
				got, err := ev.ViewShortcutForAssignments(tx, set)
				require.NoError(t, err)
				require.Equal(t, p.ViewShortcut(), got, "實際指派原樣輸入＝該主體 Principal.ViewShortcut()")
				require.Equal(t, c.want, got)
				t.Logf("EVIDENCE view-shortcut dialect=%s subject=%s items=%d principal=%v entry=%v", f.db.Dialector.Name(), c.name, len(set.Items), p.ViewShortcut(), got)
			})
		}
		t.Run("simulated_global_auditor", func(t *testing.T) {
			sim := AssignmentSet{Items: []AssignmentInput{
				{BindingSubject: model.BindingSubjectUser, RoleID: auditorRole, Scope: model.ScopeKindGlobal},
				{BindingSubject: model.BindingSubjectUser, RoleID: nodeRole, Scope: model.ScopeKindNodes, NodeIDs: []uint{f.n[4]}},
			}}
			before := tableRowCounts(t, f.db)
			tx := f.db.Begin()
			require.NoError(t, tx.Error)
			got, err := ev.ViewShortcutForAssignments(tx, sim)
			require.NoError(t, err)
			require.True(t, got, "含全域內建稽核員指派的模擬集合為真")
			require.Equal(t, before, tableRowCounts(t, tx), "呼叫入口前後所有表的列數不變")
			uid := writeAssignmentSet(t, f, tx, sim)
			p, err := ResolveUserOnWithCatalogue(tx, f.catView, uid, TokenFacts{})
			require.NoError(t, err)
			require.Equal(t, p.ViewShortcut(), got, "等於實寫後的正式判定")
			require.NoError(t, tx.Rollback().Error)
			require.Equal(t, before, tableRowCounts(t, f.db), "回滾後各表列數與開始前相同")
			t.Logf("EVIDENCE view-shortcut dialect=%s subject=simulated_global_auditor entry=%v written=%v", f.db.Dialector.Name(), got, p.ViewShortcut())
		})
	})
}
