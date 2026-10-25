package authz

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// countsEnv 可管理資產台數預覽的夾具：沿用判定夾具的節點樹與資產
//
//	節點 n1 ── n2 ── n3；n4、n5 為根
//	資產 a1 掛 n3；a2 掛 n4；a3 未分組；a4 同掛 n2 與 n4；a5 掛 n5
//
// 子樹內去重台數：n1＝2（a1、a4）、n2＝2、n3＝1、n4＝2（a2、a4）、n5＝1。
type countsEnv struct {
	f                      *decideFixture
	ev                     *ScopeEvaluator
	op                     uint
	mgr, user, auditor, nv uint // 管理角色（範本）、內建一般使用者、內建稽核員、不含檢視權限點的角色
}

func newCountsEnv(t *testing.T) *countsEnv {
	t.Helper()
	f := newDecideFixture(t)
	return &countsEnv{
		f: f, ev: NewScopeEvaluator(ProductCatalogue(), f.topo), op: f.user(t),
		mgr:     f.role(t, ScopedTemplateAssetAdminPermissions()...),
		user:    f.builtinRole(t, model.BuiltinUser),
		auditor: f.builtinRole(t, model.BuiltinAuditor),
		nv:      f.role(t, PermAssetUpdate),
	}
}

// formal 正式的管理可視投影（資產列表同一個入口）對此使用者目前實際指派求得的管理範圍台數。
func (e *countsEnv) formal(t *testing.T, uid uint) int {
	t.Helper()
	p, err := ResolveUserOn(e.f.db, uid, TokenFacts{})
	require.NoError(t, err)
	m, err := e.ev.ManagementVisibleScopeFor(e.f.db, p)
	require.NoError(t, err)
	n, err := e.ev.CountManagementVisible(e.f.db, m)
	require.NoError(t, err)
	return int(n)
}

// write 把使用者的直接指派實際替換成給定集合（模擬寫入）；群組來源的指派不動。
func (e *countsEnv) write(t *testing.T, uid uint, roles []uint, ranges map[uint]PreviewRoleRange) {
	t.Helper()
	require.NoError(t, e.f.db.Exec("DELETE FROM user_roles WHERE user_id = ?", uid).Error)
	require.NoError(t, e.f.db.Exec("DELETE FROM role_binding_nodes WHERE subject_kind = ? AND subject_id = ?", model.BindingSubjectUser, uid).Error)
	for _, r := range roles {
		if rg, ok := ranges[r]; ok && !rg.Global {
			e.f.bindDirect(t, uid, r, rg.NodeIDs...)
		} else {
			e.f.global(t, uid, r)
		}
	}
}

// state 預覽唯讀要比對的授權資料量與權限版本。
func (e *countsEnv) state(t *testing.T) []int64 {
	t.Helper()
	var out []int64
	for _, tb := range []string{"user_roles", "user_group_members", "user_group_roles", "role_binding_nodes", "audit_logs", "roles"} {
		var n int64
		require.NoError(t, e.f.db.Table(tb).Count(&n).Error, tb)
		out = append(out, n)
	}
	v, err := CurrentVersion(e.f.db)
	require.NoError(t, err)
	return append(out, v)
}

func (e *countsEnv) run(t *testing.T, req PreviewRequest) (PreviewResult, error) {
	t.Helper()
	req.OperatorID, req.Scope = e.op, e.ev
	before := e.state(t)
	res, err := PreviewEffectiveCapabilities(e.f.db, req)
	assert.Equal(t, before, e.state(t), "預覽不得改指派、成員、角色、權限版本，也不得寫審計")
	return res, err
}

// direct 直接指派預覽（要求台數）。
func (e *countsEnv) direct(t *testing.T, uid uint, roles []uint, ranges map[uint]PreviewRoleRange) *ManagedAssetCounts {
	t.Helper()
	res, err := e.run(t, PreviewRequest{Kind: PreviewDirectRoles, UserID: uid, RoleIDs: roles, RoleNodes: ranges, IncludeManagedAssetCounts: true})
	require.NoError(t, err)
	require.NotNil(t, res.ManagedAssetCounts)
	require.NotNil(t, res.ManagedAssets)
	assert.Nil(t, res.GroupAssets)
	return res.ManagedAssetCounts
}

// directChecked 預覽後把同一組指派實際寫入，before／after 與正式投影逐一相同。
func (e *countsEnv) directChecked(t *testing.T, uid uint, roles []uint, ranges map[uint]PreviewRoleRange) *ManagedAssetCounts {
	t.Helper()
	wantBefore := e.formal(t, uid)
	c := e.direct(t, uid, roles, ranges)
	e.write(t, uid, roles, ranges)
	assert.Equal(t, wantBefore, c.ManagedAssets.Before, "before 與正式管理投影一致")
	assert.Equal(t, e.formal(t, uid), c.ManagedAssets.After, "after 與寫入後的正式管理投影一致")
	return c
}

func rowOf(t *testing.T, c *ManagedAssetCounts, role uint) PreviewRoleAssets {
	t.Helper()
	for _, r := range c.RoleAssets {
		if r.RoleID == role {
			return r
		}
	}
	t.Fatalf("role_assets 沒有角色 %d：%+v", role, c.RoleAssets)
	return PreviewRoleAssets{}
}

func roleIDsOf(c *ManagedAssetCounts) []uint {
	out := []uint{}
	for _, r := range c.RoleAssets {
		out = append(out, r.RoleID)
	}
	return out
}

func TestPreviewManagedAssetCounts(t *testing.T) {
	e := newCountsEnv(t)
	f := e.f

	t.Run("由甲改為甲、乙：after 減 before 等於乙子樹內不在甲子樹的資產數", func(t *testing.T) {
		u := f.user(t)
		f.bindDirect(t, u, e.mgr, f.n[4])
		c := e.directChecked(t, u, []uint{e.mgr}, map[uint]PreviewRoleRange{e.mgr: nodes(f.n[4], f.n[3])})
		assert.Equal(t, 2, c.ManagedAssets.Before) // a2、a4
		assert.Equal(t, 1, c.ManagedAssets.After-c.ManagedAssets.Before, "只多 a1")
	})

	t.Run("同時掛在甲、乙的資產在 total 只計一次", func(t *testing.T) {
		u := f.user(t)
		c := e.directChecked(t, u, []uint{e.mgr}, map[uint]PreviewRoleRange{e.mgr: nodes(f.n[2], f.n[4])})
		row := rowOf(t, c, e.mgr)
		assert.Equal(t, 3, row.Total) // a1、a4、a2
		assert.Equal(t, 3, c.ManagedAssets.After)
	})

	t.Run("同一角色經群組在丙節點：from_groups_extra 等於 total 減 direct", func(t *testing.T) {
		u := f.user(t)
		f.bindDirect(t, u, e.mgr, f.n[4])
		f.bindGroup(t, u, e.mgr, f.n[3])
		c := e.directChecked(t, u, []uint{e.mgr}, map[uint]PreviewRoleRange{e.mgr: nodes(f.n[4])})
		row := rowOf(t, c, e.mgr)
		require.NotNil(t, row.Direct)
		require.NotNil(t, row.FromGroupsExtra)
		assert.Equal(t, 2, *row.Direct)
		assert.Equal(t, 3, row.Total)
		assert.Equal(t, row.Total-*row.Direct, *row.FromGroupsExtra)
	})

	t.Run("五類主體", func(t *testing.T) {
		t.Run("(i) 內建一般使用者再加甲節點管理角色：after 是甲子樹資產數，不是全部資產", func(t *testing.T) {
			u := f.user(t)
			f.global(t, u, e.user)
			c := e.directChecked(t, u, []uint{e.user, e.mgr}, map[uint]PreviewRoleRange{e.mgr: nodes(f.n[3])})
			assert.Equal(t, 1, c.ManagedAssets.After)
			assert.Equal(t, []uint{e.mgr}, roleIDsOf(c), "以全系統持有的角色不在 role_assets")
		})
		t.Run("(ii) 只持全域一般使用者：before＝after＝0", func(t *testing.T) {
			u := f.user(t)
			f.global(t, u, e.user)
			c := e.directChecked(t, u, []uint{e.user}, nil)
			assert.Equal(t, ManagedAssetPair{Before: 0, After: 0}, *c.ManagedAssets)
			assert.Empty(t, c.RoleAssets)
		})
		t.Run("(iii) 檢視捷徑主體（稽核員）：before／after 等於未刪除資產總數", func(t *testing.T) {
			u := f.user(t)
			f.global(t, u, e.auditor)
			var total int64
			require.NoError(t, f.db.Model(&model.Asset{}).Count(&total).Error)
			c := e.directChecked(t, u, []uint{e.auditor}, nil)
			assert.EqualValues(t, total, c.ManagedAssets.Before)
			assert.EqualValues(t, total, c.ManagedAssets.After)
		})
		t.Run("(iv) 只以甲節點範圍持有內建一般使用者：after 與該角色列三個數字皆為 0", func(t *testing.T) {
			u := f.user(t)
			c := e.directChecked(t, u, []uint{e.user}, map[uint]PreviewRoleRange{e.user: nodes(f.n[3])})
			assert.Equal(t, 0, c.ManagedAssets.After)
			row := rowOf(t, c, e.user)
			require.NotNil(t, row.Direct)
			require.NotNil(t, row.FromGroupsExtra)
			assert.Equal(t, 0, *row.Direct)
			assert.Equal(t, 0, *row.FromGroupsExtra)
			assert.Equal(t, 0, row.Total)
		})
		t.Run("(v) 經群組全域持有內建一般使用者、另以甲節點直接持有同一角色：以正式投影為對照", func(t *testing.T) {
			u := f.user(t)
			g := &model.UserGroup{Name: f.uniq("g")}
			require.NoError(t, f.db.Create(g).Error)
			require.NoError(t, f.db.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: u, Manual: true}).Error)
			require.NoError(t, f.db.Create(&model.UserGroupRole{UserGroupID: g.ID, RoleID: e.user, ScopeKind: model.ScopeKindGlobal}).Error)
			c := e.directChecked(t, u, []uint{e.user}, map[uint]PreviewRoleRange{e.user: nodes(f.n[3])})
			formalAfter := e.formal(t, u)
			assert.Equal(t, formalAfter, c.ManagedAssets.After)
			row := rowOf(t, c, e.user)
			require.NotNil(t, row.Direct)
			// 同一次解析中唯一的節點範圍來源就是這筆直接指派：direct 等於正式管理投影的台數
			assert.Equal(t, formalAfter, *row.Direct)
			assert.Equal(t, formalAfter, row.Total)
		})
	})

	t.Run("不含檢視權限點的節點範圍角色：該列三個數字為 0", func(t *testing.T) {
		u := f.user(t)
		c := e.directChecked(t, u, []uint{e.nv}, map[uint]PreviewRoleRange{e.nv: nodes(f.n[3])})
		row := rowOf(t, c, e.nv)
		assert.Equal(t, 0, *row.Direct)
		assert.Equal(t, 0, *row.FromGroupsExtra)
		assert.Equal(t, 0, row.Total)
		assert.Equal(t, 0, c.ManagedAssets.After)
	})

	t.Run("已刪除的範圍節點不計", func(t *testing.T) {
		u := f.user(t)
		f.bindDirect(t, u, e.mgr, f.n[3], f.n[5])
		f.deleteNode(t, f.n[5])
		want := e.formal(t, u)
		c := e.direct(t, u, []uint{e.mgr}, nil)
		assert.Equal(t, 1, want)
		assert.Equal(t, want, c.ManagedAssets.Before)
		assert.Equal(t, want, c.ManagedAssets.After)
		assert.Equal(t, 1, rowOf(t, c, e.mgr).Total)
	})

	t.Run("只經授權規則可連線的資產不計", func(t *testing.T) {
		u := f.user(t)
		a3 := f.a[3]
		require.NoError(t, f.db.Create(&model.AssetAuthorization{UserID: &u, AssetID: &a3,
			Permission: model.PermissionConnect, GrantedBy: 1, Source: "manual"}).Error)
		c := e.directChecked(t, u, []uint{e.mgr}, map[uint]PreviewRoleRange{e.mgr: nodes(f.n[3])})
		assert.Equal(t, 1, c.ManagedAssets.After)
	})

	t.Run("群組指派：group_assets 與各角色 total，群組帶稽核員角色時為全部未刪除資產", func(t *testing.T) {
		g := &model.UserGroup{Name: f.uniq("g")}
		require.NoError(t, f.db.Create(g).Error)
		m := f.user(t)
		require.NoError(t, f.db.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: m, Manual: true}).Error)

		wantBefore := e.formal(t, m)
		res, err := e.run(t, PreviewRequest{Kind: PreviewGroupRoles, GroupID: g.ID, RoleIDs: []uint{e.mgr},
			RoleNodes: map[uint]PreviewRoleRange{e.mgr: nodes(f.n[3], f.n[4])}, IncludeManagedAssetCounts: true})
		require.NoError(t, err)
		require.NotNil(t, res.GroupAssets)
		assert.Nil(t, res.ManagedAssets)
		row := rowOf(t, res.ManagedAssetCounts, e.mgr)
		assert.Nil(t, row.Direct, "群組列只回 total")
		assert.Nil(t, row.FromGroupsExtra)
		assert.Equal(t, 3, row.Total) // a1、a2、a4
		// 實際寫入群組角色後，成員的正式管理投影等於預覽
		require.NoError(t, f.db.Create(&model.UserGroupRole{UserGroupID: g.ID, RoleID: e.mgr, ScopeKind: model.ScopeKindNodes}).Error)
		for _, n := range []uint{f.n[3], f.n[4]} {
			require.NoError(t, f.db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUserGroup, SubjectID: g.ID, RoleID: e.mgr, NodeID: n}).Error)
		}
		assert.Equal(t, wantBefore, res.GroupAssets.Before)
		assert.Equal(t, e.formal(t, m), res.GroupAssets.After)

		// 群組帶稽核員角色
		g2 := &model.UserGroup{Name: f.uniq("g")}
		require.NoError(t, f.db.Create(g2).Error)
		var total int64
		require.NoError(t, f.db.Model(&model.Asset{}).Count(&total).Error)
		res, err = e.run(t, PreviewRequest{Kind: PreviewGroupRoles, GroupID: g2.ID, RoleIDs: []uint{e.auditor}, IncludeManagedAssetCounts: true})
		require.NoError(t, err)
		require.NotNil(t, res.GroupAssets)
		assert.EqualValues(t, total, res.GroupAssets.After)
	})

	t.Run("回應只有數字：不含資產名稱、位址或識別碼，未要求時不輸出任何台數鍵", func(t *testing.T) {
		u := f.user(t)
		c := e.direct(t, u, []uint{e.mgr}, map[uint]PreviewRoleRange{e.mgr: nodes(f.n[3])})
		raw, err := json.Marshal(c)
		require.NoError(t, err)
		for _, name := range f.names {
			assert.NotContains(t, string(raw), name)
		}
		var generic map[string]any
		require.NoError(t, json.Unmarshal(raw, &generic))
		for k := range generic {
			assert.Contains(t, []string{"managed_assets", "group_assets", "role_assets"}, k)
		}

		res, err := e.run(t, PreviewRequest{Kind: PreviewDirectRoles, UserID: u, RoleIDs: []uint{e.mgr},
			RoleNodes: map[uint]PreviewRoleRange{e.mgr: nodes(f.n[3])}})
		require.NoError(t, err)
		assert.Nil(t, res.ManagedAssetCounts)
		raw, err = json.Marshal(res)
		require.NoError(t, err)
		for _, k := range []string{"managed_assets", "group_assets", "role_assets"} {
			assert.NotContains(t, string(raw), k)
		}
	})

	t.Run("其他種類帶此欄：忽略，不報錯、不回台數", func(t *testing.T) {
		g := &model.UserGroup{Name: f.uniq("g")}
		require.NoError(t, f.db.Create(g).Error)
		for name, req := range map[string]PreviewRequest{
			"群組成員異動": {Kind: PreviewGroupMembers, GroupID: g.ID, MemberIDs: []uint{f.user(t)}},
		} {
			req.IncludeManagedAssetCounts = true
			res, err := e.run(t, req)
			require.NoError(t, err, name)
			assert.Nil(t, res.ManagedAssetCounts, name)
		}
	})

	t.Run("範圍判定器未注入：回明確錯誤，不回部分資料", func(t *testing.T) {
		u := f.user(t)
		res, err := PreviewEffectiveCapabilities(f.db, PreviewRequest{Kind: PreviewDirectRoles, OperatorID: e.op, UserID: u,
			RoleIDs: []uint{e.mgr}, IncludeManagedAssetCounts: true})
		assert.True(t, errors.Is(err, ErrPreviewScopeMissing), "%v", err)
		assert.Nil(t, res.ManagedAssetCounts)
	})
}
