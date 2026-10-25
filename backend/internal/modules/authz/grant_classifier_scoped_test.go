package authz

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// scopedGrantEnv 分類器範圍項的夾具：節點樹 n1─n2─n3、n4、n5（見 decideFixture），一個資產管理角色與一個一般角色。
type scopedGrantEnv struct {
	f        *decideFixture
	assetMgr uint // 含 asset:update 的自訂角色（管理類）
	viewer   uint // 只含 asset:view（非管理類）
}

func newScopedGrantEnv(t *testing.T) *scopedGrantEnv {
	t.Helper()
	f := newDecideFixture(t)
	require.NoError(t, f.db.AutoMigrate(&model.UserGroupRole{}, &model.UserGroupMember{}, &model.UserGroup{}))
	SetGrantNodeCoverReader(f.topo)
	t.Cleanup(func() { SetGrantNodeCoverReader(nil) })
	return &scopedGrantEnv{f: f, assetMgr: f.role(t, PermAssetUpdate), viewer: f.role(t, PermAssetView)}
}

// setDirect 把使用者在角色上的直接指派換成 nodes（nil 即全域）。
func (e *scopedGrantEnv) setDirect(t *testing.T, uid, roleID uint, nodes []uint) {
	t.Helper()
	require.NoError(t, e.f.db.Where("user_id = ? AND role_id = ?", uid, roleID).Delete(&model.UserRole{}).Error)
	require.NoError(t, e.f.db.Where("subject_kind = ? AND subject_id = ? AND role_id = ?",
		model.BindingSubjectUser, uid, roleID).Delete(&model.RoleBindingNode{}).Error)
	if nodes == nil {
		assignDirect(t, e.f.db, uid, roleID, model.ScopeKindGlobal)
		return
	}
	e.f.bindDirect(t, uid, roleID, nodes...)
}

// change 先建立 before 範圍、取摘要，換成 after 範圍後再取摘要並分類。
func (e *scopedGrantEnv) change(t *testing.T, roleID uint, before, after []uint, self bool) GrantClassification {
	t.Helper()
	uid := e.f.user(t)
	e.setDirect(t, uid, roleID, before)
	b, err := SummarizeGrants(e.f.db, uid)
	require.NoError(t, err)
	e.setDirect(t, uid, roleID, after)
	a, err := SummarizeGrants(e.f.db, uid)
	require.NoError(t, err)
	return ClassifyGrantChange(b, a, self)
}

// TestScopedGrantClassification 擋：範圍項以涵蓋比較（互不涵蓋為增加、全域改節點為縮小、改父節點增加、改子節點縮小、
// 已刪節點不計）；對他人管理類角色的範圍擴大視同管理類發放；群組路徑以群組為目標、不逐成員；
// 他人一般角色的範圍變更不產生管理類發放；標記值域與摘要內容不變。
func TestScopedGrantClassification(t *testing.T) {
	env := newScopedGrantEnv(t)
	n := env.f.n
	jia, yi := []uint{n[3]}, []uint{n[4]} // 甲、乙：互不涵蓋
	parent, child := []uint{n[1]}, []uint{n[3]}
	mid := []uint{n[2]}

	t.Run("對自己：涵蓋比較決定方向", func(t *testing.T) {
		for name, tc := range map[string]struct {
			before, after []uint
			want          GrantDirection
		}{
			"甲改乙（互不涵蓋）": {jia, yi, GrantIncrease},
			"全域改甲":      {nil, jia, GrantDecrease},
			"甲改甲的父節點":   {mid, parent, GrantIncrease},
			"甲改甲的子節點":   {mid, child, GrantDecrease},
			"甲改全域":      {jia, nil, GrantIncrease},
			"範圍不變":      {jia, jia, GrantNone},
			"甲改甲加乙":     {jia, []uint{n[3], n[4]}, GrantIncrease},
			"甲加乙改甲":     {[]uint{n[3], n[4]}, jia, GrantDecrease},
			"甲改甲加甲的子孫":  {mid, []uint{n[2], n[3]}, GrantNone},
			"全域改全域":     {nil, nil, GrantNone},
		} {
			c := env.change(t, env.assetMgr, tc.before, tc.after, true)
			assert.Equal(t, tc.want, c.SelfDirection, name)
		}
	})

	t.Run("已刪除節點不計入範圍", func(t *testing.T) {
		require.NoError(t, env.f.db.Delete(&model.AssetGroup{}, n[5]).Error)
		// 乙換成已刪節點：後範圍沒有任何存活節點，沒有新增項
		c := env.change(t, env.assetMgr, jia, []uint{n[3], n[5]}, true)
		assert.Equal(t, GrantNone, c.SelfDirection)
		c = env.change(t, env.assetMgr, []uint{n[5]}, jia, true)
		assert.Equal(t, GrantIncrease, c.SelfDirection, "前範圍只剩已刪節點＝沒有涵蓋，換成存活節點為新增")
	})

	t.Run("對他人：管理類角色範圍擴大視同發放，縮小與一般角色不算", func(t *testing.T) {
		c := env.change(t, env.assetMgr, jia, []uint{n[3], n[4]}, false)
		assert.Equal(t, GrantNone, c.SelfDirection)
		assert.Equal(t, []string{GrantMarkManagementGrant}, c.Marks)
		require.Len(t, c.ManagementGranted, 1)
		assert.Equal(t, env.assetMgr, c.ManagementGranted[0].RoleID)

		c = env.change(t, env.assetMgr, []uint{n[3], n[4]}, jia, false)
		assert.Empty(t, c.Marks, "只縮小他人範圍不產生管理類發放")
		assert.Empty(t, c.ManagementGranted)

		c = env.change(t, env.viewer, jia, yi, false)
		assert.Empty(t, c.Marks, "他人一般角色的範圍變更不產生管理類發放")
		c = env.change(t, env.viewer, jia, nil, false)
		assert.Empty(t, c.Marks)
	})

	t.Run("群組路徑：不是成員的操作者擴大群組範圍，只有一筆以群組為目標的管理類發放", func(t *testing.T) {
		operator := env.f.user(t)
		g := &model.UserGroup{Name: "scoped-grant-group"}
		require.NoError(t, env.f.db.Create(g).Error)
		for i := 0; i < 3; i++ { // 群組有多位成員，事件仍只有群組一筆
			m := env.f.user(t)
			require.NoError(t, env.f.db.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: m, Manual: true}).Error)
		}
		setGroup := func(nodes ...uint) {
			require.NoError(t, env.f.db.Where("user_group_id = ?", g.ID).Delete(&model.UserGroupRole{}).Error)
			require.NoError(t, env.f.db.Where("subject_kind = ? AND subject_id = ?", model.BindingSubjectUserGroup, g.ID).
				Delete(&model.RoleBindingNode{}).Error)
			require.NoError(t, env.f.db.Create(&model.UserGroupRole{UserGroupID: g.ID, RoleID: env.assetMgr, ScopeKind: model.ScopeKindNodes}).Error)
			for _, nd := range nodes {
				require.NoError(t, env.f.db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUserGroup,
					SubjectID: g.ID, RoleID: env.assetMgr, NodeID: nd}).Error)
			}
		}
		setGroup(n[3])
		gBefore, err := GroupGrantEntries(env.f.db, g.ID)
		require.NoError(t, err)
		require.Len(t, gBefore, 1)
		assert.True(t, gBefore[0].Management, "節點範圍的群組指派以存活節點計算管理類")
		assert.Equal(t, []uint{n[3]}, gBefore[0].Nodes)
		selfBefore, err := SummarizeGrants(env.f.db, operator)
		require.NoError(t, err)

		setGroup(n[3], n[4])
		gAfter, err := GroupGrantEntries(env.f.db, g.ID)
		require.NoError(t, err)
		selfAfter, err := SummarizeGrants(env.f.db, operator)
		require.NoError(t, err)

		assert.Equal(t, GrantNone, ClassifyGrantChange(selfBefore, selfAfter, true).SelfDirection, "操作者不是成員，自己的摘要不變")
		mgmt := ClassifyGroupManagementGrant(GrantEntriesAdded(gBefore, gAfter))
		require.Len(t, mgmt, 1, "不逐成員展開：整個群組一筆")
		assert.Equal(t, env.assetMgr, mgmt[0].RoleID)
		assert.Equal(t, uint(g.ID), mgmt[0].GroupID)

		// 縮小不產生
		shrunk := ClassifyGroupManagementGrant(GrantEntriesAdded(gAfter, gBefore))
		assert.Empty(t, shrunk)
		// 摘要只含角色名稱、範圍種類與路徑，不含節點名稱
		params := ManagementGrantParams("group_roles", g.Name, mgmt)
		for _, v := range params {
			assert.NotContains(t, v, fxSecretPrefix)
		}
		for _, nm := range env.f.names {
			for _, v := range params {
				assert.NotContains(t, v, nm)
			}
		}
	})

	t.Run("審計標記的值域與既有相同", func(t *testing.T) {
		allowed := map[string]bool{GrantMarkSelfAuthorization: true, GrantMarkManagementGrant: true}
		for _, c := range []GrantClassification{
			env.change(t, env.assetMgr, jia, yi, true),
			env.change(t, env.assetMgr, jia, []uint{n[3], n[4]}, false),
			env.change(t, env.assetMgr, nil, jia, true),
		} {
			for _, m := range c.Marks {
				assert.True(t, allowed[m], m)
			}
		}
	})

	t.Run("沒有注入涵蓋讀取器：偏向多報，不漏報", func(t *testing.T) {
		SetGrantNodeCoverReader(nil)
		t.Cleanup(func() { SetGrantNodeCoverReader(env.f.topo) })
		c := env.change(t, env.assetMgr, mid, child, true)
		assert.Equal(t, GrantIncrease, c.SelfDirection, "看不到祖先關係時，改子節點也多報為增加")
		c = env.change(t, env.assetMgr, nil, jia, true)
		assert.Equal(t, GrantDecrease, c.SelfDirection, "全域改節點仍是縮小，不受涵蓋讀取影響")
	})

	t.Run("種入範本：對他人以節點範圍發放資產管理員範本有一筆管理類發放", func(t *testing.T) {
		tpl := seededScopedTemplateRole(t, env.f.db, model.BuiltinAssetAdmin)
		c := env.change(t, tpl, nil, jia, false)
		assert.Empty(t, c.Marks, "全域改節點是縮小，不產生發放")
		c = env.change(t, tpl, jia, []uint{n[3], n[4]}, false)
		assert.Equal(t, []string{GrantMarkManagementGrant}, c.Marks)
		require.Len(t, c.ManagementGranted, 1)
		assert.Equal(t, tpl, c.ManagementGranted[0].RoleID)
		c = env.change(t, tpl, nil, nil, false)
		assert.Empty(t, c.Marks)
		c = env.change(t, tpl, jia, nil, false)
		assert.Equal(t, []string{GrantMarkManagementGrant}, c.Marks, "節點範圍改全域是擴大")
	})
}

// seededScopedTemplateRole 建立與種入資料相同形狀的範圍化範本角色列（內建識別、定義版本 1、不存權限列），
// 權限集合由程式中的範本定義提供。
func seededScopedTemplateRole(t *testing.T, db *gorm.DB, key string) uint {
	t.Helper()
	k := key
	r := &model.Role{Name: key, BuiltinKey: &k, DefinitionVersion: 1}
	require.NoError(t, db.Create(r).Error)
	return r.ID
}
