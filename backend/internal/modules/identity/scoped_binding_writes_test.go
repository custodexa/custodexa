package identity

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 範圍化角色指派寫入的測試夾具：完整目錄的關卡加上讀 asset_groups 的節點存在讀取。

type liveNodesStub struct{}

func (liveNodesStub) LiveNodesTx(tx *gorm.DB, ids []uint) (map[uint]bool, error) {
	out := map[uint]bool{}
	for _, id := range ids {
		out[id] = false
	}
	var live []uint
	if err := tx.Model(&model.AssetGroup{}).Where("id IN ?", ids).Pluck("id", &live).Error; err != nil {
		return nil, err
	}
	for _, id := range live {
		out[id] = true
	}
	return out, nil
}

type scopedEnv struct {
	*groupBindEnv
	idAdmin uint
}

func newScopedEnv(t *testing.T) *scopedEnv {
	t.Helper()
	e := newGroupBindEnv(t)
	require.NoError(t, e.db.AutoMigrate(&model.UserRoleMapping{}))
	g := NewAssignmentGuard(FullCatalog())
	g.SetNodeExistenceReader(liveNodesStub{})
	e.users.SetAssignmentGuard(g)
	e.svc.SetAssignmentGuard(g)
	e.svc = NewUserGroupService(e.db, audit.NewTxSink(), noopRevoker{})
	e.svc.SetAssignmentGuard(g)
	return &scopedEnv{groupBindEnv: e}
}

// rid 依角色名取編號（夾具建立的自訂角色不在 e.roles 內）。
func (e *scopedEnv) rid(t *testing.T, name string) uint {
	t.Helper()
	var r model.Role
	require.NoError(t, e.db.Where("name = ?", name).First(&r).Error)
	return r.ID
}

func (e *scopedEnv) node(t *testing.T, name string) uint {
	t.Helper()
	n := model.AssetGroup{Name: name}
	require.NoError(t, e.db.Create(&n).Error)
	return n.ID
}

// userScope 讀一筆直接指派的範圍種類與節點集合。
func (e *scopedEnv) userScope(t *testing.T, uid uint, role string) (string, []uint) {
	t.Helper()
	var ur model.UserRole
	require.NoError(t, e.db.Where("user_id = ? AND role_id = ?", uid, e.rid(t, role)).First(&ur).Error)
	ids, err := authz.BindingNodeIDs(e.db, model.BindingSubjectUser, uid, e.rid(t, role))
	require.NoError(t, err)
	return ur.ScopeKind, ids
}

func nodesOf(ids ...uint) RoleNodesValue { return RoleNodesValue{NodeIDs: ids} }

func (e *scopedEnv) assign(uid uint, names []string, nodes map[string]RoleNodesValue) (*RoleAssignResult, error) {
	return e.users.AssignRolesBy(e.op(e.idAdmin), uid, names, DirectAssignOptions{RoleNodes: nodes})
}

// assetsUnder 在節點 a 的子節點下放一台資產、在節點 b 下放一台資產，回傳兩者編號。
func (e *scopedEnv) assetsUnder(t *testing.T, a, b uint) (inA, inB uint) {
	t.Helper()
	require.NoError(t, e.db.AutoMigrate(&model.Asset{}, &model.AssetNode{}))
	child := model.AssetGroup{Name: "甲-子", ParentID: &a}
	require.NoError(t, e.db.Create(&child).Error)
	mk := func(name string, node uint) uint {
		as := model.Asset{Name: name, Protocol: model.ProtocolSSH, Host: "h", Port: 22}
		require.NoError(t, e.db.Create(&as).Error)
		require.NoError(t, e.db.Create(&model.AssetNode{AssetID: as.ID, NodeID: node}).Error)
		return as.ID
	}
	return mk("asset-in-a", child.ID), mk("asset-in-b", b)
}

// canView 以範圍判定器驗證主體對資產是否具 asset:view（該權限點在此標為範圍強制）。
func (e *scopedEnv) canView(t *testing.T, uid, assetID uint) bool {
	t.Helper()
	cat, err := authz.CatalogueWithScopedEnforcedForTest(authz.PermAssetView)
	require.NoError(t, err)
	res, err := authz.NewScopeEvaluator(cat, asset.NewScopeTopologyReader()).
		Decide(e.db, &authz.Principal{UserID: uid}, authz.PermAssetView, authz.AssetTarget(assetID))
	require.NoError(t, err)
	return res.Outcome == authz.ScopeAllow
}

func TestScopedBindingGuard(t *testing.T) {
	e := newScopedEnv(t)
	e.idAdmin = e.mkUser(t, "ida", "identity_admin")
	e.create(t, "assetmgr", permStrings(authz.ScopedTemplateAssetAdminPermissions())...)
	e.create(t, "authzmgr", permStrings(authz.ScopedTemplateAuthorizationAdminPermissions())...)
	e.create(t, "auditmgr", "audit:view", "asset:view")
	e.create(t, "usermgr", "user:manage")
	e.create(t, "emptyrole")
	e.create(t, "viewonly", "asset:view")
	a, b := e.node(t, "甲"), e.node(t, "乙")
	victim := e.mkUser(t, "victim")

	t.Run("可限定節點的角色以乙節點發給他人成功，含只持甲節點資產管理的主體", func(t *testing.T) {
		_, err := e.assign(victim, []string{"assetmgr"}, map[string]RoleNodesValue{"assetmgr": nodesOf(b)})
		require.NoError(t, err)
		kind, ids := e.userScope(t, victim, "assetmgr")
		assert.Equal(t, model.ScopeKindNodes, kind)
		assert.Equal(t, []uint{b}, ids)
		// 操作者自己只在甲節點持有資產管理，仍可把它以乙節點發給另一個人
		op2 := e.mkUser(t, "op2", "identity_admin")
		require.NoError(t, e.db.Create(&model.UserRole{UserID: op2, RoleID: e.rid(t, "assetmgr"), Source: model.RoleSourceManual, ScopeKind: model.ScopeKindNodes}).Error)
		require.NoError(t, authz.ReplaceBindingNodes(e.db, model.BindingSubjectUser, op2, e.rid(t, "assetmgr"), []uint{a}))
		other := e.mkUser(t, "other")
		_, err = e.users.AssignRolesBy(e.op(op2), other, []string{"assetmgr"}, DirectAssignOptions{RoleNodes: map[string]RoleNodesValue{"assetmgr": nodesOf(b)}})
		require.NoError(t, err)
	})

	t.Run("不能限定節點、空範圍、無效節點：碼正確且零寫入", func(t *testing.T) {
		v0 := e.version(t)
		for _, name := range []string{"auditmgr", "usermgr"} {
			_, err := e.assign(victim, []string{name}, map[string]RoleNodesValue{name: nodesOf(a)})
			assertCode(t, err, apierror.CodeValidationRoleNotNodeScopable)
		}
		_, err := e.assign(victim, []string{"assetmgr"}, map[string]RoleNodesValue{"assetmgr": nodesOf()})
		assertCode(t, err, apierror.CodeValidationRoleBindingNodesEmpty)
		gone := e.node(t, "已刪")
		require.NoError(t, e.db.Delete(&model.AssetGroup{}, gone).Error)
		_, errDeleted := e.assign(victim, []string{"assetmgr"}, map[string]RoleNodesValue{"assetmgr": nodesOf(gone)})
		_, errMissing := e.assign(victim, []string{"assetmgr"}, map[string]RoleNodesValue{"assetmgr": nodesOf(99999)})
		assertCode(t, errDeleted, apierror.CodeValidationRoleBindingNodesInvalid)
		assertCode(t, errMissing, apierror.CodeValidationRoleBindingNodesInvalid)
		assert.Equal(t, errDeleted.Error(), errMissing.Error())
		assert.Equal(t, "role_binding_nodes_invalid", AssignmentDenyReason(errDeleted))
		assert.Equal(t, v0, e.version(t), "被拒時權限版本不變")
		_, err = e.assign(victim, []string{"assetmgr"}, map[string]RoleNodesValue{"zzz": nodesOf(a)})
		assertCode(t, err, apierror.CodeBadParams)
	})

	t.Run("範圍不生效：空權限集與內建一般使用者照常寫入並如實列出", func(t *testing.T) {
		p := e.mkUser(t, "p1")
		res, err := e.assign(p, []string{"emptyrole"}, map[string]RoleNodesValue{"emptyrole": nodesOf(a)})
		require.NoError(t, err)
		kind, ids := e.userScope(t, p, "emptyrole")
		assert.Equal(t, model.ScopeKindNodes, kind)
		assert.Equal(t, []uint{a}, ids)
		assert.Equal(t, []NodeRangeNoEffect{{Role: "emptyrole", Reason: "no_scoped_permission"}}, res.NodeRangeNoEffect)

		res, err = e.assign(p, []string{"emptyrole", "assetmgr"}, map[string]RoleNodesValue{"emptyrole": {Global: true}, "assetmgr": nodesOf(a)})
		require.NoError(t, err)
		assert.Empty(t, res.NodeRangeNoEffect, "只含範圍生效角色時沒有此欄")

		q := e.mkUser(t, "p2")
		res, err = e.assign(q, []string{"user"}, map[string]RoleNodesValue{"user": nodesOf(a)})
		require.NoError(t, err)
		assert.Equal(t, []NodeRangeNoEffect{{Role: "user", Reason: "builtin_global_only"}}, res.NodeRangeNoEffect)
		for _, key := range []string{model.BuiltinUser, model.BuiltinApprover} {
			class, reason := authz.ClassifyNodeScopability(key, authz.TemplatePermissions(key))
			assert.Equal(t, authz.NodeScopabilityNoEffect, class)
			assert.Equal(t, authz.NoEffectBuiltinGlobalOnly, reason)
		}
	})

	t.Run("保護目標先於範圍碼；持系統安全管理員者只改別的角色範圍成功", func(t *testing.T) {
		var err error
		for _, name := range []string{"security_admin", "admin"} { // 系統安全管理員與超管
			_, err := e.assign(victim, []string{name}, map[string]RoleNodesValue{name: nodesOf(a)})
			assertCode(t, err, apierror.CodeAuthProtectedRoleAssignment)
		}
		holder := e.mkUser(t, "holder", "security_admin")
		_, err = e.users.AssignRolesBy(e.op(e.admin), holder, []string{"security_admin", "assetmgr"}, DirectAssignOptions{RoleNodes: map[string]RoleNodesValue{"assetmgr": nodesOf(a)}})
		require.NoError(t, err)
		_, err = e.assign(holder, []string{"security_admin", "assetmgr"}, map[string]RoleNodesValue{"assetmgr": nodesOf(b)})
		require.NoError(t, err)
		_, ids := e.userScope(t, holder, "assetmgr")
		assert.Equal(t, []uint{b}, ids)
		assert.Contains(t, e.manual(t, holder), "security_admin", "保護角色不變")
	})

	t.Run("agent 與含 agent 成員的群組取得節點範圍被拒（空權限集與只含 asset:view 兩案）", func(t *testing.T) {
		ag := e.agent(t, "bot")
		for _, name := range []string{"emptyrole", "viewonly"} {
			_, err := e.assign(ag, []string{name}, map[string]RoleNodesValue{name: nodesOf(a)})
			assert.ErrorIs(t, err, ErrAgentRoleForbidden, name)
			gid := e.group(t, "g-"+name, ag)
			_, err = e.svc.ReplaceRoleBindings(e.op(e.idAdmin), gid, GroupRoleBindingsRequest{
				RoleIDs: []uint{e.rid(t, name)}, RoleNodes: map[uint]RoleNodesValue{e.rid(t, name): nodesOf(a)}})
			assert.ErrorIs(t, err, ErrAgentRoleForbidden, name)
		}
	})
}

func TestScopedBindingWrites(t *testing.T) {
	e := newScopedEnv(t)
	e.idAdmin = e.mkUser(t, "ida", "identity_admin")
	e.create(t, "assetmgr", permStrings(authz.ScopedTemplateAssetAdminPermissions())...)
	e.create(t, "emptyrole")
	e.create(t, "auditmgr", "audit:view")
	a, b := e.node(t, "甲"), e.node(t, "乙")
	inA, inB := e.assetsUnder(t, a, b)

	t.Run("使用者：省略保留、null 改全域、舊入口不碰範圍", func(t *testing.T) {
		u := e.mkUser(t, "u1")
		_, err := e.assign(u, []string{"assetmgr", "user"}, map[string]RoleNodesValue{"assetmgr": nodesOf(a)})
		require.NoError(t, err)
		_, err = e.assign(u, []string{"assetmgr"}, nil) // 省略並移除另一角色
		require.NoError(t, err)
		kind, ids := e.userScope(t, u, "assetmgr")
		assert.Equal(t, model.ScopeKindNodes, kind)
		assert.Equal(t, []uint{a}, ids)
		assert.True(t, e.canView(t, u, inA), "只對甲子樹的資產具該能力")
		assert.False(t, e.canView(t, u, inB))
		vBad := e.version(t)
		_, err = e.assign(u, []string{"assetmgr"}, map[string]RoleNodesValue{"user": nodesOf(a)}) // 鍵不在清單
		assertCode(t, err, apierror.CodeBadParams)
		assert.Equal(t, vBad, e.version(t), "整筆拒絕、零變更")
		_, ids = e.userScope(t, u, "assetmgr")
		assert.Equal(t, []uint{a}, ids)
		require.NoError(t, e.users.AddRoleBy(e.op(e.idAdmin), u, "assetmgr")) // 冪等追加不改範圍
		_, ids = e.userScope(t, u, "assetmgr")
		assert.Equal(t, []uint{a}, ids)
		v0 := e.version(t)
		_, err = e.assign(u, []string{"assetmgr"}, map[string]RoleNodesValue{"assetmgr": nodesOf(a)})
		require.NoError(t, err)
		assert.Equal(t, v0, e.version(t), "重送相同範圍不推進版本")
		_, err = e.assign(u, []string{"assetmgr"}, map[string]RoleNodesValue{"assetmgr": {Global: true}})
		require.NoError(t, err)
		kind, ids = e.userScope(t, u, "assetmgr")
		assert.Equal(t, model.ScopeKindGlobal, kind)
		assert.Empty(t, ids)
		assert.Greater(t, e.version(t), v0)
		// 只收全域的入口帶範圍欄位
		assertCode(t, e.users.AddRoleBy(e.op(e.idAdmin), u, "user", DirectAssignOptions{ScopeRequested: true}), apierror.CodeValidationRoleBindingScopeUnsupported)
	})

	t.Run("使用者：只有全域指派的回應沒有範圍不生效欄；移除他角色後仍列出既有的", func(t *testing.T) {
		u := e.mkUser(t, "u2")
		res, err := e.assign(u, []string{"user"}, nil)
		require.NoError(t, err)
		assert.Empty(t, res.NodeRangeNoEffect)
		_, err = e.assign(u, []string{"emptyrole", "user"}, map[string]RoleNodesValue{"emptyrole": nodesOf(a)})
		require.NoError(t, err)
		res, err = e.assign(u, []string{"emptyrole"}, nil)
		require.NoError(t, err)
		assert.Equal(t, []NodeRangeNoEffect{{Role: "emptyrole", Reason: "no_scoped_permission"}}, res.NodeRangeNoEffect)
	})

	t.Run("群組：節點範圍寫入、省略不動、只改範圍加一版、刪除清列、不可限定被拒", func(t *testing.T) {
		m := e.mkUser(t, "m1")
		gid := e.group(t, "grp", m)
		rid := e.rid(t, "assetmgr")
		rows := func() []authz.GroupRoleBinding {
			r, err := authz.UserGroupRoleBindings(e.db, gid)
			require.NoError(t, err)
			return r
		}
		_, err := e.svc.ReplaceRoleBindings(e.op(e.idAdmin), gid, GroupRoleBindingsRequest{RoleIDs: []uint{rid}, RoleNodes: map[uint]RoleNodesValue{rid: nodesOf(a)}})
		require.NoError(t, err)
		require.Len(t, rows(), 1)
		assert.Equal(t, model.ScopeKindNodes, rows()[0].Scope)
		assert.Equal(t, []uint{a}, rows()[0].NodeIDs)
		assert.True(t, e.canView(t, m, inA), "成員只對甲子樹的資產具該能力")
		assert.False(t, e.canView(t, m, inB))
		_, err = e.svc.ReplaceRoleBindings(e.op(e.idAdmin), gid, GroupRoleBindingsRequest{RoleIDs: []uint{rid},
			RoleNodes: map[uint]RoleNodesValue{e.rid(t, "emptyrole"): nodesOf(a)}}) // 鍵不在 role_ids
		assertCode(t, err, apierror.CodeBadParams)
		v0 := e.version(t)
		_, err = e.svc.ReplaceRoleBindings(e.op(e.idAdmin), gid, GroupRoleBindingsRequest{RoleIDs: []uint{rid}})
		require.NoError(t, err)
		assert.Equal(t, v0, e.version(t), "省略範圍重送不改範圍也不推進版本")
		assert.Equal(t, []uint{a}, rows()[0].NodeIDs)
		_, err = e.svc.ReplaceRoleBindings(e.op(e.idAdmin), gid, GroupRoleBindingsRequest{RoleIDs: []uint{rid}, RoleNodes: map[uint]RoleNodesValue{rid: nodesOf(b)}})
		require.NoError(t, err)
		assert.Equal(t, []uint{b}, rows()[0].NodeIDs)
		assert.Equal(t, v0+1, e.version(t), "只改範圍推進一版")
		_, err = e.svc.ReplaceRoleBindings(e.op(e.idAdmin), gid, GroupRoleBindingsRequest{RoleIDs: []uint{rid}, RoleNodes: map[uint]RoleNodesValue{rid: {Global: true}}})
		require.NoError(t, err)
		raw, _ := json.Marshal(rows()[0])
		assert.NotContains(t, string(raw), "node_ids")
		assert.Contains(t, string(raw), `"scope":"global"`)
		bad := e.rid(t, "auditmgr")
		_, err = e.svc.ReplaceRoleBindings(e.op(e.idAdmin), gid, GroupRoleBindingsRequest{RoleIDs: []uint{rid, bad}, RoleNodes: map[uint]RoleNodesValue{bad: nodesOf(a)}})
		assertCode(t, err, apierror.CodeValidationRoleNotNodeScopable)
		// 刪除群組後節點範圍列清空
		_, err = e.svc.ReplaceRoleBindings(e.op(e.idAdmin), gid, GroupRoleBindingsRequest{RoleIDs: []uint{rid}, RoleNodes: map[uint]RoleNodesValue{rid: nodesOf(a)}})
		require.NoError(t, err)
		_, derr := e.svc.DeleteBy(e.op(e.admin), gid)
		require.NoError(t, derr)
		has, err := authz.SubjectHasBindingNodes(e.db, model.BindingSubjectUserGroup, gid)
		require.NoError(t, err)
		assert.False(t, has)
	})

	t.Run("來源轉移與範圍：並存保留節點、降為僅映射改回全域、降為僅管理者保留、忽略僅映射", func(t *testing.T) {
		role := e.rid(t, "assetmgr")
		channel := model.RoleMappingChannelKindProvider + ":1"
		epoch := func(uid uint) int { return e.epoch(t, uid) }
		// (1)(3)：管理者以甲節點持有，映射命中升並存、範圍保留；映射撤掉降回僅管理者、範圍保留
		u := e.mkUser(t, "d1")
		_, err := e.assign(u, []string{"assetmgr"}, map[string]RoleNodesValue{"assetmgr": nodesOf(a)})
		require.NoError(t, err)
		require.NoError(t, e.db.Transaction(func(tx *gorm.DB) error {
			_, err := GrantMappedRole(tx, u, role, channel, time.Now())
			return err
		}))
		src, _, _ := model.UserRoleSourceOf(e.db, u, role)
		assert.Equal(t, model.RoleSourceBoth, src)
		kind, ids := e.userScope(t, u, "assetmgr")
		assert.Equal(t, model.ScopeKindNodes, kind)
		assert.Equal(t, []uint{a}, ids)
		// (4) 並存列帶 role_nodes 照常作用
		_, err = e.assign(u, []string{"assetmgr"}, map[string]RoleNodesValue{"assetmgr": nodesOf(b)})
		require.NoError(t, err)
		_, ids = e.userScope(t, u, "assetmgr")
		assert.Equal(t, []uint{b}, ids)
		require.NoError(t, e.db.Transaction(func(tx *gorm.DB) error {
			_, err := RevokeMappedRolesForChannel(tx, u, channel, nil)
			return err
		}))
		src, _, _ = model.UserRoleSourceOf(e.db, u, role)
		assert.Equal(t, model.RoleSourceManual, src)
		kind, ids = e.userScope(t, u, "assetmgr")
		assert.Equal(t, model.ScopeKindNodes, kind, "降為僅管理者時保留節點範圍")
		assert.Equal(t, []uint{b}, ids)
		// (2)：並存後管理者移出自己那份 → 僅映射、改回全域、清節點列、版本推進、世代不變
		require.NoError(t, e.db.Transaction(func(tx *gorm.DB) error {
			_, err := GrantMappedRole(tx, u, role, channel, time.Now())
			return err
		}))
		v0, ep0 := e.version(t), epoch(u)
		_, err = e.assign(u, []string{}, nil)
		require.NoError(t, err)
		src, _, _ = model.UserRoleSourceOf(e.db, u, role)
		assert.Equal(t, model.RoleSourceMapped, src)
		kind, ids = e.userScope(t, u, "assetmgr")
		assert.Equal(t, model.ScopeKindGlobal, kind)
		assert.Empty(t, ids)
		assert.Greater(t, e.version(t), v0)
		assert.Equal(t, ep0, epoch(u), "擴大不推進憑證世代")
		var rangeRows []model.AuditLog
		require.NoError(t, e.db.Where("resource = ? AND resource_id = ? AND action = ? AND details LIKE ?",
			model.ResourceUserRole, u, model.ActionUpdate, `%role_binding_range_changed%"range_after":"global"%`).Find(&rangeRows).Error)
		require.Len(t, rangeRows, 1, "降為僅映射改回全域時留一筆範圍變更審計")
		assert.Contains(t, rangeRows[0].Details, `"range_after":"global"`)
		// (4) 僅映射的角色帶 role_nodes：忽略並揭露，不拒絕
		res, err := e.assign(u, []string{"assetmgr"}, map[string]RoleNodesValue{"assetmgr": nodesOf(a)})
		require.NoError(t, err)
		require.Len(t, res.Disclosures, 1)
		assert.Equal(t, DisclosureRoleMappedIgnored, res.Disclosures[0].Code)
		kind, ids = e.userScope(t, u, "assetmgr")
		assert.Equal(t, model.ScopeKindGlobal, kind)
		assert.Empty(t, ids)
	})

	t.Run("映射：經外部群組加入帶節點範圍指派的使用者群組，成員取得同一範圍，映射規則本身不帶範圍", func(t *testing.T) {
		rid := e.rid(t, "assetmgr")
		gid := e.group(t, "mapped-scope-group")
		_, err := e.svc.ReplaceRoleBindings(e.op(e.idAdmin), gid, GroupRoleBindingsRequest{
			RoleIDs: []uint{rid}, RoleNodes: map[uint]RoleNodesValue{rid: nodesOf(a)}})
		require.NoError(t, err)

		const providerID uint = 9
		pid := providerID
		eg := model.ExternalGroup{OIDCProviderID: &pid, MatchValue: "ext-asset-team"}
		require.NoError(t, e.db.Create(&eg).Error)
		require.NoError(t, e.db.Create(&model.GroupUserGroupMapping{OIDCProviderID: &pid, ExternalGroupID: eg.ID,
			UserGroupID: gid, Enabled: true, CreatedBy: e.admin}).Error)

		member := model.User{Username: "mapped-member", Active: true, ExternalCredential: true}
		require.NoError(t, e.db.Create(&member).Error)
		bystander := e.mkUser(t, "mapping-bystander")
		// 兩人各持一個空權限集的全域角色，避免無指派時的預設角色讓基準線具檢視能力
		for _, uid := range []uint{member.ID, bystander} {
			_, err := e.assign(uid, []string{"emptyrole"}, nil)
			require.NoError(t, err)
		}
		assert.False(t, e.canView(t, member.ID, inA), "加入前不具該能力")

		outcome, err := RecomputeMappedRoles(e.db, audit.NewTxSink(), &member, GroupObservation{
			Kind: model.RoleMappingChannelKindProvider, SourceID: providerID,
			State: GroupObservationKnown, Groups: []string{"ext-asset-team"}})
		require.NoError(t, err)
		assert.Empty(t, outcome.Skipped)
		var n int64
		require.NoError(t, e.db.Model(&model.UserGroupMember{}).Where("user_group_id = ? AND user_id = ?", gid, member.ID).Count(&n).Error)
		require.EqualValues(t, 1, n, "映射重算把使用者加入群組")

		assert.True(t, e.canView(t, member.ID, inA), "對甲子樹資產放行")
		assert.False(t, e.canView(t, member.ID, inB), "對乙子樹資產範圍拒絕")
		assert.False(t, e.canView(t, bystander, inA), "未被映射加入者不具該能力")
		has, err := authz.SubjectHasBindingNodes(e.db, model.BindingSubjectUser, member.ID)
		require.NoError(t, err)
		assert.False(t, has, "成員本人沒有節點範圍列，範圍隨群組繼承")
	})
}
