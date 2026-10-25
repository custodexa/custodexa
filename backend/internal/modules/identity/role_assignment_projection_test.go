package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

// projectionEnv 在角色定義夾具上加：自訂角色、使用者群組服務與身分來源服務（只用其映射目標檢查）。
type projectionEnv struct {
	*guardEnv
	groups *UserGroupService
	src    *IdentitySourceService
	ida    uint // 身分管理員（持指派能力，非超管）
}

func newProjectionEnv(t *testing.T, catalog AssignableCatalog) *projectionEnv {
	t.Helper()
	e := newGuardEnv(t, true)
	require.NoError(t, e.db.AutoMigrate(&model.UserGroupRole{}))
	guard := NewAssignmentGuard(catalog)
	groups := NewUserGroupService(e.db, audit.NewTxSink(), nil)
	groups.SetAssignmentGuard(guard)
	src := NewIdentitySourceService(e.db, audit.NewTxSink())
	src.SetAssignmentGuard(guard)
	legacy := model.Role{Name: "legacy-extra"}
	require.NoError(t, e.db.Create(&legacy).Error)
	require.NoError(t, e.db.Model(&model.Role{}).Where("id = ?", legacy.ID).Update("builtin_key", nil).Error)
	e.roles["legacy-extra"] = legacy.ID
	e.roles["custom-view"] = e.create(t, "custom-view", "asset:view").ID
	e.roles["custom-mgmt"] = e.create(t, "custom-mgmt", "asset:view", "asset:update").ID
	return &projectionEnv{guardEnv: e, groups: groups, src: src, ida: e.mkUser(t, "ida", "identity_admin")}
}

func (e *projectionEnv) project(t *testing.T, catalog AssignableCatalog, operator uint) *RoleProjectionSet {
	t.Helper()
	set, err := NewRoleProjector(e.db, NewAssignmentGuard(catalog)).ProjectRoles(operator)
	require.NoError(t, err)
	return set
}

func (e *projectionEnv) auditRows(t *testing.T) int64 {
	t.Helper()
	var n int64
	require.NoError(t, e.db.Model(&model.AuditLog{}).Count(&n).Error)
	return n
}

// TestRoleAssignmentProjection 擋：唯讀投影的每個欄位與對應的寫入判定分岔；投影寫了資料。
func TestRoleAssignmentProjection(t *testing.T) {
	catalogs := []struct {
		name string
		c    AssignableCatalog
	}{{"相容目錄", CompatCatalog()}, {"完整目錄", FullCatalog()}}

	t.Run("assignment_state 依受保護優先、其次未開放，與直接路徑新增時的關卡原因一致", func(t *testing.T) {
		compared := 0
		for _, cat := range catalogs {
			e := newProjectionEnv(t, cat.c)
			guard := NewAssignmentGuard(cat.c)
			victim := e.mkUser(t, "victim")
			for opName, op := range map[string]uint{"超管": e.admin, "身分管理員": e.ida} {
				set := e.project(t, cat.c, op)
				assert.Equal(t, opName == "超管", set.CanDefine, "%s %s can_define", cat.name, opName)
				for name, id := range e.roles {
					got := set.ByRole[id].AssignmentState
					err := guard.Check(e.db, e.op(op), AssignmentChange{Path: PathAdd, TargetUserID: victim, NewRoleIDs: []uint{id}})
					switch AssignmentDenyReason(err) {
					case DenyReasonProtectedRole:
						assert.Equal(t, AssignmentStateProtected, got, "%s %s %s", cat.name, opName, name)
						compared++
					case DenyReasonRoleNotAssignable:
						assert.Equal(t, AssignmentStateNotOpen, got, "%s %s %s", cat.name, opName, name)
						compared++
					case "":
						require.NoError(t, err)
						assert.Equal(t, AssignmentStateOpen, got, "%s %s %s", cat.name, opName, name)
						compared++
					default:
						t.Fatalf("%s %s %s: 非預期的關卡原因 %q（夾具應讓操作者具指派能力）", cat.name, opName, name, AssignmentDenyReason(err))
					}
				}
			}
		}
		assert.Equal(t, 2*2*len(newProjectionEnv(t, CompatCatalog()).roles), compared)

		// 對照組：相容目錄下超管看到系統安全管理員、新範本與自訂角色是 not_open，既有角色 open
		e := newProjectionEnv(t, CompatCatalog())
		set := e.project(t, CompatCatalog(), e.admin)
		for _, n := range []string{"security_admin", "identity_admin", "custom-view", "custom-mgmt"} {
			assert.Equal(t, AssignmentStateNotOpen, set.ByRole[e.roles[n]].AssignmentState, n)
		}
		for _, n := range []string{"admin", "auditor", "user", "approver", "legacy-extra"} {
			assert.Equal(t, AssignmentStateOpen, set.ByRole[e.roles[n]].AssignmentState, n)
		}
		// 非超管在兩種目錄下，超管與系統安全管理員都是 protected
		for _, cat := range catalogs {
			s := e.project(t, cat.c, e.ida)
			assert.Equal(t, AssignmentStateProtected, s.ByRole[e.roles["admin"]].AssignmentState, cat.name)
			assert.Equal(t, AssignmentStateProtected, s.ByRole[e.roles["security_admin"]].AssignmentState, cat.name)
		}
	})

	t.Run("group_bindable、direct_mappable、management_class 各自對上寫入側的判定", func(t *testing.T) {
		e := newProjectionEnv(t, FullCatalog())
		set := e.project(t, FullCatalog(), e.admin)
		gid := e.groupWith(t, "g")
		approver := model.Role{BuiltinKey: func() *string { k := model.BuiltinApprover; return &k }()}
		assert.False(t, roleGroupBindable(approver), "審核者內建角色不可給群組")
		for name, id := range e.roles {
			p := set.ByRole[id]
			// group_bindable：其他限制皆滿足下，ReplaceRoleBindings 的最終結果
			_, err := e.groups.ReplaceRoleBindings(e.op(e.admin), gid, GroupRoleBindingsRequest{RoleIDs: []uint{id}})
			if p.GroupBindable {
				require.NoError(t, err, name)
			} else {
				require.True(t, errors.Is(err, ErrRoleNotGroupBindable), "%s: %v", name, err)
			}
			_, err = e.groups.ReplaceRoleBindings(e.op(e.admin), gid, GroupRoleBindingsRequest{RoleIDs: nil})
			require.NoError(t, err)

			// direct_mappable：直接映射目標檢查（完整目錄下不會被目標集合遮住）
			_, err = e.src.mappingDirectRole(e.db, name)
			assert.Equal(t, p.DirectMappable, !errors.Is(err, ErrMappingRoleNotDirectMappable), "%s direct_mappable", name)

			// management_class：與授權變更分類器對同一指派的管理類判定一致
			require.NoError(t, e.db.Create(&model.UserGroupRole{UserGroupID: gid, RoleID: id, ScopeKind: model.ScopeKindGlobal}).Error)
			entries, err := authz.GroupGrantEntries(e.db, gid)
			require.NoError(t, err)
			require.Len(t, entries, 1, name)
			assert.Equal(t, entries[0].Management, p.ManagementClass, "%s management_class", name)
			require.NoError(t, e.db.Where("user_group_id = ?", gid).Delete(&model.UserGroupRole{}).Error)
		}
		// 固定的幾個已知值，防止兩邊同時退化成全真或全假
		assert.True(t, set.ByRole[e.roles["identity_admin"]].ManagementClass)
		assert.False(t, set.ByRole[e.roles["custom-view"]].ManagementClass)
		assert.True(t, set.ByRole[e.roles["custom-mgmt"]].ManagementClass)
		assert.True(t, set.ByRole[e.roles["admin"]].DirectMappable)
		assert.False(t, set.ByRole[e.roles["custom-view"]].DirectMappable)
		assert.False(t, set.ByRole[e.roles["approver"]].GroupBindable)
	})

	t.Run("user_count 同一人只算一次，映射以已落地者計，停用計入、已刪不計；references 與刪除共用查詢", func(t *testing.T) {
		e := newProjectionEnv(t, FullCatalog())
		cv := e.roles["custom-view"]
		cm := e.roles["custom-mgmt"]
		bindDirect := func(uid, rid uint, source string) {
			require.NoError(t, e.db.Create(&model.UserRole{UserID: uid, RoleID: rid, Source: source, ScopeKind: model.ScopeKindGlobal}).Error)
		}
		u1 := e.mkUser(t, "u1")
		u2 := e.mkUser(t, "u2") // 直接加群組，兩個來源
		u3 := e.mkUser(t, "u3") // 只經群組
		u4 := e.mkUser(t, "u4") // 映射落地
		u5 := e.mkUser(t, "u5") // 停用
		u6 := e.mkUser(t, "u6") // 已刪
		u7 := e.mkUser(t, "u7") // 直接與映射共同落地（兩種來源合一列）再加群組：三種來源同一角色
		bindDirect(u1, cv, model.RoleSourceManual)
		bindDirect(u2, cv, model.RoleSourceManual)
		bindDirect(u4, cv, model.RoleSourceMapped)
		bindDirect(u5, cv, model.RoleSourceManual)
		bindDirect(u6, cv, model.RoleSourceManual)
		bindDirect(u7, cv, model.RoleSourceBoth)
		require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", u5).Update("active", false).Error)
		require.NoError(t, e.db.Delete(&model.User{}, u6).Error)
		g1 := e.groupWith(t, "g1", u2, u3, u7)
		require.NoError(t, e.db.Create(&model.UserGroupRole{UserGroupID: g1, RoleID: cv, ScopeKind: model.ScopeKindGlobal}).Error)
		// 已刪群組的成員不經它取得角色
		gDead := e.groupWith(t, "g-dead", u1)
		require.NoError(t, e.db.Create(&model.UserGroupRole{UserGroupID: gDead, RoleID: cm, ScopeKind: model.ScopeKindGlobal}).Error)
		require.NoError(t, e.db.Delete(&model.UserGroup{}, gDead).Error)

		// 只被無成員群組與停用映射規則引用的角色
		other := e.create(t, "refs-only", "asset:view").ID
		gEmpty := e.groupWith(t, "g-empty")
		require.NoError(t, e.db.Create(&model.UserGroupRole{UserGroupID: gEmpty, RoleID: other, ScopeKind: model.ScopeKindGlobal}).Error)
		require.NoError(t, e.db.Create(&model.GroupRoleMapping{MatchValue: "cn=x", ExternalGroupID: 1, RoleID: other, Enabled: false, CreatedBy: e.admin}).Error)
		free := e.create(t, "unreferenced", "asset:view").ID

		before := e.auditRows(t)
		verBefore := e.version(t)
		set := e.project(t, FullCatalog(), e.admin)
		assert.EqualValues(t, 6, set.ByRole[cv].UserCount, "u1 u2 u3 u4 u5 u7；u7 經直接、映射、群組三來源只計一次")
		assert.Equal(t, RoleReferenceCounts{Direct: 6, GroupBindings: 1}, set.ByRole[cv].References)
		assert.EqualValues(t, 0, set.ByRole[cm].UserCount, "已刪群組不產生指派")
		assert.EqualValues(t, 0, set.ByRole[other].UserCount)
		assert.Equal(t, RoleReferenceCounts{GroupBindings: 1, MappingRules: 1}, set.ByRole[other].References)
		assert.Equal(t, RoleReferenceCounts{}, set.ByRole[free].References)
		assert.Equal(t, before, e.auditRows(t), "投影前後審計列數不變")
		assert.Equal(t, verBefore, e.version(t), "投影不推進授權世代")

		// references 任一大於 0，刪除即被拒（與 user_count 無關）；全為 0 才能刪
		ctx := context.Background()
		for _, id := range []uint{cv, other} {
			d, err := e.svc.GetDefinition(ctx, id)
			require.NoError(t, err)
			assert.ErrorIs(t, e.svc.Delete(ctx, e.admin, id, d.DefinitionVersion), ErrRoleDefinitionInUse)
		}
		d, err := e.svc.GetDefinition(ctx, free)
		require.NoError(t, err)
		require.NoError(t, e.svc.Delete(ctx, e.admin, free, d.DefinitionVersion))
	})

	t.Run("account_ops 與帳號身分操作關卡的裁決逐格一致，投影不寫資料", func(t *testing.T) {
		e := newProjectionEnv(t, FullCatalog())
		viaGroup := func(name string, role string) uint {
			uid := e.mkUser(t, name)
			g := e.groupWith(t, "g-"+name, uid)
			require.NoError(t, e.db.Create(&model.UserGroupRole{UserGroupID: g, RoleID: e.roles[role], ScopeKind: model.ScopeKindGlobal}).Error)
			return uid
		}
		viaMapping := func(name string, role string) uint {
			uid := e.mkUser(t, name)
			require.NoError(t, e.db.Create(&model.UserRole{UserID: uid, RoleID: e.roles[role], Source: model.RoleSourceMapped, ScopeKind: model.ScopeKindGlobal}).Error)
			return uid
		}
		targets := map[string]uint{
			"超管直接":    e.mkUser(t, "t-super-direct", "admin"),
			"超管群組":    viaGroup("t-super-group", "admin"),
			"超管映射":    viaMapping("t-super-map", "admin"),
			"安全管理員直接": e.mkUser(t, "t-sec-direct", "security_admin"),
			"安全管理員群組": viaGroup("t-sec-group", "security_admin"),
			"安全管理員映射": viaMapping("t-sec-map", "security_admin"),
			"一般":      e.mkUser(t, "t-plain", "user"),
		}
		ops := []struct {
			key     string
			actions []AccountOperation
		}{
			{"set_password", []AccountOperation{AccountOpPasswordChange}},
			{"disable_mfa", []AccountOperation{AccountOpMFADisabled}},
			{"bind_identity", []AccountOperation{AccountOpExternalBound}},
			{"unbind_identity", []AccountOperation{AccountOpExternalUnbound}},
			{"unbind_and_disable", []AccountOperation{AccountOpDisable, AccountOpExternalUnbound}},
			{"disable", []AccountOperation{AccountOpDisable}},
			{"enable", []AccountOperation{AccountOpEnable}},
			{"delete", []AccountOperation{AccountOpDelete}},
		}
		gate := NewProtectedAccountOps(nil, nil)
		proj := NewRoleProjector(e.db, NewAssignmentGuard(FullCatalog()))
		before := e.auditRows(t)
		cells := 0
		for opName, op := range map[string]uint{"超管": e.admin, "非超管": e.ida} {
			for tName, tid := range targets {
				got, err := proj.AccountOps(op, tid)
				require.NoError(t, err)
				require.Len(t, got, len(AccountOpKeys))
				for _, o := range ops {
					want := AccountOpClassAllowed
					for _, a := range o.actions {
						notify, gerr := gate.Gate(e.db, e.op(op), tid, a)
						if gerr != nil {
							require.ErrorIs(t, gerr, ErrProtectedAccountOperation)
							want = AccountOpClassSuperOnly
							break
						}
						if notify {
							want = AccountOpClassNotify
						}
					}
					assert.Equal(t, want, got[o.key], "%s × %s × %s", opName, tName, o.key)
					cells++
				}
			}
		}
		assert.Equal(t, 2*len(targets)*8, cells)
		assert.Equal(t, before, e.auditRows(t), "投影前後審計列數不變")
		// 已知值：非超管面對超管是 super_only，面對安全管理員改密是 notify
		ops1, err := proj.AccountOps(e.ida, targets["超管直接"])
		require.NoError(t, err)
		assert.Equal(t, AccountOpClassSuperOnly, ops1["set_password"])
		ops2, err := proj.AccountOps(e.ida, targets["安全管理員群組"])
		require.NoError(t, err)
		assert.Equal(t, AccountOpClassNotify, ops2["set_password"])
		assert.Equal(t, AccountOpClassSuperOnly, ops2["disable"])
		ops3, err := proj.AccountOps(e.ida, targets["一般"])
		require.NoError(t, err)
		for _, k := range AccountOpKeys {
			assert.Equal(t, AccountOpClassAllowed, ops3[k], k)
		}
		_, err = proj.AccountOps(e.ida, 999999)
		assert.ErrorIs(t, err, ErrUserNotFound)
	})
}

func (e *projectionEnv) groupWith(t *testing.T, name string, members ...uint) uint {
	t.Helper()
	g := model.UserGroup{Name: name}
	require.NoError(t, e.db.Create(&g).Error)
	for _, m := range members {
		require.NoError(t, e.db.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: m, Manual: true}).Error)
	}
	return g.ID
}
