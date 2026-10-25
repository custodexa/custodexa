package identity

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 指派關卡測試夾具：在角色定義夾具上加使用者服務。

type guardEnv struct {
	*roleDefEnv
	users *UserService
}

func newGuardEnv(t *testing.T, full bool) *guardEnv {
	t.Helper()
	e := newRoleDefEnv(t)
	require.NoError(t, e.db.AutoMigrate(&model.PasswordHistory{}, &model.RefreshToken{}, &model.UserRoleMappingRuleSupport{}, &model.UserGroupMappingRuleSupport{}, &model.UserChannelObservation{}))
	us := NewUserService(e.db, nil)
	if full {
		us.SetAssignmentGuard(NewAssignmentGuard(FullCatalog()))
	}
	return &guardEnv{roleDefEnv: e, users: us}
}

func (e *guardEnv) op(id uint) Operator {
	return Operator{UserID: id, Username: "op", ClientIP: "127.0.0.1"}
}

func (e *guardEnv) version(t *testing.T) int64 {
	t.Helper()
	v, err := authz.CurrentVersion(e.db)
	require.NoError(t, err)
	return v
}

func (e *guardEnv) manual(t *testing.T, uid uint) []string {
	t.Helper()
	sets, err := e.users.RoleSetsOf(uid)
	require.NoError(t, err)
	return sets.Manual
}

func (e *guardEnv) agent(t *testing.T, name string) uint {
	t.Helper()
	owner := e.admin
	u := model.User{Username: name, Kind: model.KindAgent, OwnerUserID: &owner, Active: true}
	require.NoError(t, e.db.Create(&u).Error)
	return u.ID
}

func assertCode(t *testing.T, err error, code apierror.ErrCode) {
	t.Helper()
	var pe *PrincipalError
	require.True(t, errors.As(err, &pe), "want PrincipalError %s, got %v", code, err)
	assert.Equal(t, code, pe.Code)
	// 拒絕回應不含角色名或權限名
	for _, leak := range []string{"super_admin", "security_admin", "identity_admin", "role:assign", "asset:update"} {
		assert.False(t, strings.Contains(err.Error(), leak), "拒絕訊息洩漏 %q", leak)
	}
}

// assertAssignForbidden 操作者缺指派能力的拒絕：碼為能力拒絕碼，且以哨兵與同碼的規則拒絕區分。
func assertAssignForbidden(t *testing.T, err error) {
	t.Helper()
	assertCode(t, err, apierror.CodePermissionDenied)
	assert.True(t, errors.Is(err, ErrRoleAssignmentForbidden), "want ErrRoleAssignmentForbidden, got %v", err)
	assert.False(t, errors.Is(err, ErrAgentRoleForbidden), "不得與 agent 角色限制的規則拒絕混淆")
}

func hasRoleName(names []string, n string) bool {
	for _, x := range names {
		if x == n {
			return true
		}
	}
	return false
}

// TestRoleAssignmentGuard 擋：非超管指派保護目標、缺指派能力、範圍欄位、相容目錄外的角色、
// agent 取得管理類角色；放行：超管全部、持指派能力者發放一般角色。
func TestRoleAssignmentGuard(t *testing.T) {
	t.Run("保護目標：非超管經替換追加建帳號群組指派成員加入全部拒絕，超管成功", func(t *testing.T) {
		e := newGuardEnv(t, true)
		idAdmin := e.mkUser(t, "ida", "identity_admin")
		victim := e.mkUser(t, "victim")
		v0 := e.version(t)

		// 替換、追加（超管角色、系統安全管理員角色各一）
		_, err := e.users.AssignRolesBy(e.op(idAdmin), victim, []string{"admin"})
		assertCode(t, err, apierror.CodeAuthProtectedRoleAssignment)
		_, err = e.users.AssignRolesBy(e.op(idAdmin), victim, []string{"security_admin"})
		assertCode(t, err, apierror.CodeAuthProtectedRoleAssignment)
		assertCode(t, e.users.AddRoleBy(e.op(idAdmin), victim, "admin"), apierror.CodeAuthProtectedRoleAssignment)
		assertCode(t, e.users.AddRoleBy(e.op(idAdmin), victim, "security_admin"), apierror.CodeAuthProtectedRoleAssignment)
		// 建帳號帶角色
		_, err = e.users.CreateBy(e.op(idAdmin), &CreateUserRequest{Username: "n1", Password: "Passw0rd!xyz", Roles: []string{"admin"}})
		assertCode(t, err, apierror.CodeAuthProtectedRoleAssignment)
		var n int64
		require.NoError(t, e.db.Model(&model.User{}).Where("username = ?", "n1").Count(&n).Error)
		assert.Zero(t, n, "被拒的建帳號不得留下帳號")
		// 群組角色指派與成員加入（群組已帶保護角色）
		g := model.UserGroup{Name: "g1"}
		require.NoError(t, e.db.Create(&g).Error)
		guard := NewAssignmentGuard(FullCatalog())
		err = e.db.Transaction(func(tx *gorm.DB) error {
			return guard.Check(tx, e.op(idAdmin), AssignmentChange{Path: PathGroupRoles, GroupID: g.ID, NewRoleIDs: []uint{e.roles["security_admin"]}})
		})
		assertCode(t, err, apierror.CodeAuthProtectedRoleAssignment)
		require.NoError(t, e.db.Create(&model.UserGroupRole{UserGroupID: g.ID, RoleID: e.roles["security_admin"], ScopeKind: model.ScopeKindGlobal}).Error)
		err = e.db.Transaction(func(tx *gorm.DB) error {
			return guard.Check(tx, e.op(idAdmin), AssignmentChange{Path: PathGroupMember, GroupID: g.ID, AddedMemberIDs: []uint{victim}})
		})
		assertCode(t, err, apierror.CodeAuthProtectedRoleAssignment)
		assert.Equal(t, v0, e.version(t), "被拒時權限版本不變")
		assert.Empty(t, e.manual(t, victim))

		// 超管全部成功
		_, err = e.users.AssignRolesBy(e.op(e.admin), victim, []string{"admin"})
		require.NoError(t, err)
		require.NoError(t, e.users.AddRoleBy(e.op(e.admin), victim, "security_admin"))
		assert.True(t, hasRoleName(e.manual(t, victim), "security_admin"))
		_, err = e.users.CreateBy(e.op(e.admin), &CreateUserRequest{Username: "n2", Password: "Passw0rd!xyz", Roles: []string{"security_admin"}})
		require.NoError(t, err)
		require.NoError(t, e.db.Transaction(func(tx *gorm.DB) error {
			return guard.Check(tx, e.op(e.admin), AssignmentChange{Path: PathGroupMember, GroupID: g.ID, AddedMemberIDs: []uint{victim}})
		}))
	})

	t.Run("修改或刪除舊值為保護角色的指派，非超管拒絕", func(t *testing.T) {
		e := newGuardEnv(t, true)
		idAdmin := e.mkUser(t, "ida", "identity_admin")
		holder := e.mkUser(t, "secholder", "security_admin")
		_, err := e.users.AssignRolesBy(e.op(idAdmin), holder, []string{})
		assertCode(t, err, apierror.CodeAuthProtectedRoleAssignment)
		assert.True(t, hasRoleName(e.manual(t, holder), "security_admin"))
		// 保留保護角色不動、只新增一般角色：保護項沒有被改動，放行
		_, err = e.users.AssignRolesBy(e.op(idAdmin), holder, []string{"security_admin", "auditor"})
		require.NoError(t, err)
	})

	t.Run("只持指派能力者發放含資產管理權限的角色成功；自訂角色與身分管理員結果相同", func(t *testing.T) {
		e := newGuardEnv(t, true)
		e.roles["assetmgr"] = e.create(t, "assetmgr", "asset:view", "asset:update").ID
		e.roles["assigner"] = e.create(t, "assigner", "role:view", "role:assign").ID
		idAdmin := e.mkUser(t, "ida", "identity_admin")
		custom := e.mkUser(t, "cus", "assigner")
		plain := e.mkUser(t, "plain", "user")
		for _, opID := range []uint{idAdmin, custom} {
			target := e.mkUser(t, "t"+string(rune('a'+int(opID))))
			_, err := e.users.AssignRolesBy(e.op(opID), target, []string{"assetmgr"})
			require.NoError(t, err)
			assert.True(t, hasRoleName(e.manual(t, target), "assetmgr"))
			_, err = e.users.AssignRolesBy(e.op(opID), target, []string{"admin"})
			assertCode(t, err, apierror.CodeAuthProtectedRoleAssignment)
		}
		// 不持指派能力者拒絕：持使用者管理能力但不持指派能力，與只持一般使用者角色者結果相同
		e.roles["usermgr"] = e.create(t, "usermgr", "user:manage").ID
		userMgr := e.mkUser(t, "umgr", "usermgr")
		victim := e.mkUser(t, "victim")
		assertAssignForbidden(t, e.users.AddRoleBy(e.op(userMgr), victim, "auditor"))
		_, err := e.users.AssignRolesBy(e.op(userMgr), victim, []string{"auditor"})
		assertAssignForbidden(t, err)
		assertAssignForbidden(t, e.users.AddRoleBy(e.op(plain), victim, "auditor"))
		assertAssignForbidden(t, e.users.AddRoleBy(e.op(0), victim, "auditor"))
		assert.Empty(t, e.manual(t, victim))
	})

	t.Run("目標為超管帳號：非超管一律拒絕", func(t *testing.T) {
		e := newGuardEnv(t, true)
		idAdmin := e.mkUser(t, "ida", "identity_admin")
		err := e.users.AddRoleBy(e.op(idAdmin), e.admin, "auditor")
		assertCode(t, err, apierror.CodeAuthProtectedAccountOperation)
	})

	t.Run("範圍欄位：節點或空範圍請求整筆拒絕且無寫入", func(t *testing.T) {
		e := newGuardEnv(t, true)
		g := model.UserGroup{Name: "g1"}
		require.NoError(t, e.db.Create(&g).Error)
		_, _, v0, a0 := e.snapshot(t)
		err := e.db.Transaction(func(tx *gorm.DB) error {
			return NewAssignmentGuard(FullCatalog()).Check(tx, e.op(e.admin), AssignmentChange{
				Path: PathGroupRoles, GroupID: g.ID, NewRoleIDs: []uint{e.roles["user"]}, ScopeRequested: true})
		})
		assertCode(t, err, apierror.CodeValidationRoleBindingScopeUnsupported)
		_, _, v1, a1 := e.snapshot(t)
		assert.Equal(t, v0, v1)
		assert.Equal(t, a0, a1)
	})

	t.Run("範圍欄位：直接三路徑帶範圍或節點欄位整筆拒絕且無寫入，不帶照常寫入", func(t *testing.T) {
		e := newGuardEnv(t, true)
		victim := e.mkUser(t, "victim")
		scoped := DirectAssignOptions{ScopeRequested: true}
		_, _, v0, a0 := e.snapshot(t)

		_, err := e.users.AssignRolesBy(e.op(e.admin), victim, []string{"auditor"}, scoped)
		assertCode(t, err, apierror.CodeValidationRoleBindingScopeUnsupported)
		assertCode(t, e.users.AddRoleBy(e.op(e.admin), victim, "auditor", scoped), apierror.CodeValidationRoleBindingScopeUnsupported)
		_, err = e.users.CreateBy(e.op(e.admin), &CreateUserRequest{Username: "n1", Password: "Passw0rd!xyz", Roles: []string{"auditor"}}, scoped)
		assertCode(t, err, apierror.CodeValidationRoleBindingScopeUnsupported)
		// 建帳號沒帶角色、只帶範圍欄位：同樣整筆拒絕，不建出帳號
		_, err = e.users.CreateBy(e.op(e.admin), &CreateUserRequest{Username: "n2", Password: "Passw0rd!xyz"}, scoped)
		assertCode(t, err, apierror.CodeValidationRoleBindingScopeUnsupported)

		var n int64
		require.NoError(t, e.db.Model(&model.User{}).Where("username IN ?", []string{"n1", "n2"}).Count(&n).Error)
		assert.Zero(t, n, "被拒的建帳號不得留下帳號")
		assert.Empty(t, e.manual(t, victim), "沒有任何指派以全域寫入")
		_, _, v1, a1 := e.snapshot(t)
		assert.Equal(t, v0, v1, "被拒時權限版本不變")
		assert.Equal(t, a0, a1, "被拒時不留成功審計")

		// 不帶範圍欄位：三條路徑照常寫入
		_, err = e.users.AssignRolesBy(e.op(e.admin), victim, []string{"auditor"}, DirectAssignOptions{})
		require.NoError(t, err)
		require.NoError(t, e.users.AddRoleBy(e.op(e.admin), victim, "user"))
		assert.True(t, hasRoleName(e.manual(t, victim), "auditor"))
		assert.True(t, hasRoleName(e.manual(t, victim), "user"))
		u, err := e.users.CreateBy(e.op(e.admin), &CreateUserRequest{Username: "n3", Password: "Passw0rd!xyz", Roles: []string{"auditor"}})
		require.NoError(t, err)
		assert.True(t, hasRoleName(e.manual(t, u.ID), "auditor"))
	})

	t.Run("保護角色界線：保護角色本身被移除或替換限超管，保護角色不變只增減其他角色不需超管", func(t *testing.T) {
		e := newGuardEnv(t, true)
		idAdmin := e.mkUser(t, "ida", "identity_admin")
		holder := e.mkUser(t, "secholder", "security_admin", "auditor")

		// 保護角色本身被移除：非超管拒絕
		_, err := e.users.AssignRolesBy(e.op(idAdmin), holder, []string{"auditor"})
		assertCode(t, err, apierror.CodeAuthProtectedRoleAssignment)
		// 保護角色被換成另一個保護角色：非超管拒絕
		_, err = e.users.AssignRolesBy(e.op(idAdmin), holder, []string{"admin", "auditor"})
		assertCode(t, err, apierror.CodeAuthProtectedRoleAssignment)
		assert.True(t, hasRoleName(e.manual(t, holder), "security_admin"), "被拒時保護角色仍在")
		assert.True(t, hasRoleName(e.manual(t, holder), "auditor"))

		// 保護角色不變：替換時移除其他角色、追加其他角色，非超管放行
		_, err = e.users.AssignRolesBy(e.op(idAdmin), holder, []string{"security_admin"})
		require.NoError(t, err)
		assert.False(t, hasRoleName(e.manual(t, holder), "auditor"))
		require.NoError(t, e.users.AddRoleBy(e.op(idAdmin), holder, "user"))
		assert.True(t, hasRoleName(e.manual(t, holder), "user"))
		assert.True(t, hasRoleName(e.manual(t, holder), "security_admin"))

		// 同樣的移除與替換，超管放行
		_, err = e.users.AssignRolesBy(e.op(e.admin), holder, []string{"admin"})
		require.NoError(t, err)
		assert.False(t, hasRoleName(e.manual(t, holder), "security_admin"))
	})

	t.Run("等價自訂角色：含高風險專屬權限點者同為保護角色，各路徑非超管拒絕、超管放行；只含不保護點或不含者照常可指派", func(t *testing.T) {
		e := newGuardEnv(t, true)
		secPerms := []string{}
		for _, p := range authz.TemplatePermissions(model.BuiltinSecurityAdmin) {
			secPerms = append(secPerms, string(p))
		}
		e.roles["secequiv"] = e.create(t, "secequiv", secPerms...).ID
		e.roles["secpart"] = e.create(t, "secpart", "asset:view", "recording:delete").ID // 只含一個高風險點
		// 只含不保護的專屬點（唯讀檢視、排程、清冊、輪替報告排程）：不是保護角色
		e.roles["guardview"] = e.create(t, "guardview", "instanceguard:view", "schedule:manage", "transmission:manage", "rotation_schedule:manage").ID
		e.roles["pgviewer"] = e.create(t, "pgviewer", "policygroup:view").ID // 與稽核員共有，非專屬
		e.roles["assigner"] = e.create(t, "assigner", "role:view", "role:assign").ID
		idAdmin := e.mkUser(t, "ida", "identity_admin")
		custom := e.mkUser(t, "cus", "assigner")
		guard := NewAssignmentGuard(FullCatalog())
		check := func(op uint, ch AssignmentChange) error {
			return e.db.Transaction(func(tx *gorm.DB) error { return guard.Check(tx, e.op(op), ch) })
		}
		for _, opID := range []uint{idAdmin, custom} {
			victim := e.mkUser(t, fmt.Sprintf("victim%d", opID))
			v0 := e.version(t)
			for _, name := range []string{"secequiv", "secpart"} {
				rid := e.roles[name]
				_, err := e.users.AssignRolesBy(e.op(opID), victim, []string{name})
				assertCode(t, err, apierror.CodeAuthProtectedRoleAssignment)
				assertCode(t, e.users.AddRoleBy(e.op(opID), victim, name), apierror.CodeAuthProtectedRoleAssignment)
				assertCode(t, e.users.AddRoleBy(e.op(opID), opID, name), apierror.CodeAuthProtectedRoleAssignment) // 自授
				_, err = e.users.CreateBy(e.op(opID), &CreateUserRequest{Username: fmt.Sprintf("n%d%s", opID, name), Password: "Passw0rd!xyz", Roles: []string{name}})
				assertCode(t, err, apierror.CodeAuthProtectedRoleAssignment)
				assertCode(t, check(opID, AssignmentChange{Path: PathPin, TargetUserID: victim, NewRoleIDs: []uint{rid}}), apierror.CodeAuthProtectedRoleAssignment)
				assertCode(t, check(opID, AssignmentChange{Path: PathMapping, NewRoleIDs: []uint{rid}}), apierror.CodeAuthProtectedRoleAssignment)
				g := model.UserGroup{Name: fmt.Sprintf("g%d%s", opID, name)}
				require.NoError(t, e.db.Create(&g).Error)
				assertCode(t, check(opID, AssignmentChange{Path: PathGroupRoles, GroupID: g.ID, NewRoleIDs: []uint{rid}}), apierror.CodeAuthProtectedRoleAssignment)
				require.NoError(t, e.db.Create(&model.UserGroupRole{UserGroupID: g.ID, RoleID: rid, ScopeKind: model.ScopeKindGlobal}).Error)
				assertCode(t, check(opID, AssignmentChange{Path: PathGroupMember, GroupID: g.ID, AddedMemberIDs: []uint{victim}}), apierror.CodeAuthProtectedRoleAssignment)
				assertCode(t, check(opID, AssignmentChange{Path: PathGroupDelete, GroupID: g.ID}), apierror.CodeAuthProtectedRoleAssignment)
				assert.Equal(t, DenyReasonProtectedRole, AssignmentDenyReason(check(opID, AssignmentChange{Path: PathGroupMember, GroupID: g.ID, AddedMemberIDs: []uint{victim}})))
			}
			assert.Empty(t, e.manual(t, victim))
			assert.Equal(t, v0, e.version(t), "被拒時權限版本不變")
			// 不含專屬點的自訂角色：非超管照常可指派
			require.NoError(t, e.users.AddRoleBy(e.op(opID), victim, "pgviewer"))
			assert.True(t, hasRoleName(e.manual(t, victim), "pgviewer"))
			// 只含不保護專屬點的自訂角色：非超管同樣可指派
			require.NoError(t, e.users.AddRoleBy(e.op(opID), victim, "guardview"))
			assert.True(t, hasRoleName(e.manual(t, victim), "guardview"))
		}
		// 投影與關卡同一判定：非超管看到受保護，超管看到可指派
		proj := NewRoleProjector(e.db, guard)
		s, err := proj.ProjectRoles(idAdmin)
		require.NoError(t, err)
		assert.Equal(t, AssignmentStateProtected, s.ByRole[e.roles["secequiv"]].AssignmentState)
		assert.Equal(t, AssignmentStateProtected, s.ByRole[e.roles["secpart"]].AssignmentState)
		assert.Equal(t, AssignmentStateOpen, s.ByRole[e.roles["pgviewer"]].AssignmentState)
		assert.Equal(t, AssignmentStateOpen, s.ByRole[e.roles["guardview"]].AssignmentState)
		s, err = proj.ProjectRoles(e.admin)
		require.NoError(t, err)
		assert.Equal(t, AssignmentStateOpen, s.ByRole[e.roles["secequiv"]].AssignmentState)
		// 超管放行
		target := e.mkUser(t, "target")
		require.NoError(t, e.users.AddRoleBy(e.op(e.admin), target, "secequiv"))
		_, err = e.users.AssignRolesBy(e.op(e.admin), target, []string{"secequiv", "secpart"})
		require.NoError(t, err)
		assert.True(t, hasRoleName(e.manual(t, target), "secpart"))
		g := model.UserGroup{Name: "gsuper"}
		require.NoError(t, e.db.Create(&g).Error)
		require.NoError(t, check(e.admin, AssignmentChange{Path: PathGroupRoles, GroupID: g.ID, NewRoleIDs: []uint{e.roles["secequiv"]}}))
		// 保護角色不變只增減其他角色：非超管放行（與內建保護角色同一界線）
		_, err = e.users.AssignRolesBy(e.op(idAdmin), target, []string{"secequiv", "secpart", "pgviewer"})
		require.NoError(t, err)
	})

	t.Run("追加路徑在使用者鎖之內判定與寫入", func(t *testing.T) {
		e := newGuardEnv(t, true)
		victim := e.mkUser(t, "victim")
		mu := userCredentialLockFor(victim)
		mu.Lock()
		done := make(chan error, 1)
		go func() { done <- e.users.AddRoleBy(e.op(e.admin), victim, "auditor") }()
		select {
		case err := <-done:
			mu.Unlock()
			t.Fatalf("持有使用者鎖期間追加不得完成（err=%v）", err)
		case <-time.After(200 * time.Millisecond):
		}
		// 鎖內的交易占著連線，不在這裡讀資料；沒有完成即代表尚未寫入
		mu.Unlock()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("鎖釋放後追加未完成")
		}
		assert.True(t, hasRoleName(e.manual(t, victim), "auditor"))
	})

	t.Run("開放邊界：相容目錄下新範本與自訂角色經每個入口被拒，完整集合放行", func(t *testing.T) {
		e := newGuardEnv(t, false)
		e.create(t, "assetmgr", "asset:view", "asset:update")
		victim := e.mkUser(t, "victim")
		assert.ErrorIs(t, e.users.AddRoleBy(e.op(e.admin), victim, "assetmgr"), ErrRoleNotFound)
		assert.ErrorIs(t, e.users.AddRoleBy(e.op(e.admin), victim, "identity_admin"), ErrRoleNotFound)
		_, err := e.users.AssignRolesBy(e.op(e.admin), victim, []string{"assetmgr"})
		assert.ErrorIs(t, err, ErrRoleNotFound)
		_, err = e.users.CreateBy(e.op(e.admin), &CreateUserRequest{Username: "n1", Password: "Passw0rd!xyz", Roles: []string{"assetmgr"}})
		assert.ErrorIs(t, err, ErrRoleNotFound)
		// 群組路徑：關卡自身也擋（注入相容目錄）
		g := model.UserGroup{Name: "g1"}
		require.NoError(t, e.db.Create(&g).Error)
		err = e.db.Transaction(func(tx *gorm.DB) error {
			return NewAssignmentGuard(CompatCatalog()).Check(tx, e.op(e.admin), AssignmentChange{
				Path: PathGroupRoles, GroupID: g.ID, NewRoleIDs: []uint{e.roles["identity_admin"]}})
		})
		assert.ErrorIs(t, err, ErrRoleNotFound)
		assert.Empty(t, e.manual(t, victim))

		full := newGuardEnv(t, true)
		full.create(t, "assetmgr", "asset:view", "asset:update")
		v2 := full.mkUser(t, "victim")
		require.NoError(t, full.users.AddRoleBy(full.op(full.admin), v2, "assetmgr"))
		require.NoError(t, full.users.AddRoleBy(full.op(full.admin), v2, "identity_admin"))
	})

	t.Run("agent：依能力類別拒絕管理類角色，含自訂角色", func(t *testing.T) {
		e := newGuardEnv(t, true)
		e.create(t, "assetmgr", "asset:view", "asset:update")
		e.create(t, "viewer", "asset:view")
		ag := e.agent(t, "bot")
		assert.ErrorIs(t, e.users.AddRoleBy(e.op(e.admin), ag, "assetmgr"), ErrAgentRoleForbidden)
		assert.ErrorIs(t, e.users.AddRoleBy(e.op(e.admin), ag, "identity_admin"), ErrAgentRoleForbidden)
		require.NoError(t, e.users.AddRoleBy(e.op(e.admin), ag, "viewer"))
		// 群組路徑：成員含 agent 的群組不得指派管理類角色
		g := model.UserGroup{Name: "g1"}
		require.NoError(t, e.db.Create(&g).Error)
		require.NoError(t, e.db.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: ag, Manual: true}).Error)
		err := e.db.Transaction(func(tx *gorm.DB) error {
			return NewAssignmentGuard(FullCatalog()).Check(tx, e.op(e.admin), AssignmentChange{
				Path: PathGroupRoles, GroupID: g.ID, NewRoleIDs: []uint{e.roles["identity_admin"]}})
		})
		assert.ErrorIs(t, err, ErrAgentRoleForbidden)
	})

	t.Run("群組帶來的超管不計入最後本地超管", func(t *testing.T) {
		e := newGuardEnv(t, true)
		member := e.mkUser(t, "member")
		// 兩人都具備計入本地超管的其餘條件（有密碼、本地、啟用），差別只在取得來源
		require.NoError(t, e.db.Model(&model.User{}).Where("id IN ?", []uint{e.admin, member}).Update("password", "x").Error)
		g := model.UserGroup{Name: "g1"}
		require.NoError(t, e.db.Create(&g).Error)
		require.NoError(t, e.db.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: member, Manual: true}).Error)
		require.NoError(t, e.db.Create(&model.UserGroupRole{UserGroupID: g.ID, RoleID: e.roles["admin"], ScopeKind: model.ScopeKindGlobal}).Error)
		_, err := e.users.AssignRolesBy(e.op(e.admin), e.admin, []string{})
		assert.ErrorIs(t, err, ErrLastAdmin)
	})
}
