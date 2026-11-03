package identity

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 只有審核者角色的指派斷言：直接三入口拒絕結果為此狀態者；群組三入口只拒轉入者。

type approverOnlyEnv struct {
	*scopedEnv
	node uint
}

// newApproverOnlyEnv 依 TEST_PG_DSN 選方言：非空時用獨立 schema 的 PostgreSQL（印 EVIDENCE），否則 SQLite。
func newApproverOnlyEnv(t *testing.T) *approverOnlyEnv {
	t.Helper()
	var base *roleDefEnv
	if dsn := os.Getenv("TEST_PG_DSN"); dsn != "" {
		schema := fmt.Sprintf("aog_%d", time.Now().UnixNano())
		admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
		t.Cleanup(func() {
			_ = admin.Exec("DROP SCHEMA " + schema + " CASCADE").Error
			if sd, e := admin.DB(); e == nil {
				_ = sd.Close()
			}
		})
		db, err := gorm.Open(postgres.Open(dsn+" search_path="+schema), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		t.Cleanup(func() {
			if sd, e := db.DB(); e == nil {
				_ = sd.Close()
			}
		})
		require.Equal(t, "postgres", db.Dialector.Name())
		t.Logf("EVIDENCE dialect=%s", db.Dialector.Name())
		base = newRoleDefEnvOn(t, db)
	} else {
		base = newRoleDefEnv(t)
	}
	require.NoError(t, base.db.AutoMigrate(&model.PasswordHistory{}, &model.RefreshToken{}, &model.UserRoleMappingRuleSupport{},
		&model.UserGroupMappingRuleSupport{}, &model.UserChannelObservation{}, &model.UserRoleMapping{}))
	g := NewAssignmentGuard(FullCatalog())
	g.SetNodeExistenceReader(liveNodesStub{})
	us := NewUserService(base.db, nil)
	us.SetAssignmentGuard(g)
	gs := NewUserGroupService(base.db, audit.NewTxSink(), noopRevoker{})
	gs.SetAssignmentGuard(g)
	e := &approverOnlyEnv{scopedEnv: &scopedEnv{groupBindEnv: &groupBindEnv{guardEnv: &guardEnv{roleDefEnv: base, users: us}, svc: gs}}}
	n := model.AssetGroup{Name: "node-a"}
	require.NoError(t, base.db.Create(&n).Error)
	e.node = n.ID
	return e
}

// state 指派列、群組角色列、成員列、權限版本與審計列數的指紋：拒絕後必須逐字不變。
func (e *approverOnlyEnv) state(t *testing.T) string {
	t.Helper()
	var ur, gr, gm []string
	require.NoError(t, e.db.Table("user_roles").Order("user_id, role_id").
		Select("CAST(user_id AS TEXT) || '/' || CAST(role_id AS TEXT) || '/' || scope_kind || '/' || source").Scan(&ur).Error)
	require.NoError(t, e.db.Table("user_group_roles").Order("user_group_id, role_id").
		Select("CAST(user_group_id AS TEXT) || '/' || CAST(role_id AS TEXT) || '/' || scope_kind").Scan(&gr).Error)
	require.NoError(t, e.db.Table("user_group_members").Order("user_group_id, user_id").
		Select("CAST(user_group_id AS TEXT) || '/' || CAST(user_id AS TEXT)").Scan(&gm).Error)
	var users, groups, audits int64
	require.NoError(t, e.db.Model(&model.User{}).Count(&users).Error)
	require.NoError(t, e.db.Model(&model.UserGroup{}).Count(&groups).Error)
	require.NoError(t, e.db.Model(&model.AuditLog{}).Where("status = ?", model.StatusSuccess).Count(&audits).Error)
	return fmt.Sprintf("ur=%v gr=%v gm=%v users=%d groups=%d v=%d audits=%d", ur, gr, gm, users, groups, e.version(t), audits)
}

func (e *approverOnlyEnv) grantMapped(t *testing.T, uid uint, role string) {
	t.Helper()
	require.NoError(t, e.db.Create(&model.UserRole{UserID: uid, RoleID: e.roles[role], Source: model.RoleSourceMapped, ScopeKind: model.ScopeKindGlobal}).Error)
}

func (e *approverOnlyEnv) bindGroup(t *testing.T, gid uint, role string) {
	t.Helper()
	require.NoError(t, e.db.Create(&model.UserGroupRole{UserGroupID: gid, RoleID: e.roles[role], ScopeKind: model.ScopeKindGlobal, CreatedAt: time.Now()}).Error)
}

func usernameOf(t *testing.T, db *gorm.DB, id uint) string {
	t.Helper()
	var u model.User
	require.NoError(t, db.First(&u, id).Error)
	return u.Username
}

func requireApproverOnlyCode(t *testing.T, err error) {
	t.Helper()
	var pe *PrincipalError
	require.True(t, errors.As(err, &pe), "want PrincipalError, got %v", err)
	require.Equal(t, apierror.CodeValidationRoleSetApproverOnly, pe.Code)
	require.Equal(t, 400, pe.Status)
}

func requireMembersDenial(t *testing.T, e *approverOnlyEnv, err error, wantIDs ...uint) *ApproverOnlyMembersError {
	t.Helper()
	var me *ApproverOnlyMembersError
	require.True(t, errors.As(err, &me), "want ApproverOnlyMembersError, got %v", err)
	sort.Slice(wantIDs, func(i, j int) bool { return wantIDs[i] < wantIDs[j] })
	want := make([]AffectedUser, 0, len(wantIDs))
	for _, id := range wantIDs {
		want = append(want, AffectedUser{ID: id, Username: usernameOf(t, e.db, id)})
	}
	require.Equal(t, want, me.Users)
	return me
}

// TestApproverOnlyDirectAssignmentRejected 直接三入口：結果為只有審核者角色即 400、資料與版本不變、無成功審計。
func TestApproverOnlyDirectAssignmentRejected(t *testing.T) {
	t.Run("零指派帳號追加審核者被拒", func(t *testing.T) {
		e := newApproverOnlyEnv(t)
		u := e.mkUser(t, "zero")
		before := e.state(t)
		requireApproverOnlyCode(t, e.users.AddRoleBy(e.op(e.admin), u, "approver"))
		require.Equal(t, before, e.state(t))
	})
	t.Run("一般使用者加審核者替換為只有審核者被拒", func(t *testing.T) {
		e := newApproverOnlyEnv(t)
		u := e.mkUser(t, "both", "user", "approver")
		before := e.state(t)
		_, err := e.users.AssignRolesBy(e.op(e.admin), u, []string{"approver"})
		requireApproverOnlyCode(t, err)
		require.Equal(t, before, e.state(t))
		require.ElementsMatch(t, []string{"user", "approver"}, e.manual(t, u))
	})
	t.Run("建立只帶審核者的帳號被拒", func(t *testing.T) {
		e := newApproverOnlyEnv(t)
		before := e.state(t)
		_, err := e.users.CreateBy(e.op(e.admin), &CreateUserRequest{Username: "newbie", Password: "Passw0rd!Passw0rd",
			Email: "newbie@example.com", Roles: []string{"approver"}})
		requireApproverOnlyCode(t, err)
		require.Equal(t, before, e.state(t))
		var n int64
		require.NoError(t, e.db.Model(&model.User{}).Where("username = ?", "newbie").Count(&n).Error)
		require.Zero(t, n)
	})
	t.Run("全域審核者加節點範圍一般使用者被拒", func(t *testing.T) {
		e := newApproverOnlyEnv(t)
		u := e.mkUser(t, "narrow", "user")
		before := e.state(t)
		_, err := e.users.AssignRolesBy(e.op(e.admin), u, []string{"approver", "user"},
			DirectAssignOptions{RoleNodes: map[string]RoleNodesValue{"user": nodesOf(e.node)}})
		requireApproverOnlyCode(t, err)
		require.Equal(t, before, e.state(t))
	})
	t.Run("經映射持一般使用者時替換為只有審核者成功", func(t *testing.T) {
		e := newApproverOnlyEnv(t)
		u := e.mkUser(t, "mapped")
		e.grantMapped(t, u, "user")
		_, err := e.users.AssignRolesBy(e.op(e.admin), u, []string{"approver"})
		require.NoError(t, err)
		p, err := authz.ResolveUserOn(e.db, u, authz.TokenFacts{})
		require.NoError(t, err)
		require.True(t, p.HasBuiltin(model.BuiltinUser))
		require.True(t, p.HasBuiltin(model.BuiltinApprover))
	})
	t.Run("無指派角色能力者送只有審核者仍回原能力拒絕", func(t *testing.T) {
		e := newApproverOnlyEnv(t)
		plain := e.mkUser(t, "plainop", "user")
		u := e.mkUser(t, "target", "user")
		_, err := e.users.AssignRolesBy(e.op(plain), u, []string{"approver"})
		assertAssignForbidden(t, err)
	})
}

// TestApproverOnlyGroupTransitions 群組三入口：只拒寫入前不是、寫入後是的成員；名單升冪、最多 20 筆、人數照實。
func TestApproverOnlyGroupTransitions(t *testing.T) {
	// setup：直接持審核者、只經群組持一般使用者的成員。
	turning := func(t *testing.T, e *approverOnlyEnv, gid uint, name string) uint {
		u := e.mkUser(t, name, "approver")
		require.NoError(t, e.db.Create(&model.UserGroupMember{UserGroupID: gid, UserID: u, Manual: true}).Error)
		return u
	}
	t.Run("移出成員被拒", func(t *testing.T) {
		e := newApproverOnlyEnv(t)
		gid := e.group(t, "g")
		e.bindGroup(t, gid, "user")
		m := turning(t, e, gid, "m1")
		before := e.state(t)
		empty := []uint{}
		_, err := e.svc.ReplaceMembersBy(e.op(e.admin), gid, &empty, nil)
		me := requireMembersDenial(t, e, err, m)
		require.Equal(t, 1, me.Count)
		require.Equal(t, before, e.state(t))
	})
	t.Run("群組拿掉一般使用者被拒", func(t *testing.T) {
		e := newApproverOnlyEnv(t)
		gid := e.group(t, "g")
		e.bindGroup(t, gid, "user")
		m := turning(t, e, gid, "m1")
		before := e.state(t)
		_, err := e.svc.ReplaceRoleBindings(e.op(e.admin), gid, GroupRoleBindingsRequest{RoleIDs: []uint{}})
		me := requireMembersDenial(t, e, err, m)
		require.Equal(t, 1, me.Count)
		require.Equal(t, before, e.state(t))
	})
	t.Run("刪除群組被拒", func(t *testing.T) {
		e := newApproverOnlyEnv(t)
		gid := e.group(t, "g")
		e.bindGroup(t, gid, "user")
		m := turning(t, e, gid, "m1")
		before := e.state(t)
		_, err := e.svc.DeleteBy(e.op(e.admin), gid)
		me := requireMembersDenial(t, e, err, m)
		require.Equal(t, 1, me.Count)
		require.Equal(t, before, e.state(t))
	})
	t.Run("兩位轉入時人數為二", func(t *testing.T) {
		e := newApproverOnlyEnv(t)
		gid := e.group(t, "g")
		e.bindGroup(t, gid, "user")
		a, b := turning(t, e, gid, "m1"), turning(t, e, gid, "m2")
		_, err := e.svc.ReplaceRoleBindings(e.op(e.admin), gid, GroupRoleBindingsRequest{RoleIDs: []uint{}})
		me := requireMembersDenial(t, e, err, a, b)
		require.Equal(t, 2, me.Count)
	})
	t.Run("一般使用者由全域收窄為節點範圍被拒", func(t *testing.T) {
		e := newApproverOnlyEnv(t)
		gid := e.group(t, "g")
		e.bindGroup(t, gid, "user")
		m := turning(t, e, gid, "m1")
		before := e.state(t)
		_, err := e.svc.ReplaceRoleBindings(e.op(e.admin), gid, GroupRoleBindingsRequest{RoleIDs: []uint{e.roles["user"]},
			RoleNodes: map[uint]RoleNodesValue{e.roles["user"]: nodesOf(e.node)}})
		me := requireMembersDenial(t, e, err, m)
		require.Equal(t, 1, me.Count)
		require.Equal(t, before, e.state(t))
	})
	t.Run("已處於此狀態的成員不阻擋群組加角色", func(t *testing.T) {
		e := newApproverOnlyEnv(t)
		gid := e.group(t, "g")
		x := e.mkUser(t, "already", "approver")
		require.NoError(t, e.db.Create(&model.UserGroupMember{UserGroupID: gid, UserID: x, Manual: true}).Error)
		only, err := authz.IsApproverOnlyTx(e.db, x)
		require.NoError(t, err)
		require.True(t, only, "前提：寫入前已處於此狀態")
		_, err = e.svc.ReplaceRoleBindings(e.op(e.admin), gid, GroupRoleBindingsRequest{RoleIDs: []uint{e.roles["user"]},
			RoleNodes: map[uint]RoleNodesValue{e.roles["user"]: nodesOf(e.node)}})
		require.NoError(t, err)
		// 群組已有指派後再編輯一次（走完整判定）：x 寫入前後都是此狀態，不阻擋。
		other := model.AssetGroup{Name: "node-b"}
		require.NoError(t, e.db.Create(&other).Error)
		_, err = e.svc.ReplaceRoleBindings(e.op(e.admin), gid, GroupRoleBindingsRequest{RoleIDs: []uint{e.roles["user"]},
			RoleNodes: map[uint]RoleNodesValue{e.roles["user"]: nodesOf(e.node, other.ID)}})
		require.NoError(t, err)
		only, err = authz.IsApproverOnlyTx(e.db, x)
		require.NoError(t, err)
		require.True(t, only, "寫入後仍處於此狀態（節點範圍一般使用者不產生能力）")
	})
	t.Run("名單只列轉入者不列寫入前已是者", func(t *testing.T) {
		e := newApproverOnlyEnv(t)
		gid := e.group(t, "g")
		x := e.mkUser(t, "already", "approver")
		z := e.mkUser(t, "turning", "approver")
		// 以寫入前的判定為底：x 已是、z 不是；寫入後兩者都是。
		require.NoError(t, e.db.Create(&model.UserGroupMember{UserGroupID: gid, UserID: x, Manual: true}).Error)
		require.NoError(t, e.db.Create(&model.UserGroupMember{UserGroupID: gid, UserID: z, Manual: true}).Error)
		err := assertNoApproverOnlyTransitions(e.db, map[uint]bool{x: true, z: false})
		me := requireMembersDenial(t, e, err, z)
		require.Equal(t, 1, me.Count)
	})
	t.Run("已刪除帳號不列入人數與名單", func(t *testing.T) {
		e := newApproverOnlyEnv(t)
		gid := e.group(t, "g")
		e.bindGroup(t, gid, "user")
		gone := turning(t, e, gid, "gone")
		m := turning(t, e, gid, "m1")
		require.NoError(t, e.db.Delete(&model.User{}, gone).Error)
		before := e.state(t)
		_, err := e.svc.ReplaceRoleBindings(e.op(e.admin), gid, GroupRoleBindingsRequest{RoleIDs: []uint{}})
		me := requireMembersDenial(t, e, err, m)
		require.Equal(t, 1, me.Count)
		require.Equal(t, before, e.state(t))
	})
	t.Run("轉入者全是已刪除帳號時本斷言不拒絕", func(t *testing.T) {
		e := newApproverOnlyEnv(t)
		gone := e.mkUser(t, "gone", "approver")
		only, err := authz.LoadApproverOnly(e.db, []uint{gone})
		require.NoError(t, err)
		require.True(t, only[gone], "前提：寫入後的判定仍視其為此狀態")
		require.NoError(t, e.db.Delete(&model.User{}, gone).Error)
		require.NoError(t, assertNoApproverOnlyTransitions(e.db, map[uint]bool{gone: false}))
	})
	t.Run("超過二十位轉入時名單為識別碼最小的二十位", func(t *testing.T) {
		e := newApproverOnlyEnv(t)
		gid := e.group(t, "g")
		e.bindGroup(t, gid, "user")
		var ids []uint
		for i := 0; i < 21; i++ {
			ids = append(ids, turning(t, e, gid, fmt.Sprintf("bulk%02d", i)))
		}
		_, err := e.svc.ReplaceRoleBindings(e.op(e.admin), gid, GroupRoleBindingsRequest{RoleIDs: []uint{}})
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		me := requireMembersDenial(t, e, err, ids[:20]...)
		require.Equal(t, 21, me.Count)
	})
}

// TestApproverOnlyListMarker 列表與單筆讀取的標示：同一判定、列表查詢數不隨筆數線性增加。
func TestApproverOnlyListMarker(t *testing.T) {
	e := newApproverOnlyEnv(t)
	only := e.mkUser(t, "m-only", "approver")
	zero := e.mkUser(t, "m-zero")
	both := e.mkUser(t, "m-both", "approver", "user")
	narrow := e.mkUser(t, "m-narrow", "approver")
	require.NoError(t, e.db.Create(&model.UserRole{UserID: narrow, RoleID: e.roles["user"], Source: model.RoleSourceManual, ScopeKind: model.ScopeKindNodes}).Error)
	want := map[uint]bool{only: true, zero: false, both: false, narrow: true}

	count := func(fn func()) int {
		n := 0
		name := fmt.Sprintf("count-%d", time.Now().UnixNano())
		require.NoError(t, e.db.Callback().Query().Before("gorm:query").Register(name, func(*gorm.DB) { n++ }))
		require.NoError(t, e.db.Callback().Raw().Before("gorm:raw").Register(name, func(*gorm.DB) { n++ }))
		fn()
		_ = e.db.Callback().Query().Remove(name)
		_ = e.db.Callback().Raw().Remove(name)
		return n
	}
	var res *UserListResponse
	small := count(func() {
		var err error
		res, err = e.users.List(&ListUsersRequest{Page: 1, PageSize: 2})
		require.NoError(t, err)
	})
	large := count(func() {
		var err error
		res, err = e.users.List(&ListUsersRequest{Page: 1, PageSize: 50})
		require.NoError(t, err)
	})
	require.Equal(t, small, large, "列表查詢數不得隨當頁筆數增加")
	seen := 0
	for _, u := range res.Data {
		if v, ok := want[u.ID]; ok {
			require.NotNil(t, u.ApproverOnly, u.Username)
			require.Equal(t, v, *u.ApproverOnly, u.Username)
			seen++
		}
	}
	require.Equal(t, len(want), seen)
	for id, v := range want {
		u, err := e.users.GetByID(id)
		require.NoError(t, err)
		require.Nil(t, u.ApproverOnly, "共用讀取不填標示")
		require.NoError(t, e.users.MarkApproverOnly(u))
		require.Equal(t, v, *u.ApproverOnly, u.Username)
	}
}
