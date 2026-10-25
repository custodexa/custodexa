package identity

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
)

// 停用與刪除持保護角色的帳號（超級管理者、系統安全管理員，直接、群組、映射任一來源）：
// 效果等於收回該帳號的全部角色，與「取得或失去保護角色限超管」同一界線——只有超管能做。
// 重新啟用持保護角色的帳號同樣限超管（讓該帳號重新取得保護角色）。
// 一般帳號的停用、啟用與刪除、最後一位超管不可停用或刪除的既有規則都不變。

func newLifecycleEnv(t *testing.T) *acctEnv {
	t.Helper()
	e := newAcctEnv(t, nil)
	require.NoError(t, e.db.AutoMigrate(&model.UserRoleMapping{}))
	e.users.authzRevoker = noopRevoker{}
	return e
}

func (e *acctEnv) isActive(t *testing.T, uid uint) bool {
	t.Helper()
	var u model.User
	require.NoError(t, e.db.First(&u, uid).Error)
	return u.Active
}

func (e *acctEnv) alive(t *testing.T, uid uint) bool {
	t.Helper()
	var n int64
	require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", uid).Count(&n).Error)
	return n == 1
}

// protectedTargets 三種來源的超管帳號與一個系統安全管理員帳號。
func (e *acctEnv) protectedTargets(t *testing.T) map[string]uint {
	t.Helper()
	direct := e.mkUser(t, "sa-direct", "admin")
	viaGroup := e.mkUser(t, "sa-group")
	g := model.UserGroup{Name: "sg"}
	require.NoError(t, e.db.Create(&g).Error)
	require.NoError(t, e.db.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: viaGroup, Manual: true}).Error)
	require.NoError(t, e.db.Create(&model.UserGroupRole{UserGroupID: g.ID, RoleID: e.roles["admin"], ScopeKind: model.ScopeKindGlobal}).Error)
	mapped := e.mkUser(t, "sa-mapped")
	require.NoError(t, e.db.Create(&model.UserRole{UserID: mapped, RoleID: e.roles["admin"], Source: model.RoleSourceMapped, ScopeKind: model.ScopeKindGlobal}).Error)
	sec := e.mkUser(t, "sec", "security_admin")
	return map[string]uint{"super-direct": direct, "super-group": viaGroup, "super-mapped": mapped, "security-admin": sec}
}

func (e *acctEnv) addIdentity(t *testing.T, uid uint, subject string) uint {
	t.Helper()
	id := model.UserExternalIdentity{UserID: uid, ProviderID: e.provider, Issuer: "https://idp.example", ClientID: "cid", Subject: subject}
	require.NoError(t, e.db.Create(&id).Error)
	return id.ID
}

func TestProtectedAccountLifecycle(t *testing.T) {
	denied := apierror.CodeAuthProtectedAccountOperation

	t.Run("非超管停用持保護角色的帳號被拒，帳號維持啟用且憑證世代不變", func(t *testing.T) {
		e := newLifecycleEnv(t)
		ida := e.mkUser(t, "ida", "identity_admin")
		for name, uid := range e.protectedTargets(t) {
			epoch := e.credentialEpoch(t, uid)
			assertCode(t, e.users.UpdateStatusBy(e.op(ida), uid, false), denied)
			assert.True(t, e.isActive(t, uid), name)
			assert.Equal(t, epoch, e.credentialEpoch(t, uid), "被拒時憑證世代不變："+name)
		}
	})

	t.Run("非超管刪除持保護角色的帳號被拒，帳號與外部身分綁定都還在", func(t *testing.T) {
		e := newLifecycleEnv(t)
		ida := e.mkUser(t, "ida", "identity_admin")
		for name, uid := range e.protectedTargets(t) {
			e.addIdentity(t, uid, "subj-"+name)
			_, err := e.users.DeleteWithSummaryBy(e.op(ida), uid)
			assertCode(t, err, denied)
			assert.True(t, e.alive(t, uid), name)
			assert.EqualValues(t, 1, e.bindings(t, uid), name)
		}
	})

	t.Run("非超管解除綁定並停用持保護角色的帳號被拒，綁定與啟用狀態不變", func(t *testing.T) {
		e := newLifecycleEnv(t)
		ida := e.mkUser(t, "ida", "identity_admin")
		for name, uid := range e.protectedTargets(t) {
			iid := e.addIdentity(t, uid, "subj-"+name)
			assertCode(t, e.users.UnbindExternalIdentityAndDisableBy(e.op(ida), uid, iid), denied)
			assert.True(t, e.isActive(t, uid), name)
			assert.EqualValues(t, 1, e.bindings(t, uid), name)
		}
		assert.Zero(t, e.alerts(t), "被拒不產生系統安全管理員操作事件")
	})

	t.Run("超管可以停用、刪除另一位超管或系統安全管理員", func(t *testing.T) {
		e := newLifecycleEnv(t)
		targets := e.protectedTargets(t)
		for _, name := range []string{"super-direct", "super-group", "security-admin"} {
			require.NoError(t, e.users.UpdateStatusBy(e.op(e.admin), targets[name], false), name)
			assert.False(t, e.isActive(t, targets[name]), name)
		}
		require.NoError(t, e.users.UpdateStatusBy(e.op(e.admin), targets["super-direct"], true))
		assert.True(t, e.isActive(t, targets["super-direct"]))
		for _, name := range []string{"super-direct", "super-mapped", "security-admin"} {
			summary, err := e.users.DeleteWithSummaryBy(e.op(e.admin), targets[name])
			require.NoError(t, err, name)
			assert.NotEmpty(t, summary.Username, name)
			assert.False(t, e.alive(t, targets[name]), name)
		}
		iid := e.addIdentity(t, targets["super-group"], "subj-g")
		require.NoError(t, e.users.UpdateStatusBy(e.op(e.admin), targets["super-group"], true))
		require.NoError(t, e.users.UnbindExternalIdentityAndDisableBy(e.op(e.admin), targets["super-group"], iid))
		assert.False(t, e.isActive(t, targets["super-group"]))
	})

	t.Run("非超管停用、啟用、刪除一般帳號照常成功", func(t *testing.T) {
		e := newLifecycleEnv(t)
		ida := e.mkUser(t, "ida", "identity_admin")
		plain := e.mkUser(t, "plain", "user")
		aud := e.mkUser(t, "aud", "auditor")
		require.NoError(t, e.users.UpdateStatusBy(e.op(ida), plain, false))
		assert.False(t, e.isActive(t, plain))
		require.NoError(t, e.users.UpdateStatusBy(e.op(ida), plain, true))
		assert.True(t, e.isActive(t, plain))
		iid := e.addIdentity(t, aud, "subj-aud")
		require.NoError(t, e.users.UnbindExternalIdentityAndDisableBy(e.op(ida), aud, iid))
		assert.False(t, e.isActive(t, aud))
		_, err := e.users.DeleteWithSummaryBy(e.op(ida), plain)
		require.NoError(t, err)
		assert.False(t, e.alive(t, plain))
	})

	// 重新啟用等於讓該帳號重新取得保護角色：若其憑證落在他人手上即為提權路徑，與停用同一界線
	t.Run("非超管啟用已停用的超管或系統安全管理員帳號被拒，帳號維持停用", func(t *testing.T) {
		e := newLifecycleEnv(t)
		ida := e.mkUser(t, "ida", "identity_admin")
		for name, uid := range e.protectedTargets(t) {
			require.NoError(t, e.users.UpdateStatusBy(e.op(e.admin), uid, false), name)
			assertCode(t, e.users.UpdateStatusBy(e.op(ida), uid, true), denied)
			assert.False(t, e.isActive(t, uid), "被拒時帳號維持停用："+name)
		}
	})

	t.Run("超管可以啟用已停用的超管或系統安全管理員帳號", func(t *testing.T) {
		e := newLifecycleEnv(t)
		for name, uid := range e.protectedTargets(t) {
			require.NoError(t, e.users.UpdateStatusBy(e.op(e.admin), uid, false), name)
			require.NoError(t, e.users.UpdateStatusBy(e.op(e.admin), uid, true), name)
			assert.True(t, e.isActive(t, uid), name)
		}
	})

	t.Run("非超管啟用已停用的一般帳號照常成功", func(t *testing.T) {
		e := newLifecycleEnv(t)
		ida := e.mkUser(t, "ida", "identity_admin")
		for _, uid := range []uint{e.mkUser(t, "plain", "user"), e.mkUser(t, "aud", "auditor")} {
			require.NoError(t, e.users.UpdateStatusBy(e.op(ida), uid, false))
			require.NoError(t, e.users.UpdateStatusBy(e.op(ida), uid, true))
			assert.True(t, e.isActive(t, uid))
		}
	})

	t.Run("缺操作者一律拒絕（fail-close）", func(t *testing.T) {
		e := newLifecycleEnv(t)
		plain := e.mkUser(t, "plain", "user")
		assertCode(t, e.users.UpdateStatusBy(Operator{}, plain, false), denied)
		_, err := e.users.DeleteWithSummaryBy(Operator{}, plain)
		assertCode(t, err, denied)
		assert.True(t, e.alive(t, plain))
		assert.True(t, e.isActive(t, plain))
		require.NoError(t, e.users.UpdateStatus(plain, false))
		assertCode(t, e.users.UpdateStatusBy(Operator{}, plain, true), denied)
		assert.False(t, e.isActive(t, plain))
	})

	t.Run("最後一位超管仍不可停用或刪除，超管操作也一樣", func(t *testing.T) {
		e := newLifecycleEnv(t)
		err := e.users.UpdateStatusBy(e.op(e.admin), e.admin, false)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrLastAdmin), "want ErrLastAdmin, got %v", err)
		_, err = e.users.DeleteWithSummaryBy(e.op(e.admin), e.admin)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrLastAdmin), "want ErrLastAdmin, got %v", err)
		assert.True(t, e.isActive(t, e.admin))
		assert.True(t, e.alive(t, e.admin))
	})
}
