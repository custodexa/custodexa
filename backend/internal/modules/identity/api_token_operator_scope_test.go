package identity

import (
	"context"
	"testing"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 帶角色限定的請求主體（API token 的形狀）經操作者關卡時，操作者的重解帶上限定、目標的重解維持完整身分。
// 這一段系統裡還沒有任何入口會建立帶限定的主體，故直接以帶限定的事實建構請求主體。

// tokenOp 帶角色限定的請求操作者。
func (e *guardEnv) tokenOp(t *testing.T, id uint, roleIDs ...uint) Operator {
	t.Helper()
	return Operator{UserID: id, Username: "op", ClientIP: "127.0.0.1", Principal: filteredPrincipalOf(t, e.db, id, roleIDs...)}
}

// TestAPITokenProtectedAccountSuperAdminWithoutAdminRoleDenied 超級管理者帳號的 token 只授權身分管理角色：
// 操作受保護帳號（超管目標）被拒；操作系統安全管理員帳號照常成功，且留痕與告警照常產生。
// 對照組：同一帳號以人類工作階段操作，行為與修改前相同（超管目標放行、安全管理員目標不產生事件）。
func TestAPITokenProtectedAccountSuperAdminWithoutAdminRoleDenied(t *testing.T) {
	const newPw = "N3w-Passw0rd!xyz"
	e := newAcctEnv(t, nil)
	root := e.mkUser(t, "root2", "admin", "identity_admin")
	superTarget := e.mkUser(t, "sa-target", "admin")
	secTarget := e.mkUser(t, "sec-target", "security_admin")
	e.withPassword(t, superTarget)
	e.withPassword(t, secTarget)
	token := e.tokenOp(t, root, e.roles["identity_admin"])

	before := e.password(t, superTarget)
	assertCode(t, e.users.ChangePasswordBy(token, superTarget, newPw), apierror.CodeAuthProtectedAccountOperation)
	assert.Equal(t, before, e.password(t, superTarget), "被拒時密碼不變")
	assertCode(t, e.users.UpdateStatusBy(token, superTarget, false), apierror.CodeAuthProtectedAccountOperation)
	_, err := e.users.DeleteWithSummaryBy(token, superTarget)
	assertCode(t, err, apierror.CodeAuthProtectedAccountOperation)

	require.NoError(t, e.users.ChangePasswordBy(token, secTarget, newPw))
	assert.EqualValues(t, 1, e.alerts(t), "安全管理員被操作的系統告警照常產生")
	assert.EqualValues(t, 1, e.acctAudits(t), "安全管理員被操作的留痕照常產生")

	// 人類工作階段：與修改前相同
	require.NoError(t, e.users.ChangePasswordBy(e.op(root), superTarget, newPw+"1"))
	require.NoError(t, e.users.ChangePasswordBy(e.op(root), secTarget, newPw+"2"))
	assert.EqualValues(t, 1, e.alerts(t), "超管以工作階段操作不產生事件")
	assert.EqualValues(t, 1, e.acctAudits(t))

	// token 授權了超級管理者角色：等同超管
	full := e.tokenOp(t, root, e.roles["admin"], e.roles["identity_admin"])
	require.NoError(t, e.users.ChangePasswordBy(full, superTarget, newPw+"3"))
}

// TestAPITokenTargetProtectedRoleNotFilteredByOperatorToken 目標的受保護角色不因操作者 token 的限定而被濾掉：
// 目標超管的角色不在操作者 token 的授權內，指派關卡仍以目標完整身分判定為受保護帳號。
func TestAPITokenTargetProtectedRoleNotFilteredByOperatorToken(t *testing.T) {
	e := newGuardEnv(t, true)
	ida := e.mkUser(t, "ida", "identity_admin")
	target := e.mkUser(t, "sa", "admin")
	token := e.tokenOp(t, ida, e.roles["identity_admin"])

	err := e.users.AddRoleBy(token, target, "auditor")
	assert.ErrorIs(t, err, ErrProtectedAccountOperation)
	assert.False(t, hasRoleName(e.manual(t, target), "auditor"))

	// 投影的目標分類同樣維持完整身分
	ops, err := NewRoleProjector(e.db, nil).AccountOps(token.Principal, target)
	require.NoError(t, err)
	assert.Equal(t, AccountOpClassSuperOnly, ops["set_password"])

	// 人類工作階段：與修改前相同
	assert.ErrorIs(t, e.users.AddRoleBy(e.op(ida), target, "auditor"), ErrProtectedAccountOperation)
}

// TestAPITokenRoleAssignDeniedWhenGrantedRolesLackCapability token 授權的角色不含角色指派能力時指派角色被拒，
// 即使本人經其他角色持有該能力（路由閘只要求帳號管理能力）。
func TestAPITokenRoleAssignDeniedWhenGrantedRolesLackCapability(t *testing.T) {
	e := newGuardEnv(t, true)
	manager := e.create(t, "acct-only", string(authz.PermUserManage))
	op := e.mkUser(t, "op", "identity_admin")
	require.NoError(t, e.db.Create(&model.UserRole{UserID: op, RoleID: manager.ID, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
	plain := e.mkUser(t, "plain")
	token := e.tokenOp(t, op, manager.ID)
	require.True(t, token.Principal.Has(authz.PermUserManage), "token 仍持有路由閘要求的帳號管理能力")
	require.False(t, token.Principal.Has(authz.PermRoleAssign))

	err := e.users.AddRoleBy(token, plain, "auditor")
	assert.ErrorIs(t, err, ErrRoleAssignmentForbidden)
	assert.False(t, hasRoleName(e.manual(t, plain), "auditor"), "被拒時沒有寫入")

	// 授權了含角色指派能力的角色即可
	require.NoError(t, e.users.AddRoleBy(e.tokenOp(t, op, e.roles["identity_admin"]), plain, "auditor"))
	// 人類工作階段：與修改前相同
	require.NoError(t, e.users.AddRoleBy(e.op(op), plain, "user"))
}

// TestRequestOperatorWithoutPrincipalDenied 由請求建構卻未帶主體的操作者被兩個關卡拒絕，不退回完整身分。
func TestRequestOperatorWithoutPrincipalDenied(t *testing.T) {
	e := newAcctEnv(t, nil)
	plain := e.mkUser(t, "plain")
	e.withPassword(t, plain)
	bare := Operator{UserID: e.admin, Username: "root", ClientIP: "127.0.0.1", Method: "PUT", Path: "/api/v1/users/x"}

	assert.ErrorIs(t, e.users.AddRoleBy(bare, plain, "auditor"), ErrRoleAssignmentForbidden)
	assertCode(t, e.users.ChangePasswordBy(bare, plain, "N3w-Passw0rd!xyz"), apierror.CodeAuthProtectedAccountOperation)
	assertCode(t, e.users.UpdateStatusBy(bare, plain, false), apierror.CodeAuthProtectedAccountOperation)

	// 主體與操作者編號不符同樣拒絕
	mismatch := bare
	mismatch.Principal = testSessionPrincipal(plain)
	assert.ErrorIs(t, e.users.AddRoleBy(mismatch, plain, "auditor"), ErrRoleAssignmentForbidden)

	// nil 不是系統操作者
	assert.ErrorIs(t, e.users.gateLifecycle(e.db, nil, plain, AccountOpDisable), ErrProtectedAccountOperation)
	// 零值操作者也不是系統操作者
	assertCode(t, e.users.UpdateStatusBy(Operator{}, plain, false), apierror.CodeAuthProtectedAccountOperation)
}

// TestInactivityAutoDisableRunsAsSystemOperator 閒置自動停用的專用入口以明確的系統操作者執行，照常停用
// 持保護角色的帳號（系統工作不經操作者關卡）。
func TestInactivityAutoDisableRunsAsSystemOperator(t *testing.T) {
	e := newAcctEnv(t, nil)
	target := e.mkUser(t, "idle-sa", "admin", "security_admin")
	require.NoError(t, e.users.UpdateStatus(target, false))
	var u model.User
	require.NoError(t, e.db.First(&u, target).Error)
	assert.False(t, u.Active, "系統工作照常停用")
	assert.Zero(t, e.alerts(t))
	assert.True(t, systemOperator().IsSystem())
	assert.False(t, Operator{}.IsSystem())
}

// TestAPITokenRoleProjectionCarriesFilter 角色清單與帳號詳情的操作者投影帶上限定：
// 超管帳號的 token 未授權超級管理者角色時，受保護角色不標為可指派、不能定義角色、帳號操作不一律放行。
func TestAPITokenRoleProjectionCarriesFilter(t *testing.T) {
	e := newGuardEnv(t, true)
	root := e.mkUser(t, "root2", "admin", "identity_admin")
	target := e.mkUser(t, "sa", "admin")
	proj := NewRoleProjector(e.db, NewAssignmentGuard(FullCatalog()))

	human, err := proj.ProjectRoles(principalOf(t, e.db, root))
	require.NoError(t, err)
	assert.True(t, human.CanDefine)
	token, err := proj.ProjectRoles(filteredPrincipalOf(t, e.db, root, e.roles["identity_admin"]))
	require.NoError(t, err)
	assert.False(t, token.CanDefine, "未授權超級管理者角色的 token 不能定義角色")
	assert.NotEqual(t, human.ByRole[e.roles["admin"]].AssignmentState, token.ByRole[e.roles["admin"]].AssignmentState, "受保護角色的可指派判定隨限定改變")

	opsHuman, err := proj.AccountOps(principalOf(t, e.db, root), target)
	require.NoError(t, err)
	assert.Equal(t, AccountOpClassAllowed, opsHuman["set_password"])
	opsToken, err := proj.AccountOps(filteredPrincipalOf(t, e.db, root, e.roles["identity_admin"]), target)
	require.NoError(t, err)
	assert.Equal(t, AccountOpClassSuperOnly, opsToken["set_password"])
}

// TestAPITokenRoleDefinitionWriteCarriesFilter 角色定義寫入的超管重驗取請求主體的事實：
// 超管帳號的 token 未授權超級管理者角色被拒；請求脈絡缺主體被拒；人類工作階段與修改前相同。
func TestAPITokenRoleDefinitionWriteCarriesFilter(t *testing.T) {
	e := newRoleDefEnv(t)
	ida := e.roles["identity_admin"]
	require.NoError(t, e.db.Create(&model.UserRole{UserID: e.admin, RoleID: ida, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
	in := func(name string) RoleInput { return RoleInput{Name: name, Permissions: []string{"asset:view"}} }

	tokenCtx := authz.ContextWithPrincipal(
		model.WithRequestCredential(context.Background(), model.RequestCredentialAPIToken),
		filteredPrincipalOf(t, e.db, e.admin, ida))
	_, err := e.svc.Create(tokenCtx, e.admin, in("via-token"))
	assert.ErrorIs(t, err, ErrRoleDefinitionForbidden)

	bareRequest := model.WithRequestCredential(context.Background(), model.RequestCredentialHumanSession)
	_, err = e.svc.Create(bareRequest, e.admin, in("bare-request"))
	assert.ErrorIs(t, err, ErrRoleDefinitionForbidden, "請求脈絡缺主體不退回完整身分")

	mismatch := authz.ContextWithPrincipal(bareRequest, testSessionPrincipal(e.mkUser(t, "other")))
	_, err = e.svc.Create(mismatch, e.admin, in("mismatch"))
	assert.ErrorIs(t, err, ErrRoleDefinitionForbidden)

	humanCtx := authz.ContextWithPrincipal(bareRequest, principalOf(t, e.db, e.admin))
	_, err = e.svc.Create(humanCtx, e.admin, in("via-session"))
	require.NoError(t, err)
	granted := authz.ContextWithPrincipal(tokenCtx, filteredPrincipalOf(t, e.db, e.admin, e.roles["admin"]))
	_, err = e.svc.Create(granted, e.admin, in("via-admin-token"))
	require.NoError(t, err, "授權了超級管理者角色的 token 可寫入")
}
