package identity

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 以 API token 認證的請求不能改動所屬帳號本人的登入材料、狀態、角色，以及本人所屬身分來源的映射規則與提供者設定。
// 每一項都對照三件事：token 對本人被拒且資料不變；token 對其他帳號照常；同一帳號以人類工作階段操作本人，
// 結果與加入本限制之前相同（成功）。

type selfEnv struct {
	*acctEnv
	groups    *UserGroupService
	src       *IdentitySourceService
	providers *OIDCProviderService
	directory uint
}

func newSelfEnv(t *testing.T) *selfEnv {
	t.Helper()
	e := newLifecycleEnv(t)
	require.NoError(t, e.db.AutoMigrate(&model.UserGroupRole{}, &model.LDAPDirectory{}, &model.GroupRoleMapping{},
		&model.GroupUserGroupMapping{}, &model.ExternalGroup{}, &model.ApproverScope{}))
	guard := NewAssignmentGuard(FullCatalog())
	e.users.SetAssignmentGuard(guard)
	e.users.SetPinAuditSink(audit.NewTxSink())
	groups := NewUserGroupService(e.db, audit.NewTxSink(), noopRevoker{})
	groups.SetAssignmentGuard(guard)
	src := NewIdentitySourceService(e.db, audit.NewTxSink())
	src.SetAssignmentGuard(guard)
	providers := newOIDCProviderServiceT(e.db, nil, testEgress(), nil, "https://bastion.example.com")
	dir := model.LDAPDirectory{Name: "dir", URL: "ldaps://dir.example", BaseDN: "dc=example,dc=com", AttrGroup: "memberOf"}
	require.NoError(t, e.db.Create(&dir).Error)
	// acctEnv 的身分提供者補上群組宣告，映射規則才不需另外確認
	require.NoError(t, e.db.Model(&model.OIDCProvider{}).Where("id = ?", e.provider).Updates(map[string]any{"groups_claim": "groups", "scopes": "openid groups"}).Error)
	return &selfEnv{acctEnv: e, groups: groups, src: src, providers: providers, directory: dir.ID}
}

func (e *selfEnv) actorOf(op Operator) GroupRoleMappingActor {
	return GroupRoleMappingActor{ID: op.UserID, Name: op.Username, IP: op.ClientIP, Principal: op.Principal}
}

func (e *selfEnv) cidrs(t *testing.T, uid uint) string {
	t.Helper()
	var u model.User
	require.NoError(t, e.db.First(&u, uid).Error)
	return u.AllowedCIDRs
}

func (e *selfEnv) exempt(t *testing.T, uid uint) bool {
	t.Helper()
	var u model.User
	require.NoError(t, e.db.First(&u, uid).Error)
	return u.InactivityExempt
}

func (e *selfEnv) group(t *testing.T, name string, roleNames []string, members ...uint) uint {
	t.Helper()
	g := model.UserGroup{Name: name}
	require.NoError(t, e.db.Create(&g).Error)
	for _, rn := range roleNames {
		require.NoError(t, e.db.Create(&model.UserGroupRole{UserGroupID: g.ID, RoleID: e.roles[rn], ScopeKind: model.ScopeKindGlobal}).Error)
	}
	for _, m := range members {
		require.NoError(t, e.db.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: m, Manual: true}).Error)
	}
	return g.ID
}

func (e *selfEnv) members(t *testing.T, gid uint) []uint {
	t.Helper()
	var ids []uint
	require.NoError(t, e.db.Table("user_group_members").Where("user_group_id = ?", gid).Order("user_id").Pluck("user_id", &ids).Error)
	return ids
}

func (e *selfEnv) groupRoles(t *testing.T, gid uint) []uint {
	t.Helper()
	var ids []uint
	require.NoError(t, e.db.Table("user_group_roles").Where("user_group_id = ?", gid).Order("role_id").Pluck("role_id", &ids).Error)
	return ids
}

func (e *selfEnv) ruleCount(t *testing.T) (roleRules, groupRules int64) {
	t.Helper()
	require.NoError(t, e.db.Model(&model.GroupRoleMapping{}).Count(&roleRules).Error)
	require.NoError(t, e.db.Model(&model.GroupUserGroupMapping{}).Count(&groupRules).Error)
	return
}

func assertSelfDenied(t *testing.T, err error) {
	t.Helper()
	assertCode(t, err, apierror.CodeAuthAPITokenSelfChangeForbidden)
}

// TestAPITokenSelfAccountOperations 帳號操作：清空或改動本人來源網段、重設本人密碼、停用本人兩步驟驗證、改為僅外部登入、
// 解除外部綁定（含解綁並停用）、替本人綁定外部身分、停用本人、刪除本人、變更本人的閒置停用豁免，皆被拒且資料不變；
// 帶相同值的更新、解除本人的鎖定、啟用中帳號的啟用、沒有兩步驟驗證時的停用成功；對其他帳號照常；人類工作階段照常。
func TestAPITokenSelfAccountOperations(t *testing.T) {
	const newPw = "N3w-Passw0rd!xyz"
	e := newSelfEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	e.withPassword(t, owner)
	require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", owner).Update("allowed_cidrs", "10.0.0.0/8").Error)
	other := e.mkUser(t, "other")
	e.withPassword(t, other)
	token := e.tokenOp(t, owner, e.roles["identity_admin"])
	require.True(t, token.ViaAPIToken())

	t.Run("清空或改動本人來源網段被拒", func(t *testing.T) {
		empty, repl := []string{}, []string{"192.0.2.0/24"}
		_, _, err := e.users.Update(token, owner, &UpdateUserRequest{AllowedCIDRs: &empty})
		assertSelfDenied(t, err)
		_, _, err = e.users.Update(token, owner, &UpdateUserRequest{AllowedCIDRs: &repl, FullName: "改名"})
		assertSelfDenied(t, err)
		assert.Equal(t, "10.0.0.0/8", e.cidrs(t, owner))
		var u model.User
		require.NoError(t, e.db.First(&u, owner).Error)
		assert.NotEqual(t, "改名", u.FullName, "被拒時同一請求的其他欄位也不寫入")
	})
	t.Run("帶相同值的更新成功", func(t *testing.T) {
		same := []string{"10.0.0.0/8"}
		_, _, err := e.users.Update(token, owner, &UpdateUserRequest{AllowedCIDRs: &same, FullName: "Owner Name"})
		require.NoError(t, err)
		var u model.User
		require.NoError(t, e.db.First(&u, owner).Error)
		assert.Equal(t, "Owner Name", u.FullName)
		assert.Equal(t, "10.0.0.0/8", u.AllowedCIDRs)
	})
	t.Run("重設本人密碼被拒", func(t *testing.T) {
		before := e.password(t, owner)
		assertSelfDenied(t, e.users.ChangePasswordBy(token, owner, newPw))
		assert.Equal(t, before, e.password(t, owner))
	})
	t.Run("停用本人兩步驟驗證被拒，沒有啟用時不是變更", func(t *testing.T) {
		e.totp(t, owner, true)
		assertSelfDenied(t, e.auth.AdminDisableMFABy(token, owner))
		assert.True(t, e.totpOn(t, owner))
		e.totp(t, owner, false)
		require.NoError(t, e.auth.AdminDisableMFABy(token, owner))
		e.totp(t, owner, true)
	})
	ident := e.addIdentity(t, owner, "owner-sub")
	t.Run("改為僅外部登入被拒", func(t *testing.T) {
		before := e.password(t, owner)
		assertSelfDenied(t, e.users.ConvertToExternalOnlyBy(token, owner))
		assert.Equal(t, before, e.password(t, owner))
	})
	t.Run("解除外部綁定與解綁並停用被拒", func(t *testing.T) {
		assertSelfDenied(t, e.users.UnbindExternalIdentityBy(token, owner, ident))
		assertSelfDenied(t, e.users.UnbindExternalIdentityAndDisableBy(token, owner, ident))
		assert.EqualValues(t, 1, e.bindings(t, owner))
		assert.True(t, e.isActive(t, owner))
	})
	t.Run("替本人綁定外部身分被拒", func(t *testing.T) {
		_, err := e.users.BindExternalIdentityBy(token, owner, e.provider, "owner-second")
		assertSelfDenied(t, err)
		assert.EqualValues(t, 1, e.bindings(t, owner))
	})
	t.Run("停用本人被拒，啟用中帳號的啟用不是變更", func(t *testing.T) {
		assertSelfDenied(t, e.users.UpdateStatusBy(token, owner, false))
		assert.True(t, e.isActive(t, owner))
		require.NoError(t, e.users.UpdateStatusBy(token, owner, true))
	})
	t.Run("刪除本人被拒", func(t *testing.T) {
		_, err := e.users.DeleteWithSummaryBy(token, owner)
		assertSelfDenied(t, err)
		assert.True(t, e.alive(t, owner))
	})
	t.Run("變更本人的閒置停用豁免被拒，相同值成功", func(t *testing.T) {
		assertSelfDenied(t, e.users.SetInactivityExemptBy(token, owner, true))
		assert.False(t, e.exempt(t, owner))
		require.NoError(t, e.users.SetInactivityExemptBy(token, owner, false))
	})
	t.Run("解除本人的鎖定成功", func(t *testing.T) {
		until := time.Now().Add(time.Hour)
		require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", owner).
			Updates(map[string]any{"locked_until": until, "failed_login_attempts": 5}).Error)
		require.NoError(t, e.users.Unlock(owner))
		var u model.User
		require.NoError(t, e.db.First(&u, owner).Error)
		assert.Nil(t, u.LockedUntil)
	})
	t.Run("對其他帳號的同類操作成功", func(t *testing.T) {
		repl := []string{"192.0.2.0/24"}
		_, _, err := e.users.Update(token, other, &UpdateUserRequest{AllowedCIDRs: &repl})
		require.NoError(t, err)
		assert.Equal(t, "192.0.2.0/24", e.cidrs(t, other))
		require.NoError(t, e.users.ChangePasswordBy(token, other, newPw))
		e.totp(t, other, true)
		require.NoError(t, e.auth.AdminDisableMFABy(token, other))
		assert.False(t, e.totpOn(t, other))
		require.NoError(t, e.users.SetInactivityExemptBy(token, other, true))
		assert.True(t, e.exempt(t, other))
		_, err = e.users.BindExternalIdentityBy(token, other, e.provider, "other-sub")
		require.NoError(t, err)
		require.NoError(t, e.users.ConvertToExternalOnlyBy(token, other))
		require.NoError(t, e.users.UpdateStatusBy(token, other, false))
		assert.False(t, e.isActive(t, other))
		_, err = e.users.DeleteWithSummaryBy(token, other)
		require.NoError(t, err)
		assert.False(t, e.alive(t, other))
	})
	t.Run("人類工作階段對本人的同類操作與修改前相同", func(t *testing.T) {
		human := e.op(owner)
		empty := []string{}
		_, _, err := e.users.Update(human, owner, &UpdateUserRequest{AllowedCIDRs: &empty})
		require.NoError(t, err)
		assert.Equal(t, "", e.cidrs(t, owner))
		require.NoError(t, e.users.ChangePasswordBy(human, owner, newPw))
		require.NoError(t, e.auth.AdminDisableMFABy(human, owner))
		assert.False(t, e.totpOn(t, owner))
		require.NoError(t, e.users.SetInactivityExemptBy(human, owner, true))
		assert.True(t, e.exempt(t, owner))
		_, err = e.users.BindExternalIdentityBy(human, owner, e.provider, "owner-second")
		require.NoError(t, err)
		require.NoError(t, e.users.UnbindExternalIdentityBy(human, owner, ident))
		require.NoError(t, e.users.ConvertToExternalOnlyBy(human, owner))
		require.NoError(t, e.users.UpdateStatusBy(human, owner, false))
		assert.False(t, e.isActive(t, owner))
		_, err = e.users.DeleteWithSummaryBy(human, owner)
		require.NoError(t, err)
		assert.False(t, e.alive(t, owner))
	})
}

// TestAPITokenSelfAccountOperationsSuperAdminToken 授權了超級管理者角色的 token 同樣不能改動所屬帳號本人。
func TestAPITokenSelfAccountOperationsSuperAdminToken(t *testing.T) {
	e := newSelfEnv(t)
	root := e.mkUser(t, "root2", "admin")
	e.withPassword(t, root)
	token := e.tokenOp(t, root, e.roles["admin"])
	assertSelfDenied(t, e.users.ChangePasswordBy(token, root, "N3w-Passw0rd!xyz"))
	assertSelfDenied(t, e.users.AddRoleBy(token, root, "auditor"))
}

// TestAPITokenSelfRoleAssignments 角色途徑：直接替本人增減角色、把本人的映射角色釘選為手動、把本人加入與移出帶角色的群組、
// 變更本人所屬群組的角色、刪除本人所屬且帶角色的群組，皆被拒且資料不變；值未變的替換、不帶角色的群組成員異動、
// 對其他帳號與本人不在其中的群組照常；人類工作階段照常。
func TestAPITokenSelfRoleAssignments(t *testing.T) {
	e := newSelfEnv(t)
	owner := e.mkUser(t, "owner", "identity_admin")
	other := e.mkUser(t, "other")
	token := e.tokenOp(t, owner, e.roles["identity_admin"])

	t.Run("直接替本人增減角色被拒", func(t *testing.T) {
		assertSelfDenied(t, e.users.AddRoleBy(token, owner, "auditor"))
		_, err := e.users.AssignRolesBy(token, owner, []string{"identity_admin", "auditor"})
		assertSelfDenied(t, err)
		_, err = e.users.AssignRolesBy(token, owner, []string{})
		assertSelfDenied(t, err)
		assert.Equal(t, []string{"identity_admin"}, e.manual(t, owner))
	})
	t.Run("帶相同角色集的替換與已持有角色的追加成功", func(t *testing.T) {
		_, err := e.users.AssignRolesBy(token, owner, []string{"identity_admin"})
		require.NoError(t, err)
		require.NoError(t, e.users.AddRoleBy(token, owner, "identity_admin"))
		assert.Equal(t, []string{"identity_admin"}, e.manual(t, owner))
	})
	t.Run("把本人的映射角色釘選為手動被拒", func(t *testing.T) {
		require.NoError(t, e.db.Create(&model.UserRole{UserID: owner, RoleID: e.roles["auditor"], Source: model.RoleSourceMapped, ScopeKind: model.ScopeKindGlobal}).Error)
		_, err := e.users.PinMappedRoleBy(token, owner, "auditor")
		assertSelfDenied(t, err)
		// 以追加把只由映射取得的角色升為並存，等同釘選
		assertSelfDenied(t, e.users.AddRoleBy(token, owner, "auditor"))
		source, _, err := model.UserRoleSourceOf(e.db, owner, e.roles["auditor"])
		require.NoError(t, err)
		assert.Equal(t, model.RoleSourceMapped, source)
	})
	withRoles := e.group(t, "with-roles", []string{"auditor"})
	noRoles := e.group(t, "no-roles", nil)
	t.Run("把本人加入帶角色的群組被拒，不帶角色的群組成功", func(t *testing.T) {
		ids := []uint{owner}
		_, err := e.groups.ReplaceMembersBy(token, withRoles, &ids, nil)
		assertSelfDenied(t, err)
		assert.Empty(t, e.members(t, withRoles))
		_, err = e.groups.ReplaceMembersBy(token, noRoles, &ids, nil)
		require.NoError(t, err)
		assert.Equal(t, []uint{owner}, e.members(t, noRoles))
	})
	memberOf := e.group(t, "member-of", []string{"auditor"}, owner, other)
	t.Run("把本人移出帶角色的群組被拒", func(t *testing.T) {
		ids := []uint{other}
		_, err := e.groups.ReplaceMembersBy(token, memberOf, &ids, nil)
		assertSelfDenied(t, err)
		assert.Equal(t, []uint{owner, other}, e.members(t, memberOf))
	})
	t.Run("變更本人所屬群組的角色被拒，相同角色集成功", func(t *testing.T) {
		_, err := e.groups.ReplaceRoleBindings(token, memberOf, GroupRoleBindingsRequest{RoleIDs: []uint{e.roles["auditor"], e.roles["user"]}})
		assertSelfDenied(t, err)
		_, err = e.groups.ReplaceRoleBindings(token, memberOf, GroupRoleBindingsRequest{RoleIDs: nil})
		assertSelfDenied(t, err)
		assert.Equal(t, []uint{e.roles["auditor"]}, e.groupRoles(t, memberOf))
		_, err = e.groups.ReplaceRoleBindings(token, memberOf, GroupRoleBindingsRequest{RoleIDs: []uint{e.roles["auditor"]}})
		require.NoError(t, err)
	})
	t.Run("刪除本人所屬且帶角色的群組被拒", func(t *testing.T) {
		_, err := e.groups.DeleteBy(token, memberOf)
		assertSelfDenied(t, err)
		var n int64
		require.NoError(t, e.db.Model(&model.UserGroup{}).Where("id = ?", memberOf).Count(&n).Error)
		assert.EqualValues(t, 1, n)
	})
	t.Run("對其他帳號與本人不在其中的群組照常", func(t *testing.T) {
		require.NoError(t, e.users.AddRoleBy(token, other, "auditor"))
		assert.Contains(t, e.manual(t, other), "auditor")
		foreign := e.group(t, "foreign", []string{"auditor"}, other)
		ids := []uint{}
		_, err := e.groups.ReplaceMembersBy(token, foreign, &ids, nil)
		require.NoError(t, err)
		_, err = e.groups.ReplaceRoleBindings(token, foreign, GroupRoleBindingsRequest{RoleIDs: []uint{e.roles["user"]}})
		require.NoError(t, err)
		_, err = e.groups.DeleteBy(token, foreign)
		require.NoError(t, err)
	})
	t.Run("人類工作階段對本人的同類操作與修改前相同", func(t *testing.T) {
		human := e.op(owner)
		require.NoError(t, e.users.AddRoleBy(human, owner, "user"))
		_, err := e.users.PinMappedRoleBy(human, owner, "auditor")
		require.NoError(t, err)
		ids := []uint{owner}
		_, err = e.groups.ReplaceMembersBy(human, withRoles, &ids, nil)
		require.NoError(t, err)
		_, err = e.groups.ReplaceRoleBindings(human, memberOf, GroupRoleBindingsRequest{RoleIDs: []uint{e.roles["auditor"], e.roles["user"]}})
		require.NoError(t, err)
		_, err = e.groups.DeleteBy(human, memberOf)
		require.NoError(t, err)
	})
}

// TestAPITokenSelfIdentitySource 身分來源：所屬帳號在該來源有外部身分時，映射規則（角色映射與使用者群組映射的建立、修改、
// 啟停、刪除）與提供者設定（建立、更新、刪除）皆被拒且資料不變；來源判準四組：目錄服務來源帳號且沒有任何映射歷史（被拒）、
// 外部身分提供者的設定重建後尚未登入（以身分域判定，被拒）、本地帳號已綁定外部身分（被拒）、本地帳號沒有任何外部身分（成功）；
// 其他來源照常；人類工作階段照常。
func TestAPITokenSelfIdentitySource(t *testing.T) {
	dirKind, provKind := model.RoleMappingChannelKindDirectory, model.RoleMappingChannelKindProvider

	t.Run("目錄服務來源帳號且沒有任何映射歷史被拒", func(t *testing.T) {
		e := newSelfEnv(t)
		owner := e.mkUser(t, "dir-owner", "identity_admin")
		require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", owner).
			Updates(map[string]any{"is_ldap": true, "provisioning_origin": model.AuthSourceLDAP}).Error)
		token := e.tokenOp(t, owner, e.roles["identity_admin"])
		g := e.group(t, "dir-g", []string{"auditor"})
		rr0, gr0 := e.ruleCount(t)
		_, err := e.src.CreateMapping(dirKind, e.directory, GroupRoleMappingInput{MatchValue: "cn=ops,dc=example,dc=com",
			Role: "auditor", RiskAcknowledged: true, Actor: e.actorOf(token)})
		assertSelfDenied(t, err)
		_, err = e.src.CreateUserGroupMapping(dirKind, e.directory, UserGroupMappingInput{MatchValue: "cn=ops,dc=example,dc=com",
			UserGroupID: g, RiskAcknowledged: true, SourceConfigAcknowledged: true, Actor: e.actorOf(token)})
		assertSelfDenied(t, err)
		rr, gr := e.ruleCount(t)
		assert.Equal(t, []int64{rr0, gr0}, []int64{rr, gr})
		// 其他來源（帳號在身分提供者沒有外部身分）照常
		_, err = e.src.CreateMapping(provKind, e.provider, GroupRoleMappingInput{MatchValue: "ops", Role: "auditor",
			RiskAcknowledged: true, Actor: e.actorOf(token)})
		require.NoError(t, err)
		// 人類工作階段照常
		_, err = e.src.CreateMapping(dirKind, e.directory, GroupRoleMappingInput{MatchValue: "cn=ops,dc=example,dc=com",
			Role: "auditor", RiskAcknowledged: true, Actor: e.actorOf(e.op(owner))})
		require.NoError(t, err)
	})

	t.Run("外部身分提供者的設定重建後尚未登入以身分域判定被拒", func(t *testing.T) {
		e := newSelfEnv(t)
		owner := e.mkUser(t, "oidc-owner", "identity_admin")
		token := e.tokenOp(t, owner, e.roles["identity_admin"])
		// 本人的外部身分仍指向已刪除的設定載體
		gone := model.OIDCProvider{Name: "gone", Issuer: "https://rebuilt.example", ClientID: "rc", Enabled: true}
		require.NoError(t, e.db.Create(&gone).Error)
		require.NoError(t, e.db.Create(&model.UserExternalIdentity{UserID: owner, ProviderID: gone.ID,
			Issuer: gone.Issuer, ClientID: gone.ClientID, Subject: "owner-sub"}).Error)
		require.NoError(t, e.db.Delete(&model.OIDCProvider{}, gone.ID).Error)

		var before int64
		require.NoError(t, e.db.Model(&model.OIDCProvider{}).Count(&before).Error)
		_, err := e.providers.Create(&OIDCProviderRequest{Name: "rebuilt", Issuer: "https://rebuilt.example", ClientID: "rc",
			ClientSecret: "s", Actor: e.actorOf(token)})
		assertSelfDenied(t, err)
		var after int64
		require.NoError(t, e.db.Model(&model.OIDCProvider{}).Count(&after).Error)
		assert.Equal(t, before, after, "設定不建立")

		// 人類工作階段重建後，token 對該來源的映射規則與設定更新、刪除皆被拒
		rebuilt, err := e.providers.Create(&OIDCProviderRequest{Name: "rebuilt", Issuer: "https://rebuilt.example", ClientID: "rc",
			ClientSecret: "s", GroupsClaim: strPtr("groups"), Scopes: "openid groups", Enabled: boolPtrSelf(true), Actor: e.actorOf(e.op(owner))})
		require.NoError(t, err)
		_, err = e.src.CreateMapping(provKind, rebuilt.ID, GroupRoleMappingInput{MatchValue: "ops", Role: "auditor",
			RiskAcknowledged: true, Actor: e.actorOf(token)})
		assertSelfDenied(t, err)
		_, err = e.providers.Update(rebuilt.ID, &OIDCProviderRequest{Name: "renamed", Actor: e.actorOf(token)})
		assertSelfDenied(t, err)
		_, err = e.providers.Update(rebuilt.ID, &OIDCProviderRequest{Enabled: boolPtrSelf(false), Actor: e.actorOf(token)})
		assertSelfDenied(t, err)
		assertSelfDenied(t, e.providers.DeleteBy(e.actorOf(token), rebuilt.ID))
		var p model.OIDCProvider
		require.NoError(t, e.db.First(&p, rebuilt.ID).Error)
		assert.Equal(t, "rebuilt", p.Name)
		assert.True(t, p.Enabled)
		// 沒有實際變更的存檔不拒絕
		_, err = e.providers.Update(rebuilt.ID, &OIDCProviderRequest{Name: "rebuilt", Actor: e.actorOf(token)})
		require.NoError(t, err)
	})

	t.Run("本地帳號已綁定外部身分被拒", func(t *testing.T) {
		e := newSelfEnv(t)
		owner := e.mkUser(t, "bound-owner", "identity_admin")
		e.addIdentity(t, owner, "bound-sub")
		token := e.tokenOp(t, owner, e.roles["identity_admin"])
		human := e.actorOf(e.op(owner))
		rule, err := e.src.CreateMapping(provKind, e.provider, GroupRoleMappingInput{MatchValue: "ops", Role: "auditor",
			RiskAcknowledged: true, Actor: human})
		require.NoError(t, err)
		g := e.group(t, "bound-g", []string{"auditor"})
		grule, err := e.src.CreateUserGroupMapping(provKind, e.provider, UserGroupMappingInput{MatchValue: "ops",
			UserGroupID: g, RiskAcknowledged: true, SourceConfigAcknowledged: true, Actor: human})
		require.NoError(t, err)
		rr0, gr0 := e.ruleCount(t)

		_, err = e.src.CreateMapping(provKind, e.provider, GroupRoleMappingInput{MatchValue: "devs", Role: "auditor",
			RiskAcknowledged: true, Actor: e.actorOf(token)})
		assertSelfDenied(t, err)
		_, err = e.src.UpdateMapping(provKind, e.provider, rule.ID, GroupRoleMappingInput{MatchValue: "ops2", Role: "auditor",
			RiskAcknowledged: true, Actor: e.actorOf(token)})
		assertSelfDenied(t, err)
		_, err = e.src.UpdateMapping(provKind, e.provider, rule.ID, GroupRoleMappingInput{MatchValue: "ops", Role: "auditor",
			Enabled: boolPtrSelf(false), RiskAcknowledged: true, Actor: e.actorOf(token)})
		assertSelfDenied(t, err)
		assertSelfDenied(t, e.src.DeleteMapping(provKind, e.provider, rule.ID, e.actorOf(token)))
		_, err = e.src.CreateUserGroupMapping(provKind, e.provider, UserGroupMappingInput{MatchValue: "devs",
			UserGroupID: g, RiskAcknowledged: true, SourceConfigAcknowledged: true, Actor: e.actorOf(token)})
		assertSelfDenied(t, err)
		_, err = e.src.UpdateUserGroupMapping(provKind, e.provider, grule.ID, UserGroupMappingInput{MatchValue: "ops",
			UserGroupID: g, Enabled: boolPtrSelf(false), RiskAcknowledged: true, SourceConfigAcknowledged: true, Actor: e.actorOf(token)})
		assertSelfDenied(t, err)
		assertSelfDenied(t, e.src.DeleteUserGroupMapping(provKind, e.provider, grule.ID, e.actorOf(token)))
		_, err = e.providers.Update(e.provider, &OIDCProviderRequest{Name: "renamed", Actor: e.actorOf(token)})
		assertSelfDenied(t, err)

		rr, gr := e.ruleCount(t)
		assert.Equal(t, []int64{rr0, gr0}, []int64{rr, gr})
		var kept model.GroupRoleMapping
		require.NoError(t, e.db.First(&kept, rule.ID).Error)
		assert.Equal(t, "ops", kept.MatchValue)
		assert.True(t, kept.Enabled)

		// 其他來源照常：另一個本人沒有外部身分的提供者
		otherP := model.OIDCProvider{Name: "other", Issuer: "https://other.example", ClientID: "oc", GroupsClaim: "groups", Scopes: "openid groups", Enabled: true}
		require.NoError(t, e.db.Create(&otherP).Error)
		_, err = e.src.CreateMapping(provKind, otherP.ID, GroupRoleMappingInput{MatchValue: "ops", Role: "auditor",
			RiskAcknowledged: true, Actor: e.actorOf(token)})
		require.NoError(t, err)
		_, err = e.providers.Update(otherP.ID, &OIDCProviderRequest{Name: "other-renamed", Actor: e.actorOf(token)})
		require.NoError(t, err)

		// 人類工作階段照常
		require.NoError(t, e.src.DeleteMapping(provKind, e.provider, rule.ID, human))
	})

	t.Run("本地帳號沒有任何外部身分成功", func(t *testing.T) {
		e := newSelfEnv(t)
		owner := e.mkUser(t, "local-owner", "identity_admin")
		token := e.tokenOp(t, owner, e.roles["identity_admin"])
		rule, err := e.src.CreateMapping(provKind, e.provider, GroupRoleMappingInput{MatchValue: "ops", Role: "auditor",
			RiskAcknowledged: true, Actor: e.actorOf(token)})
		require.NoError(t, err)
		_, err = e.src.CreateMapping(dirKind, e.directory, GroupRoleMappingInput{MatchValue: "cn=ops,dc=example,dc=com",
			Role: "auditor", RiskAcknowledged: true, Actor: e.actorOf(token)})
		require.NoError(t, err)
		require.NoError(t, e.src.DeleteMapping(provKind, e.provider, rule.ID, e.actorOf(token)))
		created, err := e.providers.Create(&OIDCProviderRequest{Name: "fresh", Issuer: "https://fresh.example", ClientID: "fc",
			ClientSecret: "s", Actor: e.actorOf(token)})
		require.NoError(t, err)
		_, err = e.providers.Update(created.ID, &OIDCProviderRequest{Name: "fresh2", Actor: e.actorOf(token)})
		require.NoError(t, err)
		require.NoError(t, e.providers.DeleteBy(e.actorOf(token), created.ID))
	})
}

func boolPtrSelf(b bool) *bool { return &b }
