package identity

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
	"gorm.io/gorm"
)

// 映射守衛夾具：角色定義夾具上加身分來源服務與一個身分提供者。

type mappingGuardEnv struct {
	*roleDefEnv
	src      *IdentitySourceService
	users    *UserService
	provider uint
}

func newMappingGuardEnv(t *testing.T, full bool) *mappingGuardEnv {
	t.Helper()
	e := newRoleDefEnv(t)
	require.NoError(t, e.db.AutoMigrate(&model.OIDCProvider{}, &model.LDAPDirectory{}, &model.UserRoleMapping{},
		&model.UserRoleMappingRuleSupport{}, &model.AssetAuthorization{}, &model.ApproverScope{}, &model.PasswordHistory{}, &model.RefreshToken{}, &model.UserRoleMappingRuleSupport{}, &model.UserGroupMappingRuleSupport{}, &model.UserChannelObservation{}))
	var guard *AssignmentGuard
	if full {
		guard = NewAssignmentGuard(FullCatalog())
	} else {
		guard = NewAssignmentGuard(CompatCatalog())
	}
	src := NewIdentitySourceService(e.db, audit.NewTxSink())
	src.SetAssignmentGuard(guard)
	us := NewUserService(e.db, nil)
	us.SetAssignmentGuard(guard)
	us.SetPinAuditSink(audit.NewTxSink())
	p := model.OIDCProvider{Name: "idp", Issuer: "https://idp.example.com", ClientID: "c", GroupsClaim: "groups",
		Enabled: true, AdmissionMode: model.AdmissionPreboundOnly, ClientSecretEnc: "enc"}
	require.NoError(t, e.db.Create(&p).Error)
	return &mappingGuardEnv{roleDefEnv: e, src: src, users: us, provider: p.ID}
}

func (e *mappingGuardEnv) actor(id uint, name string) GroupRoleMappingActor {
	return GroupRoleMappingActor{ID: id, Name: name, IP: "10.0.0.1"}
}

func (e *mappingGuardEnv) roleRule(t *testing.T, actor GroupRoleMappingActor, match, role string) *GroupRoleMappingView {
	t.Helper()
	v, err := e.src.CreateMapping(model.RoleMappingChannelKindProvider, e.provider,
		GroupRoleMappingInput{MatchValue: match, Role: role, RiskAcknowledged: true, Actor: actor})
	require.NoError(t, err)
	return v
}

func (e *mappingGuardEnv) group(t *testing.T, name string, roleNames ...string) uint {
	t.Helper()
	g := model.UserGroup{Name: name}
	require.NoError(t, e.db.Create(&g).Error)
	for _, rn := range roleNames {
		require.NoError(t, e.db.Create(&model.UserGroupRole{UserGroupID: g.ID, RoleID: e.roles[rn], ScopeKind: model.ScopeKindGlobal}).Error)
	}
	return g.ID
}

func (e *mappingGuardEnv) groupRule(t *testing.T, actor GroupRoleMappingActor, match string, groupID uint) *model.GroupUserGroupMapping {
	t.Helper()
	r, err := e.src.CreateUserGroupMapping(model.RoleMappingChannelKindProvider, e.provider,
		UserGroupMappingInput{MatchValue: match, UserGroupID: groupID, RiskAcknowledged: true, SourceConfigAcknowledged: true, Actor: actor})
	require.NoError(t, err)
	return r
}

// ruleCounts 規則表與外部群組字典筆數（含軟刪除），用來證明被拒時零變更。
func (e *mappingGuardEnv) ruleCounts(t *testing.T) (roleRules, groupRules, groups int64) {
	t.Helper()
	require.NoError(t, e.db.Unscoped().Model(&model.GroupRoleMapping{}).Count(&roleRules).Error)
	require.NoError(t, e.db.Unscoped().Model(&model.GroupUserGroupMapping{}).Count(&groupRules).Error)
	require.NoError(t, e.db.Model(&model.ExternalGroup{}).Count(&groups).Error)
	return
}

// TestMappingDirectRoleAllowlist 直接映射目標只認無範圍內建範本（以內建鍵判定）；
// 自訂角色與範圍欄位整筆拒絕且規則表零變更。
func TestMappingDirectRoleAllowlist(t *testing.T) {
	kind := model.RoleMappingChannelKindProvider

	t.Run("六個內建鍵各建立成功", func(t *testing.T) {
		e := newMappingGuardEnv(t, true)
		for i, name := range []string{"admin", "auditor", "user", "approver", "identity_admin", "security_admin"} {
			v := e.roleRule(t, e.actor(e.admin, "root"), "grp-"+name, name)
			assert.Equal(t, name, v.Role, "第 %d 個", i)
		}
		rr, _, _ := e.ruleCounts(t)
		assert.EqualValues(t, 6, rr)
	})

	t.Run("自訂角色帶確認仍被拒且規則表零變更", func(t *testing.T) {
		e := newMappingGuardEnv(t, true)
		e.create(t, "custom", "asset:view")
		rr0, gr0, g0 := e.ruleCounts(t)
		_, err := e.src.CreateMapping(kind, e.provider,
			GroupRoleMappingInput{MatchValue: "grp", Role: "custom", RiskAcknowledged: true, Actor: e.actor(e.admin, "root")})
		assertCode(t, err, apierror.CodeMappingRoleNotDirectMappable)
		rr, gr, g := e.ruleCounts(t)
		assert.Equal(t, []int64{rr0, gr0, g0}, []int64{rr, gr, g})
	})

	t.Run("內建鍵不在 allowlist 的範本（例如日後新增的可範圍化範本）被拒且規則表零變更", func(t *testing.T) {
		e := newMappingGuardEnv(t, true)
		key := "future_scoped_template"
		role := model.Role{Name: "future-scoped", BuiltinKey: &key, DefinitionVersion: 1}
		require.NoError(t, e.db.Create(&role).Error)
		rr0, gr0, g0 := e.ruleCounts(t)
		_, err := e.src.CreateMapping(kind, e.provider,
			GroupRoleMappingInput{MatchValue: "grp", Role: "future-scoped", RiskAcknowledged: true, Actor: e.actor(e.admin, "root")})
		assertCode(t, err, apierror.CodeMappingRoleNotDirectMappable)
		rr, gr, g := e.ruleCounts(t)
		assert.Equal(t, []int64{rr0, gr0, g0}, []int64{rr, gr, g})
	})

	t.Run("兩個範圍化範本（資產管理員、授權管理員）不可直接映射，被拒且規則表零變更", func(t *testing.T) {
		e := newMappingGuardEnv(t, true)
		for _, key := range []string{model.BuiltinAssetAdmin, model.BuiltinAuthzAdmin} {
			k := key
			require.NoError(t, e.db.Create(&model.Role{Name: key, BuiltinKey: &k, DefinitionVersion: 1}).Error)
		}
		rr0, gr0, g0 := e.ruleCounts(t)
		for _, key := range []string{model.BuiltinAssetAdmin, model.BuiltinAuthzAdmin} {
			_, err := e.src.CreateMapping(kind, e.provider,
				GroupRoleMappingInput{MatchValue: "grp-" + key, Role: key, RiskAcknowledged: true, Actor: e.actor(e.admin, "root")})
			assertCode(t, err, apierror.CodeMappingRoleNotDirectMappable)
		}
		rr, gr, g := e.ruleCounts(t)
		assert.Equal(t, []int64{rr0, gr0, g0}, []int64{rr, gr, g})
	})

	t.Run("請求含 nodes 兩類規則各回範圍欄位拒絕且零變更", func(t *testing.T) {
		e := newMappingGuardEnv(t, true)
		gid := e.group(t, "g1")
		rr0, gr0, g0 := e.ruleCounts(t)
		var rin GroupRoleMappingInput
		require.NoError(t, json.Unmarshal([]byte(`{"match_value":"grp","role":"user","nodes":[1]}`), &rin))
		rin.Actor = e.actor(e.admin, "root")
		_, err := e.src.CreateMapping(kind, e.provider, rin)
		assertCode(t, err, apierror.CodeMappingScopeFieldRejected)
		var gin UserGroupMappingInput
		require.NoError(t, json.Unmarshal([]byte(`{"match_value":"grp","user_group_id":`+itoa(gid)+`,"scope_kind":"nodes"}`), &gin))
		gin.Actor = e.actor(e.admin, "root")
		_, err = e.src.CreateUserGroupMapping(kind, e.provider, gin)
		assertCode(t, err, apierror.CodeMappingScopeFieldRejected)
		// 修改既有規則帶範圍欄位同樣整筆拒絕
		v := e.roleRule(t, e.actor(e.admin, "root"), "grp2", "user")
		require.NoError(t, json.Unmarshal([]byte(`{"match_value":"grp2","role":"auditor","scope":{"kind":"nodes"}}`), &rin))
		rin.Actor = e.actor(e.admin, "root")
		_, err = e.src.UpdateMapping(kind, e.provider, v.ID, rin)
		assertCode(t, err, apierror.CodeMappingScopeFieldRejected)
		rr, gr, g := e.ruleCounts(t)
		assert.Equal(t, []int64{rr0 + 1, gr0, g0 + 1}, []int64{rr, gr, g})
	})

	t.Run("改名為 admin 的自訂角色不被當成超級管理者", func(t *testing.T) {
		e := newMappingGuardEnv(t, true)
		custom := e.create(t, "custom", "asset:view")
		require.NoError(t, e.db.Model(&model.Role{}).Where("id = ?", e.roles["admin"]).Update("name", "legacy-root").Error)
		require.NoError(t, e.db.Model(&model.Role{}).Where("id = ?", custom.ID).Update("name", "admin").Error)
		_, err := e.src.CreateMapping(kind, e.provider,
			GroupRoleMappingInput{MatchValue: "grp", Role: "admin", Actor: e.actor(e.admin, "root")})
		assertCode(t, err, apierror.CodeMappingRoleNotDirectMappable)
		// 內建超管即使改了名，仍以內建鍵判定為超管目標而要求確認
		_, err = e.src.CreateMapping(kind, e.provider,
			GroupRoleMappingInput{MatchValue: "grp", Role: "legacy-root", Actor: e.actor(e.admin, "root")})
		var ack *MappingAckRequiredError
		require.ErrorAs(t, err, &ack)
		assert.Contains(t, ack.Warnings, mappingWarningTargetsAdminRole)
	})
}

func itoa(n uint) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// ruleState 規則的可比對現況（含軟刪除標記）。
type ruleState struct {
	Match   string
	RoleID  uint
	Enabled bool
	Deleted bool
}

func (e *mappingGuardEnv) roleRuleState(t *testing.T, id uint) ruleState {
	t.Helper()
	var r model.GroupRoleMapping
	require.NoError(t, e.db.Unscoped().First(&r, id).Error)
	return ruleState{Match: r.MatchValue, RoleID: r.RoleID, Enabled: r.Enabled, Deleted: r.DeletedAt.Valid}
}

func (e *mappingGuardEnv) groupRuleState(t *testing.T, id uint) ruleState {
	t.Helper()
	var r model.GroupUserGroupMapping
	require.NoError(t, e.db.Unscoped().First(&r, id).Error)
	return ruleState{RoleID: r.UserGroupID, Enabled: r.Enabled, Deleted: r.DeletedAt.Valid}
}

func boolp(b bool) *bool { return &b }

// TestMappingProtectedTargetGuard 兩類規則的建立、改舊值、改新值、啟用、停用、刪除與釘住：
// 目標為超級管理者或系統安全管理員（或帶這兩種角色指派的使用者群組）時，非超管一律被拒；
// 風險確認欄位不改變結論；超管成功；對非保護目標，持指派能力者成功且不檢查自身權限。
func TestMappingProtectedTargetGuard(t *testing.T) {
	kind := model.RoleMappingChannelKindProvider
	denied := apierror.CodeAuthProtectedRoleAssignment

	setup := func(t *testing.T) (*mappingGuardEnv, map[string]GroupRoleMappingActor) {
		e := newMappingGuardEnv(t, true)
		e.roles["assigner"] = e.create(t, "assigner", "role:view", "role:assign").ID
		actors := map[string]GroupRoleMappingActor{
			"super":    e.actor(e.admin, "root"),
			"idadmin":  e.actor(e.mkUser(t, "ida", "identity_admin"), "ida"),
			"custom":   e.actor(e.mkUser(t, "cust", "assigner"), "cust"),
			"noassign": e.actor(e.mkUser(t, "plain", "user"), "plain"),
		}
		return e, actors
	}

	t.Run("角色規則：非超管對保護目標六種動作全拒，規則零變更", func(t *testing.T) {
		e, actors := setup(t)
		su := actors["super"]
		rAdmin := e.roleRule(t, su, "g-admin", "admin")
		rSec := e.roleRule(t, su, "g-sec", "security_admin")
		rUser := e.roleRule(t, su, "g-user", "user")
		rOff, err := e.src.CreateMapping(kind, e.provider, GroupRoleMappingInput{MatchValue: "g-off", Role: "security_admin", Enabled: boolp(false), RiskAcknowledged: true, Actor: su})
		require.NoError(t, err)
		v0 := e.version(t)
		snap := func() []ruleState {
			return []ruleState{e.roleRuleState(t, rAdmin.ID), e.roleRuleState(t, rSec.ID), e.roleRuleState(t, rUser.ID), e.roleRuleState(t, rOff.ID)}
		}
		before := snap()
		rr0, _, g0 := e.ruleCounts(t)

		for _, who := range []string{"idadmin", "custom"} {
			a := actors[who]
			for _, ack := range []bool{true, false} {
				for _, role := range []string{"admin", "security_admin"} {
					_, err := e.src.CreateMapping(kind, e.provider, GroupRoleMappingInput{MatchValue: "new-" + role, Role: role, RiskAcknowledged: ack, Actor: a})
					assertCode(t, err, denied)
				}
				// 改新值：一般規則改成保護目標
				_, err := e.src.UpdateMapping(kind, e.provider, rUser.ID, GroupRoleMappingInput{MatchValue: "g-user", Role: "admin", RiskAcknowledged: ack, Actor: a})
				assertCode(t, err, denied)
				// 改舊值：保護目標改成一般角色；只改比對值；停用；刪除；啟用
				_, err = e.src.UpdateMapping(kind, e.provider, rAdmin.ID, GroupRoleMappingInput{MatchValue: "g-admin", Role: "user", RiskAcknowledged: ack, Actor: a})
				assertCode(t, err, denied)
				_, err = e.src.UpdateMapping(kind, e.provider, rSec.ID, GroupRoleMappingInput{MatchValue: "g-sec-2", Role: "security_admin", RiskAcknowledged: ack, Actor: a})
				assertCode(t, err, denied)
				_, err = e.src.UpdateMapping(kind, e.provider, rAdmin.ID, GroupRoleMappingInput{MatchValue: "g-admin", Role: "admin", Enabled: boolp(false), RiskAcknowledged: ack, Actor: a})
				assertCode(t, err, denied)
				_, err = e.src.UpdateMapping(kind, e.provider, rOff.ID, GroupRoleMappingInput{MatchValue: "g-off", Role: "security_admin", Enabled: boolp(true), RiskAcknowledged: ack, Actor: a})
				assertCode(t, err, denied)
				assertCode(t, e.src.DeleteMapping(kind, e.provider, rSec.ID, a), denied)
			}
		}
		assert.Equal(t, before, snap(), "被拒時四條規則零變更")
		rr, _, g := e.ruleCounts(t)
		assert.Equal(t, []int64{rr0, g0}, []int64{rr, g})
		assert.Equal(t, v0, e.version(t), "被拒時權限版本不變")
	})

	t.Run("角色規則：超管同樣操作成功", func(t *testing.T) {
		e, actors := setup(t)
		su := actors["super"]
		r := e.roleRule(t, su, "g-admin", "admin")
		_, err := e.src.UpdateMapping(kind, e.provider, r.ID, GroupRoleMappingInput{MatchValue: "g-admin", Role: "security_admin", RiskAcknowledged: true, Actor: su})
		require.NoError(t, err)
		rules, err := e.src.ListMappings(kind, e.provider)
		require.NoError(t, err)
		require.Len(t, rules, 1)
		_, err = e.src.UpdateMapping(kind, e.provider, rules[0].ID, GroupRoleMappingInput{MatchValue: "g-admin", Role: "security_admin", Enabled: boolp(false), RiskAcknowledged: true, Actor: su})
		require.NoError(t, err)
		require.NoError(t, e.src.DeleteMapping(kind, e.provider, rules[0].ID, su))
	})

	t.Run("角色規則：兩種非超管對非保護目標成功且不檢查自身權限，不持指派能力者全拒", func(t *testing.T) {
		e, actors := setup(t)
		// 身分管理員範本與自訂指派角色都不持有稽核員的任何權限
		for _, who := range []string{"idadmin", "custom"} {
			a := actors[who]
			v, err := e.src.CreateMapping(kind, e.provider, GroupRoleMappingInput{MatchValue: "ok-" + who, Role: "auditor", Actor: a})
			require.NoError(t, err, who)
			v2, err := e.src.UpdateMapping(kind, e.provider, v.ID, GroupRoleMappingInput{MatchValue: "ok-" + who, Role: "user", Enabled: boolp(false), Actor: a})
			require.NoError(t, err, who)
			require.NoError(t, e.src.DeleteMapping(kind, e.provider, v2.ID, a), who)
		}
		a := actors["noassign"]
		v := e.roleRule(t, actors["super"], "g-user", "user")
		_, err := e.src.CreateMapping(kind, e.provider, GroupRoleMappingInput{MatchValue: "x", Role: "user", Actor: a})
		assertAssignForbidden(t, err)
		_, err = e.src.UpdateMapping(kind, e.provider, v.ID, GroupRoleMappingInput{MatchValue: "g-user", Role: "auditor", Actor: a})
		assertAssignForbidden(t, err)
		assertAssignForbidden(t, e.src.DeleteMapping(kind, e.provider, v.ID, a))
		// 沒有操作者主體（編號 0）fail-close
		_, err = e.src.CreateMapping(kind, e.provider, GroupRoleMappingInput{MatchValue: "x", Role: "user", Actor: GroupRoleMappingActor{}})
		assertAssignForbidden(t, err)
		assert.Equal(t, ruleState{Match: "g-user", RoleID: e.roles["user"], Enabled: true}, e.roleRuleState(t, v.ID))
	})

	t.Run("使用者群組規則：保護目標群組六種動作全拒，超管成功，一般群組放行", func(t *testing.T) {
		e, actors := setup(t)
		su := actors["super"]
		gSec := e.group(t, "g-sec", "security_admin")
		gAdm := e.group(t, "g-adm", "admin")
		gPlain := e.group(t, "g-plain")
		gOther := e.group(t, "g-other", "auditor")
		rSec := e.groupRule(t, su, "m-sec", gSec)
		rPlain := e.groupRule(t, su, "m-plain", gPlain)
		rOff, err := e.src.CreateUserGroupMapping(kind, e.provider, UserGroupMappingInput{MatchValue: "m-off", UserGroupID: gAdm, Enabled: boolp(false), RiskAcknowledged: true, SourceConfigAcknowledged: true, Actor: su})
		require.NoError(t, err)
		v0 := e.version(t)
		before := []ruleState{e.groupRuleState(t, rSec.ID), e.groupRuleState(t, rPlain.ID), e.groupRuleState(t, rOff.ID)}
		_, gr0, _ := e.ruleCounts(t)

		for _, who := range []string{"idadmin", "custom"} {
			a := actors[who]
			for _, ack := range []bool{true, false} {
				in := func(match string, gid uint, en *bool) UserGroupMappingInput {
					return UserGroupMappingInput{MatchValue: match, UserGroupID: gid, Enabled: en, RiskAcknowledged: ack, SourceConfigAcknowledged: ack, Actor: a}
				}
				_, err := e.src.CreateUserGroupMapping(kind, e.provider, in("new-sec", gSec, nil))
				assertCode(t, err, denied)
				_, err = e.src.CreateUserGroupMapping(kind, e.provider, in("new-adm", gAdm, nil))
				assertCode(t, err, denied)
				// 改新值：一般規則改指保護群組
				_, err = e.src.UpdateUserGroupMapping(kind, e.provider, rPlain.ID, in("m-plain", gSec, nil))
				assertCode(t, err, denied)
				// 改舊值：保護群組規則改指一般群組；只改比對值；停用；啟用；刪除
				_, err = e.src.UpdateUserGroupMapping(kind, e.provider, rSec.ID, in("m-sec", gPlain, nil))
				assertCode(t, err, denied)
				_, err = e.src.UpdateUserGroupMapping(kind, e.provider, rSec.ID, in("m-sec-2", gSec, nil))
				assertCode(t, err, denied)
				_, err = e.src.UpdateUserGroupMapping(kind, e.provider, rSec.ID, in("m-sec", gSec, boolp(false)))
				assertCode(t, err, denied)
				_, err = e.src.UpdateUserGroupMapping(kind, e.provider, rOff.ID, in("m-off", gAdm, boolp(true)))
				assertCode(t, err, denied)
				assertCode(t, e.src.DeleteUserGroupMapping(kind, e.provider, rSec.ID, a), denied)
			}
		}
		assert.Equal(t, before, []ruleState{e.groupRuleState(t, rSec.ID), e.groupRuleState(t, rPlain.ID), e.groupRuleState(t, rOff.ID)})
		_, gr, _ := e.ruleCounts(t)
		assert.Equal(t, gr0, gr)
		assert.Equal(t, v0, e.version(t))

		// 兩種非超管對一般群組（含帶一般角色的群組）成功
		for _, who := range []string{"idadmin", "custom"} {
			a := actors[who]
			r, err := e.src.CreateUserGroupMapping(kind, e.provider, UserGroupMappingInput{MatchValue: "ok-" + who, UserGroupID: gOther, RiskAcknowledged: true, SourceConfigAcknowledged: true, Actor: a})
			require.NoError(t, err, who)
			r2, err := e.src.UpdateUserGroupMapping(kind, e.provider, r.ID, UserGroupMappingInput{MatchValue: "ok-" + who, UserGroupID: gPlain, Enabled: boolp(false), RiskAcknowledged: true, SourceConfigAcknowledged: true, Actor: a})
			require.NoError(t, err, who)
			require.NoError(t, e.src.DeleteUserGroupMapping(kind, e.provider, r2.ID, a), who)
		}
		// 不持指派能力者對一般群組也被拒
		_, err = e.src.CreateUserGroupMapping(kind, e.provider, UserGroupMappingInput{MatchValue: "x", UserGroupID: gPlain, RiskAcknowledged: true, SourceConfigAcknowledged: true, Actor: actors["noassign"]})
		assertAssignForbidden(t, err)

		// 超管對保護群組六種動作成功
		_, err = e.src.UpdateUserGroupMapping(kind, e.provider, rSec.ID, UserGroupMappingInput{MatchValue: "m-sec", UserGroupID: gAdm, RiskAcknowledged: true, SourceConfigAcknowledged: true, Actor: su})
		require.NoError(t, err)
		rules, err := e.src.ListUserGroupMappings(kind, e.provider)
		require.NoError(t, err)
		var secRule uint
		for _, r := range rules {
			if r.MatchValue == "m-sec" {
				secRule = r.ID
			}
		}
		require.NotZero(t, secRule)
		_, err = e.src.UpdateUserGroupMapping(kind, e.provider, secRule, UserGroupMappingInput{MatchValue: "m-sec", UserGroupID: gAdm, Enabled: boolp(false), RiskAcknowledged: true, SourceConfigAcknowledged: true, Actor: su})
		require.NoError(t, err)
		require.NoError(t, e.src.DeleteUserGroupMapping(kind, e.provider, secRule, su))
	})

	// 釘住：把外部群組賦予的角色固定為管理者指派。
	mapped := func(t *testing.T, e *mappingGuardEnv, name string, roleName string) uint {
		uid := e.mkUser(t, name)
		require.NoError(t, e.db.Create(&model.UserRole{UserID: uid, RoleID: e.roles[roleName], Source: model.RoleSourceMapped, ScopeKind: model.ScopeKindGlobal}).Error)
		return uid
	}
	srcOf := func(t *testing.T, e *mappingGuardEnv, uid uint, roleName string) string {
		s, _, err := model.UserRoleSourceOf(e.db, uid, e.roles[roleName])
		require.NoError(t, err)
		return s
	}
	pinAudits := func(t *testing.T, e *mappingGuardEnv) int64 {
		var n int64
		require.NoError(t, e.db.Model(&model.AuditLog{}).Where("details LIKE ?", "%\"role_mapping_pin\"%").Count(&n).Error)
		return n
	}

	t.Run("釘住：非超管釘住保護角色被拒且仍為 mapped，超管成功", func(t *testing.T) {
		e, actors := setup(t)
		for _, who := range []string{"idadmin", "custom"} {
			op := Operator{UserID: actors[who].ID, Username: who}
			for _, role := range []string{"admin", "security_admin"} {
				victim := mapped(t, e, "v-"+who+"-"+role, role)
				v0 := e.version(t)
				_, err := e.users.PinMappedRoleBy(op, victim, role)
				if role == "admin" {
					// 持有超級管理者身分的帳號本身即為受保護對象，先於角色判定
					assertCode(t, err, apierror.CodeAuthProtectedAccountOperation)
				} else {
					assertCode(t, err, denied)
				}
				assert.Equal(t, model.RoleSourceMapped, srcOf(t, e, victim, role))
				assert.Equal(t, v0, e.version(t))
			}
		}
		assert.Zero(t, pinAudits(t, e))
		victim := mapped(t, e, "v-super", "security_admin")
		_, err := e.users.PinMappedRoleBy(Operator{UserID: e.admin, Username: "root"}, victim, "security_admin")
		require.NoError(t, err)
		assert.Equal(t, model.RoleSourceBoth, srcOf(t, e, victim, "security_admin"))
		assert.EqualValues(t, 1, pinAudits(t, e))
	})

	t.Run("釘住：兩種持指派權限者釘住非保護角色成功各留一列審計且世代不變", func(t *testing.T) {
		e, actors := setup(t)
		for _, who := range []string{"idadmin", "custom"} {
			victim := mapped(t, e, "v-"+who, "auditor")
			epoch0 := e.epoch(t, victim)
			_, err := e.users.PinMappedRoleBy(Operator{UserID: actors[who].ID, Username: who, ClientIP: "10.0.0.1"}, victim, "auditor")
			require.NoError(t, err, who)
			assert.Equal(t, model.RoleSourceBoth, srcOf(t, e, victim, "auditor"))
			assert.Equal(t, epoch0, e.epoch(t, victim), "釘住不推進憑證世代")
		}
		assert.EqualValues(t, 2, pinAudits(t, e))
		// 已是 both 的重複釘住是 no-op，不再留列
		victim := mapped(t, e, "v-again", "auditor")
		op := Operator{UserID: e.admin, Username: "root"}
		_, err := e.users.PinMappedRoleBy(op, victim, "auditor")
		require.NoError(t, err)
		_, err = e.users.PinMappedRoleBy(op, victim, "auditor")
		require.NoError(t, err)
		assert.EqualValues(t, 3, pinAudits(t, e))
		// 不持指派能力者被拒；對超管帳號的釘住由非超管發起被拒
		v2 := mapped(t, e, "v-noassign", "auditor")
		_, err = e.users.PinMappedRoleBy(Operator{UserID: actors["noassign"].ID, Username: "plain"}, v2, "auditor")
		assertAssignForbidden(t, err)
		assert.Equal(t, model.RoleSourceMapped, srcOf(t, e, v2, "auditor"))
		_, err = e.users.PinMappedRoleBy(Operator{UserID: actors["idadmin"].ID, Username: "ida"}, e.admin, "auditor")
		assertCode(t, err, apierror.CodeAuthProtectedAccountOperation)
	})

	t.Run("釘住：審計寫入失敗時來源維持 mapped", func(t *testing.T) {
		e, actors := setup(t)
		e.users.SetPinAuditSink(failingPinSink{})
		victim := mapped(t, e, "v-fail", "auditor")
		_, err := e.users.PinMappedRoleBy(Operator{UserID: actors["idadmin"].ID, Username: "ida"}, victim, "auditor")
		require.Error(t, err)
		assert.Equal(t, model.RoleSourceMapped, srcOf(t, e, victim, "auditor"))
		// 未注入審計落地面時 fail-close
		e.users.SetPinAuditSink(nil)
		_, err = e.users.PinMappedRoleBy(Operator{UserID: e.admin, Username: "root"}, victim, "auditor")
		assert.ErrorIs(t, err, ErrPinAuditUnavailable)
		assert.Equal(t, model.RoleSourceMapped, srcOf(t, e, victim, "auditor"))
	})
}

type failingPinSink struct{}

func (failingPinSink) WriteInTx(*gorm.DB, port.AuditEvent) error {
	return errors.New("注入的審計寫入失敗")
}

func (e *mappingGuardEnv) version(t *testing.T) int64 {
	t.Helper()
	v, err := authz.CurrentVersion(e.db)
	require.NoError(t, err)
	return v
}

func (e *mappingGuardEnv) epoch(t *testing.T, uid uint) int {
	t.Helper()
	var u model.User
	require.NoError(t, e.db.First(&u, uid).Error)
	return u.CredentialEpoch
}
