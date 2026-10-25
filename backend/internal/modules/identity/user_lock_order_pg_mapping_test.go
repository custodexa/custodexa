package identity

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 映射規則寫入的操作者同時是受影響使用者時的鎖序交錯（正式 created_by 外鍵）。
// 同一個停點名稱會被兩個連線池的交易各走一次，所以停點以「名稱@連線池」分派。

// installAppHooks 以「停點名稱@連線池名稱」分派的通用停點；只有 filter 回 true 的呼叫才停。
// 回傳的函式放行全部停點並解除掛點。
func (e *lockOrderEnv) installAppHooks(stops map[string]*lockStop, filter func(point string, ids []uint) bool) func() {
	dispatch := func(point string, tx *gorm.DB, ids ...uint) {
		if tx == nil || !filter(point, ids) {
			return
		}
		var app string
		if err := tx.Raw("SELECT current_setting('application_name')").Scan(&app).Error; err != nil {
			return
		}
		if st := stops[point+"@"+app]; st != nil {
			st.hit(tx)
		}
	}
	restoreIdentity := SetLockOrderHookForTest(dispatch)
	restoreAuthz := authz.SetLockOrderHookForTest(dispatch)
	return func() {
		for _, st := range stops {
			st.open()
		}
		restoreAuthz()
		restoreIdentity()
	}
}

// ruleUpdateAudit 某來源的映射規則更新審計（角色映射與群組映射各有一種事件，details 帶 source_id）。
func (e *lockOrderEnv) ruleUpdateAudit(t *testing.T, sourceID uint) int64 {
	t.Helper()
	return e.scalar(t, `SELECT count(*) FROM audit_logs WHERE action = ? AND details::jsonb->>'source_id' = ? AND details::jsonb->>'event' IN (?, ?)`,
		string(model.ActionUpdate), fmt.Sprint(sourceID), MappingAuditEventUpdate, UserGroupMappingEventUpdate)
}

// supportRevokeAudit 某使用者在某通道因規則被撤銷而留下的撤權審計。
func (e *lockOrderEnv) supportRevokeAudit(t *testing.T, userID uint, channel string) int64 {
	t.Helper()
	return e.scalar(t, `SELECT count(*) FROM audit_logs WHERE resource = ? AND resource_id = ? AND action = ? AND error_msg = ? AND details::jsonb->>'channel' = ?`,
		string(model.ResourceUser), userID, string(model.ActionUpdate), MappingRuleRevokedEvent, channel)
}

// mappedRoleFixture 補齊角色映射的事實列、mapped 角色投影與一枚有效 refresh token，
// 使正式的角色撤銷分支（版本推進、mapped 角色移除、世代與 refresh 撤銷）會真的執行。
func (e *lockOrderEnv) mappedRoleFixture(t *testing.T, userID, roleID uint, channels ...string) {
	t.Helper()
	require.NoError(t, e.dbA.Create(&model.UserRole{UserID: userID, RoleID: roleID, Source: model.RoleSourceMapped, ScopeKind: model.ScopeKindGlobal}).Error)
	for _, ch := range channels {
		require.NoError(t, e.dbA.Create(&model.UserRoleMapping{UserID: userID, RoleID: roleID, Channel: ch, MatchedAt: time.Now()}).Error)
	}
	e.refreshFixture(t, userID)
}

func (e *lockOrderEnv) refreshFixture(t *testing.T, userID uint) {
	t.Helper()
	now := time.Now()
	require.NoError(t, e.dbA.Create(&model.RefreshToken{UserID: userID, TokenHash: fmt.Sprintf("lo-refresh-%d-%d", userID, now.UnixNano()), SessionStartedAt: now, ExpiresAt: now.Add(time.Hour), LastUsedAt: now}).Error)
}

func (e *lockOrderEnv) newAdmin(t *testing.T, name string) uint {
	t.Helper()
	u := model.User{Username: name, Active: true, Kind: model.KindHuman}
	require.NoError(t, e.dbA.Create(&u).Error)
	var adminRole model.Role
	require.NoError(t, e.dbA.Where("name = ?", model.RoleAdmin).First(&adminRole).Error)
	require.NoError(t, e.dbA.Create(&model.UserRole{UserID: u.ID, RoleID: adminRole.ID, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
	return u.ID
}

func (e *lockOrderEnv) mappingProvider(t *testing.T, name string) model.OIDCProvider {
	t.Helper()
	p := model.OIDCProvider{Name: name, Issuer: "https://id.example.test/" + name, ClientID: "client", Scopes: "openid groups", GroupsClaim: "groups", Enabled: true, AdmissionMode: model.AdmissionPreboundOnly, AdmissionRules: "{}"}
	require.NoError(t, e.dbA.Create(&p).Error)
	return p
}

func (e *lockOrderEnv) mappingService(db *gorm.DB) *IdentitySourceService {
	svc := NewIdentitySourceService(db, audit.NewTxSink())
	svc.SetAssignmentGuard(NewAssignmentGuard(FullCatalog()))
	return svc
}

// runMappingCreator：換規則的操作者 U 同時是被換掉那條規則所支持的使用者（U 要被撤銷），
// 新規則 INSERT 寫 created_by＝U（外鍵取 U 列的 KEY SHARE）；帳號寫入（停用 U）持 U 的憑證鎖。
// 映射先行（停在新規則 INSERT 之後）修後是 nowait；帳號寫入先行（停在取得 U 的憑證鎖之後）修後是 wait。
func runMappingCreator(t *testing.T, sub string) {
	eachOrder(t, "mapping", "write", func(t *testing.T, order string) {
		isRole := sub == "role"
		fk := "fk_group_role_mappings_created_by_user"
		if !isRole {
			fk = "fk_group_user_group_mappings_creator"
		}
		e := newLockOrderEnv(t, fk)
		u := e.newAdmin(t, "lo-n1-admin-"+sub)
		p := e.mappingProvider(t, "lo-n1-"+sub)
		channel := model.RoleMappingChannel(model.RoleMappingChannelKindProvider, p.ID)
		ext := model.ExternalGroup{OIDCProviderID: &p.ID, MatchValue: "old"}
		require.NoError(t, e.dbA.Create(&ext).Error)
		var userRole model.Role
		require.NoError(t, e.dbA.Where("name = ?", model.RoleUser).First(&userRole).Error)
		var oldRuleID uint
		var g1, g2 model.UserGroup
		if isRole {
			rule := model.GroupRoleMapping{OIDCProviderID: &p.ID, ExternalGroupID: ext.ID, MatchValue: "old", RoleID: userRole.ID, Enabled: true, CreatedBy: e.root}
			require.NoError(t, e.dbA.Create(&rule).Error)
			oldRuleID = rule.ID
			require.NoError(t, e.dbA.Create(&model.UserRoleMappingRuleSupport{UserID: u, RoleID: userRole.ID, Channel: channel, RuleID: rule.ID}).Error)
			e.mappedRoleFixture(t, u, userRole.ID, channel)
		} else {
			g1, g2 = model.UserGroup{Name: "lo-n1-g1"}, model.UserGroup{Name: "lo-n1-g2"}
			require.NoError(t, e.dbA.Create(&g1).Error)
			require.NoError(t, e.dbA.Create(&g2).Error)
			rule := model.GroupUserGroupMapping{OIDCProviderID: &p.ID, ExternalGroupID: ext.ID, UserGroupID: g1.ID, Enabled: true, CreatedBy: e.root}
			require.NoError(t, e.dbA.Create(&rule).Error)
			oldRuleID = rule.ID
			require.NoError(t, e.dbA.Create(&model.UserGroupMappingRuleSupport{UserID: u, UserGroupID: g1.ID, Channel: channel, RuleID: rule.ID}).Error)
			require.NoError(t, e.dbA.Exec("INSERT INTO user_group_members (user_group_id, user_id, manual) VALUES (?, ?, false)", g1.ID, u).Error)
			e.refreshFixture(t, u)
		}
		// fixture 自檢：U 是被撤銷規則的支持者，也是操作者（created_by 外鍵指向 U）
		var supp int64
		require.NoError(t, e.obs.Raw("SELECT (SELECT count(*) FROM user_role_mapping_rule_supports WHERE user_id = ? AND rule_id = ?) + (SELECT count(*) FROM user_group_mapping_rule_supports WHERE user_id = ? AND rule_id = ?)", u, oldRuleID, u, oldRuleID).Scan(&supp).Error)
		require.EqualValues(t, 1, supp)

		mappingPoint := "mapping_role_after_rule_insert"
		if !isRole {
			mappingPoint = "mapping_group_after_rule_insert"
		}
		mapStop, writeStop := newLockStop(), newLockStop()
		release := e.installAppHooks(map[string]*lockStop{
			mappingPoint + "@" + e.appA:               mapStop,
			"user_credential_lock_acquired@" + e.appB: writeStop,
		}, func(point string, ids []uint) bool { return len(ids) > 0 && ids[0] == u })
		defer release()

		rules := "group_role_mappings"
		if !isRole {
			rules = "group_user_group_mappings"
		}
		snap := func() map[string]int64 {
			m := map[string]int64{
				"authz_version": e.scalar(t, "SELECT version FROM authz_state WHERE id = 1"),
				"new_rule":      e.scalar(t, "SELECT count(*) FROM "+rules+" WHERE deleted_at IS NULL AND created_by = ?", u),
				"old_rule_live": e.scalar(t, "SELECT count(*) FROM "+rules+" WHERE id = ? AND deleted_at IS NULL", oldRuleID),
				"supports": e.scalar(t, "SELECT (SELECT count(*) FROM user_role_mapping_rule_supports WHERE user_id = ? AND rule_id = ?) + (SELECT count(*) FROM user_group_mapping_rule_supports WHERE user_id = ? AND rule_id = ?)",
					u, oldRuleID, u, oldRuleID),
				"u_active":          e.scalar(t, "SELECT count(*) FROM users WHERE id = ? AND active", u),
				"u_epoch":           e.scalar(t, "SELECT credential_epoch FROM users WHERE id = ?", u),
				"refresh_active":    e.scalar(t, "SELECT count(*) FROM refresh_tokens WHERE user_id = ? AND revoked_at IS NULL", u),
				"audit_rule_update": e.ruleUpdateAudit(t, p.ID),
				"audit_revoke":      e.supportRevokeAudit(t, u, channel),
				"audit_user_update": e.auditCount(t, model.ResourceUser, u, model.ActionUpdate),
				"audit_role_revoke": e.auditCount(t, model.ResourceUserRole, u, model.ActionRevoke),
			}
			if isRole {
				m["mapping_fact"] = e.scalar(t, "SELECT count(*) FROM user_role_mappings WHERE user_id = ? AND channel = ?", u, channel)
				m["mapped_role"] = e.scalar(t, "SELECT count(*) FROM user_roles WHERE user_id = ? AND role_id = ? AND source = ?", u, userRole.ID, model.RoleSourceMapped)
			}
			if !isRole {
				m["u_in_old_group"] = e.scalar(t, "SELECT count(*) FROM user_group_members WHERE user_id = ? AND user_group_id = ?", u, g1.ID)
			}
			return m
		}
		want := func(base map[string]int64, c map[string]bool, _ string) map[string]int64 {
			m, w := b2i(c["mapping"]), b2i(c["write"])
			out := map[string]int64{
				"authz_version": base["authz_version"] + m + w,
				"new_rule":      base["new_rule"] + m,
				"old_rule_live": base["old_rule_live"] - m,
				"supports":      base["supports"] - m,
				"u_active":      base["u_active"] - w,
				"u_epoch":       base["u_epoch"] + w,
				// 任一方提交都會撤銷該使用者全部 refresh token；映射撤銷另寫規則更新與撤權審計
				"refresh_active":    base["refresh_active"] - b2i(m+w > 0),
				"audit_rule_update": base["audit_rule_update"] + m,
				"audit_revoke":      base["audit_revoke"] + m,
				"audit_user_update": base["audit_user_update"] + m,
				"audit_role_revoke": base["audit_role_revoke"],
			}
			if isRole {
				// 正式角色撤銷分支：映射事實移除並推進版本一次、mapped 角色投影收回（寫一筆角色撤銷審計）、世代推進
				out["authz_version"] += m
				out["u_epoch"] += m
				out["mapping_fact"] = base["mapping_fact"] - m
				out["mapped_role"] = base["mapped_role"] - m
				out["audit_role_revoke"] += m
			}
			if !isRole {
				// 撤銷支持列同時移出由映射帶入的成員，並推進世代
				out["u_in_old_group"] = base["u_in_old_group"] - m
				out["u_epoch"] += m
				out["authz_version"] += m
			}
			return out
		}
		e.runCycle(t, cycleSpec{
			subcase: "mapping_creator_fk_vs_user_write/" + sub,
			shared:  fmt.Sprintf("users:%d", u),
			a: lockActor{name: "mapping", stop: mapStop, app: e.appA, start: func() error {
				svc := e.mappingService(e.dbA)
				actor := GroupRoleMappingActor{ID: u, Name: "lo-n1-admin", IP: "127.0.0.1"}
				if isRole {
					_, err := svc.UpdateMapping(model.RoleMappingChannelKindProvider, p.ID, oldRuleID, GroupRoleMappingInput{MatchValue: "new", Role: model.RoleUser, Actor: actor})
					return err
				}
				_, err := svc.UpdateUserGroupMapping(model.RoleMappingChannelKindProvider, p.ID, oldRuleID, UserGroupMappingInput{MatchValue: "new", UserGroupID: g2.ID, Actor: actor})
				return err
			}},
			b: lockActor{name: "write", stop: writeStop, app: e.appB, start: func() error {
				return NewUserService(e.dbB, nil).UpdateStatus(u, false)
			}},
			plans: map[string]cyclePlan{
				"mapping": {class: "nowait"},
				"write":   {class: "wait", kind: "advisory", advisoryUser: u},
			},
			snap: snap, want: want,
		}, order)
	})
}

// runMappingReplacementSameCreator：兩個不同來源的換規則，操作者同為 U，且 U 也是兩邊被撤銷規則的支持者。
// 兩個新規則的 created_by 外鍵各自對 U 列取 KEY SHARE（互相相容），之後兩邊都要取 U 的憑證鎖；
// 候選補丁在憑證鎖之後對 U 列升級成排他鎖，兩邊各持對方要升級的 KEY SHARE 而成環。
// 先行停在新規則 INSERT 之後（修後 nowait）或停在取得 U 的憑證鎖之後（修後 wait）。
func runMappingReplacementSameCreator(t *testing.T) {
	for _, label := range []string{"first_insert", "first_ua"} {
		label := label
		t.Run(label+"_released_first", func(t *testing.T) {
			e := newLockOrderEnv(t, "fk_group_role_mappings_created_by_user")
			u := e.newAdmin(t, "lo-n1p-admin")
			var userRole model.Role
			require.NoError(t, e.dbA.Where("name = ?", model.RoleUser).First(&userRole).Error)
			type src struct {
				p    model.OIDCProvider
				rule uint
			}
			mk := func(name string) src {
				p := e.mappingProvider(t, name)
				ext := model.ExternalGroup{OIDCProviderID: &p.ID, MatchValue: "old"}
				require.NoError(t, e.dbA.Create(&ext).Error)
				rule := model.GroupRoleMapping{OIDCProviderID: &p.ID, ExternalGroupID: ext.ID, MatchValue: "old", RoleID: userRole.ID, Enabled: true, CreatedBy: e.root}
				require.NoError(t, e.dbA.Create(&rule).Error)
				require.NoError(t, e.dbA.Create(&model.UserRoleMappingRuleSupport{UserID: u, RoleID: userRole.ID, Channel: model.RoleMappingChannel(model.RoleMappingChannelKindProvider, p.ID), RuleID: rule.ID}).Error)
				return src{p: p, rule: rule.ID}
			}
			s1, s2 := mk("lo-n1p-one"), mk("lo-n1p-two")
			ch := func(s src) string { return model.RoleMappingChannel(model.RoleMappingChannelKindProvider, s.p.ID) }
			e.mappedRoleFixture(t, u, userRole.ID, ch(s1), ch(s2))

			firstStop, secondStop := newLockStop(), newLockStop()
			firstPoint := "mapping_role_after_rule_insert"
			if label == "first_ua" {
				firstPoint = "upfront_after_user"
			}
			release := e.installAppHooks(map[string]*lockStop{
				firstPoint + "@" + e.appA:                  firstStop,
				"mapping_role_after_rule_insert@" + e.appB: secondStop,
			}, func(point string, ids []uint) bool { return len(ids) > 0 && ids[0] == u })
			defer release()

			per := func(m map[string]int64, tag string, s src) {
				m["new_"+tag] = e.scalar(t, "SELECT count(*) FROM group_role_mappings WHERE oidc_provider_id = ? AND created_by = ? AND deleted_at IS NULL", s.p.ID, u)
				m["old_total_"+tag] = e.scalar(t, "SELECT count(*) FROM group_role_mappings WHERE id = ?", s.rule)
				m["old_live_"+tag] = e.scalar(t, "SELECT count(*) FROM group_role_mappings WHERE id = ? AND deleted_at IS NULL", s.rule)
				m["old_soft_"+tag] = e.scalar(t, "SELECT count(*) FROM group_role_mappings WHERE id = ? AND deleted_at IS NOT NULL", s.rule)
				m["supports_"+tag] = e.scalar(t, "SELECT count(*) FROM user_role_mapping_rule_supports WHERE user_id = ? AND rule_id = ?", u, s.rule)
				m["fact_"+tag] = e.scalar(t, "SELECT count(*) FROM user_role_mappings WHERE user_id = ? AND channel = ?", u, ch(s))
				m["audit_update_"+tag] = e.ruleUpdateAudit(t, s.p.ID)
				m["audit_revoke_"+tag] = e.supportRevokeAudit(t, u, ch(s))
			}
			snap := func() map[string]int64 {
				m := map[string]int64{
					"authz_version":     e.scalar(t, "SELECT version FROM authz_state WHERE id = 1"),
					"u_epoch":           e.scalar(t, "SELECT credential_epoch FROM users WHERE id = ?", u),
					"mapped_role":       e.scalar(t, "SELECT count(*) FROM user_roles WHERE user_id = ? AND role_id = ? AND source = ?", u, userRole.ID, model.RoleSourceMapped),
					"refresh_active":    e.scalar(t, "SELECT count(*) FROM refresh_tokens WHERE user_id = ? AND revoked_at IS NULL", u),
					"audit_role_revoke": e.auditCount(t, model.ResourceUserRole, u, model.ActionRevoke),
				}
				per(m, "s1", s1)
				per(m, "s2", s2)
				return m
			}
			want := func(base map[string]int64, c map[string]bool, _ string) map[string]int64 {
				// s1 由 label 一方換規則，s2 由 second 一方換規則
				m1, m2 := b2i(c[label]), b2i(c["second"])
				n := m1 + m2
				both := b2i(n == 2)
				out := map[string]int64{
					// 每個提交者：規則更新推進一次，撤銷自己通道的映射事實再推進一次
					"authz_version": base["authz_version"] + 2*n,
					// 兩條通道都映射同一角色：只有最後一條通道被撤時角色才失去，之後才推進世代、收回投影、撤銷 refresh
					"u_epoch":           base["u_epoch"] + both,
					"mapped_role":       base["mapped_role"] - both,
					"refresh_active":    base["refresh_active"] - both,
					"audit_role_revoke": base["audit_role_revoke"] + both,
				}
				for tag, mm := range map[string]int64{"s1": m1, "s2": m2} {
					out["new_"+tag] = base["new_"+tag] + mm
					out["old_total_"+tag] = base["old_total_"+tag]
					out["old_live_"+tag] = base["old_live_"+tag] - mm
					out["old_soft_"+tag] = base["old_soft_"+tag] + mm
					out["supports_"+tag] = base["supports_"+tag] - mm
					out["fact_"+tag] = base["fact_"+tag] - mm
					out["audit_update_"+tag] = base["audit_update_"+tag] + mm
					out["audit_revoke_"+tag] = base["audit_revoke_"+tag] + mm
				}
				return out
			}
			replace := func(db *gorm.DB, s src) func() error {
				return func() error {
					_, err := e.mappingService(db).UpdateMapping(model.RoleMappingChannelKindProvider, s.p.ID, s.rule,
						GroupRoleMappingInput{MatchValue: "new", Role: model.RoleUser, Actor: GroupRoleMappingActor{ID: u, Name: "lo-n1p-admin", IP: "127.0.0.1"}})
					return err
				}
			}
			e.runCycle(t, cycleSpec{
				subcase: "mapping_replacement_same_creator",
				shared:  fmt.Sprintf("users:%d", u),
				a:       lockActor{name: label, stop: firstStop, app: e.appA, start: replace(e.dbA, s1)},
				b:       lockActor{name: "second", stop: secondStop, app: e.appB, start: replace(e.dbB, s2)},
				plans: map[string]cyclePlan{
					"first_insert": {class: "nowait"},
					"first_ua":     {class: "wait", kind: "advisory", advisoryUser: u},
					"second":       {class: "wait", kind: "advisory", advisoryUser: u},
				},
				snap: snap, want: want,
			}, label+"_released_first")
		})
	}
}

// runTokenOwnerVsSortedSubjects：agent A 的編號小於其擁有者 O。簽 token 先取 O（憑證鎖與列鎖）再取 A；
// 批次授權守衛以 id 升冪鎖 [A, O]，兩邊取同兩列的順序相反。
// 簽 token 先行停在取得 O 之後、尚未取 A；守衛先行停在鎖完兩列之後。另一方以 pg_locks 正向等待證據判定。
func runTokenOwnerVsSortedSubjects(t *testing.T) {
	eachOrder(t, "token", "guard", func(t *testing.T, order string) {
		e := newLockOrderEnv(t)
		a := model.User{Username: "lo-n2-agent", Active: true, Kind: model.KindAgent, OwnerUserID: &e.owner}
		require.NoError(t, e.dbA.Create(&a).Error)
		o := model.User{Username: "lo-n2-owner", Active: true, Kind: model.KindHuman}
		require.NoError(t, e.dbA.Create(&o).Error)
		require.NoError(t, e.dbA.Model(&model.User{}).Where("id = ?", a.ID).Update("owner_user_id", o.ID).Error)
		// fixture 自檢：A 的編號小於 O，且 A 已由 O 接手
		require.Less(t, a.ID, o.ID)
		require.EqualValues(t, 1, e.scalar(t, "SELECT count(*) FROM users WHERE id = ? AND owner_user_id = ?", a.ID, o.ID))

		tokenStop, guardStop := newLockStop(), newLockStop()
		release := e.installAppHooks(map[string]*lockStop{
			"agent_token_after_owner_lock@" + e.appA: tokenStop,
			"user_rows_locked@" + e.appB:             guardStop,
		}, func(point string, ids []uint) bool { return len(ids) > 0 })
		defer release()

		snap := func() map[string]int64 {
			return map[string]int64{
				"tokens":           e.scalar(t, "SELECT count(*) FROM agent_tokens WHERE user_id = ?", a.ID),
				"token_audits":     e.scalar(t, "SELECT count(*) FROM audit_logs WHERE resource = ? AND action = ? AND resource_id IN (SELECT id FROM agent_tokens WHERE user_id = ?)", string(model.ResourceAgentToken), string(model.ActionCreate), a.ID),
				"token_audits_all": e.scalar(t, "SELECT count(*) FROM audit_logs WHERE resource = ? AND action = ?", string(model.ResourceAgentToken), string(model.ActionCreate)),
			}
		}
		want := func(base map[string]int64, c map[string]bool, _ string) map[string]int64 {
			x := b2i(c["token"])
			return map[string]int64{"tokens": base["tokens"] + x, "token_audits": base["token_audits"] + x, "token_audits_all": base["token_audits_all"] + x}
		}
		e.runCycle(t, cycleSpec{
			subcase: "token_owner_after_agent_vs_sorted_subjects",
			shared:  fmt.Sprintf("users:%d,users:%d", a.ID, o.ID),
			a: lockActor{name: "token", stop: tokenStop, app: e.appA, start: func() error {
				_, err := NewAgentTokenService(e.dbA, audit.NewTxSink()).Create(a.ID,
					CreateAgentTokenRequest{Name: "lo-n2", ExpiresAt: time.Now().Add(time.Hour)}, gatewayapi.Actor{UserID: e.root, Username: "lo-root"})
				return err
			}},
			b: lockActor{name: "guard", stop: guardStop, app: e.appB, start: func() error {
				return e.dbB.Transaction(func(tx *gorm.DB) error {
					return authz.SelfGrantGuard{}.CheckRuleSubjects(tx, e.root, []uint{o.ID, a.ID}, nil)
				})
			}},
			plans: map[string]cyclePlan{
				"token": {class: "wait", kind: "row"},
				"guard": {class: "wait", kind: "row"},
			},
			snap: snap, want: want,
		}, order)
	})

	// 擁有者在簽發讀取 agent 之後、取得鎖之前被轉移：鎖後重讀發現擁有者已變，回 ErrAgentOwnerRequired、
	// 不簽出 token、不寫審計（不在持鎖時改鎖新擁有者）。
	t.Run("owner_transferred_between_read_and_lock", func(t *testing.T) {
		e := newLockOrderEnv(t)
		agent := model.User{Username: "lo-n2-moved-agent", Active: true, Kind: model.KindAgent, OwnerUserID: &e.owner}
		require.NoError(t, e.dbA.Create(&agent).Error)
		newOwner := e.humanUser(t, "lo-n2-moved-owner")

		// 另一連線先持有 agent 的列鎖，使簽發在讀完 agent、取完擁有者鎖之後停在 agent 列鎖上
		holder := e.dbB.Begin()
		require.NoError(t, holder.Error)
		defer holder.Rollback()
		require.NoError(t, lockUserRowTx(holder, agent.ID))

		done := make(chan error, 1)
		go func() {
			_, err := NewAgentTokenService(e.dbA, audit.NewTxSink()).Create(agent.ID,
				CreateAgentTokenRequest{Name: "lo-n2-moved", ExpiresAt: time.Now().Add(time.Hour)}, gatewayapi.Actor{UserID: e.root, Username: "lo-root"})
			done <- err
		}()
		require.Eventually(t, func() bool {
			return e.scalar(t, `SELECT count(*) FROM pg_locks l JOIN pg_stat_activity s ON s.pid = l.pid
 WHERE NOT l.granted AND s.application_name = ?`, e.appA) > 0
		}, 10*time.Second, 50*time.Millisecond, "簽發必須停在 agent 列鎖上")

		require.NoError(t, holder.Exec("UPDATE users SET owner_user_id = ? WHERE id = ?", newOwner, agent.ID).Error)
		require.NoError(t, holder.Commit().Error)

		select {
		case err := <-done:
			require.ErrorIs(t, err, ErrAgentOwnerRequired)
		case <-time.After(15 * time.Second):
			t.Fatal("轉移提交後簽發沒有返回")
		}
		require.EqualValues(t, 0, e.scalar(t, "SELECT count(*) FROM agent_tokens WHERE user_id = ?", agent.ID), "不得簽出 token")
		require.EqualValues(t, 0, e.scalar(t, "SELECT count(*) FROM audit_logs WHERE resource = ? AND action = ?", string(model.ResourceAgentToken), string(model.ActionCreate)))
		t.Logf("EVIDENCE dialect=postgres subcase=token_owner_after_agent_vs_sorted_subjects/owner_transferred_between_read_and_lock result=ErrAgentOwnerRequired tokens=0")
	})
}
