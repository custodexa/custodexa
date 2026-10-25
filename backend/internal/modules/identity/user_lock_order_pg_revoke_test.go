package identity

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 映射撤銷的多人命題：受影響使用者 U1 與 U2 都是人類使用者（編號 U1 < U2），由同一條規則支持
// （人類使用者可經外部身分登入取得映射支持，是產品可達的狀態；agent 不經外部身分登入，不用作受影響者）。
// 與 U2 的帳號停用交錯：停用先取 U2 的憑證鎖、之後才推進版本；
// 撤銷在處理 U1 時已推進版本，之後要處理 U2。U2 的憑證鎖若不在第一次推進之前取得即成環。
// 兩個子案例共用夾具：normal 是同一交易內處理多人（刪除規則），
// expiry 是到期撤銷，產品上每人各自一個交易（先處理 U1 並提交，再讓 U2 的交易與停用交錯）。

type revokeMultiFixture struct {
	u1, u2   uint
	provider model.OIDCProvider
	channel  string
	rule     uint
	roleID   uint
}

func (e *lockOrderEnv) revokeMultiFixture(t *testing.T, external bool) revokeMultiFixture {
	t.Helper()
	f := revokeMultiFixture{u1: e.owner, u2: e.newOwner}
	require.Less(t, f.u1, f.u2, "U1 的編號必須小於 U2，撤銷才先處理 U1")
	require.EqualValues(t, 1, e.scalar(t, "SELECT count(*) FROM users WHERE id = ? AND kind = ?", f.u2, model.KindHuman), "U2 必須是人類使用者")
	f.provider = e.mappingProvider(t, "lo-n2j-provider")
	f.channel = model.RoleMappingChannel(model.RoleMappingChannelKindProvider, f.provider.ID)
	ext := model.ExternalGroup{OIDCProviderID: &f.provider.ID, MatchValue: "old"}
	require.NoError(t, e.dbA.Create(&ext).Error)
	var userRole model.Role
	require.NoError(t, e.dbA.Where("name = ?", model.RoleUser).First(&userRole).Error)
	f.roleID = userRole.ID
	rule := model.GroupRoleMapping{OIDCProviderID: &f.provider.ID, ExternalGroupID: ext.ID, MatchValue: "old", RoleID: userRole.ID, Enabled: true, CreatedBy: e.root}
	require.NoError(t, e.dbA.Create(&rule).Error)
	f.rule = rule.ID
	for _, u := range []uint{f.u1, f.u2} {
		require.NoError(t, e.dbA.Create(&model.UserRoleMappingRuleSupport{UserID: u, RoleID: userRole.ID, Channel: f.channel, RuleID: rule.ID}).Error)
		e.mappedRoleFixture(t, u, userRole.ID, f.channel)
		if external {
			require.NoError(t, e.dbA.Model(&model.User{}).Where("id = ?", u).Update("external_credential", true).Error)
		}
		// fixture 自檢：支持列、映射事實、mapped 投影、有效 refresh token 各一
		require.EqualValues(t, 1, e.scalar(t, "SELECT count(*) FROM user_role_mapping_rule_supports WHERE user_id = ? AND rule_id = ?", u, rule.ID))
		require.EqualValues(t, 1, e.scalar(t, "SELECT count(*) FROM user_role_mappings WHERE user_id = ? AND channel = ?", u, f.channel))
		require.EqualValues(t, 1, e.scalar(t, "SELECT count(*) FROM user_roles WHERE user_id = ? AND role_id = ? AND source = ?", u, userRole.ID, model.RoleSourceMapped))
		require.EqualValues(t, 1, e.scalar(t, "SELECT count(*) FROM refresh_tokens WHERE user_id = ? AND revoked_at IS NULL", u))
	}
	return f
}

// perUser 某位受影響使用者在撤銷前後會變的資料；revokeCode 是該使用者撤權審計的事件碼。
func (e *lockOrderEnv) revokeUserSnap(t *testing.T, m map[string]int64, tag string, f revokeMultiFixture, u uint, revokeCode string) {
	m["fact_"+tag] = e.scalar(t, "SELECT count(*) FROM user_role_mappings WHERE user_id = ? AND channel = ?", u, f.channel)
	m["support_"+tag] = e.scalar(t, "SELECT count(*) FROM user_role_mapping_rule_supports WHERE user_id = ? AND rule_id = ?", u, f.rule)
	m["mapped_"+tag] = e.scalar(t, "SELECT count(*) FROM user_roles WHERE user_id = ? AND role_id = ? AND source = ?", u, f.roleID, model.RoleSourceMapped)
	m["epoch_"+tag] = e.scalar(t, "SELECT credential_epoch FROM users WHERE id = ?", u)
	m["refresh_"+tag] = e.scalar(t, "SELECT count(*) FROM refresh_tokens WHERE user_id = ? AND revoked_at IS NULL", u)
	m["audit_revoke_"+tag] = e.scalar(t, `SELECT count(*) FROM audit_logs WHERE resource = ? AND resource_id = ? AND action = ? AND error_msg = ? AND details::jsonb->>'channel' = ?`,
		string(model.ResourceUser), u, string(model.ActionUpdate), revokeCode, f.channel)
	m["audit_role_revoke_"+tag] = e.auditCount(t, model.ResourceUserRole, u, model.ActionRevoke)
}

func wantRevokeUser(out, base map[string]int64, tag string, r int64) {
	out["fact_"+tag] = base["fact_"+tag] - r
	out["support_"+tag] = base["support_"+tag] - r
	out["mapped_"+tag] = base["mapped_"+tag] - r
	out["epoch_"+tag] = base["epoch_"+tag] + r
	out["refresh_"+tag] = base["refresh_"+tag] - r
	out["audit_revoke_"+tag] = base["audit_revoke_"+tag] + r
	out["audit_role_revoke_"+tag] = base["audit_role_revoke_"+tag] + r
}

// runMappingRevokeMultiUser：sub 為 normal 或 expiry。
// 撤銷先行（停在 U1 處理完、U2 尚未處理之處，或到期交易取得 U2 的鎖之後）與停用先行（停在 U2 的憑證鎖之後、推進版本之前）兩序，
// 修後預期都是等 U2 的憑證鎖。
func runMappingRevokeMultiUser(t *testing.T, sub string) {
	eachOrder(t, "revoke", "disable", func(t *testing.T, order string) {
		expiry := sub == "expiry"
		e := newLockOrderEnv(t)
		f := e.revokeMultiFixture(t, expiry)
		revokeCode := MappingRuleRevokedEvent
		if expiry {
			revokeCode = MembershipRevalidationExpired
		}
		hours := 1
		obsOf := func() GroupObservation {
			return GroupObservation{Kind: model.RoleMappingChannelKindProvider, SourceID: f.provider.ID, State: GroupObservationUnknown, RevalidationHours: &hours}
		}
		if expiry {
			// 到期撤銷逐人各自一個交易：先處理 U1（無並發），驗它的結果；U2 的交易才與停用交錯
			var u1 model.User
			require.NoError(t, e.dbA.First(&u1, f.u1).Error)
			before := e.scalar(t, "SELECT credential_epoch FROM users WHERE id = ?", f.u1)
			out, err := RecomputeMappedRoles(e.dbA, audit.NewTxSink(), &u1, obsOf())
			require.NoError(t, err)
			require.True(t, out.Expired && out.EpochBumped, "U1 的到期撤銷必須實際收回")
			require.EqualValues(t, 0, e.scalar(t, "SELECT count(*) FROM user_role_mapping_rule_supports WHERE user_id = ? AND rule_id = ?", f.u1, f.rule))
			require.EqualValues(t, before+1, e.scalar(t, "SELECT credential_epoch FROM users WHERE id = ?", f.u1))
		}
		revokePoint := "mapping_revoke_after_user"
		revokeUser := f.u1
		if expiry {
			revokePoint, revokeUser = "recompute_after_user_lock", f.u2
		}
		revokeStop, disableStop := newLockStop(), newLockStop()
		release := e.installAppHooks(map[string]*lockStop{
			revokePoint + "@" + e.appA:             revokeStop,
			"user_status_before_advance@" + e.appB: disableStop,
		}, func(point string, ids []uint) bool {
			if point == "user_status_before_advance" {
				return len(ids) > 0 && ids[0] == f.u2
			}
			return len(ids) > 0 && ids[0] == revokeUser
		})
		defer release()

		snap := func() map[string]int64 {
			m := map[string]int64{
				"authz_version": e.scalar(t, "SELECT version FROM authz_state WHERE id = 1"),
				"rule_live":     e.scalar(t, "SELECT count(*) FROM group_role_mappings WHERE id = ? AND deleted_at IS NULL", f.rule),
				"u2_active":     e.scalar(t, "SELECT count(*) FROM users WHERE id = ? AND active", f.u2),
			}
			// 規則刪除本身的審計：綁定規則編號、來源、事件碼與操作者
			m["audit_rule_delete"] = e.scalar(t, `SELECT count(*) FROM audit_logs WHERE resource = ? AND resource_id = ? AND action = ? AND user_id = ?
 AND details::jsonb->>'event' = ? AND details::jsonb->>'rule_id' = ? AND details::jsonb->>'source_id' = ? AND details::jsonb->>'source_kind' = ?`,
				string(model.ResourceAuth), f.rule, string(model.ActionDelete), e.root,
				MappingAuditEventDelete, fmt.Sprint(f.rule), fmt.Sprint(f.provider.ID), model.RoleMappingChannelKindProvider)
			e.revokeUserSnap(t, m, "u1", f, f.u1, revokeCode)
			e.revokeUserSnap(t, m, "u2", f, f.u2, revokeCode)
			return m
		}
		want := func(base map[string]int64, c map[string]bool, _ string) map[string]int64 {
			r, d := b2i(c["revoke"]), b2i(c["disable"])
			out := map[string]int64{"u2_active": base["u2_active"] - d}
			if expiry {
				// U1 已先處理完；本交錯只有 U2 的到期撤銷（角色收回推進一次）與停用（推進一次）
				out["authz_version"] = base["authz_version"] + r + d
				out["rule_live"] = base["rule_live"]
				out["audit_rule_delete"] = base["audit_rule_delete"]
				wantRevokeUser(out, base, "u1", 0)
			} else {
				// 刪除規則推進一次，U1 與 U2 各因角色收回推進一次，停用再推進一次
				out["authz_version"] = base["authz_version"] + 3*r + d
				out["rule_live"] = base["rule_live"] - r
				out["audit_rule_delete"] = base["audit_rule_delete"] + r
				wantRevokeUser(out, base, "u1", r)
			}
			wantRevokeUser(out, base, "u2", r)
			// U2 的世代：撤銷收回與停用各推進一次；refresh：任一方提交即全撤
			out["epoch_u2"] = base["epoch_u2"] + r + d
			out["refresh_u2"] = base["refresh_u2"] - b2i(c["revoke"] || c["disable"])
			return out
		}
		e.runCycle(t, cycleSpec{
			subcase: "mapping_revoke_multi_user/" + sub,
			shared:  fmt.Sprintf("users:%d", f.u2),
			a: lockActor{name: "revoke", stop: revokeStop, app: e.appA, start: func() error {
				if expiry {
					var au model.User
					if err := e.dbA.First(&au, f.u2).Error; err != nil {
						return err
					}
					_, err := RecomputeMappedRoles(e.dbA, audit.NewTxSink(), &au, obsOf())
					return err
				}
				return e.mappingService(e.dbA).DeleteMapping(model.RoleMappingChannelKindProvider, f.provider.ID, f.rule,
					GroupRoleMappingActor{ID: e.root, Name: "lo-root", IP: "127.0.0.1"})
			}},
			b: lockActor{name: "disable", stop: disableStop, app: e.appB, start: func() error {
				return e.users.UpdateStatusBy(e.op(), f.u2, false)
			}},
			plans: map[string]cyclePlan{
				"revoke":  {class: "wait", kind: "advisory", advisoryUser: f.u2},
				"disable": {class: "wait", kind: "advisory", advisoryUser: f.u2},
			},
			snap: snap, want: want,
		}, order)
	})
}

// 撤銷的取鎖順序（不靠交錯，直接看真交易送出的語句）：
// 受影響使用者的鎖語句（憑證鎖 advisory 與 users 列鎖兩種，各別驗）都必須早於交易內第一次權限版本推進，
// 推進之後出現的同種鎖語句只允許針對推進之前已取得的使用者。
// 與上面的交錯案例互補：交錯案例只能證明某一把鎖上的等待，這裡證明第一次推進之前每位使用者都已持鎖。

var authzAdvanceRe = regexp.MustCompile(`(?i)^\s*UPDATE\s+"?authz_state"?\s+SET\s+version\b`)
var usersTableRe = regexp.MustCompile(`(?i)\bFROM\s+"?users"?\b`)

type userLockStmt struct {
	idx  int
	kind string // advisory | row
	ids  []uint
}

func isUserAdvisory(sql string, vars []any) bool {
	_, ok := userCredentialAdvisoryUser(sql, vars)
	return ok
}

// userLockStatements 取出一串語句中的使用者鎖語句；firstAdvance 是第一次權限版本推進的位置（沒有則 -1）。
func userLockStatements(recs []sqlRecord) (locks []userLockStmt, firstAdvance int) {
	firstAdvance = -1
	for i, r := range recs {
		if firstAdvance < 0 && authzAdvanceRe.MatchString(r.sql) {
			firstAdvance = i
		}
		ids := numericVars(r.vars)
		switch {
		case isUserAdvisory(r.sql, r.vars):
			// 兩個參數：鎖類別（須為使用者憑證鎖 class，K8c）、使用者編號
			locks = append(locks, userLockStmt{idx: i, kind: "advisory", ids: ids[len(ids)-1:]})
		case usersTableRe.MatchString(r.sql) && lockSelectRe.MatchString(r.sql):
			locks = append(locks, userLockStmt{idx: i, kind: "row", ids: ids})
		}
	}
	return locks, firstAdvance
}

// requireUserLocksBeforeAdvance 對 kind 這種鎖：users 內每位的第一句都在第一次推進之前，
// 推進之後出現的同種鎖語句，其使用者都在推進之前已取得。
func requireUserLocksBeforeAdvance(t *testing.T, recs []sqlRecord, kind string, users []uint) {
	t.Helper()
	locks, adv := userLockStatements(recs)
	require.GreaterOrEqual(t, adv, 0, "交易內必須出現權限版本推進")
	held := map[uint]int{}
	for _, l := range locks {
		if l.kind != kind {
			continue
		}
		for _, id := range l.ids {
			if _, ok := held[id]; !ok && l.idx < adv {
				held[id] = l.idx
			}
		}
	}
	for _, u := range users {
		first, ok := held[u]
		require.True(t, ok, "%s 鎖：使用者 %d 在第一次權限版本推進（語句 %d）之前沒有任何鎖語句", kind, u, adv)
		require.Less(t, first, adv)
	}
	var late []string
	for _, l := range locks {
		if l.kind != kind || l.idx < adv {
			continue
		}
		for _, id := range l.ids {
			if _, ok := held[id]; !ok {
				late = append(late, fmt.Sprintf("語句 %d 的使用者 %d", l.idx, id))
			}
		}
	}
	require.Empty(t, late, "%s 鎖：第一次推進之後出現推進前未取得的使用者", kind)
	t.Logf("EVIDENCE dialect=postgres subcase=lock_statement_order kind=%s users=%v first_lock=%v first_advance=%d statements=%d", kind, users, held, adv, len(recs))
}

// runMappingRevokeLockOrder：sub 為 normal（同一交易處理 U1、U2）或 expiry（U1、U2 各自一個交易）；
// kind 為 advisory 或 row。
func runMappingRevokeLockOrder(t *testing.T, sub, kind string) {
	e := newLockOrderEnv(t)
	expiry := sub == "expiry"
	f := e.revokeMultiFixture(t, expiry)
	if !expiry {
		get, stop := collectSQL(e.dbA, "lock_order_revoke_normal")
		defer stop()
		require.NoError(t, e.mappingService(e.dbA).DeleteMapping(model.RoleMappingChannelKindProvider, f.provider.ID, f.rule,
			GroupRoleMappingActor{ID: e.root, Name: "lo-root", IP: "127.0.0.1"}))
		stop()
		require.EqualValues(t, 0, e.scalar(t, "SELECT count(*) FROM user_role_mapping_rule_supports WHERE rule_id = ?", f.rule), "fixture：兩人的支持都被撤銷")
		requireUserLocksBeforeAdvance(t, get(), kind, []uint{f.u1, f.u2})
		return
	}
	hours := 1
	for _, u := range []uint{f.u1, f.u2} {
		var user model.User
		require.NoError(t, e.dbA.First(&user, u).Error)
		get, stop := collectSQL(e.dbA, fmt.Sprintf("lock_order_revoke_expiry_%d", u))
		out, err := RecomputeMappedRoles(e.dbA, audit.NewTxSink(), &user, GroupObservation{
			Kind: model.RoleMappingChannelKindProvider, SourceID: f.provider.ID, State: GroupObservationUnknown, RevalidationHours: &hours})
		stop()
		require.NoError(t, err)
		require.True(t, out.Expired && out.EpochBumped, "使用者 %d 的到期撤銷必須實際收回", u)
		requireUserLocksBeforeAdvance(t, get(), kind, []uint{u})
	}
}
