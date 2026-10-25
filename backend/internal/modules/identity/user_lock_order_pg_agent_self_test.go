package identity

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// runAgentSelfCreateVsOwnerRoleRevoke：擁有者 O 只經群組擁有被移除的角色（真 loser），
// 與 O 自建 agent 競爭。自建在擁有者列鎖之後停住；群組停在推進版本之後、loser 世代更新之前。
// 這是回歸守衛：不預期死結。plans 是修後的預期類別（群組在 upfront 持擁有者的非鍵更新鎖，
// 自建對擁有者取同級鎖，兩序都等列鎖）；未修碼的實測類別另記在證據檔，不當作常數。
func runAgentSelfCreateVsOwnerRoleRevoke(t *testing.T) {
	eachOrder(t, "create", "group", func(t *testing.T, order string) {
		e := newLockOrderEnv(t)
		require.NoError(t, e.dbA.AutoMigrate(&model.SecurityPolicy{}))
		_, err := policy.NewSecurityPolicyService(e.dbA).Update(policy.PolicyAgentSelfCreateEnabled, "true", "test")
		require.NoError(t, err)
		require.NoError(t, e.dbA.Create(&model.UserGroupMember{UserGroupID: e.group, UserID: e.owner, Manual: true}).Error)
		losers, err := authzLosers(e)
		require.NoError(t, err)
		require.Contains(t, losers, e.owner, "O 必須是真 loser")

		createStop, groupStop := newLockStop(), newLockStop()
		release := e.installAppHooks(map[string]*lockStop{
			"agent_self_create_owner_locked@" + e.appB: createStop,
			"group_roles_after_advance@" + e.appA:      groupStop,
		}, func(point string, ids []uint) bool { return true })
		defer release()

		newAgent := "SELECT id FROM users WHERE username = 'lo-self-agent' AND kind = '" + string(model.KindAgent) + "' AND owner_user_id = " + fmt.Sprint(e.owner)
		createAudit := func(key string) int64 {
			return e.scalar(t, `SELECT count(*) FROM audit_logs WHERE resource = ? AND action = ? AND resource_id IN (`+newAgent+`) AND details::jsonb->>'`+key+`' IS NOT NULL`,
				string(model.ResourceUser), string(model.ActionCreate))
		}
		snap := func() map[string]int64 {
			return map[string]int64{
				"authz_version":      e.scalar(t, "SELECT version FROM authz_state WHERE id = 1"),
				"group_roles":        e.scalar(t, "SELECT count(*) FROM user_group_roles WHERE user_group_id = ?", e.group),
				"audit_revoke":       e.groupRoleAudit(t, e.group, e.role, model.ActionRevoke),
				"owner_epoch":        e.scalar(t, "SELECT credential_epoch FROM users WHERE id = ?", e.owner),
				"old_agent_epoch":    e.scalar(t, "SELECT credential_epoch FROM users WHERE id = ?", e.agent),
				"agents":             e.scalar(t, "SELECT count(*) FROM users WHERE kind = ? AND owner_user_id = ?", string(model.KindAgent), e.owner),
				"new_agent":          e.scalar(t, "SELECT count(*) FROM ("+newAgent+") x"),
				"new_agent_roles":    e.scalar(t, "SELECT count(*) FROM user_roles WHERE user_id IN ("+newAgent+")"),
				"audit_state_create": createAudit("state_table"),
				"audit_self_create":  createAudit("self_service"),
			}
		}
		want := func(base map[string]int64, c map[string]bool, _ string) map[string]int64 {
			g, x := b2i(c["group"]), b2i(c["create"])
			return map[string]int64{
				"authz_version":      base["authz_version"] + g,
				"group_roles":        base["group_roles"] - g,
				"audit_revoke":       base["audit_revoke"] + g,
				"owner_epoch":        base["owner_epoch"] + g,
				"old_agent_epoch":    base["old_agent_epoch"] + g,
				"agents":             base["agents"] + x,
				"new_agent":          base["new_agent"] + x,
				"new_agent_roles":    base["new_agent_roles"],
				"audit_state_create": base["audit_state_create"] + x,
				"audit_self_create":  base["audit_self_create"] + x,
			}
		}
		svc := NewUserService(e.dbB, nil)
		e.runCycle(t, cycleSpec{
			subcase: "agent_self_create_vs_owner_role_revoke",
			shared:  fmt.Sprintf("users:%d", e.owner),
			a: lockActor{name: "group", stop: groupStop, app: e.appA, start: func() error {
				_, err := e.groups.ReplaceRoleBindings(e.op(), e.group, GroupRoleBindingsRequest{RoleIDs: nil})
				return err
			}},
			b: lockActor{name: "create", stop: createStop, app: e.appB, start: func() error {
				_, err := svc.CreateMyAgent(gatewayapi.Actor{UserID: e.owner, Username: "lo-owner"}, CreateMyAgentRequest{Username: "lo-self-agent", Purpose: "lock order"})
				return err
			}},
			plans: map[string]cyclePlan{
				"create": {class: "wait", kind: "row"},
				"group":  {class: "wait", kind: "row"},
			},
			snap: snap, want: want,
		}, order)
	})
}

func authzLosers(e *lockOrderEnv) ([]uint, error) {
	return authz.MembersLosingRoles(e.dbA, e.group, []uint{e.role})
}
