package identity

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 群組純新增角色（預取全體成員的憑證鎖）與「寫入時對另一位成員取外鍵」的雙方交錯。
// 群組先行停在已持較小編號成員的憑證鎖與使用者列、尚未請求下一位成員的憑證鎖之處；另一方先行停在它自己的守衛鎖之後。

// groupAddEnv 建一個含兩位成員（lo < hi）的群組並回傳群組編號。
func (e *lockOrderEnv) groupAddGroup(t *testing.T, name string, members ...uint) uint {
	t.Helper()
	g := model.UserGroup{Name: name}
	require.NoError(t, e.dbA.Create(&g).Error)
	for _, m := range members {
		require.NoError(t, e.dbA.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: m, Manual: true}).Error)
	}
	return g.ID
}

// groupRoleAudit 某群組某角色的指派或撤銷審計筆數（details 的 role_id 辨認角色）。
func (e *lockOrderEnv) groupRoleAudit(t *testing.T, gid, roleID uint, action model.AuditAction) int64 {
	t.Helper()
	return e.scalar(t, `SELECT count(*) FROM audit_logs WHERE resource = ? AND resource_id = ? AND action = ? AND details::jsonb->>'role_id' = ?`,
		string(model.ResourceUserGroupRole), gid, string(action), fmt.Sprint(roleID))
}

func (e *lockOrderEnv) humanUser(t *testing.T, name string) uint {
	t.Helper()
	u := model.User{Username: name, Active: true, Kind: model.KindHuman}
	require.NoError(t, e.dbA.Create(&u).Error)
	return u.ID
}

// runOwnerTransferVsGroupAdd：agent A 的新擁有者 O 的編號小於 A，二者同在群組 G；
// 群組純新增角色依序取 O、A 的憑證鎖，轉移寫 owner 外鍵（對 O 列取 KEY SHARE）並先鎖 A 列。
func runOwnerTransferVsGroupAdd(t *testing.T) {
	eachOrder(t, "group", "transfer", func(t *testing.T, order string) {
		e := newLockOrderEnv(t)
		o := e.newOwner
		require.Less(t, o, e.agent)
		gid := e.groupAddGroup(t, "lo-n3-group", o, e.agent)
		require.EqualValues(t, 1, e.scalar(t, "SELECT count(*) FROM users WHERE id = ? AND owner_user_id = ?", e.agent, e.owner))

		groupStop, transferStop := newLockStop(), newLockStop()
		release := e.installAppHooks(map[string]*lockStop{
			"upfront_before_user@" + e.appA:        groupStop,
			"owner_transfer_after_guard@" + e.appB: transferStop,
		}, func(point string, ids []uint) bool {
			return len(ids) > 0 && (point != "upfront_before_user" || ids[0] == e.agent)
		})
		defer release()

		snap := func() map[string]int64 {
			return map[string]int64{
				"authz_version":      e.scalar(t, "SELECT version FROM authz_state WHERE id = 1"),
				"group_roles":        e.scalar(t, "SELECT count(*) FROM user_group_roles WHERE user_group_id = ?", gid),
				"group_role_target":  e.scalar(t, "SELECT count(*) FROM user_group_roles WHERE user_group_id = ? AND role_id = ?", gid, e.role),
				"audit_assign":       e.groupRoleAudit(t, gid, e.role, model.ActionAssign),
				"owner_is_new":       e.scalar(t, "SELECT count(*) FROM users WHERE id = ? AND owner_user_id = ?", e.agent, o),
				"owner_is_old":       e.scalar(t, "SELECT count(*) FROM users WHERE id = ? AND owner_user_id = ?", e.agent, e.owner),
				"audit_agent_update": e.auditCount(t, model.ResourceUser, e.agent, model.ActionUpdate),
			}
		}
		want := func(base map[string]int64, c map[string]bool, _ string) map[string]int64 {
			g, x := b2i(c["group"]), b2i(c["transfer"])
			return map[string]int64{
				"authz_version":      base["authz_version"] + g + x,
				"group_roles":        base["group_roles"] + g,
				"group_role_target":  base["group_role_target"] + g,
				"audit_assign":       base["audit_assign"] + g,
				"owner_is_new":       base["owner_is_new"] + x,
				"owner_is_old":       base["owner_is_old"] - x,
				"audit_agent_update": base["audit_agent_update"] + x,
			}
		}
		e.runCycle(t, cycleSpec{
			subcase: "owner_transfer_fk_vs_group_add",
			shared:  fmt.Sprintf("users:%d,users:%d", o, e.agent),
			a: lockActor{name: "group", stop: groupStop, app: e.appA, start: func() error {
				_, err := e.groups.ReplaceRoleBindings(e.op(), gid, GroupRoleBindingsRequest{RoleIDs: []uint{e.role}})
				return err
			}},
			b: lockActor{name: "transfer", stop: transferStop, app: e.appB, start: func() error {
				no := o
				_, _, err := e.users.Update(e.agent, &UpdateUserRequest{OwnerUserID: &no})
				return err
			}},
			plans: map[string]cyclePlan{
				"group":    {class: "nowait"},
				"transfer": {class: "wait", kind: "row"},
			},
			snap: snap, want: want,
		}, order)
	})
}

// runGrantActorVsGroupAdd：非超管操作者 U（編號小於主體 V）建授權，granted_by 外鍵指向 U，守衛先鎖主體 V 的列；
// U、V 同在群組 G，群組純新增角色依序取 U、V 的憑證鎖。batch 另帶不在群組內的第二位主體 W。
func runGrantActorVsGroupAdd(t *testing.T, sub string) {
	eachOrder(t, "group", "grant", func(t *testing.T, order string) {
		e := newLockOrderEnv(t, "fk_asset_authorizations_granted_by_user")
		u, v := e.humanUser(t, "lo-n3b-actor"), e.humanUser(t, "lo-n3b-subject")
		w := e.humanUser(t, "lo-n3b-extra")
		require.Less(t, u, v)
		gid := e.groupAddGroup(t, "lo-n3b-group", u, v)
		asset := model.Asset{Name: "lo-n3b-box", Protocol: model.ProtocolSSH, Host: "h", Port: 22, CreatedBy: e.root, Active: true}
		require.NoError(t, e.dbA.Create(&asset).Error)

		groupStop, grantStop := newLockStop(), newLockStop()
		release := e.installAppHooks(map[string]*lockStop{
			"upfront_before_user@" + e.appA: groupStop,
			"user_rows_locked@" + e.appB:    grantStop,
		}, func(point string, ids []uint) bool {
			return len(ids) > 0 && (point != "user_rows_locked" || ids[0] == v) && (point != "upfront_before_user" || ids[0] == v)
		})
		defer release()

		grantOf := func(subject uint) int64 {
			return e.scalar(t, "SELECT count(*) FROM asset_authorizations WHERE granted_by = ? AND user_id = ? AND asset_id = ? AND permission = ? AND accounts = ? AND deleted_at IS NULL",
				u, subject, asset.ID, string(model.PermissionConnect), `["@ALL"]`)
		}
		snap := func() map[string]int64 {
			return map[string]int64{
				"group_roles":       e.scalar(t, "SELECT count(*) FROM user_group_roles WHERE user_group_id = ?", gid),
				"group_role_target": e.scalar(t, "SELECT count(*) FROM user_group_roles WHERE user_group_id = ? AND role_id = ?", gid, e.role),
				"audit_assign":      e.groupRoleAudit(t, gid, e.role, model.ActionAssign),
				"grants_total":      e.scalar(t, "SELECT count(*) FROM asset_authorizations WHERE granted_by = ? AND deleted_at IS NULL", u),
				"grant_v":           grantOf(v),
				"grant_w":           grantOf(w),
			}
		}
		want := func(base map[string]int64, c map[string]bool, _ string) map[string]int64 {
			g, x := b2i(c["group"]), b2i(c["grant"])
			wGrant := int64(0)
			if sub == "batch" {
				wGrant = x
			}
			return map[string]int64{
				"group_roles":       base["group_roles"] + g,
				"group_role_target": base["group_role_target"] + g,
				"audit_assign":      base["audit_assign"] + g,
				"grants_total":      base["grants_total"] + x + wGrant,
				"grant_v":           base["grant_v"] + x,
				"grant_w":           base["grant_w"] + wGrant,
			}
		}
		svc := authz.NewAssetAuthorizationService(e.dbB)
		ctx := authz.ContextWithPrincipal(context.Background(), &authz.Principal{UserID: u})
		e.runCycle(t, cycleSpec{
			subcase: "grant_actor_fk_vs_group_add/" + sub,
			shared:  fmt.Sprintf("users:%d,users:%d", u, v),
			a: lockActor{name: "group", stop: groupStop, app: e.appA, start: func() error {
				_, err := e.groups.ReplaceRoleBindings(e.op(), gid, GroupRoleBindingsRequest{RoleIDs: []uint{e.role}})
				return err
			}},
			b: lockActor{name: "grant", stop: grantStop, app: e.appB, start: func() error {
				if sub == "batch" {
					res, err := svc.GrantBatch(ctx, []uint{v, w}, nil, []uint{asset.ID}, nil, model.PermissionConnect, u, nil)
					if err == nil && (res.Created != 2 || res.Skipped != 0) {
						return fmt.Errorf("批次授權回傳 created=%d skipped=%d，預期 2／0", res.Created, res.Skipped)
					}
					return err
				}
				vv, aa := v, asset.ID
				row, err := svc.Grant(ctx, authz.GrantSpec{UserID: &vv, AssetID: &aa, Permission: model.PermissionConnect, GrantedBy: u})
				if err == nil && (row == nil || row.UserID == nil || *row.UserID != v) {
					return fmt.Errorf("單筆授權回傳的主體不是 V")
				}
				return err
			}},
			plans: map[string]cyclePlan{
				"group": {class: "nowait"},
				"grant": {class: "wait", kind: "row"},
			},
			snap: snap, want: want,
		}, order)
	})
}
