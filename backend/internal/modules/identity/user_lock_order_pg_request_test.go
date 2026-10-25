package identity

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/policy"
)

// 存取申請的外鍵與群組純新增角色的交錯。
// 申請人 AG 是 agent，申請單寫入前先以列鎖鎖住申請人，之後的外鍵檢查（executor 或核決者）
// 對編號較小的另一位取共享鎖；群組純新增角色依編號升冪取憑證鎖（較小者在前）。
// 二者都在群組 G 內，且申請人編號較大。

// fkNameOn 以 pg_constraint 實查某表某欄上的正式外鍵名稱（必須恰有一條）。
func (e *lockOrderEnv) fkNameOn(t *testing.T, table, column string) string {
	t.Helper()
	var names []string
	require.NoError(t, e.obs.Raw(`SELECT c.conname FROM pg_constraint c
 JOIN pg_class r ON r.oid = c.conrelid JOIN pg_namespace n ON n.oid = r.relnamespace
 JOIN pg_attribute a ON a.attrelid = r.oid AND a.attnum = ANY (c.conkey)
 WHERE n.nspname = ? AND r.relname = ? AND a.attname = ? AND c.contype = 'f' ORDER BY c.conname`,
		lockOrderSchema, table, column).Scan(&names).Error)
	require.Len(t, names, 1, "%s.%s 上的外鍵", table, column)
	e.fks = append(e.fks, names[0])
	return names[0]
}

type requestFixture struct {
	svc      *authz.AccessRequestService
	asset    model.Asset
	ag       uint // 申請人 agent
	gid      uint
	executor uint
	approver uint
}

// requestEnv 建申請服務（副本 B 的連線池）、需核准的資產與帳號、雙方可視；sub 決定另一位成員是 executor 或核決者。
func (e *lockOrderEnv) requestEnv(t *testing.T, sub string) requestFixture {
	t.Helper()
	f := requestFixture{}
	owner := e.owner
	if sub == "decide_approver" {
		// 核決者 D 是人類使用者，編號小於申請人
		f.approver = e.humanUser(t, "lo-n3c-approver")
	}
	ag := model.User{Username: "lo-n3c-requester", Active: true, Kind: model.KindAgent, OwnerUserID: &owner}
	require.NoError(t, e.dbA.Create(&ag).Error)
	f.ag = ag.ID
	lo := e.agent // executor 與 group 的較小者
	if sub == "decide_approver" {
		lo = f.approver
	} else {
		f.executor = e.agent
	}
	require.Less(t, lo, f.ag)
	approval := model.AccessPolicyApproval
	f.asset = model.Asset{Name: "lo-n3c-box", Protocol: model.ProtocolSSH, Host: "h", Port: 22, CreatedBy: e.root, Active: true, AccessPolicy: &approval}
	require.NoError(t, e.dbA.Create(&f.asset).Error)
	cred := model.Credential{Username: "app", Scope: model.CredentialScopeDedicated, SecretType: "password", ProtocolFamily: model.ProtocolFamilySSH}
	require.NoError(t, e.dbA.Create(&cred).Error)
	require.NoError(t, e.dbA.Create(&model.AssetAccount{AssetID: f.asset.ID, CredentialID: cred.ID, Username: "app"}).Error)
	viewers := []uint{f.ag}
	if sub == "submit_executor" {
		viewers = append(viewers, f.executor)
	}
	for _, u := range viewers {
		uu, aa := u, f.asset.ID
		require.NoError(t, e.dbA.Create(&model.AssetAuthorization{UserID: &uu, AssetID: &aa, Permission: model.PermissionView, GrantedBy: e.root}).Error)
	}
	if sub == "decide_approver" {
		aid := f.asset.ID
		ap := f.approver
		require.NoError(t, e.dbA.Create(&model.ApproverScope{ApproverID: &ap, AssetID: &aid, GrantedBy: e.root}).Error)
	}
	policies := policy.NewSecurityPolicyService(e.dbB)
	if sub == "decide_approver" {
		// 門檻 2：核決者的一票只記票，單維持待審，後置資料單純
		_, err := policies.Update(policy.PolicyAccessRequestMinApprovals, "2", "admin")
		require.NoError(t, err)
	}
	accessPolicy := policy.NewAccessPolicyService(e.dbB, policies, authz.NewAssetAuthorizationService(e.dbB))
	f.svc = authz.NewAccessRequestService(e.dbB, policies, accessPolicy, nil, nil)
	f.svc.SetAccountPresenceSource(func(db *gorm.DB, id uint, name string) (bool, error) {
		var n int64
		err := db.Table("asset_accounts").Where("asset_id=? AND username=? AND deleted_at IS NULL", id, name).Count(&n).Error
		return n > 0, err
	})
	members := []uint{lo, f.ag}
	f.gid = e.groupAddGroup(t, "lo-n3c-group", members...)
	return f
}

func (f requestFixture) submitInput() authz.SubmitAccessRequestInput {
	names := []string{"app"}
	in := authz.SubmitAccessRequestInput{AssetID: f.asset.ID, Accounts: &names, Reason: "maintenance", DurationMinutes: 60}
	if f.executor != 0 {
		ex := f.executor
		in.ExecutorUserID = &ex
	}
	return in
}

// runRequestFKVsGroupAdd：sub 為 submit_executor 或 decide_approver。
// 群組先行停在已持較小編號者的憑證鎖、尚未請求申請人的憑證鎖之處（修後：群組對較小者持 NKU，
// 申請單的外鍵共享鎖相容，故後行者不被擋）；申請或核決先行停在已鎖申請人列之後（持列鎖，
// 修後群組預取在較小者之後等申請人的列，列鎖等待）。
func runRequestFKVsGroupAdd(t *testing.T, sub string) {
	eachOrder(t, "group", "request", func(t *testing.T, order string) {
		decide := sub == "decide_approver"
		e := newLockOrderEnv(t)
		f := e.requestEnv(t, sub)
		if decide {
			e.fkNameOn(t, "access_request_approvals", "approver_id")
		} else {
			e.fkNameOn(t, "access_requests", "executor_user_id")
		}
		var reqID uint
		if decide {
			// 申請單於夾具階段建立（掛點尚未安裝）；agent 申請人的核准單維持待審
			r, err := f.svc.Submit(f.ag, "lo-n3c-requester", false, f.submitInput())
			require.NoError(t, err)
			require.Equal(t, model.AccessRequestPending, r.Status)
			reqID = r.ID
		}
		groupStop, reqStop := newLockStop(), newLockStop()
		reqPoint := "request_submit_after_requester_lock"
		if decide {
			reqPoint = "user_rows_locked"
		}
		release := e.installAppHooks(map[string]*lockStop{
			"upfront_before_user@" + e.appA: groupStop,
			reqPoint + "@" + e.appB:         reqStop,
		}, func(point string, ids []uint) bool {
			return len(ids) > 0 && ids[0] == f.ag
		})
		defer release()

		snap := func() map[string]int64 {
			return map[string]int64{
				"authz_version":     e.scalar(t, "SELECT version FROM authz_state WHERE id = 1"),
				"group_roles":       e.scalar(t, "SELECT count(*) FROM user_group_roles WHERE user_group_id = ?", f.gid),
				"group_role_target": e.scalar(t, "SELECT count(*) FROM user_group_roles WHERE user_group_id = ? AND role_id = ?", f.gid, e.role),
				"audit_assign":      e.groupRoleAudit(t, f.gid, e.role, model.ActionAssign),
				// 申請單與項目（以申請人與資產辨認）
				"requests": e.scalar(t, "SELECT count(*) FROM access_requests WHERE requester_id = ? AND asset_id = ? AND (executor_user_id = ? OR ? = 0)", f.ag, f.asset.ID, f.executor, f.executor),
				"items":    e.scalar(t, "SELECT count(*) FROM access_request_items WHERE requester_id = ? AND asset_id = ? AND status = ?", f.ag, f.asset.ID, model.AccessRequestPending),
				"votes":    e.scalar(t, "SELECT count(*) FROM access_request_approvals WHERE approver_id = ?", f.approver),
				// 票必須綁定這張申請單及它的項目（與正式計票條件同：申請單編號與項目編號都吻合）；核決者為 0 時恆為 0
				"votes_bound": e.scalar(t, `SELECT count(*) FROM access_request_approvals a JOIN access_request_items i ON i.id = a.item_id AND i.request_id = a.request_id
 WHERE a.request_id = ? AND a.approver_id = ? AND i.requester_id = ? AND i.asset_id = ? AND i.status = ?`, reqID, f.approver, f.ag, f.asset.ID, model.AccessRequestPending),
				// 申請單與項目的綁定：項目必須指向一張與它同申請人、同資產（及同執行者）的申請單；孤立項目與未掛項目的申請單都不得出現
				"items_bound": e.scalar(t, `SELECT count(*) FROM access_request_items i JOIN access_requests r ON r.id = i.request_id
 WHERE i.requester_id = ? AND i.asset_id = ? AND r.requester_id = ? AND r.asset_id = ? AND (r.executor_user_id = ? OR ? = 0)`, f.ag, f.asset.ID, f.ag, f.asset.ID, f.executor, f.executor),
				"requests_with_item": e.scalar(t, `SELECT count(*) FROM access_requests r WHERE r.requester_id = ? AND r.asset_id = ?
 AND EXISTS (SELECT 1 FROM access_request_items i WHERE i.request_id = r.id AND i.requester_id = r.requester_id AND i.asset_id = r.asset_id)`, f.ag, f.asset.ID),
				"requests_all": e.scalar(t, "SELECT count(*) FROM access_requests WHERE requester_id = ? AND asset_id = ?", f.ag, f.asset.ID),
				"items_all":    e.scalar(t, "SELECT count(*) FROM access_request_items WHERE requester_id = ? AND asset_id = ?", f.ag, f.asset.ID),
				"pending":      e.scalar(t, "SELECT count(*) FROM access_requests WHERE requester_id = ? AND status = ?", f.ag, model.AccessRequestPending),
				"grants":       e.scalar(t, "SELECT count(*) FROM asset_authorizations WHERE source = 'ticket' AND deleted_at IS NULL"),
			}
		}
		want := func(base map[string]int64, c map[string]bool, _ string) map[string]int64 {
			g, x := b2i(c["group"]), b2i(c["request"])
			out := map[string]int64{
				"authz_version":     base["authz_version"] + g,
				"group_roles":       base["group_roles"] + g,
				"group_role_target": base["group_role_target"] + g,
				"audit_assign":      base["audit_assign"] + g,
				"grants":            base["grants"],
			}
			if decide {
				// 一票記入、單維持待審；申請單與項目已在夾具階段存在
				out["requests"], out["items"], out["pending"] = base["requests"], base["items"], base["pending"]
				out["votes"] = base["votes"] + x
				out["votes_bound"] = base["votes_bound"] + x
				out["items_bound"], out["requests_with_item"] = base["items_bound"], base["requests_with_item"]
				out["requests_all"], out["items_all"] = base["requests_all"], base["items_all"]
			} else {
				out["requests"] = base["requests"] + x
				out["items"] = base["items"] + x
				out["pending"] = base["pending"] + x
				out["votes"] = base["votes"]
				// 新申請單恰帶一個項目，項目掛在這張申請單上；沒有孤立項目、沒有空申請單
				out["votes_bound"] = base["votes_bound"]
				out["items_bound"] = base["items_bound"] + x
				out["requests_with_item"] = base["requests_with_item"] + x
				out["requests_all"] = base["requests_all"] + x
				out["items_all"] = base["items_all"] + x
			}
			return out
		}
		e.runCycle(t, cycleSpec{
			subcase: "request_fk_vs_group_add/" + sub,
			shared:  fmt.Sprintf("users:%d", f.ag),
			a: lockActor{name: "group", stop: groupStop, app: e.appA, start: func() error {
				_, err := e.groups.ReplaceRoleBindings(e.op(), f.gid, GroupRoleBindingsRequest{RoleIDs: []uint{e.role}})
				return err
			}},
			b: lockActor{name: "request", stop: reqStop, app: e.appB, start: func() error {
				if decide {
					_, err := f.svc.Approve(f.approver, false, reqID, authz.DecideInput{})
					return err
				}
				_, err := f.svc.Submit(f.ag, "lo-n3c-requester", false, f.submitInput())
				return err
			}},
			plans: map[string]cyclePlan{
				"group":   {class: "nowait"},
				"request": {class: "wait", kind: "row"},
			},
			snap: snap, want: want,
		}, order)
	})
}
