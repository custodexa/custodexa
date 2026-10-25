package session

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 會話建立與使用者層鎖序的真 PostgreSQL 交錯測試（三組、六個葉子）。
//
//   - agent_session_owner_fk：建立 agent 會話（寫 sessions.owner_user_id 外鍵、鎖 token 列）
//     與簽發 token、與停用擁有者交錯。
//   - capability_paths：連線兌換建會話、監看訂閱建立，各與停用交錯，世代重驗在鎖內。
//   - agent_session_vs_request_decision：agent 會話（鎖 token 列、再鎖申請單）與申請單核准、拒絕
//     （鎖申請單、再鎖申請人）的交錯。
//
// 掛點是包級共用狀態，本測試不使用 t.Parallel。

// sessionLockFKSessionOwner 是 sessions.owner_user_id 的正式外鍵（遷移以匿名 REFERENCES 建立，預設命名）。
const sessionLockFKSessionOwner = "sessions_owner_user_id_fkey"

func TestSessionUserLockOrderPG(t *testing.T) {
	t.Run("agent_session_owner_fk", func(t *testing.T) {
		t.Run("token_create", func(t *testing.T) { runAgentSessionOwnerFK(t, "token_create") })
		t.Run("owner_disable", func(t *testing.T) { runAgentSessionOwnerFK(t, "owner_disable") })
	})
	t.Run("capability_paths", func(t *testing.T) {
		t.Run("create", func(t *testing.T) { runSessionCapabilityPaths(t, "create") })
		t.Run("join", func(t *testing.T) { runSessionCapabilityPaths(t, "join") })
	})
	t.Run("agent_session_vs_request_decision", func(t *testing.T) {
		t.Run("approve", func(t *testing.T) { runAgentSessionVsRequestDecision(t, "approve") })
		t.Run("reject", func(t *testing.T) { runAgentSessionVsRequestDecision(t, "reject") })
	})
}

// agentSessionFixture 一個擁有者 O、其 agent A（A 的編號大於 O）、A 的一把現行 token，
// 與 A 自己申請且自己執行的任務單 R（會話綁定的任務）。withPending 時 R 另有一項待審。
type agentSessionFixture struct {
	e                      *sessionLockEnv
	owner, agent, approver uint
	token, task            uint
	pendingAsset           uint
	svc                    *SessionService
	reqSvc                 *authz.AccessRequestService
}

func (e *sessionLockEnv) newAgentSessionFixture(t *testing.T, withPending bool) *agentSessionFixture {
	t.Helper()
	f := &agentSessionFixture{e: e}
	f.owner = e.humanUser(t, "slo-owner")
	f.agent = e.agentUser(t, "slo-agent", f.owner)
	f.approver = e.humanUser(t, "slo-approver")
	require.Less(t, f.owner, f.agent, "fixture：擁有者編號必須小於 agent")

	approval := model.AccessPolicyApproval
	mkAsset := func(name string, ap *string) model.Asset {
		a := model.Asset{Name: name, Protocol: model.ProtocolSSH, Host: "h", Port: 22, CreatedBy: e.root, Active: true, AccessPolicy: ap}
		require.NoError(t, e.dbA.Create(&a).Error)
		cred := model.Credential{Username: "app", Scope: model.CredentialScopeDedicated, SecretType: "password", ProtocolFamily: model.ProtocolFamilySSH}
		require.NoError(t, e.dbA.Create(&cred).Error)
		require.NoError(t, e.dbA.Create(&model.AssetAccount{AssetID: a.ID, CredentialID: cred.ID, Username: "app"}).Error)
		aa, uu := a.ID, f.agent
		require.NoError(t, e.dbA.Create(&model.AssetAuthorization{UserID: &uu, AssetID: &aa, Permission: model.PermissionView, GrantedBy: e.root}).Error)
		return a
	}
	open := mkAsset("slo-open", nil)
	items := []authz.ItemInput{{AssetID: open.ID, Accounts: strs("app")}}
	if withPending {
		pending := mkAsset("slo-approval", &approval)
		f.pendingAsset = pending.ID
		pa, ap := pending.ID, f.approver
		require.NoError(t, e.dbA.Create(&model.ApproverScope{ApproverID: &ap, AssetID: &pa, GrantedBy: e.root}).Error)
		items = append([]authz.ItemInput{{AssetID: pending.ID, Accounts: strs("app")}}, items...)
	}

	policies := policy.NewSecurityPolicyService(e.dbB)
	accessPolicy := policy.NewAccessPolicyService(e.dbB, policies, authz.NewAssetAuthorizationService(e.dbB))
	f.reqSvc = authz.NewAccessRequestService(e.dbB, policies, accessPolicy, nil, nil)
	f.reqSvc.SetAccountPresenceSource(func(db *gorm.DB, id uint, name string) (bool, error) {
		var n int64
		err := db.Table("asset_accounts").Where("asset_id=? AND username=? AND deleted_at IS NULL", id, name).Count(&n).Error
		return n > 0, err
	})
	r, err := f.reqSvc.Submit(f.agent, "slo-agent", false, authz.SubmitAccessRequestInput{Items: items, Reason: "maintenance", DurationMinutes: 60})
	require.NoError(t, err, "fixture：agent 自己申請並自己執行的任務單")
	f.task = r.ID
	if withPending {
		require.Equal(t, model.AccessRequestPending, r.Status, "fixture：任務單一項已核准、一項待審")
	}

	tok := model.AgentToken{UserID: f.agent, Name: "slo-t0", TokenHash: strings.Repeat("a", 64), CreatedBy: e.root, ExpiresAt: time.Now().Add(24 * time.Hour)}
	require.NoError(t, e.dbA.Create(&tok).Error)
	f.token = tok.ID

	// 會話來源以正式組裝的兩個回呼組合（同服務啟動組裝），不用只鎖 token 的替身
	f.svc = NewSessionService(nil)
	f.svc.SetAgentActorSource(func(tx *gorm.DB, sess *model.Session) error {
		if err := identity.BindAgentSessionPrincipal(tx, sess); err != nil {
			return err
		}
		return authz.BindAgentSessionTask(tx, sess)
	})
	return f
}

func strs(v ...string) *[]string { return &v }

// create 以正式的鎖內建立路徑建立 agent 會話（全域資料庫連線，即連線池 A）。
func (f *agentSessionFixture) create() error {
	tok, task := f.token, f.task
	sess := model.Session{UserID: f.agent, Protocol: model.ProtocolSSH, AgentTokenID: &tok, AccessRequestID: &task}
	return f.svc.CreateWithGenerationGuard(crypto.AuthContext{}, &sess)
}

func (f *agentSessionFixture) sessions(t *testing.T) int64 {
	return f.e.scalar(t, `SELECT count(*) FROM sessions WHERE user_id = ? AND agent_token_id = ? AND access_request_id = ? AND owner_user_id = ? AND actor_kind = 'agent' AND deleted_at IS NULL`,
		f.agent, f.token, f.task, f.owner)
}

// runAgentSessionOwnerFK：agent 會話建立在持有 A 的憑證鎖與 token 列之後，寫 sessions.owner_user_id 外鍵（對擁有者列取共享鎖）。
//   - token_create：簽發 token 先持擁有者 O 的鎖、尚未取 agent A 的鎖；會話先行則簽發等 A 的鎖。
//   - owner_disable：停用 O 在推進擁有者世代、尚未碰 token 列時；會話先行則停用等 token 列。
func runAgentSessionOwnerFK(t *testing.T, sub string) {
	other := "token"
	otherPoint, otherApp := "agent_token_after_owner_lock", ""
	if sub == "owner_disable" {
		other, otherPoint = "disable", "agent_tokens_before_suspend"
	}
	eachOrder(t, other, "session", func(t *testing.T, order string) {
		e := newSessionLockEnv(t, "fk_users_owner")
		f := e.newAgentSessionFixture(t, false)
		e.fkNameOn(t, "sessions", "owner_user_id")
		require.Equal(t, sessionLockFKSessionOwner, e.fks[len(e.fks)-1])
		otherApp = e.appB

		otherStop, sessStop := newSessionLockStop(), newSessionLockStop()
		release := e.installAppHooks(map[string]*sessionLockStop{
			otherPoint + "@" + otherApp:                otherStop,
			"agent_session_after_token_lock@" + e.appA: sessStop,
		}, func(point string, ids []uint) bool {
			if len(ids) == 0 {
				return false
			}
			if point == "agent_session_after_token_lock" {
				return ids[0] == f.agent
			}
			return ids[0] == f.owner
		})
		defer release()

		tokenSvc := identity.NewAgentTokenService(e.dbB, audit.NewTxSink())
		snap := func() map[string]int64 {
			return map[string]int64{
				"sessions":         f.sessions(t),
				"tokens":           e.scalar(t, "SELECT count(*) FROM agent_tokens WHERE user_id = ?", f.agent),
				"token_audit":      e.scalar(t, "SELECT count(*) FROM audit_logs WHERE resource = ? AND action = ?", string(model.ResourceAgentToken), string(model.ActionCreate)),
				"t0_suspended":     e.scalar(t, "SELECT count(*) FROM agent_tokens WHERE id = ? AND suspended_at IS NOT NULL", f.token),
				"owner_active":     e.scalar(t, "SELECT count(*) FROM users WHERE id = ? AND active", f.owner),
				"owner_epoch":      e.scalar(t, "SELECT credential_epoch FROM users WHERE id = ?", f.owner),
				"authz_version":    e.scalar(t, "SELECT version FROM authz_state WHERE id = 1"),
				"suspend_lifecyle": e.scalar(t, "SELECT count(*) FROM audit_logs WHERE action = ?", string(model.ActionAgentTokenSuspended)),
			}
		}
		want := func(base map[string]int64, c map[string]bool, _ string) map[string]int64 {
			s, o := b2i(c["session"]), b2i(c[other])
			out := map[string]int64{
				"sessions": base["sessions"] + s, "tokens": base["tokens"], "token_audit": base["token_audit"],
				"t0_suspended": base["t0_suspended"], "owner_active": base["owner_active"], "owner_epoch": base["owner_epoch"],
				"authz_version": base["authz_version"], "suspend_lifecyle": base["suspend_lifecyle"],
			}
			if sub == "token_create" {
				out["tokens"] += o
				out["token_audit"] += o
			} else {
				// 停用擁有者：擁有者世代與權限版本各推進一次，擁有者名下的 token 被暫停（含會話所用的那把）
				out["owner_active"] -= o
				out["owner_epoch"] += o
				out["authz_version"] += o
				out["t0_suspended"] += o
				out["suspend_lifecyle"] += o
			}
			return out
		}
		actorOther := sessionLockActor{name: other, stop: otherStop, app: e.appB}
		if sub == "token_create" {
			actorOther.start = func() error {
				_, err := tokenSvc.Create(f.agent, identity.CreateAgentTokenRequest{Name: "slo-t1", ExpiresAt: time.Now().Add(48 * time.Hour)},
					gatewayapi.Actor{UserID: e.root, Username: "slo-root"})
				return err
			}
		} else {
			actorOther.start = func() error { return e.users.UpdateStatusBy(e.op(), f.owner, false) }
		}
		e.runCycle(t, sessionCycleSpec{
			subcase: "agent_session_owner_fk/" + sub,
			shared:  fmt.Sprintf("users:%d,agent_tokens:%d", f.owner, f.token),
			a:       actorOther,
			b:       sessionLockActor{name: "session", stop: sessStop, app: e.appA, start: f.create},
			plans: map[string]sessionCyclePlan{
				// 簽發／停用先行：持擁有者的鎖（修後為不擋外鍵共享鎖的模式）、尚未碰 agent 或 token 列，會話完成它的外鍵寫入
				other: {class: "nowait"},
				// 會話先行：持 A 的鎖與 token 列，簽發等 A 的鎖、停用等 token 列
				"session": {class: "wait", kind: "row"},
			},
			snap: snap, want: want,
		}, order)
	})
}

// runSessionCapabilityPaths：連線兌換建會話（CreateWithGenerationGuard）與監看訂閱建立（JoinWithGenerationGuardTx）
// 各與帳號停用交錯。兩者都在 provider 鎖之後取該使用者的憑證鎖並在鎖內重驗世代，停用在同一把憑證鎖內推進世代；
// 所以兩個先後都只會在同一把憑證鎖上等待。能力路徑先行：它在停用之前完成；停用先行：它在鎖內看到帳號已停用而拒絕，
// 不建會話、不註冊訂閱。
func runSessionCapabilityPaths(t *testing.T, sub string) {
	eachOrder(t, sub, "disable", func(t *testing.T, order string) {
		e := newSessionLockEnv(t)
		u := model.User{Username: "slo-cap-user", Active: true, Kind: model.KindHuman, ExternalCredential: true}
		require.NoError(t, e.dbA.Create(&u).Error)
		p := model.OIDCProvider{Name: "slo-cap-provider", Issuer: "https://id.example.test/slo", ClientID: "client", Scopes: "openid", Enabled: true, AdmissionMode: model.AdmissionPreboundOnly, AdmissionRules: "{}"}
		require.NoError(t, e.dbA.Create(&p).Error)
		authCtx := crypto.AuthContext{AuthMethod: crypto.AuthMethodOIDC, ProviderID: p.ID, AuthEpoch: p.AuthEpoch, CredEpoch: u.CredentialEpoch}

		capStop, disableStop := newSessionLockStop(), newSessionLockStop()
		site := identity.OIDCSiteSessionCreate
		if sub == "join" {
			site = identity.OIDCSiteMonitorJoin
		}
		restoreSite := identity.SetOIDCProviderPreWriteStopForTest(func(s string) {
			if s == site {
				capStop.hit(nil)
			}
		})
		defer restoreSite()
		release := e.installAppHooks(map[string]*sessionLockStop{"user_status_before_advance@" + e.appB: disableStop},
			func(point string, ids []uint) bool { return len(ids) > 0 && ids[0] == u.ID })
		defer release()
		defer capStop.open()

		var registered atomic.Int64
		var capErr error
		svc := NewSessionService(nil)
		run := func() error {
			if sub == "create" {
				sess := model.Session{UserID: u.ID, Protocol: model.ProtocolSSH}
				capErr = svc.CreateWithGenerationGuard(authCtx, &sess)
			} else {
				_, capErr = JoinWithGenerationGuardTx(authCtx, u.ID, func(*gorm.DB) (bool, error) {
					registered.Add(1)
					return true, nil
				})
			}
			if errors.Is(capErr, identity.ErrCredentialGenerationStale) {
				return nil // 世代閘的合法業務拒絕，結果由資料斷言
			}
			return capErr
		}
		snap := func() map[string]int64 {
			return map[string]int64{
				"sessions":      e.scalar(t, "SELECT count(*) FROM sessions WHERE user_id = ? AND deleted_at IS NULL", u.ID),
				"registered":    registered.Load(),
				"active":        e.scalar(t, "SELECT count(*) FROM users WHERE id = ? AND active", u.ID),
				"epoch":         e.scalar(t, "SELECT credential_epoch FROM users WHERE id = ?", u.ID),
				"authz_version": e.scalar(t, "SELECT version FROM authz_state WHERE id = 1"),
			}
		}
		want := func(base map[string]int64, c map[string]bool, lead string) map[string]int64 {
			d := b2i(c["disable"])
			// 能力路徑只有先行才成功；停用先行時鎖內重驗拒絕，什麼都不留下
			made := b2i(lead == sub && c[sub])
			out := map[string]int64{"sessions": base["sessions"], "registered": base["registered"],
				"active": base["active"] - d, "epoch": base["epoch"] + d, "authz_version": base["authz_version"] + d}
			if sub == "create" {
				out["sessions"] += made
			} else {
				out["registered"] += made
			}
			return out
		}
		e.runCycle(t, sessionCycleSpec{
			subcase: "capability_paths/" + sub,
			shared:  fmt.Sprintf("users:%d,oidc_providers:%d", u.ID, p.ID),
			a:       sessionLockActor{name: sub, stop: capStop, app: e.appA, start: run},
			b:       sessionLockActor{name: "disable", stop: disableStop, app: e.appB, start: func() error { return e.users.UpdateStatusBy(e.op(), u.ID, false) }},
			plans: map[string]sessionCyclePlan{
				sub:       {class: "wait", kind: "advisory", advisoryUser: u.ID},
				"disable": {class: "wait", kind: "advisory", advisoryUser: u.ID},
			},
			snap: snap, want: want,
		}, order)
		if order == "disable_released_first" {
			require.ErrorIs(t, capErr, identity.ErrCredentialGenerationStale, "停用先行：鎖內重驗必須拒絕")
			// 失敗不留下任何東西，重試同樣被拒、仍不註冊
			require.NoError(t, run())
			require.ErrorIs(t, capErr, identity.ErrCredentialGenerationStale)
			require.EqualValues(t, 0, snap()["registered"]+snap()["sessions"], "拒絕後不得重複註冊或建立")
		} else {
			require.NoError(t, capErr)
		}
	})
}

// runAgentSessionVsRequestDecision：agent 會話建立（持 A 的憑證鎖、鎖 token 列、再鎖任務單）與任務單的
// 核准或拒絕（鎖任務單列、再鎖申請人 A 的使用者列）互相請求對方的資源。A 是申請人兼執行者，任務單一項已核准、一項待審。
// 兩種先後修後都是 wait：決定先行持任務單，會話等任務單前先被擋；會話先行持 A 的鎖，決定等 A 的列。
func runAgentSessionVsRequestDecision(t *testing.T, sub string) {
	eachOrder(t, sub, "session", func(t *testing.T, order string) {
		e := newSessionLockEnv(t)
		f := e.newAgentSessionFixture(t, true)

		decStop, sessStop := newSessionLockStop(), newSessionLockStop()
		release := e.installAppHooks(map[string]*sessionLockStop{
			"request_decide_before_requester_lock@" + e.appB: decStop,
			"agent_session_principal_bound@" + e.appA:        sessStop,
		}, func(point string, ids []uint) bool { return len(ids) > 0 && ids[0] == f.agent })
		defer release()

		itemCount := func(t *testing.T, status model.AccessRequestStatus) int64 {
			return e.scalar(t, "SELECT count(*) FROM access_request_items WHERE request_id = ? AND status = ? AND deleted_at IS NULL", f.task, status)
		}
		var decideErr error
		snap := func() map[string]int64 {
			return map[string]int64{
				"sessions":      f.sessions(t),
				"items_pending": itemCount(t, model.AccessRequestPending),
				"items_approve": itemCount(t, model.AccessRequestApproved),
				"items_reject":  itemCount(t, model.AccessRequestRejected),
				"req_pending":   e.scalar(t, "SELECT count(*) FROM access_requests WHERE id = ? AND status = ?", f.task, model.AccessRequestPending),
				"grants":        e.scalar(t, "SELECT count(*) FROM asset_authorizations WHERE user_id = ? AND source = 'ticket' AND deleted_at IS NULL", f.agent),
				// 決定者與核准後回填的授權：決定的效果落在項目列上
				"decided_by_approver": e.scalar(t, "SELECT count(*) FROM access_request_items WHERE request_id = ? AND decided_by = ? AND deleted_at IS NULL", f.task, f.approver),
				"items_authorized":    e.scalar(t, "SELECT count(*) FROM access_request_items WHERE request_id = ? AND authorization_id IS NOT NULL AND deleted_at IS NULL", f.task),
			}
		}
		want := func(base map[string]int64, c map[string]bool, _ string) map[string]int64 {
			s, d := b2i(c["session"]), b2i(c[sub])
			out := map[string]int64{
				"sessions": base["sessions"] + s, "items_pending": base["items_pending"], "items_approve": base["items_approve"],
				"items_reject": base["items_reject"], "req_pending": base["req_pending"], "grants": base["grants"],
				"decided_by_approver": base["decided_by_approver"] + d, "items_authorized": base["items_authorized"],
			}
			out["items_pending"] -= d
			out["req_pending"] -= d // 唯一待審項目被決定，整張單離開待審
			if sub == "approve" {
				out["items_approve"] += d
				out["grants"] += d
				out["items_authorized"] += d
			} else {
				out["items_reject"] += d
			}
			return out
		}
		e.runCycle(t, sessionCycleSpec{
			subcase: "agent_session_vs_request_decision/" + sub,
			shared:  fmt.Sprintf("users:%d,access_requests:%d", f.agent, f.task),
			a: sessionLockActor{name: sub, stop: decStop, app: e.appB, start: func() error {
				if sub == "approve" {
					_, decideErr = f.reqSvc.Approve(f.approver, false, f.task, authz.DecideInput{})
				} else {
					_, decideErr = f.reqSvc.Reject(f.approver, false, f.task, "not needed")
				}
				return decideErr
			}},
			b: sessionLockActor{name: "session", stop: sessStop, app: e.appA, start: f.create},
			plans: map[string]sessionCyclePlan{
				sub:       {class: "wait", kind: "row"},
				"session": {class: "wait", kind: "row"},
			},
			snap: snap, want: want,
		}, order)
	})
}
