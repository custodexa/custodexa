package session

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/crypto"
)

// 輔助模式（人類申請人指定 agent 執行）的使用者層鎖序真 PostgreSQL 測試。
//
// 單的執行者 agent A 的編號小於申請人 X。三個入口各自存取 A 與 X：
//   - 核准剩餘項目：交易第一個動作以一條升冪語句鎖申請人與執行者的使用者列，之後才碰申請單。
//   - agent 以已核准項目建立會話：先取 A 的憑證鎖與 token 列，再鎖申請單，外鍵寫入涉及 X 與擁有者。
//   - A 的擁有者轉移：鎖 A 的使用者列後判定，外鍵寫入涉及新擁有者。
//
// 兩個測試：
//   - 併發：三者並行多輪，不得出現死結（40P01）或鎖等待逾時（55P03），三者都要完成且結果一致。
//   - 等待證明：擁有者轉移停在已持 A 的使用者列鎖之處，核准入口必須被它擋住（pg_locks 正向證明），
//     且此刻核准入口尚未鎖申請單（觀測連線對申請單列取 NOWAIT 鎖會成功）。
//
// 掛點是包級共用狀態，本測試不使用 t.Parallel。

const executorLockRounds = 20

type executorLockFixture struct {
	agent, owner, newOwner, approver, requester uint
	token, task                                 uint
	svc                                         *SessionService
}

// newExecutorLockFixture 建一組輔助模式的單：X 指定 A 執行，兩項（一項自動核准、一項待審），
// 審核者 P 的審核範圍涵蓋待審資產；X 與 A 對兩項資產都持常設 connect。
func (e *sessionLockEnv) newExecutorLockFixture(t *testing.T, reqSvc *authz.AccessRequestService, tag string) *executorLockFixture {
	t.Helper()
	f := &executorLockFixture{}
	f.owner = e.humanUser(t, "xo-owner-"+tag)
	f.agent = e.agentUser(t, "xo-agent-"+tag, f.owner)
	f.newOwner = e.humanUser(t, "xo-newowner-"+tag)
	f.approver = e.humanUser(t, "xo-approver-"+tag)
	f.requester = e.humanUser(t, "xo-requester-"+tag)
	require.Less(t, f.agent, f.requester, "夾具：執行者編號必須小於申請人")

	approval := model.AccessPolicyApproval
	mkAsset := func(name string, ap *string) model.Asset {
		a := model.Asset{Name: name + "-" + tag, Protocol: model.ProtocolSSH, Host: "h", Port: 22, CreatedBy: e.root, Active: true, AccessPolicy: ap}
		require.NoError(t, e.dbA.Create(&a).Error)
		cred := model.Credential{Username: "app", Scope: model.CredentialScopeDedicated, SecretType: "password", ProtocolFamily: model.ProtocolFamilySSH}
		require.NoError(t, e.dbA.Create(&cred).Error)
		require.NoError(t, e.dbA.Create(&model.AssetAccount{AssetID: a.ID, CredentialID: cred.ID, Username: "app"}).Error)
		for _, u := range []uint{f.requester, f.agent} {
			uu, aa := u, a.ID
			require.NoError(t, e.dbA.Create(&model.AssetAuthorization{UserID: &uu, AssetID: &aa, Permission: model.PermissionConnect, GrantedBy: e.root}).Error)
		}
		return a
	}
	open := mkAsset("xo-open", nil)
	pending := mkAsset("xo-approval", &approval)
	pa, ap := pending.ID, f.approver
	require.NoError(t, e.dbA.Create(&model.ApproverScope{ApproverID: &ap, AssetID: &pa, GrantedBy: e.root}).Error)

	agent := f.agent
	r, err := reqSvc.Submit(f.requester, "xo-requester-"+tag, false, authz.SubmitAccessRequestInput{
		Items:          []authz.ItemInput{{AssetID: pending.ID, Accounts: strs("app")}, {AssetID: open.ID, Accounts: strs("app")}},
		ExecutorUserID: &agent, Reason: "maintenance", DurationMinutes: 60,
	})
	require.NoError(t, err, "夾具：輔助模式建單")
	require.Equal(t, model.AccessRequestPending, r.Status, "夾具：一項自動核准、一項待審")
	f.task = r.ID

	tok := model.AgentToken{UserID: f.agent, Name: "xo-t0-" + tag, TokenHash: fmt.Sprintf("%064s", tag), CreatedBy: e.root, ExpiresAt: time.Now().Add(24 * time.Hour)}
	require.NoError(t, e.dbA.Create(&tok).Error)
	f.token = tok.ID

	f.svc = NewSessionService(nil)
	f.svc.SetAgentActorSource(func(tx *gorm.DB, sess *model.Session) error {
		if err := identity.BindAgentSessionPrincipal(tx, sess); err != nil {
			return err
		}
		return authz.BindAgentSessionTask(tx, sess)
	})
	return f
}

func (e *sessionLockEnv) newExecutorRequestService() *authz.AccessRequestService {
	policies := policy.NewSecurityPolicyService(e.dbB)
	accessPolicy := policy.NewAccessPolicyService(e.dbB, policies, authz.NewAssetAuthorizationService(e.dbB))
	svc := authz.NewAccessRequestService(e.dbB, policies, accessPolicy, nil, nil)
	svc.SetAccountPresenceSource(func(db *gorm.DB, id uint, name string) (bool, error) {
		var n int64
		err := db.Table("asset_accounts").Where("asset_id=? AND username=? AND deleted_at IS NULL", id, name).Count(&n).Error
		return n > 0, err
	})
	return svc
}

func (f *executorLockFixture) approve(reqSvc *authz.AccessRequestService) error {
	_, err := reqSvc.Approve(f.approver, false, f.task, authz.DecideInput{})
	return err
}

// createSession 走正式的鎖內建立路徑（全域資料庫連線，即連線池 A）。
func (f *executorLockFixture) createSession() error {
	tok, task := f.token, f.task
	sess := model.Session{UserID: f.agent, Protocol: model.ProtocolSSH, AgentTokenID: &tok, AccessRequestID: &task}
	return f.svc.CreateWithGenerationGuard(crypto.AuthContext{}, &sess)
}

func (e *sessionLockEnv) transferOwner(f *executorLockFixture) error {
	no := f.newOwner
	_, _, err := e.users.Update(identity.Operator{}, f.agent, &identity.UpdateUserRequest{OwnerUserID: &no})
	return err
}

// 三者並行多輪：無死結、無逾時、結果一致。
func TestExecutorSideUserLockOrderPGConcurrent(t *testing.T) {
	e := newSessionLockEnv(t)
	reqSvc := e.newExecutorRequestService()

	for round := 1; round <= executorLockRounds; round++ {
		tag := fmt.Sprintf("c%02d", round)
		f := e.newExecutorLockFixture(t, reqSvc, tag)

		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := map[string]error{}
		var mu sync.Mutex
		run := func(name string, fn func() error) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				err := fn()
				mu.Lock()
				errs[name] = err
				mu.Unlock()
			}()
		}
		run("approve", func() error { return f.approve(reqSvc) })
		run("session", f.createSession)
		run("transfer", func() error { return e.transferOwner(f) })
		close(start)
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(sessionLockDeadline):
			t.Fatalf("round %d：三者在 deadline 內未全部返回（疑似死結或鎖等待）", round)
		}
		for name, err := range errs {
			c := pgCode(err)
			require.NotEqual(t, "40P01", c, "round %d %s 死結：%v", round, name, err)
			require.NotEqual(t, "55P03", c, "round %d %s 鎖等待逾時：%v", round, name, err)
			require.NoError(t, err, "round %d %s", round, name)
		}
		require.EqualValues(t, 1, e.scalar(t, "SELECT count(*) FROM access_requests WHERE id = ? AND status = 'approved'", f.task), "round %d：單應已核准", round)
		require.EqualValues(t, 1, e.scalar(t, "SELECT count(*) FROM users WHERE id = ? AND owner_user_id = ?", f.agent, f.newOwner), "round %d：擁有者應已轉移", round)
		require.EqualValues(t, 1, e.scalar(t, "SELECT count(*) FROM sessions WHERE user_id = ? AND access_request_id = ? AND deleted_at IS NULL", f.agent, f.task), "round %d：會話應已建立", round)
	}
	t.Logf("EVIDENCE dialect=postgres subcase=executor_side_concurrent rounds=%d deadlock=0 lock_timeout=0 attested=false", executorLockRounds)
}

// 等待證明：擁有者轉移持有 A 的使用者列鎖時，核准入口在鎖使用者列的第一步就被擋住，尚未碰申請單。
func TestExecutorSideUserLockOrderPGApproveWaitsOnUserRow(t *testing.T) {
	e := newSessionLockEnv(t)
	reqSvc := e.newExecutorRequestService()
	f := e.newExecutorLockFixture(t, reqSvc, "w")

	transferStop := newSessionLockStop()
	release := e.installAppHooks(map[string]*sessionLockStop{
		"owner_transfer_after_guard@" + e.appB: transferStop,
	}, func(point string, ids []uint) bool { return len(ids) > 0 && ids[0] == f.agent })
	defer release()

	doneTransfer, doneApprove := make(chan error, 1), make(chan error, 1)
	go func() { doneTransfer <- e.transferOwner(f) }()
	pidTransfer := awaitSessionStop(t, transferStop, "擁有者轉移")
	e.caseBackends(t, pidTransfer)

	go func() { doneApprove <- f.approve(reqSvc) }()
	var pidApprove int64
	deadline := time.Now().Add(sessionLockDeadline)
	for time.Now().Before(deadline) {
		if pidApprove = e.pidBlockedBy(t, e.appB, pidTransfer); pidApprove != 0 {
			break
		}
		select {
		case err := <-doneApprove:
			t.Fatalf("核准在被觀測到等待之前就返回了（err=%v）：沒有被擁有者轉移擋住", err)
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
	require.NotZero(t, pidApprove, "核准入口未被觀測到正在等擁有者轉移")
	proof := e.awaitBlocked(t, pidApprove, pidTransfer, 0, doneApprove)
	require.Equal(t, "row", proof.kind, "等待的是使用者列鎖")

	// 核准入口此刻停在鎖使用者列這一步，尚未鎖申請單：觀測連線能立即取得該列的 NOWAIT 鎖
	require.NoError(t, e.obs.Transaction(func(tx *gorm.DB) error {
		var id uint
		return tx.Raw("SELECT id FROM access_requests WHERE id = ? FOR UPDATE NOWAIT", f.task).Scan(&id).Error
	}), "核准入口先鎖了申請單再等使用者列：鎖序與其他入口相反")

	t.Logf("EVIDENCE dialect=postgres subcase=executor_side_wait pids=%d,%d blocked=%s/%s/%s kind=%s key=%s request_row_free=true attested=false",
		pidTransfer, pidApprove, proof.locktype, proof.wmode, proof.hmode, proof.kind, proof.key)

	transferStop.open()
	require.NoError(t, recvErr(t, doneTransfer, "擁有者轉移"))
	require.NoError(t, recvErr(t, doneApprove, "核准"))
	require.EqualValues(t, 1, e.scalar(t, "SELECT count(*) FROM access_requests WHERE id = ? AND status = 'approved'", f.task))
}
