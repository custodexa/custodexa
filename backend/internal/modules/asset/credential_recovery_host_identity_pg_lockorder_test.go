package asset

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 本檔是 TestCredentialRecoveryHostIdentityPG 的 lock_order_with_dispatch（M-6A-d）。
//
// 鎖序主張：綁定短交易（bindWorkRow）與承接短交易不持 assets 列或憑證列；提交交易取主機金鑰鎖時已持 assets 列、
// 尚未持憑證列；任何交易不碰 authz_state。以真實共用列（同一資產、同一憑證）起三條交易並用 pg_locks 正向證明交錯確實發生：
//
//	T1  提交交易（promoteToCredential）：取得 assets 列與主機金鑰鎖後，停在第一個對憑證表的鎖定語句之前。
//	T2  綁定短交易（bindWorkRow，同資產）：排在主機金鑰鎖上，此時不持 assets 列或憑證列。
//	T3  另一個提交交易（同資產另一帳號）：排在 T1 持有的 assets 列鎖上，尚未取主機金鑰鎖。
//
//	T4  成員派送的判定＋領取短交易（revalidateMember，同資產另一個掛載）：第一個動作取拓撲序列化鎖，
//	    鎖後判定並寫 dispatch claim。T1 持 assets 列與主機金鑰鎖、T2／T3 在等時，T4 停在領取寫入之後：
//	    它只持拓撲鎖與成員列，不請求也不持主機金鑰鎖、assets 列或憑證列，也沒有被任何一方擋住；
//	    T1–T3 都不取拓撲鎖。兩組之間沒有等待邊，四方不會成環。成員表沒有外鍵，更新非鍵欄不對父列取 KEY SHARE。

// loHooks 取 pid 與停 T1 的掛點。pid 一律在交易內以 pg_backend_pid() 取得（同一條連線）。
type loHooks struct {
	t1Armed   atomic.Bool
	t1Reached chan int
	t1Release chan struct{}
	t1Timeout atomic.Bool
	relOnce   sync.Once
	armed     atomic.Int32 // 0＝未啟用；2＝下一條交易是 T2；3＝下一條交易是 T3

	mu     sync.Mutex
	t2Pid  int
	t3Pid  int
	sqlLog []string
}

func (h *loHooks) release() { h.relOnce.Do(func() { close(h.t1Release) }) }

func (h *loHooks) pids() (int, int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.t2Pid, h.t3Pid
}

func loTxPid(tx *gorm.DB) (int, bool) {
	if tx.Statement == nil || tx.Statement.ConnPool == nil {
		return 0, false
	}
	if _, ok := tx.Statement.ConnPool.(gorm.TxCommitter); !ok {
		return 0, false
	}
	var pid int
	if err := tx.Statement.ConnPool.QueryRowContext(tx.Statement.Context, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		return 0, false
	}
	return pid, true
}

func (h *loHooks) installRecorder(t *testing.T, db *gorm.DB, tag string) {
	t.Helper()
	rec := func(tx *gorm.DB) {
		if tx.Statement != nil {
			h.mu.Lock()
			h.sqlLog = append(h.sqlLog, tx.Statement.SQL.String())
			h.mu.Unlock()
		}
	}
	cb := db.Callback()
	require.NoError(t, cb.Query().After("gorm:query").Register("lo:rec_q_"+tag, rec))
	require.NoError(t, cb.Row().After("gorm:row").Register("lo:rec_r_"+tag, rec))
	require.NoError(t, cb.Raw().After("gorm:raw").Register("lo:rec_w_"+tag, rec))
	require.NoError(t, cb.Create().After("gorm:create").Register("lo:rec_c_"+tag, rec))
	require.NoError(t, cb.Update().After("gorm:update").Register("lo:rec_u_"+tag, rec))
	require.NoError(t, cb.Delete().After("gorm:delete").Register("lo:rec_d_"+tag, rec))
}

// installT1 在實例一的連線池上攔截第一個「SELECT id FROM credentials ... FOR UPDATE」：
// 此時 T1 已持 assets 列與主機金鑰鎖，憑證列尚未取。
func (h *loHooks) installT1(t *testing.T, db *gorm.DB) {
	t.Helper()
	fn := func(tx *gorm.DB) {
		sql := tx.Statement.SQL.String()
		if !strings.Contains(sql, "FROM credentials WHERE id") || !strings.Contains(sql, "FOR UPDATE") {
			return
		}
		if !h.t1Armed.CompareAndSwap(true, false) {
			return
		}
		pid, ok := loTxPid(tx)
		if !ok {
			pid = -1
		}
		h.t1Reached <- pid
		select {
		case <-h.t1Release:
		case <-time.After(60 * time.Second):
			h.t1Timeout.Store(true)
		}
	}
	require.NoError(t, db.Callback().Row().Before("gorm:row").Register("lo:t1_row", fn))
	require.NoError(t, db.Callback().Query().Before("gorm:query").Register("lo:t1_query", fn))
}

// installT2T3 在實例二的連線池上，由 arm 指定的槽位記下「下一條交易的第一個語句」所在連線的 pid。
// 呼叫端依序 arm(T2)、啟動 T2、等到 pid、再 arm(T3)、啟動 T3，所以不依賴語句內容（突變後取鎖次序不同時仍能取到 pid）。
func (h *loHooks) installT2T3(t *testing.T, db *gorm.DB) {
	t.Helper()
	fn := func(tx *gorm.DB) {
		slot := h.armed.Load()
		if slot == 0 {
			return
		}
		pid, ok := loTxPid(tx)
		if !ok || !h.armed.CompareAndSwap(slot, 0) {
			return
		}
		h.mu.Lock()
		if slot == 2 {
			h.t2Pid = pid
		} else {
			h.t3Pid = pid
		}
		h.mu.Unlock()
	}
	require.NoError(t, db.Callback().Raw().Before("gorm:raw").Register("lo:slot_raw", fn))
	require.NoError(t, db.Callback().Row().Before("gorm:row").Register("lo:slot_row", fn))
	require.NoError(t, db.Callback().Query().Before("gorm:query").Register("lo:slot_query", fn))
}

const loKeyFilter = `locktype='advisory' AND database=(SELECT oid FROM pg_database WHERE datname=current_database())
	AND classid::bigint = ? AND objid::bigint = ? AND objsubid = 2 AND pid = ?`

func (e *pgBatchEnv) loCount(t *testing.T, where string, args ...any) int {
	t.Helper()
	var n int
	require.NoError(t, e.db2.Raw("SELECT count(*) FROM pg_locks WHERE "+where, args...).Scan(&n).Error)
	return n
}

// advisoryCount 限定 database、命名空間、資產 id、objsubid=2 與 pid；granted 為 nil 時不限。
func (e *pgBatchEnv) loAdvisory(t *testing.T, assetID uint, pid int, granted *bool) int {
	t.Helper()
	w, args := loKeyFilter, []any{int64(hostKeyLockNamespace), int64(assetID), pid}
	if granted != nil {
		w += " AND granted = ?"
		args = append(args, *granted)
	}
	return e.loCount(t, w, args...)
}

func (e *pgBatchEnv) loBlockedBy(t *testing.T, blocker, waiter int) bool {
	t.Helper()
	var ok bool
	require.NoError(t, e.db2.Raw("SELECT ? = ANY(pg_blocking_pids(?))", blocker, waiter).Scan(&ok).Error)
	return ok
}

// loRowLockHeld 用獨立交易以 NOWAIT 探該列：取得失敗（55P03）＝別人持有列鎖。
func (e *pgBatchEnv) loRowLockHeld(t *testing.T, table string, id uint) bool {
	t.Helper()
	tx := e.db2.Begin()
	require.NoError(t, tx.Error)
	defer tx.Rollback()
	err := tx.Exec("SELECT id FROM "+table+" WHERE id = ? FOR UPDATE NOWAIT", id).Error
	if err == nil {
		return false
	}
	require.Contains(t, err.Error(), "55P03", "NOWAIT 探測只允許 lock_not_available")
	return true
}

func runLockOrderWithDispatch(t *testing.T, e *pgBatchEnv) {
	f := e.f
	// T4 走正式的判定＋領取短交易：資產服務接上取真拓撲鎖的 port（T1–T3 的路徑不取拓撲鎖，行為不變）
	f.assets.SetTopologyPermissionPort(&pgTopologyPort{})

	// 同一資產兩個帳號（各自專用憑證），外加一個 pending 候選供 T2 綁定
	assetID, acc1 := f.addHost(t, "lo-h1", "10.38.9.1", "ops")
	acct2, err := f.accounts.Create(WithSystemCaller(adminCtx()), assetID, &CreateAssetAccountRequest{Username: "ops2", Password: "pw2"})
	require.NoError(t, err)
	acc2 := acct2.ID

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	_, err = e.svc2.Evaluate(assetID, "10.38.9.1", 22, sshPub)
	require.NoError(t, err)
	var own model.AssetHostKey
	require.NoError(t, e.db2.Where("asset_id = ?", assetID).First(&own).Error)

	mkBound := func(accountID uint) *model.ChangeSecretCandidate {
		b := f.bindingOf(t, accountID)
		require.NotNil(t, b.EffectiveVersionID)
		now := time.Now()
		c := model.ChangeSecretCandidate{
			AccountID: accountID, AssetID: assetID, AccountUsername: b.Username, SecretType: model.ChangeSecretTypePassword,
			CredentialID: b.CredentialID, TargetVersionID: *b.EffectiveVersionID,
			HostKeyBinding: model.HostKeyBindingBound, HostKeyTransport: model.HostKeyTransportSSH,
			HostKeyRecordID: own.ID, HostKeyAlgorithm: own.Algorithm, HostKeyFingerprint: own.Fingerprint,
			HostKeyGeneration: own.TrustGeneration, HostKeyBoundAt: &now,
		}
		require.NoError(t, f.db.Create(&c).Error)
		return &c
	}
	cand1, cand3 := mkBound(acc1), mkBound(acc2)
	pending := model.ChangeSecretCandidate{AccountID: 990001, AssetID: assetID, SecretType: model.ChangeSecretTypePassword,
		HostKeyBinding: model.HostKeyBindingPending}
	require.NoError(t, f.db.Create(&pending).Error)
	cred1 := f.bindingOf(t, acc1).CredentialID
	require.NotZero(t, cred1)

	h := &loHooks{t1Reached: make(chan int, 1), t1Release: make(chan struct{})}
	h.t1Armed.Store(true)
	t.Cleanup(h.release)
	h.installT1(t, f.db)
	h.installT2T3(t, e.db2)
	h.installRecorder(t, f.db, "p1")
	h.installRecorder(t, e.db2, "p2")
	candidates2, err := NewChangeSecretCandidateService(e.db2, aesColumnCodec(t, make([]byte, 32)), f.assets, audit.NewTxSink())
	require.NoError(t, err)

	yes, no := true, false
	var wg sync.WaitGroup
	errs := make(chan [2]any, 3)
	run := func(name string, fn func() error) {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- [2]any{name, fn()} }()
	}

	// T1：提交交易，停在憑證列之前
	run("T1", func() error { return f.candidates.promoteToCredential(adminCtx(), cand1, nil) })
	var t1 int
	select {
	case t1 = <-h.t1Reached:
	case <-time.After(10 * time.Second):
		t.Fatal("barrier 未觸發：T1 沒有走到憑證列鎖定語句")
	}
	require.Greater(t, t1, 0, "T1 pid 取得失敗（非交易連線）")

	// T1 的持有狀態：主機金鑰鎖 granted 恰 1、assets 列被鎖、憑證列未被鎖
	assert.Equal(t, 1, e.loAdvisory(t, assetID, t1, &yes), "T1 已持主機金鑰鎖")
	assert.Zero(t, e.loAdvisory(t, assetID, t1, &no), "T1 沒有在等主機金鑰鎖")
	assert.True(t, e.loRowLockHeld(t, "assets", assetID), "T1 已持 assets 列鎖")
	assert.False(t, e.loRowLockHeld(t, "credentials", cred1), "T1 尚未持憑證列鎖")

	// (i) T2：綁定短交易，同資產
	h.armed.Store(2)
	run("T2", func() error {
		_, err := e.svc2.bindWorkRow(assetID, HostKeyBindTarget{CandidateID: pending.ID}, sshPub)
		return err
	})
	var t2 int
	pollUntil(t, "T2 pid 取得", 5*time.Second, func() bool { t2, _ = h.pids(); return t2 > 0 })
	pollUntil(t, "T2 在主機金鑰鎖上等待（限定 database、key、pid）", 5*time.Second,
		func() bool { return e.loAdvisory(t, assetID, t2, &no) == 1 })
	assert.True(t, e.loBlockedBy(t, t1, t2), "擋住 T2 的是 T1")
	assert.Equal(t, 1, e.loAdvisory(t, assetID, t1, &yes), "同一 key 上 T1 granted 恰 1 列")
	assert.Zero(t, e.loAdvisory(t, assetID, t2, &yes))
	assert.Zero(t, e.loCount(t, `pid = ? AND locktype IN ('transactionid','tuple')`, t2), "T2 不持任何列鎖（沒有 xid、沒有 tuple）")
	assert.Zero(t, e.loCount(t, `pid = ? AND locktype = 'relation' AND granted AND relation IN
		(SELECT c.oid FROM pg_class c WHERE c.relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = current_schema())
		 AND c.relname IN ('assets','credentials'))`, t2), "T2 未碰 assets 或 credentials")

	// (ii) T3：同資產另一個提交交易
	h.armed.Store(3)
	run("T3", func() error { return candidates2.promoteToCredential(adminCtx(), cand3, nil) })
	var t3 int
	pollUntil(t, "T3 pid 取得", 5*time.Second, func() bool { _, t3 = h.pids(); return t3 > 0 })
	pollUntil(t, "T3 在 assets 列鎖上等待（限定 pid）", 5*time.Second, func() bool {
		return e.loCount(t, `pid = ? AND NOT granted AND locktype IN ('transactionid','tuple')`, t3) >= 1
	})
	assert.True(t, e.loBlockedBy(t, t1, t3), "擋住 T3 的是 T1")
	assert.Zero(t, e.loAdvisory(t, assetID, t3, &yes), "T3 尚未取得主機金鑰鎖")
	assert.Zero(t, e.loAdvisory(t, assetID, t3, &no), "T3 尚未請求主機金鑰鎖：先取 assets 列、後取主機金鑰鎖")
	assert.Equal(t, 1, e.loAdvisory(t, assetID, t2, &no), "T2 仍在等")
	assert.Equal(t, 1, e.loAdvisory(t, assetID, t1, &yes), "T1 仍持有")
	assert.False(t, e.loRowLockHeld(t, "credentials", cred1), "T1 仍未持憑證列鎖")

	// (iii) T4：成員派送的判定＋領取短交易（同資產的第二個掛載）
	runLockOrderMemberClaim(t, e, h, assetID, acc2, t1, t2, t3)

	// 放行 T1：三者照常完成，沒有死鎖
	h.release()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("放行 T1 後三條交易未在 30 秒內完成")
	}
	close(errs)
	for r := range errs {
		if r[1] != nil {
			err := r[1].(error)
			assert.NotContains(t, err.Error(), "40P01", "%v 不得死鎖", r[0])
			assert.NoError(t, err, "%v 必須成功完成", r[0])
		}
	}
	assert.False(t, h.t1Timeout.Load(), "T1 barrier 本身逾時")

	assert.Zero(t, f.candidateCountFor(t, acc1), "T1 消耗候選")
	assert.Zero(t, f.candidateCountFor(t, acc2), "T3 消耗候選")
	got := f.candidateOf(t, pending.ID)
	assert.Equal(t, model.HostKeyBindingBound, got.HostKeyBinding, "T2 綁定寫入")
	assert.Equal(t, own.Fingerprint, got.HostKeyFingerprint)

	h.mu.Lock()
	defer h.mu.Unlock()
	require.NotEmpty(t, h.sqlLog)
	for _, s := range h.sqlLog {
		assert.NotContains(t, s, "authz_state", "沒有任何交易觸碰 authz_state")
	}
}

// runLockOrderMemberClaim T1 持鎖、T2／T3 等待期間跑第四方：成員派送的判定＋領取短交易。
func runLockOrderMemberClaim(t *testing.T, e *pgBatchEnv, h *loHooks, assetID, accountID uint, t1, t2, t3 int) {
	t.Helper()
	f := e.f
	b := f.bindingOf(t, accountID)
	rot := model.CredentialRotation{CredentialID: b.CredentialID, Epoch: 1, Mode: model.CredentialRotationModeGroup,
		Status: model.CredentialRotationRunning, StartedAt: time.Now()}
	require.NoError(t, e.db2.Create(&rot).Error)
	auth, err := insertJobAuthorization(f.rotations.mgmt, e.db2, jobAuthInput{
		kind: model.JobAuthSourceRotation, sourceID: rot.ID, revision: 1, actorID: 1, actorName: "admin",
		via: model.JobAuthViaReauthorized, capabilities: []string{CredCapRotate},
	})
	require.NoError(t, err)
	require.NoError(t, e.db2.Model(&model.CredentialRotation{}).Where("id = ?", rot.ID).
		Update("authorization_id", auth.ID).Error)
	rot.AuthorizationID = &auth.ID
	member := model.CredentialRotationMember{RotationID: rot.ID, AccountID: accountID, CredentialID: b.CredentialID,
		AssetID: assetID, Username: b.Username, State: model.CredentialMemberQueued}
	require.NoError(t, e.db2.Create(&member).Error)

	reached := make(chan int, 1)
	release := make(chan struct{})
	var relOnce sync.Once
	rel := func() { relOnce.Do(func() { close(release) }) }
	t.Cleanup(rel)
	f.rotations.claimHook = func(stage string, tx *gorm.DB, _ uint) {
		if stage != claimStageClaimed {
			return
		}
		pid, ok := loTxPid(tx)
		if !ok {
			pid = -1
		}
		reached <- pid
		// 只等測試主程序觀測完成的訊號，不等任何被本交易擋住的交易
		select {
		case <-release:
		case <-time.After(30 * time.Second):
		}
	}
	defer func() { f.rotations.claimHook = nil }()
	done := make(chan string, 1)
	go func() { done <- f.rotations.revalidateMember(context.Background(), &rot, &member) }()

	var t4 int
	select {
	case t4 = <-reached:
	case <-time.After(10 * time.Second):
		t.Fatal("T4 未走到領取寫入點：判定＋領取短交易被 T1–T3 的鎖擋住")
	}
	require.Greater(t, t4, 0, "T4 pid 取得失敗（非交易連線）")

	class := int64(pgTopologyClassForTest)
	topo := `locktype='advisory' AND database=(SELECT oid FROM pg_database WHERE datname=current_database())
	AND classid::bigint = ? AND objid::bigint = 1 AND objsubid = 2 AND pid = ?`
	assert.Equal(t, 1, e.loCount(t, topo+" AND granted", class, t4), "T4 已持拓撲序列化鎖")
	for _, p := range []int{t1, t2, t3} {
		assert.Zero(t, e.loCount(t, topo, class, p), "T1–T3 不取拓撲序列化鎖（pid=%d）", p)
	}
	assert.Zero(t, e.loCount(t, "pid = ? AND NOT granted", t4), "T4 沒有在等任何鎖")
	var blockers int
	require.NoError(t, e.db2.Raw("SELECT coalesce(array_length(pg_blocking_pids(?), 1), 0)", t4).Scan(&blockers).Error)
	assert.Zero(t, blockers, "沒有任何交易擋住 T4")
	assert.Zero(t, e.loAdvisory(t, assetID, t4, nil), "T4 不請求也不持主機金鑰鎖")
	assert.Zero(t, e.loCount(t, `pid = ? AND locktype = 'relation' AND relation IN
		(SELECT c.oid FROM pg_class c WHERE c.relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = current_schema())
		 AND c.relname IN ('assets','credentials','asset_host_keys'))`, t4), "T4 未碰 assets、credentials 或主機金鑰表")
	assert.Equal(t, 1, e.loAdvisory(t, assetID, t1, boolPtr(true)), "T1 仍持主機金鑰鎖")
	assert.Equal(t, 1, e.loAdvisory(t, assetID, t2, boolPtr(false)), "T2 仍在等")
	t.Logf("EVIDENCE t4_pid=%d topology_granted=1 waiting=0 blockers=0 hostkey=0 t1_t3_topology=0", t4)
	fmt.Printf("EVIDENCE lock_order_fourth_party t4_pid=%d topology_granted=1 blockers=0\n", t4)

	rel()
	select {
	case reason := <-done:
		assert.Empty(t, reason, "T4 判定通過並提交領取")
	case <-time.After(10 * time.Second):
		t.Fatal("T4 放行後未完成")
	}
	var got model.CredentialRotationMember
	require.NoError(t, e.db2.First(&got, member.ID).Error)
	assert.NotNil(t, got.DispatchClaimedAt, "領取與判定一起提交")
}
