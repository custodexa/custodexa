package asset

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 本檔是 TestCredentialRecoveryHostIdentityPG 的第四、五個子測試（M-6A-c）：
// manual_confirm_vs_adopt、confirm_crash_barrier。工作種類為一般候選（真 SSH 靶機）。
// 第二實例（db2）負責採用、第二個確認；崩潰以測試掛點模擬行程在該點結束。

// pgConfirmTarget 一個停在「主機身分已變」的候選，承接服務接在實例一，另有實例二的承接服務。
type pgConfirmTarget struct {
	takeoverTarget
	e                 *pgIdentityEnv
	svc2              *HostIdentityTakeoverService
	verifies, rotates *atomic.Int32
	secretBefore      string
}

func newPGConfirmTarget(t *testing.T, e *pgIdentityEnv) *pgConfirmTarget {
	t.Helper()
	s := newPGRetryScenario(t, e)
	f := s.f
	cand := candidateOfAccount(t, f)
	g := &pgConfirmTarget{e: e, verifies: &atomic.Int32{}, rotates: &atomic.Int32{}, secretBefore: f.storedPassword(t)}
	orig := f.retry.executors
	f.retry.executors = func(ch string) rotationExecutor { return countingExecutor{orig(ch), g.verifies, g.rotates} }
	adoptRemoteKey(t, f.server, e.db2, f.assetID, true) // 實例二採用 B，遠端出示 B
	require.NoError(t, f.db.AutoMigrate(&model.CredentialHostIdentityConfirmation{}))
	svc := NewHostIdentityTakeoverService(f.db, s.authz).WithCandidateRunner(f.retry)
	svc.SetAuditTxSink(audit.NewTxSink())
	g.svc2 = NewHostIdentityTakeoverService(e.db2, s.authz).WithCandidateRunner(f.retry)
	g.svc2.SetAuditTxSink(audit.NewTxSink())
	g.takeoverTarget = takeoverTarget{kind: takeoverKindCandidate, jobID: cand.ID, svc: svc, db: f.db, authz: s.authz,
		capKey: CredCapAccountRotate, assetID: f.assetID,
		req: validConfirmRequest(t, f.db, f.assetID), attempts: f.server.authAttempts.Load}
	return g
}

func (g *pgConfirmTarget) confirm(svc *HostIdentityTakeoverService, req HostIdentityConfirmRequest) error {
	return svc.ConfirmHostIdentityAndVerify(adminCtx(), g.kind, g.jobID, req)
}

func recvErr(t *testing.T, ch <-chan error, what string) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(30 * time.Second):
		t.Fatalf("等待逾時（30 秒上限）：%s", what)
		return nil
	}
}

func recvSignal(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(30 * time.Second):
		t.Fatalf("等待逾時（30 秒上限）：%s", what)
	}
}

// --- manual_confirm_vs_adopt ---

// 取得確認資料（記錄 B）之後，實例二採用 C：以 B 送出的舊確認 409，不建紀錄、不送認證；
// 以 C 重新確認則成功。
func runConfirmAfterAdopt(t *testing.T, e *pgIdentityEnv) {
	g := newPGConfirmTarget(t, e)
	staleReq := acceptDifferent(g.req) // 確認畫面當下看到的是 B
	adoptRemoteKey(t, e.f.server, e.db2, e.f.assetID, true)
	attBase, auditBase := g.attempts(), confirmAuditCount(t, g.db)

	err := g.confirm(g.svc, staleReq)
	requireConflict(t, err, "")
	assert.Empty(t, confirmRecords(t, g.takeoverTarget), "舊確認不建承接紀錄")
	assert.Equal(t, auditBase, confirmAuditCount(t, g.db), "不寫確認審計")
	assert.Equal(t, attBase, g.attempts(), "authAttempts 0")
	assert.EqualValues(t, 0, g.verifies.Load())

	fresh := acceptDifferent(validConfirmRequest(t, g.db, e.f.assetID))
	require.NotEqual(t, staleReq.Fingerprint, fresh.Fingerprint, "採用確實換了金鑰")
	require.NoError(t, g.confirm(g.svc, fresh), "重新取得確認資料後的確認成功")
	rows := confirmRecords(t, g.takeoverTarget)
	require.Len(t, rows, 1)
	assert.Equal(t, takeoverOutcomeVerified, rows[0].Outcome)
	assert.EqualValues(t, 0, e.f.candidateCount(t), "候選轉正")
}

// 兩個確認並行（實例一、實例二各一個承接服務）：恰一列承接紀錄生效，另一個 409 confirmation_pending。
// 次序：第一個停在建立交易內（紀錄已寫、未提交，持信任鎖），第二個此時啟動；放行後第一個停在紀錄提交之後，
// 第二個必須在此時回 409；最後放行第一個完成。
func runConcurrentConfirm(t *testing.T, e *pgIdentityEnv) {
	g := newPGConfirmTarget(t, e)
	req := acceptDifferent(g.req)
	attBase := g.attempts()
	inTx, paused := make(chan struct{}), make(chan struct{})
	goTx, goRec := make(chan struct{}), make(chan struct{})
	var txOnce, recOnce atomic.Bool
	g.svc.createTxBarrier = func(*gorm.DB) error {
		if txOnce.CompareAndSwap(false, true) {
			close(inTx)
			<-goTx
		}
		return nil
	}
	g.svc.crashAfterRecord = func() error {
		if recOnce.CompareAndSwap(false, true) {
			close(paused)
			<-goRec
		}
		return nil
	}
	res1, res2 := make(chan error, 1), make(chan error, 1)
	go func() { res1 <- g.confirm(g.svc, req) }()
	recvSignal(t, inTx, "第一個確認進入建立交易")
	go func() { res2 <- g.confirm(g.svc2, req) }()
	close(goTx)
	recvSignal(t, paused, "第一個確認的紀錄提交")
	requireConflict(t, recvErr(t, res2, "第二個確認的結果"), takeoverDetailConfirmationPending)
	assert.Len(t, confirmRecords(t, g.takeoverTarget), 1, "此刻只有一列")
	close(goRec)
	require.NoError(t, recvErr(t, res1, "第一個確認完成"))

	rows := confirmRecords(t, g.takeoverTarget)
	require.Len(t, rows, 1, "恰一列承接紀錄生效")
	assert.EqualValues(t, 1, rows[0].Revision)
	assert.Equal(t, takeoverOutcomeVerified, rows[0].Outcome)
	assert.EqualValues(t, 1, confirmAuditCount(t, g.db), "恰一筆確認審計")
	assert.Equal(t, attBase+1, g.attempts(), "恰一次邏輯驗證")
	assert.EqualValues(t, 1, g.verifies.Load())
}

// 跨實例的資料庫層證明：第一個確認的建立交易已寫紀錄、尚未提交時，實例二另一條連線寫同一
// (kind, job_id, revision) 必須被擋在列鎖上，第一個提交後以唯一索引失敗；最終恰一列。
func runConfirmRevisionUnique(t *testing.T, e *pgIdentityEnv) {
	g := newPGConfirmTarget(t, e)
	// 唯一索引的形狀本身就是被測物：必須恰是 (kind, job_id, revision) 的唯一索引。
	// 只剩 (kind, job_id) 的索引會讓「同 revision 被擋」照樣成立，卻讓第二次確認（revision 2）寫不進去。
	var indexDef string
	require.NoError(t, e.db2.Raw(`SELECT indexdef FROM pg_indexes WHERE schemaname = current_schema()
		AND tablename = 'credential_host_identity_confirmations'
		AND indexname = 'idx_credential_host_identity_confirmations_job'`).Scan(&indexDef).Error)
	require.Contains(t, indexDef, "UNIQUE", "承接紀錄必須有唯一索引")
	require.Contains(t, indexDef, "(kind, job_id, revision)", "唯一索引須含 revision")

	inTx, goTx := make(chan struct{}), make(chan struct{})
	var releaseTx sync.Once
	release := func() { releaseTx.Do(func() { close(goTx) }) }
	defer release() // 失敗時也放行第一個確認，避免遺留卡住的交易
	g.svc.createTxBarrier = func(*gorm.DB) error {
		close(inTx)
		<-goTx
		return nil
	}
	res1, res2 := make(chan error, 1), make(chan error, 1)
	go func() { res1 <- g.confirm(g.svc, acceptDifferent(g.req)) }()
	recvSignal(t, inTx, "第一個確認進入建立交易")
	go func() {
		now := time.Now()
		res2 <- e.db2.Create(&model.CredentialHostIdentityConfirmation{Kind: g.kind, JobID: g.jobID, Revision: 1,
			AssetID: e.f.assetID, ConfirmedBy: 1, ConfirmedTransport: model.HostKeyTransportSSH, CreatedAt: now, StartedAt: &now}).Error
	}()
	pollUntil(t, "實例二的寫入被擋在第一個交易的未提交列上", 10*time.Second, func() bool {
		var n int
		require.NoError(t, e.db2.Raw(`SELECT count(*) FROM pg_locks l WHERE l.locktype='transactionid' AND NOT l.granted
			AND l.pid IN (SELECT pid FROM pg_stat_activity WHERE application_name = ?)`, e.appName).Scan(&n).Error)
		return n >= 1
	})
	release()
	require.NoError(t, recvErr(t, res1, "第一個確認完成"))
	err2 := recvErr(t, res2, "實例二的寫入結果")
	require.Error(t, err2, "第二筆同 revision 必須失敗")
	assert.Contains(t, err2.Error(), "23505", "唯一索引（kind, job_id, revision）")
	rows := confirmRecords(t, g.takeoverTarget)
	require.Len(t, rows, 1)
	assert.Equal(t, takeoverOutcomeVerified, rows[0].Outcome)
}

// --- confirm_crash_barrier ---

func runConfirmCrashBarrier(t *testing.T, e *pgIdentityEnv, point string) {
	g := newPGConfirmTarget(t, e)
	f := e.f
	crash := errors.New("simulated process end")
	set := func(fn func() error) {
		switch point {
		case "create":
			if fn == nil {
				g.svc.createTxBarrier = nil
			} else {
				g.svc.createTxBarrier = func(*gorm.DB) error { return fn() }
			}
		case "record":
			g.svc.crashAfterRecord = fn
		default:
			f.retry.crashAfterVerify = fn
		}
	}
	set(func() error { return crash })
	attBase, auditBase := g.attempts(), confirmAuditCount(t, g.db)

	err := g.confirm(g.svc, acceptDifferent(g.req))
	require.ErrorIs(t, err, crash, "掛點必須真的觸發（否則為假綠）")
	rows := confirmRecords(t, g.takeoverTarget)
	assert.EqualValues(t, 0, g.rotates.Load(), "從不下達")
	assert.EqualValues(t, 1, f.candidateCount(t), "候選保留")
	assert.Equal(t, g.secretBefore, f.storedPassword(t), "本地憑證不動")

	if point == "create" {
		assert.Empty(t, rows, "提交前中止：無紀錄")
		assert.Equal(t, auditBase, confirmAuditCount(t, g.db), "審計隨交易回滾")
		assert.Equal(t, attBase, g.attempts())
		assert.EqualValues(t, 0, g.verifies.Load())
		set(nil)
		require.NoError(t, g.confirm(g.svc, acceptDifferent(g.req)))
		rows = confirmRecords(t, g.takeoverTarget)
		require.Len(t, rows, 1)
		assert.EqualValues(t, 1, rows[0].Revision, "新確認建 revision 1")
		assert.Equal(t, takeoverOutcomeVerified, rows[0].Outcome)
		return
	}

	wantVerifies, wantAuth := int32(0), int32(0)
	if point == "verify" {
		wantVerifies, wantAuth = 1, 1
	}
	require.Len(t, rows, 1)
	assert.Nil(t, rows[0].ConsumedAt, "崩潰：不寫任何結果")
	assert.Equal(t, auditBase+1, confirmAuditCount(t, g.db))
	assert.Equal(t, wantVerifies, g.verifies.Load())
	assert.Equal(t, attBase+wantAuth, g.attempts())

	// 啟動收束
	n, rerr := recoverInterruptedConfirmations(g.db)
	require.NoError(t, rerr)
	assert.EqualValues(t, 1, n)
	rows = confirmRecords(t, g.takeoverTarget)
	require.Len(t, rows, 1)
	assert.Equal(t, takeoverOutcomeUnknown, rows[0].Outcome)
	require.NotNil(t, rows[0].ConsumedAt)
	assert.Equal(t, wantVerifies, g.verifies.Load(), "收束不重放")
	assert.Equal(t, attBase+wantAuth, g.attempts(), "收束不增加認證次數")
	assert.Equal(t, auditBase+1, confirmAuditCount(t, g.db), "收束不另寫審計")
	assert.EqualValues(t, 1, f.candidateCount(t), "候選保留")
	unknownAt := *rows[0].ConsumedAt

	set(nil)
	require.NoError(t, g.confirm(g.svc, acceptDifferent(g.req)))
	rows = confirmRecords(t, g.takeoverTarget)
	require.Len(t, rows, 2)
	assert.Equal(t, takeoverOutcomeUnknown, rows[0].Outcome)
	assert.True(t, unknownAt.Equal(*rows[0].ConsumedAt), "舊紀錄不被改寫")
	assert.EqualValues(t, 2, rows[1].Revision, "新確認建 revision 2")
	assert.Equal(t, takeoverOutcomeVerified, rows[1].Outcome)
	assert.Equal(t, wantVerifies+1, g.verifies.Load(), "新確認恰一次邏輯驗證")
	assert.EqualValues(t, 0, f.candidateCount(t))
}
