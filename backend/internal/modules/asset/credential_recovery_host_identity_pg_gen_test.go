package asset

import (
	"context"
	"fmt"
	"net"
	"strconv"
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

// 本檔承接 TestCredentialRecoveryHostIdentityPG 的第二批子測試（M-6A-b）：
// reset_relearn_vs_adopt、app_generation_concurrent、duplicate_workers_and_audit_failure。
// 夾具與排隊手法沿用 credential_recovery_host_identity_pg_test.go。

// --- 共用輔助 ---

func (e *pgIdentityEnv) dialTarget(t *testing.T) (string, net.Addr) {
	t.Helper()
	host, port := e.serverHostPort(t)
	return net.JoinHostPort(host, strconv.Itoa(port)), &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
}

// observe 讓 svc 的背景作業回呼看到 pub：與自身記錄不符，寫觀察紀錄並拒絕（正式觀察路徑）。
func (e *pgIdentityEnv) observe(t *testing.T, svc *HostKeyService, pub ssh.PublicKey) {
	t.Helper()
	addr, remote := e.dialTarget(t)
	cb, _ := svc.CallbackFor(e.dialContext())
	require.ErrorIs(t, cb(addr, remote, pub), ErrHostKeyChanged, "與自身記錄不符的金鑰必須被觀察並拒絕")
}

// relearn 以 svc 的正常連線回呼出示 pub（重置待記錄時即為重錄）；不用 require，可在 goroutine 內呼叫。
func (e *pgIdentityEnv) relearn(svc *HostKeyService, pub ssh.PublicKey, port int) error {
	host, _, _ := net.SplitHostPort(e.f.server.addr())
	cb, _ := svc.CallbackFor(e.dialContext())
	return cb(net.JoinHostPort(host, strconv.Itoa(port)), &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}, pub)
}

func (e *pgIdentityEnv) adopt(t *testing.T, svc *HostKeyService, pub ssh.PublicKey) (*model.AssetHostKey, error) {
	t.Helper()
	return svc.Adopt(e.f.assetID, ssh.FingerprintSHA256(pub), pgIdentityActor)
}

func (e *pgIdentityEnv) targetPort(t *testing.T) int {
	t.Helper()
	_, p := e.serverHostPort(t)
	return p
}

func recvOrFail[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(30 * time.Second):
		t.Fatalf("逾時（30 秒上限）：%s", what)
		var zero T
		return zero
	}
}

func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(30 * time.Second):
		t.Fatalf("barrier 未觸發（30 秒上限）：%s", what)
	}
}

// --- reset_relearn_vs_adopt ---

// 重錄的 Evaluate 在鎖前讀到「重置待記錄」之後、進入信任變更交易之前，另一實例的採用提交：
// 最終列必須是採用結果（B），不被鎖前讀到的舊 struct 覆寫成重錄的 A。
// 同一子測試內再走 A→B→A：回到 A 後，綁定在世代 1 的舊工作仍停止。
func runResetRelearnVsAdopt(t *testing.T, e *pgIdentityEnv) {
	s := newPGRetryScenario(t, e)
	pubA := e.f.server.currentHostKey().PublicKey()
	pubB := genHostKey(t)
	before := e.ownRecord(t)
	cand := candidateOfAccount(t, e.f)
	require.Equal(t, cand.HostKeyGeneration, before.TrustGeneration)

	e.observe(t, e.svc2, pubB) // 觀察 B（採用的素材）
	res, err := e.svc2.MarkResetWithGeneration(e.f.assetID, pgIdentityActor)
	require.NoError(t, err)
	require.True(t, res.Reset)
	require.Equal(t, before.TrustGeneration+1, res.GenerationAfter)

	// 實例一的重錄卡在 evalWriteBarrier（鎖前、已依「重置待記錄」分類）
	atBarrier, proceed := make(chan struct{}), make(chan struct{})
	var fired atomic.Int32
	e.f.hostKeys.evalWriteBarrier = func() {
		if fired.Add(1) == 1 {
			close(atBarrier)
			<-proceed
		}
	}
	port := e.targetPort(t)
	relearnCh := make(chan error, 1)
	go func() { relearnCh <- e.relearn(e.f.hostKeys, pubA, port) }()
	waitClosed(t, atBarrier, "重錄的 Evaluate 鎖前")

	// 重錄在途時，實例二採用 B 並提交
	adopted, err := e.adopt(t, e.svc2, pubB)
	require.NoError(t, err)
	require.Equal(t, ssh.FingerprintSHA256(pubB), adopted.Fingerprint)
	require.Equal(t, before.TrustGeneration+2, adopted.TrustGeneration)

	close(proceed)
	rerr := recvOrFail(t, relearnCh, "重錄結束")
	e.f.hostKeys.evalWriteBarrier = nil
	require.Equal(t, int32(1), fired.Load(), "barrier 必須真的觸發且只在鎖前一次")
	assert.ErrorIs(t, rerr, ErrHostKeyChanged, "鎖內重讀發現已被採用：重新分類，A 與已採用的 B 不符而被拒")

	final := e.ownRecord(t)
	assert.Equal(t, before.ID, final.ID, "同一列")
	assert.Equal(t, ssh.FingerprintSHA256(pubB), final.Fingerprint, "最終列是採用結果 B，不被舊 struct 覆寫成 A")
	assert.Equal(t, before.TrustGeneration+2, final.TrustGeneration, "世代只被重置與採用各推進一次")
	assert.False(t, final.ResetPending)

	// A→B→A：回到 A（採用 A），世代再推進；綁定在世代 1 的舊工作仍停止
	e.observe(t, e.svc2, pubA)
	back, err := e.adopt(t, e.svc2, pubA)
	require.NoError(t, err)
	assert.Equal(t, before.Fingerprint, back.Fingerprint, "金鑰回到 A")
	assert.Equal(t, before.ID, back.ID, "記錄 ID 同")
	assert.Equal(t, before.TrustGeneration+3, back.TrustGeneration, "A→B→A 世代不同於舊工作綁定的世代")
	assert.False(t, s.retry(t, false))
	s.requireStopped(t, model.ChangeSecretReasonHostIdentityChanged)
	s.requireStopAudit(t, hostIdentityGenerationChanged, hostIdentityPhasePrecheck, verificationSentFalse)
}

// --- app_generation_concurrent ---

// genRow 一次對 asset_host_keys 的 UPDATE：同一條連線（同一交易）內執行前後的信任世代，與正規化後的 SQL。
type genRow struct {
	label         string
	before, after int64
	sql           string
}

// genTrace 以 gorm callback 在兩個連線池上攔截 asset_host_keys 的 UPDATE，
// 在同一交易內（UPDATE 前後各一次 SELECT）記下 before／after。
type genTrace struct {
	mu    sync.Mutex
	label string
	rows  []genRow
}

func (g *genTrace) install(t *testing.T, db *gorm.DB) {
	t.Helper()
	read := func(tx *gorm.DB) (int64, bool) {
		if tx.Statement == nil || tx.Statement.Table != "asset_host_keys" || tx.Statement.ConnPool == nil {
			return 0, false
		}
		var n int64
		if err := tx.Statement.ConnPool.QueryRowContext(tx.Statement.Context,
			"SELECT trust_generation FROM asset_host_keys LIMIT 1").Scan(&n); err != nil {
			return 0, false
		}
		return n, true
	}
	name := fmt.Sprintf("test:gen_trace_%p_%p", g, db)
	require.NoError(t, db.Callback().Update().Before("gorm:update").Register(name+"_b", func(tx *gorm.DB) {
		if n, ok := read(tx); ok {
			tx.InstanceSet("p2m:gen_before", n)
		}
	}))
	require.NoError(t, db.Callback().Update().After("gorm:update").Register(name+"_a", func(tx *gorm.DB) {
		if tx.Error != nil || tx.Statement == nil || tx.Statement.Table != "asset_host_keys" {
			return
		}
		b, okb := tx.InstanceGet("p2m:gen_before")
		after, oka := read(tx)
		if !okb || !oka {
			return
		}
		norm := strings.NewReplacer("`", "", "\"", "", " ", "").Replace(tx.Statement.SQL.String())
		g.mu.Lock()
		g.rows = append(g.rows, genRow{label: g.label, before: b.(int64), after: after, sql: norm})
		g.mu.Unlock()
	}))
}

func (g *genTrace) setLabel(l string) {
	g.mu.Lock()
	g.label = l
	g.mu.Unlock()
}

func (g *genTrace) take(label string) []genRow {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []genRow
	for _, r := range g.rows {
		if r.label == label {
			out = append(out, r)
		}
	}
	return out
}

// genStep 一筆交易的期待：before／after；rejected 表示該交易被拒（沒有任何 UPDATE，世代停在 before＝after）。
type genStep struct {
	label         string
	before, after int64
	rejected      bool
}

// 驗句的期待表（逐值照抄）：after 序列依提交順序。
var appGenerationOrders = []struct {
	name  string
	steps []genStep
}{
	{"X全部先於Y", []genStep{
		{"Reset", 1, 2, false}, {"重錄A(同鑰)", 2, 2, false}, {"Adopt B", 2, 3, false}, {"Adopt A", 3, 4, false}}},
	{"Y全部先於X", []genStep{
		{"Adopt B", 1, 2, false}, {"Adopt A", 2, 3, false}, {"Reset", 3, 4, false}, {"重錄A(同鑰)", 4, 4, false}}},
	{"AdoptB_Reset_重錄A_AdoptA", []genStep{
		{"Adopt B", 1, 2, false}, {"Reset", 2, 3, false}, {"重錄A(與B不同鑰)", 3, 4, false}, {"Adopt A(被拒)", 4, 4, true}}},
}

// runAppGenerationConcurrent：流程 X（實例一：Reset→重錄 A）與流程 Y（實例二：Adopt B→Adopt A），
// 初始 A／世代 1，三種提交順序；逐交易 before／after 與期待表逐值相同，最終世代皆 4。
// 順序2的 Reset 與順序3的 Adopt A 在鎖前停住（讀完前置資料後），別的交易先提交，放行後才取鎖：
// 這是真正的交錯，覆寫式寫入（SET trust_generation=<鎖前讀到的值+1>）會在此丟失更新。
func runAppGenerationConcurrent(t *testing.T, e *pgIdentityEnv, orderIdx int) {
	order := appGenerationOrders[orderIdx]
	s := newPGRetryScenario(t, e)
	pubA := e.f.server.currentHostKey().PublicKey()
	pubB := genHostKey(t)
	port := e.targetPort(t)
	tr := &genTrace{}
	tr.install(t, e.f.db)
	tr.install(t, e.db2)
	X, Y := e.f.hostKeys, e.svc2
	start := e.ownRecord(t)
	require.EqualValues(t, 1, start.TrustGeneration)

	var got []genStep
	check := func(want genStep, run func()) {
		t.Helper()
		tr.setLabel(want.label)
		run()
		rows := tr.take(want.label)
		cur := e.ownRecord(t).TrustGeneration
		if want.rejected {
			require.Empty(t, rows, "%s：被拒的交易不得有任何 asset_host_keys UPDATE", want.label)
			got = append(got, genStep{want.label, cur, cur, true})
			require.Equal(t, want.after, cur)
			return
		}
		require.Len(t, rows, 1, "%s：恰一條 asset_host_keys UPDATE", want.label)
		r := rows[0]
		got = append(got, genStep{want.label, r.before, r.after, false})
		assert.Equal(t, want.before, r.before, "%s：before", want.label)
		assert.Equal(t, want.after, r.after, "%s：after", want.label)
		if want.after != want.before {
			assert.Contains(t, r.sql, hostKeyGenExpr, "%s：世代以欄位運算在同一條語句推進", want.label)
		} else {
			assert.NotContains(t, r.sql, "trust_generation", "%s：不改金鑰不寫世代", want.label)
		}
	}
	reset := func(want genStep) {
		check(want, func() {
			res, err := X.MarkResetWithGeneration(e.f.assetID, pgIdentityActor)
			require.NoError(t, err)
			require.True(t, res.Reset)
		})
	}
	relearn := func(want genStep) {
		check(want, func() { require.NoError(t, e.relearn(X, pubA, port)) })
	}
	adoptY := func(want genStep, pub ssh.PublicKey) {
		check(want, func() {
			e.observe(t, Y, pub)
			_, err := e.adopt(t, Y, pub)
			require.NoError(t, err)
		})
	}
	st := order.steps
	switch orderIdx {
	case 0:
		reset(st[0])
		relearn(st[1])
		adoptY(st[2], pubB)
		adoptY(st[3], pubA)
	case 1:
		// Reset 讀完前置資料（世代 1）後停在鎖前；採用方的兩次採用先提交，再放行 Reset
		atBarrier, proceed := make(chan struct{}), make(chan struct{})
		X.resetTxBarrier = func() { close(atBarrier); <-proceed }
		resetCh := make(chan error, 1)
		go func() {
			res, err := X.MarkResetWithGeneration(e.f.assetID, pgIdentityActor)
			if err == nil && !res.Reset {
				err = fmt.Errorf("重置未生效")
			}
			resetCh <- err
		}()
		waitClosed(t, atBarrier, "Reset 鎖前")
		adoptY(st[0], pubB)
		adoptY(st[1], pubA)
		check(st[2], func() {
			close(proceed)
			require.NoError(t, recvOrFail(t, resetCh, "Reset 結束"))
		})
		X.resetTxBarrier = nil
		relearn(st[3])
	case 2:
		adoptY(st[0], pubB)
		// 在途的 Adopt A：觀察 A 已存在，停在 adoptTxBarrier（鎖前）；X 的 Reset 與重錄先提交（重錄會清空觀察）
		e.observe(t, Y, pubA)
		atBarrier, proceed := make(chan struct{}), make(chan struct{})
		Y.adoptTxBarrier = func() { close(atBarrier); <-proceed }
		adoptCh := make(chan error, 1)
		go func() { _, err := e.adopt(t, Y, pubA); adoptCh <- err }()
		waitClosed(t, atBarrier, "Adopt A 鎖前")
		reset(st[1])
		relearn(st[2])
		check(st[3], func() {
			close(proceed)
			assert.ErrorIs(t, recvOrFail(t, adoptCh, "Adopt A 結束"), ErrHostKeyObservationNotFound, "觀察已被重錄清空：不生效")
		})
		Y.adoptTxBarrier = nil
	}
	t.Logf("APP_GENERATION order=%s sequence=%v", order.name, got)

	final := e.ownRecord(t)
	assert.EqualValues(t, 4, final.TrustGeneration, "最終世代都是 4，沒有遺失更新")
	assert.Equal(t, ssh.FingerprintSHA256(pubA), final.Fingerprint, "最終金鑰 A")
	assert.False(t, final.ResetPending)
	// 既有工作（綁定世代 1）在 (a) 停止、authAttempts 0
	assert.False(t, s.retry(t, false))
	s.requireStopped(t, model.ChangeSecretReasonHostIdentityChanged)
	s.requireStopAudit(t, hostIdentityGenerationChanged, hostIdentityPhasePrecheck, verificationSentFalse)
}

// --- duplicate_workers_and_audit_failure ---

// stopKeyRendezvous 在兩個連線池上攔截「推進停止去重鍵」的 UPDATE：前兩個到達者互相等待，
// 兩邊都進入交易、都尚未執行 UPDATE 時才同時放行，使兩個 worker 真的同時遇到同一身分狀態。
type stopKeyRendezvous struct {
	mu      sync.Mutex
	tokens  []string
	arrived int
	gate    chan struct{}
	timeout atomic.Bool
}

func (r *stopKeyRendezvous) install(t *testing.T, db *gorm.DB) {
	t.Helper()
	name := fmt.Sprintf("test:stopkey_rdv_%p_%p", r, db)
	require.NoError(t, db.Callback().Update().Before("gorm:update").Register(name, func(tx *gorm.DB) {
		if tx.Statement == nil || tx.Statement.Table != "change_secret_candidates" {
			return
		}
		m, ok := tx.Statement.Dest.(map[string]interface{})
		if !ok {
			return
		}
		tok, ok := m["host_identity_alerted_key"]
		if !ok {
			return
		}
		r.mu.Lock()
		r.tokens = append(r.tokens, fmt.Sprint(tok))
		r.arrived++
		if r.arrived == 2 {
			close(r.gate)
		}
		gate := r.gate
		r.mu.Unlock()
		select {
		case <-gate:
		case <-time.After(20 * time.Second):
			r.timeout.Store(true)
		}
	}))
}

func (e *pgIdentityEnv) candidateAlertedKey(t *testing.T) *string {
	t.Helper()
	var k *string
	require.NoError(t, e.db2.Raw("SELECT host_identity_alerted_key FROM change_secret_candidates WHERE account_id = ?",
		e.f.accountID).Row().Scan(&k))
	return k
}

// secondRetryRunner 實例二的重試 worker：獨立連線池，共用通知器以便計總通知數。
func (e *pgIdentityEnv) secondRetryRunner(t *testing.T, notifier *audit.AlertNotifier) *ChangeSecretRetryRunner {
	t.Helper()
	candidates2, err := NewChangeSecretCandidateService(e.db2, aesColumnCodec(t, make([]byte, 32)), e.f.assets, audit.NewTxSink())
	require.NoError(t, err)
	r := NewChangeSecretRetryRunner(e.db2, candidates2, e.f.assets, e.svc2, notifier).
		WithManagementAuthorizer(newAllowAllAuthorizer())
	r.WithAuditSink(audit.NewTxSink())
	return r
}

// 兩個 worker（各在自己的連線池）同時遇到同一個身分異動：停止審計恰一筆、同一 token、通知一次，
// 兩邊都沒有送出新認證。
func runDuplicateWorkers(t *testing.T, e *pgIdentityEnv) {
	s := newPGRetryScenario(t, e)
	notifier := audit.NewAlertNotifier(e.f.db, nil)
	e.f.retry.notifier = notifier
	r2 := e.secondRetryRunner(t, notifier)
	adoptRemoteKey(t, e.f.server, e.db2, e.f.assetID, true) // 身分異動：採用 B

	rdv := &stopKeyRendezvous{gate: make(chan struct{})}
	rdv.install(t, e.f.db)
	rdv.install(t, e.db2)
	basePending := notifier.PendingNotifications()

	var wg sync.WaitGroup
	results := make([]bool, 2)
	for i, runner := range []*ChangeSecretRetryRunner{e.f.retry, r2} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cand := candidateOfAccount(t, e.f)
			results[i] = runner.RetryOneAs(context.Background(), &cand)
		}()
	}
	wg.Wait()

	require.False(t, rdv.timeout.Load(), "兩個 worker 必須同時進入去重鍵更新（會合點逾時代表沒有真的同時）")
	require.Equal(t, 2, rdv.arrived)
	require.Len(t, rdv.tokens, 2)
	assert.Equal(t, rdv.tokens[0], rdv.tokens[1], "兩個 worker 對同一身分狀態算出同一個 token")
	assert.Equal(t, []bool{false, false}, results)
	s.requireStopped(t, model.ChangeSecretReasonHostIdentityChanged) // authAttempts 0、候選保留
	s.requireStopAudit(t, hostIdentityGenerationChanged, hostIdentityPhasePrecheck, verificationSentFalse)
	key := e.candidateAlertedKey(t)
	require.NotNil(t, key)
	assert.Equal(t, rdv.tokens[0], *key, "去重鍵就是那個 token")
	assert.EqualValues(t, 1, notifier.PendingNotifications()-basePending, "通知恰一次")
}

// 注入審計失敗：停止審計與去重鍵同交易回滾（鍵不前進、無審計、無通知、authAttempts 0）；
// 換回好的落地面後同一狀態仍會被寫入並通知一次。
func runStopAuditFailure(t *testing.T, e *pgIdentityEnv) {
	s := newPGRetryScenario(t, e)
	notifier := audit.NewAlertNotifier(e.f.db, nil)
	e.f.retry.notifier = notifier
	adoptRemoteKey(t, e.f.server, e.db2, e.f.assetID, true)
	require.Nil(t, e.candidateAlertedKey(t))

	e.f.retry.WithAuditSink(failingTxSink{err: fmt.Errorf("audit down")})
	assert.False(t, s.retry(t, false))
	assert.Nil(t, e.candidateAlertedKey(t), "審計失敗：去重鍵不前進")
	assert.Empty(t, stopAuditDetails(t, e.f), "審計失敗：沒有停止審計列")
	assert.EqualValues(t, 0, notifier.PendingNotifications(), "審計沒落地不通知")
	assert.EqualValues(t, s.baseAuth, e.f.server.authAttempts.Load(), "authAttempts 0")

	e.f.retry.WithAuditSink(audit.NewTxSink())
	assert.False(t, s.retry(t, false))
	s.requireStopped(t, model.ChangeSecretReasonHostIdentityChanged)
	s.requireStopAudit(t, hostIdentityGenerationChanged, hostIdentityPhasePrecheck, verificationSentFalse)
	assert.NotNil(t, e.candidateAlertedKey(t), "好的落地面：同一狀態仍被寫入（沒有被誤判為已留痕）")
	assert.EqualValues(t, 1, notifier.PendingNotifications())
}

// 採用交易在審計寫入失敗：金鑰、世代、重置旗標與觀察紀錄同時回滾；之後同一觀察仍可採用。
func runAdoptTxRollback(t *testing.T, e *pgIdentityEnv) {
	e.seedOwnRecord(t)
	pubB := genHostKey(t)
	e.observe(t, e.svc2, pubB)
	before := e.ownRecord(t)
	var obsBefore []model.AssetHostKeyMismatch
	require.NoError(t, e.db2.Where("asset_id = ?", e.f.assetID).Find(&obsBefore).Error)
	require.Len(t, obsBefore, 1)

	e.svc2.SetAuditTxSink(failingTxSink{err: fmt.Errorf("audit down")})
	_, err := e.adopt(t, e.svc2, pubB)
	require.Error(t, err, "審計失敗時採用必須失敗")
	after := e.ownRecord(t)
	assert.Equal(t, before, after, "金鑰與世代等整列同時回滾")
	var obsAfter []model.AssetHostKeyMismatch
	require.NoError(t, e.db2.Where("asset_id = ?", e.f.assetID).Find(&obsAfter).Error)
	assert.Equal(t, obsBefore, obsAfter, "觀察紀錄保留（消耗隨交易回滾）")
	var adoptAudits int64
	require.NoError(t, e.db2.Model(&model.AuditLog{}).Where("action = ?", string(model.ActionHostKeyAdopt)).Count(&adoptAudits).Error)
	assert.Zero(t, adoptAudits)

	e.svc2.SetAuditTxSink(audit.NewTxSink())
	adopted, err := e.adopt(t, e.svc2, pubB)
	require.NoError(t, err, "回滾後同一觀察仍可採用")
	assert.Equal(t, before.TrustGeneration+1, adopted.TrustGeneration)
	assert.Equal(t, ssh.FingerprintSHA256(pubB), adopted.Fingerprint)
}
