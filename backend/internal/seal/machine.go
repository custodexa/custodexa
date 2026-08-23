package seal

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// VerifiedMaterial 是材料驗證通過後交給段 2 的控制代碼。
// 本套件不解讀 Payload；它由接線批次填入已驗證的 KEK provider／key manager。
type VerifiedMaterial struct {
	// Bootstrap 為 true 代表走初始化解封路徑（data_keys 為空）
	Bootstrap bool
	// Payload 由呼叫端自訂
	Payload any
}

// VerifyFunc 為材料格式檢查＋材料驗證（解包現行代表列／初始化路徑的憑證驗證）。
// 它在臨界區之內執行——CAS 取得持有權在任何驗證之前。
type VerifyFunc func(ctx context.Context, material []byte) (VerifiedMaterial, error)

// Stage2Func 為段 2 完整圖建構。
//
// 實作 SHALL 於每個具外部副作用的步驟之前呼叫 CheckCancel(ctx)（見 cancel.go）。
// 回傳的 ServiceGraph 即使在 err != nil 時也可為非 nil（半建構圖）——狀態機會
// 對它呼叫 Release 以收束已取得的資源。
type Stage2Func func(ctx context.Context, v VerifiedMaterial) (ServiceGraph, error)

// UnsealRequest 為一次解封嘗試的輸入。
type UnsealRequest struct {
	// Material 為 UI 輸入的 KEK 材料。驗證結束後由狀態機就地歸零。
	Material []byte
	// SourceKey 為 per-source 限速鍵。未設定可信代理時，呼叫端 SHALL 傳固定值
	// 使 per-source 退避保守降級為全域退避。
	SourceKey string
	// SourceDigest 為寫入 journal 的來源摘要。
	// SHALL NOT 含請求體、KEK 材料或任何認證憑證及其衍生值。
	SourceDigest string
}

// Result 為解封成功的結果。
type Result struct {
	Generation uint64
	State      SealState
	Services   ServiceGraph
}

// Config 為 Machine 建構參數。
type Config struct {
	Journal Journal
	Verify  VerifyFunc
	Stage2  Stage2Func
	Limiter *Limiter

	// PrepareTimeout 為 received 寫入＋兩次 fdatasync 的獨立逾時（格 3b）
	PrepareTimeout time.Duration
	// Stage2Timeout 為段 2 逾時（格 7）。缺此逾時即可能永久卡在 unsealing。
	Stage2Timeout time.Duration
	// JournalWriteTimeout 為終局 outcome／published 寫入的逾時
	JournalWriteTimeout time.Duration
	// CleanupTimeout 為舊持有者釋放資源的逾時
	CleanupTimeout time.Duration

	// Now 為時間來源；預設 time.Now（其回傳值帶單調時鐘讀數，
	// 使冷卻／退避比較不受 NTP 校時或手動改時影響）
	Now func() time.Time
}

// Machine 為四態封印狀態機。
type Machine struct {
	node    atomic.Pointer[sealNode]
	journal Journal
	verify  VerifyFunc
	stage2  Stage2Func
	limiter *Limiter
	now     func() time.Time

	prepareTimeout time.Duration
	stage2Timeout  time.Duration
	journalTimeout time.Duration
	cleanupTimeout time.Duration

	wg sync.WaitGroup

	// discarded 累計「因非當代而被 CAS 丟棄的終局副作用」次數，
	// 使殭屍丟棄成為可觀察事實而非只能靠推論
	discarded atomic.Uint64
}

// New 建立 B 模式的狀態機，初始態為 sealed（格 1：不讀 data_keys）。
func New(cfg Config) (*Machine, error) {
	if cfg.Journal == nil {
		return nil, errors.New("seal: Config.Journal 為必填")
	}
	if cfg.Verify == nil {
		return nil, errors.New("seal: Config.Verify 為必填")
	}
	if cfg.Stage2 == nil {
		return nil, errors.New("seal: Config.Stage2 為必填")
	}
	m := &Machine{
		journal:        cfg.Journal,
		verify:         cfg.Verify,
		stage2:         cfg.Stage2,
		limiter:        cfg.Limiter,
		now:            cfg.Now,
		prepareTimeout: cfg.PrepareTimeout,
		stage2Timeout:  cfg.Stage2Timeout,
		journalTimeout: cfg.JournalWriteTimeout,
		cleanupTimeout: cfg.CleanupTimeout,
	}
	if m.limiter == nil {
		m.limiter = NewLimiter(DefaultLimiterConfig())
	}
	if m.now == nil {
		m.now = time.Now
	}
	if m.prepareTimeout <= 0 {
		m.prepareTimeout = 5 * time.Second
	}
	if m.stage2Timeout <= 0 {
		m.stage2Timeout = 2 * time.Minute
	}
	if m.journalTimeout <= 0 {
		m.journalTimeout = 5 * time.Second
	}
	if m.cleanupTimeout <= 0 {
		m.cleanupTimeout = 30 * time.Second
	}
	boot, ok := Resolve(Situation{From: stateBoot, Event: EventBoot})
	if !ok {
		return nil, errors.New("seal: 遷移表缺格 1（啟動）")
	}
	m.node.Store(&sealNode{state: boot.Target})
	return m, nil
}

// NewUnsealed 建立 A／C 模式的狀態機：恆 unsealed，服務圖於啟動時即已建構。
// 其上的 Unseal 一律回 SEAL_ALREADY_UNSEALED（格 3），且不重跑任何初始化。
func NewUnsealed(graph ServiceGraph) *Machine {
	m := &Machine{
		journal: noopJournal{},
		limiter: NewLimiter(DefaultLimiterConfig()),
		now:     time.Now,
	}
	m.node.Store(&sealNode{generation: 1, state: StateUnsealed, services: graph})
	return m
}

// Snapshot 是對外唯一的狀態讀取入口：閘的狀態判定與 handler 的服務取用
// 讀同一次指標載入結果，故「閘看到 unsealed、handler 拿到 nil」不可達。
func (m *Machine) Snapshot() Snapshot { return snapshotOf(m.node.Load()) }

// DiscardedTerminalEffects 回傳被 CAS 丟棄的終局副作用次數。
func (m *Machine) DiscardedTerminalEffects() uint64 { return m.discarded.Load() }

// TimeoutTotal 回傳累計段 2 逾時次數（逾時另計，不入材料失敗計數）。
func (m *Machine) TimeoutTotal() uint64 { return m.limiter.TimeoutTotal() }

// WaitCleanup 等待全部背景收束作業結束（測試與行程收尾用）。
func (m *Machine) WaitCleanup() { m.wg.Wait() }

// CompleteCleanup 為格 8：前代持有者收束完成後以 CAS 清除 cleanup。
// 僅當目前的 cleanup 屬於 gen 時才清除，避免清掉別代的 token。
func (m *Machine) CompleteCleanup(gen uint64) bool {
	for {
		cur := m.node.Load()
		if cur.cleanup == nil || cur.cleanup.generation != gen {
			return false
		}
		cell, ok := Resolve(Situation{From: cur.state, Event: EventCleanupDone, HasCleanup: true})
		if !ok {
			return false
		}
		next := applyCell(cur, cell, m.now(), nil)
		if m.node.CompareAndSwap(cur, next) {
			return true
		}
	}
}

func (m *Machine) go_(fn func()) {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		fn()
	}()
}

func (m *Machine) recordRejected(kind string) {
	if _, ok := validRejectedKinds[kind]; !ok {
		return
	}
	m.journal.RecordRejected(kind)
}

// noopJournal 供 A／C 模式使用：該模式恆 unsealed，不存在封印期留痕。
type noopJournal struct{}

func (noopJournal) WriteReceived(context.Context, uint64, string) (uint64, error) { return 0, nil }
func (noopJournal) WriteOutcome(context.Context, uint64, uint64, string) error    { return nil }
func (noopJournal) WritePublished(context.Context, uint64, uint64) error          { return nil }
func (noopJournal) RecordRejected(string)                                         {}
func (noopJournal) Close() error                                                  { return nil }

// ---------------------------------------------------------------------------
// 持有權取得（格 2／3）
// ---------------------------------------------------------------------------

// acquireBlocker 判定 CAS 前置是否成立，並回傳阻擋成因的專屬機器碼。
// 前置＝cleanup == nil 且來源態 ∈ {sealed, sealed-faulted}。
func acquireBlocker(n *sealNode) (string, bool) {
	switch {
	case n.state == StateUnsealed:
		return CodeAlreadyUnsealed, true
	case n.cleanup != nil:
		return CodeCleanupPending, true
	case n.state == StateUnsealing:
		return CodeUnsealInProgress, true
	default:
		return "", false
	}
}

// rejected 產生格 3 的出口錯誤：態不變，成因以機器碼區分。
func (m *Machine) rejected(observed *sealNode, code string) error {
	cell, ok := Resolve(Situation{
		From:           observed.state,
		Event:          EventUnsealRequest,
		HasCleanup:     observed.cleanup != nil,
		HolderAcquired: false,
	})
	cellID := cellRejected
	if ok {
		cellID = cell.ID
	}
	m.recordRejected(RejectedConflict)
	return newError(code, cellID, observed.generation, nil)
}

// acquire 取得持有權。冷卻／退避檢查在 CAS 之前，且一律不進行任何驗證。
func (m *Machine) acquire(req UnsealRequest) (*attempt, error) {
	cur := m.node.Load()
	now := m.now()

	// 冷卻期間抵達的嘗試 SHALL 直接被拒——不驗證、不進 CAS、
	// SHALL NOT 計入失敗計數、SHALL NOT 刷新或延長冷卻到期時間。
	if now.Before(cur.cooldownUntil) {
		m.recordRejected(RejectedCooldown)
		return nil, newError(CodeCooldownActive, cellRejected, cur.generation, nil)
	}
	if allowed, _ := m.limiter.AllowSource(req.SourceKey, now); !allowed {
		m.recordRejected(RejectedBackoff)
		return nil, newError(CodeBackoffActive, cellRejected, cur.generation, nil)
	}
	if code, blocked := acquireBlocker(cur); blocked {
		return nil, m.rejected(cur, code)
	}

	cell, ok := Resolve(Situation{
		From:           cur.state,
		Event:          EventUnsealRequest,
		HasCleanup:     false,
		HolderAcquired: true,
	})
	if !ok {
		return nil, newError(CodeUnsealInProgress, cellRejected, cur.generation, nil)
	}
	next := applyCell(cur, cell, now, nil)
	// 唯一形式：CompareAndSwap(observed, new)。observed 為進入時讀到的那個節點指標。
	if !m.node.CompareAndSwap(cur, next) {
		latest := m.node.Load()
		code, blocked := acquireBlocker(latest)
		if !blocked {
			code = CodeUnsealInProgress
		}
		return nil, m.rejected(latest, code)
	}
	return &attempt{m: m, node: next, gen: next.generation, sourceKey: req.SourceKey}, nil
}

// ---------------------------------------------------------------------------
// 單次解封嘗試
// ---------------------------------------------------------------------------

type phase int

const (
	phasePrePrepare  phase = iota // 已取得 CAS，received 尚未落地（格 3b 涵蓋）
	phasePostPrepare              // received 已落地，驗證前／中（格 4b 涵蓋）
	phaseStage2                   // 已進入段 2（格 6／7 涵蓋）
)

type attempt struct {
	m         *Machine
	node      *sealNode // 本世代安裝的節點指標＝後續所有 CAS 的 observed
	gen       uint64
	seq       uint64
	sourceKey string
	baseCtx   context.Context

	phase   phase
	settled bool

	// outcomeClaimed 保證同一 seq 至多一筆 outcome：第一個抵達的終局處置
	// 取得寫入權，殭屍搶不到即不寫，但其狀態轉移仍走 CAS 並必然被丟棄。
	outcomeClaimed atomic.Bool
}

// Unseal 執行一次解封嘗試。臨界區為「取得持有權 → 材料格式檢查 → 材料驗證 →
// bootstrap 或 load → 段 2 建構 → 原子發佈」全程；其他請求在任何驗證開始前即被拒。
func (m *Machine) Unseal(ctx context.Context, req UnsealRequest) (Result, error) {
	a, err := m.acquire(req)
	if err != nil {
		return Result{}, err
	}
	return a.run(ctx, req)
}

func (a *attempt) run(ctx context.Context, req UnsealRequest) (res Result, err error) {
	a.baseCtx = ctx

	// 格 3b／4b／6 的安全網：取得 CAS 後立即註冊回滾，涵蓋 panic 與所有提前 return。
	// 缺此註冊時，任一未預期的出口都會讓行程永久卡在 unsealing。
	// panic 於此轉為 error 而非續拋——狀態已回滾，續拋只會讓呼叫端在
	// 「狀態已一致」與「連線被中斷」之間看到不一致。
	defer func() {
		r := recover()
		if a.settled {
			if r != nil {
				err = newError(CodeAborted, cellPostAbort, a.gen, fmt.Errorf("seal: 終局處置後 panic: %v", r))
			}
			return
		}
		cause := errors.New("seal: 解封嘗試未經終局處置即返回")
		if r != nil {
			cause = fmt.Errorf("seal: 解封嘗試 panic: %v", r)
		}
		res = Result{}
		err = a.abortUnsettled(cause)
	}()

	// 格 3b：received 的寫入＋同步有獨立逾時；失敗即回滾 CAS、拒絕該次、不驗證。
	seq, werr := a.writeReceived(ctx, req.SourceDigest)
	if werr != nil {
		code := CodeJournalIOFailure
		if ctx.Err() != nil {
			code = CodeAborted
		}
		return Result{}, a.abortPrePrepare(code, werr)
	}
	a.seq = seq
	a.phase = phasePostPrepare

	// 格 4b：received 已落地後、驗證前的取消。
	if cerr := ctx.Err(); cerr != nil {
		return Result{}, a.abortPostPrepare(cerr)
	}

	v, verr := a.runVerify(ctx, req.Material)
	if verr != nil {
		// 取消／panic 走格 4b（未得出材料判定），其餘為格 4 材料驗證失敗。
		if ctx.Err() != nil || errors.Is(verr, errVerifyPanic) {
			return Result{}, a.abortPostPrepare(verr)
		}
		return Result{}, a.materialFailure(verr)
	}

	a.phase = phaseStage2
	done, pending := a.runStage2(ctx, v)
	if done == nil {
		// 格 7：SHALL 先完成逾時回退並設 cleanup，之後才啟動殭屍收束。
		// 反序會讓收束方在 cleanup 尚未寫入時就試圖清除它，token 便永遠留著，
		// 使「取得持有權的 CAS 前置 cleanup == nil」永不成立而鎖死解封。
		terr := a.timedOut()
		a.m.go_(func() { a.reap(<-pending) })
		return Result{}, terr
	}
	if done.err != nil {
		return Result{}, a.initFailed(done.err, done.graph)
	}
	return a.publish(done.graph)
}

// writeReceived 以獨立逾時寫入 PREPARE／RECEIVED 並確認 durable。
func (a *attempt) writeReceived(ctx context.Context, digest string) (uint64, error) {
	pctx, cancel := context.WithTimeout(ctx, a.m.prepareTimeout)
	defer cancel()
	return a.m.journal.WriteReceived(pctx, a.gen, digest)
}

var errVerifyPanic = errors.New("seal: 材料驗證 panic")

// runVerify 執行材料格式檢查與材料驗證，並在結束後就地歸零材料位元組。
func (a *attempt) runVerify(ctx context.Context, material []byte) (v VerifiedMaterial, err error) {
	defer zeroize(material)
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%w: %v", errVerifyPanic, r)
		}
	}()
	return a.m.verify(ctx, material)
}

type stage2Result struct {
	graph ServiceGraph
	err   error
}

// runStage2 於獨立 goroutine 執行段 2，並以逾時決定是否放棄等待。
//
// 逾時 SHALL 取消段 2 的 context；舊持有者成為殭屍，其終局副作用因 CAS 必然
// 失敗而被丟棄。放棄等待而非阻塞至段 2 返回，是「段 2 無逾時而可永久卡在
// unsealing」這條失敗判準的正面保證：不合作的段 2 也不能拖住狀態機。
//
// 回傳 done != nil 代表段 2 已返回；done == nil 代表逾時，呼叫端 SHALL 先完成
// 格 7 的回退，再以 pending 收束殭屍。
func (a *attempt) runStage2(ctx context.Context, v VerifiedMaterial) (*stage2Result, <-chan stage2Result) {
	s2ctx, cancel := context.WithCancel(ctx)
	resCh := make(chan stage2Result, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				resCh <- stage2Result{err: fmt.Errorf("seal: 段 2 panic: %v", r)}
			}
		}()
		g, err := a.m.stage2(s2ctx, v)
		resCh <- stage2Result{graph: g, err: err}
	}()

	timer := time.NewTimer(a.m.stage2Timeout)
	defer timer.Stop()
	select {
	case r := <-resCh:
		cancel()
		return &r, nil
	case <-timer.C:
		cancel()
		return nil, resCh
	}
}

// reap 收束逾時後才返回的殭屍段 2。
//
// 殭屍的終局副作用仍走與正常路徑同一組 CAS 助手——observed 為本世代安裝的
// 節點指標，早已被格 7 的回退取代，故 publish 與 faulted 轉態皆必然失敗而被
// 丟棄。丟棄後才釋放資源並以 CAS 清 cleanup（格 8）。
func (a *attempt) reap(r stage2Result) {
	if r.err == nil {
		a.casCell(EventStage2Published, func(n *sealNode) { n.services = r.graph })
	} else {
		a.casCell(EventStage2Failure, func(n *sealNode) { n.faultCode = CodeInitFailed })
	}
	a.releaseAndClear(r.graph)
}

// casCell 以遷移表計算目標節點並執行單一 CAS。
// 回傳是否成功；失敗即代表本世代已被取代，計入丟棄計數。
func (a *attempt) casCell(ev Event, mut func(*sealNode)) bool {
	cell, ok := Resolve(Situation{From: StateUnsealing, Event: ev})
	if !ok {
		return false
	}
	next := applyCell(a.node, cell, a.m.now(), mut)
	if a.m.node.CompareAndSwap(a.node, next) {
		return true
	}
	a.m.discarded.Add(1)
	return false
}

// claimOutcome 取得該 seq 的 outcome 寫入權；同一 seq 至多一筆。
func (a *attempt) claimOutcome() bool { return a.outcomeClaimed.CompareAndSwap(false, true) }

// writeOutcome 寫入結果碼並確認 durable。
// 終局寫入一律使用 WithoutCancel 的 context：請求已取消時仍必須把 aborted
// 寫下去，否則該筆會被誤判為「結果未知」。
func (a *attempt) writeOutcome(outcome string) error {
	if _, ok := validOutcomes[outcome]; !ok {
		return fmt.Errorf("seal: 未知的 outcome %q", outcome)
	}
	if !a.claimOutcome() {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(a.baseCtx), a.m.journalTimeout)
	defer cancel()
	return a.m.journal.WriteOutcome(ctx, a.gen, a.seq, outcome)
}

func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
