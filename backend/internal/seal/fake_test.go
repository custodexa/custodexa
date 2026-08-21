package seal

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// fake journal：記錄逐筆寫入與寫入當下的機器狀態，供定序斷言使用
// ---------------------------------------------------------------------------

type journalEvent struct {
	Kind         string // received | outcome | published | rejected
	Gen          uint64
	Seq          uint64
	Value        string // outcome 結果碼、rejected kind 或 sourceDigest
	StateAtWrite SealState
}

type fakeJournal struct {
	mu      sync.Mutex
	events  []journalEvent
	nextSeq uint64

	// stateFn 讓 journal 記錄「寫入當下」的機器態，用於驗證 4b 的寫入先於回滾
	stateFn func() SealState

	failReceived  error
	blockReceived bool
	failOutcome   map[string]error
	// afterOutcome 於 outcome 寫入成功後、回到狀態機之前執行，
	// 用於製造「SUCCESS 已 durable 而 publish CAS 未成功」的窗口
	afterOutcome func(outcome string)
	closed       atomic.Bool
}

func newFakeJournal() *fakeJournal {
	return &fakeJournal{failOutcome: map[string]error{}}
}

func (f *fakeJournal) state() SealState {
	if f.stateFn == nil {
		return ""
	}
	return f.stateFn()
}

func (f *fakeJournal) WriteReceived(ctx context.Context, gen uint64, digest string) (uint64, error) {
	f.mu.Lock()
	block := f.blockReceived
	fail := f.failReceived
	f.mu.Unlock()

	if block {
		<-ctx.Done()
		return 0, ctx.Err()
	}
	if fail != nil {
		return 0, fail
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextSeq++
	seq := f.nextSeq
	f.events = append(f.events, journalEvent{Kind: "received", Gen: gen, Seq: seq, Value: digest, StateAtWrite: f.state()})
	return seq, nil
}

func (f *fakeJournal) WriteOutcome(ctx context.Context, gen, seq uint64, outcome string) error {
	f.mu.Lock()
	err := f.failOutcome[outcome]
	after := f.afterOutcome
	if err == nil {
		f.events = append(f.events, journalEvent{Kind: "outcome", Gen: gen, Seq: seq, Value: outcome, StateAtWrite: f.state()})
	}
	f.mu.Unlock()

	if err != nil {
		return err
	}
	if after != nil {
		after(outcome)
	}
	return nil
}

func (f *fakeJournal) WritePublished(ctx context.Context, gen, seq uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, journalEvent{Kind: "published", Gen: gen, Seq: seq, StateAtWrite: f.state()})
	return nil
}

func (f *fakeJournal) RecordRejected(kind string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, journalEvent{Kind: "rejected", Value: kind, StateAtWrite: f.state()})
}

func (f *fakeJournal) Close() error { f.closed.Store(true); return nil }

func (f *fakeJournal) snapshot() []journalEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]journalEvent, len(f.events))
	copy(out, f.events)
	return out
}

func (f *fakeJournal) find(kind, value string) (journalEvent, bool) {
	for _, e := range f.snapshot() {
		if e.Kind == kind && (value == "" || e.Value == value) {
			return e, true
		}
	}
	return journalEvent{}, false
}

func (f *fakeJournal) count(kind, value string) int {
	n := 0
	for _, e := range f.snapshot() {
		if e.Kind == kind && (value == "" || e.Value == value) {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// fake 服務圖與段 2 控制器
// ---------------------------------------------------------------------------

type fakeGraph struct {
	name      string
	released  atomic.Int32
	onRelease func()
}

func (g *fakeGraph) Release(ctx context.Context) error {
	g.released.Add(1)
	if g.onRelease != nil {
		g.onRelease()
	}
	return nil
}

// ctl 集中一次測試中 verify／stage2 的行為與呼叫計數
type ctl struct {
	verifyCalls atomic.Int64
	stage2Calls atomic.Int64

	verifyErr   error
	verifyPanic bool
	// verifyEnter 於進入 verify 時關閉（僅一次），verifyRelease 用於阻塞 verify
	verifyEnter     chan struct{}
	verifyEnterOnce sync.Once
	verifyRelease   chan struct{}
	verifyObserve   func()

	stage2Err   error
	stage2Panic bool
	stage2Block chan struct{} // 非 nil 時 stage2 阻塞直到關閉或 ctx 結束（合作式）
	// stage2Hard 非 nil 時 stage2 阻塞直到關閉，且「不理會」ctx 取消——
	// 用於模擬不合作的段 2，驗證逾時仍能把狀態機推離 unsealing
	stage2Hard chan struct{}
	// stage2IgnoreCancel 模擬完全不理會取消的段 2：逾時後仍「成功」返回，
	// 用於驗證殭屍的 publish 會被 CAS 丟棄
	stage2IgnoreCancel bool
	stage2Graph        *fakeGraph
	stage2Cancel       atomic.Bool // 記錄 stage2 觀察到取消
	stage2Started      chan struct{}
	stage2Once         sync.Once
}

func (c *ctl) verify(ctx context.Context, material []byte) (VerifiedMaterial, error) {
	c.verifyCalls.Add(1)
	if c.verifyEnter != nil {
		c.verifyEnterOnce.Do(func() { close(c.verifyEnter) })
	}
	if c.verifyObserve != nil {
		c.verifyObserve()
	}
	if c.verifyRelease != nil {
		select {
		case <-c.verifyRelease:
		case <-ctx.Done():
		}
	}
	if c.verifyPanic {
		panic("測試用 verify panic")
	}
	// 真實的驗證於取消後 SHALL 中止並回傳 ctx 錯誤（走格 4b）
	if err := ctx.Err(); err != nil {
		return VerifiedMaterial{}, err
	}
	if c.verifyErr != nil {
		return VerifiedMaterial{}, c.verifyErr
	}
	return VerifiedMaterial{}, nil
}

func (c *ctl) stage2fn(ctx context.Context, v VerifiedMaterial) (ServiceGraph, error) {
	c.stage2Calls.Add(1)
	if c.stage2Started != nil {
		c.stage2Once.Do(func() { close(c.stage2Started) })
	}
	if c.stage2Hard != nil {
		<-c.stage2Hard
	}
	if c.stage2Block != nil {
		select {
		case <-c.stage2Block:
		case <-ctx.Done():
			c.stage2Cancel.Store(true)
		}
	}
	if err := CheckCancel(ctx); err != nil && !c.stage2IgnoreCancel {
		c.stage2Cancel.Store(true)
		if c.stage2Graph != nil {
			return c.stage2Graph, err
		}
		return nil, err
	}
	if c.stage2Panic {
		panic("測試用段 2 panic")
	}
	if c.stage2Err != nil {
		if c.stage2Graph != nil {
			return c.stage2Graph, c.stage2Err
		}
		return nil, c.stage2Err
	}
	if c.stage2Graph == nil {
		c.stage2Graph = &fakeGraph{name: "graph"}
	}
	return c.stage2Graph, nil
}

// ---------------------------------------------------------------------------
// 測試機器建構
// ---------------------------------------------------------------------------

type harness struct {
	m *Machine
	j *fakeJournal
	c *ctl
}

func newHarness(t *testing.T, tune func(*Config)) *harness {
	t.Helper()
	j := newFakeJournal()
	c := &ctl{}
	cfg := Config{
		Journal:             j,
		Verify:              c.verify,
		Stage2:              c.stage2fn,
		PrepareTimeout:      200 * time.Millisecond,
		Stage2Timeout:       10 * time.Second,
		JournalWriteTimeout: time.Second,
		CleanupTimeout:      time.Second,
		// 預設關掉退避與冷卻的干擾（各自另有專屬測試），
		// 使狀態機測試只驗證狀態機本身
		Limiter: NewLimiter(LimiterConfig{
			GlobalThreshold: 1000,
			BaseBackoff:     time.Nanosecond,
			MaxBackoff:      time.Nanosecond,
		}),
	}
	if tune != nil {
		tune(&cfg)
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("New 失敗: %v", err)
	}
	j.stateFn = func() SealState { return m.Snapshot().State }
	t.Cleanup(m.WaitCleanup)
	return &harness{m: m, j: j, c: c}
}

func (h *harness) unseal(ctx context.Context) (Result, error) {
	return h.m.Unseal(ctx, UnsealRequest{
		Material:     []byte("material"),
		SourceKey:    "src-1",
		SourceDigest: "digest",
	})
}

// driveToFaulted 讓機器走一次段 2 失敗，落到 sealed-faulted 且 cleanup 已清除。
func (h *harness) driveToFaulted(t *testing.T) {
	t.Helper()
	h.c.stage2Err = errors.New("測試用段 2 失敗")
	if _, err := h.unseal(context.Background()); CodeOf(err) != CodeInitFailed {
		t.Fatalf("預期 %s，實得 %v", CodeInitFailed, err)
	}
	h.m.WaitCleanup()
	h.c.stage2Err = nil
	if got := h.m.Snapshot(); got.State != StateSealedFaulted || got.CleanupPending {
		t.Fatalf("預期 sealed-faulted 且 cleanup 已清，實得 %+v", got)
	}
}

func mustCode(t *testing.T, err error, want string) {
	t.Helper()
	if got := CodeOf(err); got != want {
		t.Fatalf("預期機器碼 %s，實得 %q（err=%v）", want, got, err)
	}
}

func mustCell(t *testing.T, err error, want string) {
	t.Helper()
	if got := CellOf(err); got != want {
		t.Fatalf("預期遷移格 %s，實得 %q（err=%v）", want, got, err)
	}
}
