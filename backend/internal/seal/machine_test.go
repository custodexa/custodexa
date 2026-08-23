package seal

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 格 1：啟動
// ---------------------------------------------------------------------------

func TestBootStateIsSealed(t *testing.T) {
	h := newHarness(t, nil)
	got := h.m.Snapshot()
	if got.State != StateSealed {
		t.Fatalf("B 模式啟動應為 sealed，實得 %s", got.State)
	}
	if got.Generation != 0 || got.Services != nil || got.CleanupPending {
		t.Fatalf("啟動節點應為乾淨的 sealed，實得 %+v", got)
	}
}

// ---------------------------------------------------------------------------
// 格 2：CAS 進入 unsealing 發生在任何驗證之前
// ---------------------------------------------------------------------------

func TestAcquireEntersUnsealingBeforeAnyVerification(t *testing.T) {
	h := newHarness(t, nil)
	var atVerify Snapshot
	h.c.verifyObserve = func() { atVerify = h.m.Snapshot() }

	if _, err := h.unseal(context.Background()); err != nil {
		t.Fatalf("解封應成功: %v", err)
	}
	if atVerify.State != StateUnsealing {
		t.Fatalf("驗證開始時狀態應已是 unsealing，實得 %s", atVerify.State)
	}
	if atVerify.Generation != 1 {
		t.Fatalf("驗證開始時 generation 應已 +1，實得 %d", atVerify.Generation)
	}
	if atVerify.SourceState != StateSealed {
		t.Fatalf("進入 unsealing 應記住來源態，實得 %s", atVerify.SourceState)
	}
}

func TestGenerationIncrementsOnEveryAcquireFromBothSources(t *testing.T) {
	h := newHarness(t, nil)

	h.c.verifyErr = errors.New("材料錯誤")
	if _, err := h.unseal(context.Background()); CodeOf(err) != CodeMaterialInvalid {
		t.Fatalf("預期材料失敗: %v", err)
	}
	if got := h.m.Snapshot().Generation; got != 1 {
		t.Fatalf("第一次進入後 generation 應為 1，實得 %d", got)
	}

	// 自 sealed 再次進入
	if _, err := h.unseal(context.Background()); CodeOf(err) != CodeMaterialInvalid {
		t.Fatalf("預期材料失敗: %v", err)
	}
	if got := h.m.Snapshot().Generation; got != 2 {
		t.Fatalf("自 sealed 再次進入後 generation 應為 2，實得 %d", got)
	}

	// 自 sealed-faulted 進入（另一個來源態）
	h.c.verifyErr = nil
	h.driveToFaulted(t)
	genBefore := h.m.Snapshot().Generation
	h.c.verifyErr = errors.New("材料錯誤")
	if _, err := h.unseal(context.Background()); CodeOf(err) != CodeMaterialInvalid {
		t.Fatalf("預期材料失敗: %v", err)
	}
	if got := h.m.Snapshot().Generation; got != genBefore+1 {
		t.Fatalf("自 sealed-faulted 進入也應 +1：預期 %d 實得 %d", genBefore+1, got)
	}
}

// ---------------------------------------------------------------------------
// 格 3：未取得持有權的三種成因，各有專屬機器碼
// ---------------------------------------------------------------------------

func TestRejectedWhileUnsealing(t *testing.T) {
	h := newHarness(t, nil)
	h.c.verifyEnter = make(chan struct{})
	h.c.verifyRelease = make(chan struct{})

	done := make(chan error, 1)
	go func() { _, err := h.unseal(context.Background()); done <- err }()
	<-h.c.verifyEnter

	_, err := h.unseal(context.Background())
	mustCode(t, err, CodeUnsealInProgress)
	mustCell(t, err, "3")
	if h.c.verifyCalls.Load() != 1 {
		t.Fatalf("第二個請求不得進行任何驗證，verify 呼叫 %d 次", h.c.verifyCalls.Load())
	}

	close(h.c.verifyRelease)
	if err := <-done; err != nil {
		t.Fatalf("持有者應成功: %v", err)
	}
}

func TestRejectedWhileCleanupPending(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Stage2Timeout = 30 * time.Millisecond })
	h.c.stage2Hard = make(chan struct{})

	_, err := h.unseal(context.Background())
	mustCode(t, err, CodeStage2Timeout)

	snap := h.m.Snapshot()
	if !snap.CleanupPending {
		t.Fatal("逾時後應有待收束的前代")
	}
	if snap.CleanupGeneration != 1 || snap.CleanupReason != CodeStage2Timeout {
		t.Fatalf("/seal/status 應暴露待收束世代與成因，實得 %+v", snap)
	}

	before := h.c.verifyCalls.Load()
	_, err = h.unseal(context.Background())
	mustCode(t, err, CodeCleanupPending)
	mustCell(t, err, "3")
	if h.c.verifyCalls.Load() != before {
		t.Fatal("待收束期間的請求不得進行任何驗證")
	}

	close(h.c.stage2Hard)
	h.m.WaitCleanup()
	if h.m.Snapshot().CleanupPending {
		t.Fatal("收束完成後 cleanup 應被 CAS 清除（格 8）")
	}
}

func TestUnsealedRejectsWithoutRerunningInit(t *testing.T) {
	h := newHarness(t, nil)
	if _, err := h.unseal(context.Background()); err != nil {
		t.Fatalf("首次解封應成功: %v", err)
	}
	verifyBefore := h.c.verifyCalls.Load()
	stage2Before := h.c.stage2Calls.Load()

	_, err := h.unseal(context.Background())
	mustCode(t, err, CodeAlreadyUnsealed)
	mustCell(t, err, "3")
	if h.c.verifyCalls.Load() != verifyBefore || h.c.stage2Calls.Load() != stage2Before {
		t.Fatal("已解封時不得重跑驗證或初始化")
	}
	if h.m.Snapshot().State != StateUnsealed {
		t.Fatal("已解封狀態不應改變")
	}
}

// A／C 模式恆 unsealed：解封端點一律 409 且不跑任何初始化。
func TestModeACAlwaysUnsealed(t *testing.T) {
	g := &fakeGraph{name: "ac"}
	m := NewUnsealed(g)
	snap := m.Snapshot()
	if snap.State != StateUnsealed || snap.Services != ServiceGraph(g) {
		t.Fatalf("A／C 模式應恆 unsealed 且服務圖已就緒，實得 %+v", snap)
	}
	_, err := m.Unseal(context.Background(), UnsealRequest{Material: []byte("x")})
	mustCode(t, err, CodeAlreadyUnsealed)
}

// ---------------------------------------------------------------------------
// 格 3b：pre-PREPARE abort 三路徑
// ---------------------------------------------------------------------------

func TestPrePrepareAbortOnJournalIOFailure(t *testing.T) {
	h := newHarness(t, nil)
	h.j.failReceived = errors.New("磁碟故障")

	_, err := h.unseal(context.Background())
	mustCode(t, err, CodeJournalIOFailure)
	mustCell(t, err, "3b")
	if got := h.m.Snapshot().State; got != StateSealed {
		t.Fatalf("應回滾至 sourceState，實得 %s", got)
	}
	if h.c.verifyCalls.Load() != 0 {
		t.Fatal("received 未落地時不得進行任何驗證")
	}
	if h.m.limiter.GlobalFailures() != 0 {
		t.Fatal("pre-PREPARE abort 不得計入材料失敗計數")
	}
}

func TestPrePrepareAbortOnPrepareWriteBlocking(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.PrepareTimeout = 20 * time.Millisecond })
	h.j.blockReceived = true

	_, err := h.unseal(context.Background())
	mustCode(t, err, CodeJournalIOFailure)
	mustCell(t, err, "3b")
	if got := h.m.Snapshot().State; got != StateSealed {
		t.Fatalf("PREPARE 寫入阻塞應回滾至 sourceState，實得 %s", got)
	}
	if h.c.verifyCalls.Load() != 0 {
		t.Fatal("PREPARE 未完成時不得驗證")
	}
}

func TestPrePrepareAbortOnRequestCancel(t *testing.T) {
	h := newHarness(t, nil)
	h.j.blockReceived = true
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()

	_, err := h.unseal(ctx)
	mustCode(t, err, CodeAborted)
	mustCell(t, err, "3b")
	if got := h.m.Snapshot().State; got != StateSealed {
		t.Fatalf("請求取消應回滾至 sourceState，實得 %s", got)
	}
	if h.m.limiter.GlobalFailures() != 0 {
		t.Fatal("請求取消不得計入材料失敗計數")
	}
}

func TestPrePrepareAbortFromFaultedReturnsToFaulted(t *testing.T) {
	h := newHarness(t, nil)
	h.driveToFaulted(t)
	h.j.failReceived = errors.New("磁碟故障")

	_, err := h.unseal(context.Background())
	mustCell(t, err, "3b")
	snap := h.m.Snapshot()
	if snap.State != StateSealedFaulted || snap.FaultCode != CodeInitFailed {
		t.Fatalf("自 faulted 進入者應回 faulted 並保留機器碼，實得 %+v", snap)
	}
}

// ---------------------------------------------------------------------------
// 格 4：材料驗證失敗
// ---------------------------------------------------------------------------

func TestMaterialFailureReturnsToSourceState(t *testing.T) {
	h := newHarness(t, nil)
	h.c.verifyErr = errors.New("解包失敗")

	_, err := h.unseal(context.Background())
	mustCode(t, err, CodeMaterialInvalid)
	mustCell(t, err, "4")
	if got := h.m.Snapshot().State; got != StateSealed {
		t.Fatalf("預期回 sealed，實得 %s", got)
	}
	if e, ok := h.j.find("outcome", OutcomeMaterialFailure); !ok || e.Gen != 1 {
		t.Fatalf("應寫入 material_failure，實得 %+v", h.j.snapshot())
	}
	if h.m.limiter.GlobalFailures() != 1 {
		t.Fatalf("材料失敗應計數 +1，實得 %d", h.m.limiter.GlobalFailures())
	}
	if h.c.stage2Calls.Load() != 0 {
		t.Fatal("材料驗證失敗不得進入段 2")
	}
}

func TestMaterialFailureFromFaultedReturnsToFaulted(t *testing.T) {
	h := newHarness(t, nil)
	h.driveToFaulted(t)
	h.c.verifyErr = errors.New("解包失敗")

	_, err := h.unseal(context.Background())
	mustCell(t, err, "4")
	snap := h.m.Snapshot()
	if snap.State != StateSealedFaulted || snap.FaultCode != CodeInitFailed {
		t.Fatalf("預期回 sealed-faulted 並保留機器碼，實得 %+v", snap)
	}
}

// 全域冷卻經與轉態同一道 CAS 寫入 sealNode（柵欄涵蓋全域冷卻）。
func TestMaterialFailureArmsGlobalCooldownInSameCAS(t *testing.T) {
	h := newHarness(t, func(c *Config) {
		c.Limiter = NewLimiter(LimiterConfig{GlobalThreshold: 1, GlobalCooldown: time.Hour, MaxGlobalCooldown: time.Hour})
	})
	h.c.verifyErr = errors.New("解包失敗")
	if _, err := h.unseal(context.Background()); CodeOf(err) != CodeMaterialInvalid {
		t.Fatalf("預期材料失敗: %v", err)
	}
	armed := h.m.Snapshot().CooldownUntil
	if armed.IsZero() {
		t.Fatal("達門檻後應武裝全域冷卻")
	}

	// 冷卻期間的嘗試：直接被拒、不驗證、不進 CAS、不刷新到期時間
	verifyBefore := h.c.verifyCalls.Load()
	genBefore := h.m.Snapshot().Generation
	_, err := h.unseal(context.Background())
	mustCode(t, err, CodeCooldownActive)
	if h.c.verifyCalls.Load() != verifyBefore {
		t.Fatal("冷卻期的嘗試不得進行驗證")
	}
	if h.m.Snapshot().Generation != genBefore {
		t.Fatal("冷卻期的嘗試不得進入 CAS（generation 不應變動）")
	}
	if !h.m.Snapshot().CooldownUntil.Equal(armed) {
		t.Fatal("冷卻期的嘗試不得刷新或延長冷卻到期時間")
	}
	if h.j.count("rejected", RejectedCooldown) == 0 {
		t.Fatal("被拒的冷卻嘗試應留痕")
	}
}

// ---------------------------------------------------------------------------
// 格 4b：post-PREPARE abort——先寫 aborted 並確認 durable，成功後才回滾
// ---------------------------------------------------------------------------

func TestPostPrepareAbortWritesAbortedBeforeRollback(t *testing.T) {
	h := newHarness(t, nil)
	h.c.verifyEnter = make(chan struct{})
	h.c.verifyRelease = make(chan struct{})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := h.unseal(ctx); done <- err }()
	<-h.c.verifyEnter
	cancel()

	err := <-done
	mustCode(t, err, CodeAborted)
	mustCell(t, err, "4b")

	ev, ok := h.j.find("outcome", OutcomeAborted)
	if !ok {
		t.Fatalf("received 已落地的中止 SHALL 補寫 aborted，實得 %+v", h.j.snapshot())
	}
	// 定序守衛：aborted 寫入當下狀態仍為 unsealing；若實作反序（先回滾再補寫），
	// 這裡會看到 sealed 而失敗。
	if ev.StateAtWrite != StateUnsealing {
		t.Fatalf("aborted SHALL 先於回滾寫入：寫入當下狀態為 %s", ev.StateAtWrite)
	}
	if got := h.m.Snapshot().State; got != StateSealed {
		t.Fatalf("補寫成功後才回 sourceState，實得 %s", got)
	}
	if h.m.limiter.GlobalFailures() != 0 {
		t.Fatal("post-PREPARE abort 不得計入材料失敗計數")
	}
}

func TestPostPrepareAbortOnVerifyPanic(t *testing.T) {
	h := newHarness(t, nil)
	h.c.verifyPanic = true

	_, err := h.unseal(context.Background())
	mustCell(t, err, "4b")
	if got := h.m.Snapshot().State; got != StateSealed {
		t.Fatalf("verify panic 應回滾至 sourceState，實得 %s", got)
	}
	if _, ok := h.j.find("outcome", OutcomeAborted); !ok {
		t.Fatal("panic 中止亦應補寫 aborted")
	}
}

func TestPostPrepareAbortJournalWriteFailureStillRollsBack(t *testing.T) {
	h := newHarness(t, nil)
	h.c.verifyPanic = true
	h.j.failOutcome[OutcomeAborted] = errors.New("磁碟故障")

	_, err := h.unseal(context.Background())
	mustCode(t, err, CodeJournalIOFailure)
	mustCell(t, err, "4b")
	if got := h.m.Snapshot().State; got != StateSealed {
		t.Fatalf("補寫失敗仍 SHALL 回 sourceState，不得滯留 unsealing，實得 %s", got)
	}
}

// ---------------------------------------------------------------------------
// 格 5：段 2 完成 → 寫 SUCCESS ＋同步 → 成功才 publish → 回應
// ---------------------------------------------------------------------------

func TestPublishOrdersSuccessBeforePublish(t *testing.T) {
	h := newHarness(t, nil)
	res, err := h.unseal(context.Background())
	if err != nil {
		t.Fatalf("解封應成功: %v", err)
	}
	if res.State != StateUnsealed || res.Services == nil || res.Generation != 1 {
		t.Fatalf("結果不符: %+v", res)
	}

	evs := h.j.snapshot()
	var kinds []string
	for _, e := range evs {
		kinds = append(kinds, e.Kind+":"+e.Value)
	}
	if len(kinds) != 3 || kinds[0] != "received:digest" || kinds[1] != "outcome:success" || kinds[2] != "published:" {
		t.Fatalf("定序應為 received → success → published，實得 %v", kinds)
	}
	// SUCCESS 寫在 publish 之前：寫入當下狀態必須仍是 unsealing
	if evs[1].StateAtWrite != StateUnsealing {
		t.Fatalf("SUCCESS SHALL 寫在 publish 之前，寫入當下狀態為 %s", evs[1].StateAtWrite)
	}
	if evs[2].StateAtWrite != StateUnsealed {
		t.Fatalf("published SHALL 寫在 publish 之後，寫入當下狀態為 %s", evs[2].StateAtWrite)
	}
	snap := h.m.Snapshot()
	if snap.State != StateUnsealed || snap.Services == nil {
		t.Fatalf("發佈後應為 unsealed 且服務圖非 nil，實得 %+v", snap)
	}
}

// ---------------------------------------------------------------------------
// 格 5b：兩成因同一處置——服務從未放行
// ---------------------------------------------------------------------------

func TestSuccessNotDurableNeverPublishes(t *testing.T) {
	h := newHarness(t, nil)
	h.j.failOutcome[OutcomeSuccess] = errors.New("磁碟故障")

	_, err := h.unseal(context.Background())
	mustCode(t, err, CodePublishUnconfirmed)
	mustCell(t, err, "5b")

	if _, ok := h.j.find("published", ""); ok {
		t.Fatal("SUCCESS 未 durable 時服務不得被 publish")
	}
	snap := h.m.Snapshot()
	if snap.State != StateSealed || snap.Services != nil {
		t.Fatalf("應丟棄服務圖並回 sourceState，實得 %+v", snap)
	}
	if h.c.stage2Graph.released.Load() != 1 {
		t.Fatalf("服務圖應被釋放一次，實得 %d", h.c.stage2Graph.released.Load())
	}
}

func TestSuccessDurableButPublishCASFailsIsRetryableWithNewGeneration(t *testing.T) {
	h := newHarness(t, nil)
	// 於 SUCCESS 已 durable、publish CAS 之前製造「較新世代搶先」的窗口
	var once sync.Once
	h.j.afterOutcome = func(outcome string) {
		if outcome != OutcomeSuccess {
			return
		}
		once.Do(func() { h.m.node.Store(&sealNode{generation: 99, state: StateSealed}) })
	}

	_, err := h.unseal(context.Background())
	mustCode(t, err, CodePublishUnconfirmed)
	mustCell(t, err, "5b")

	if _, ok := h.j.find("outcome", OutcomeSuccess); !ok {
		t.Fatal("本案例的 SUCCESS 應已 durable")
	}
	if _, ok := h.j.find("published", ""); ok {
		t.Fatal("publish CAS 未成功時不得寫 published（回灌據此標示「已驗證通過但未確認發佈」）")
	}
	if h.m.DiscardedTerminalEffects() == 0 {
		t.Fatal("被取代的終局副作用應被 CAS 丟棄並計數")
	}
	if h.c.stage2Graph.released.Load() != 1 {
		t.Fatal("未發佈時應丟棄服務圖")
	}
	if h.m.Snapshot().Services != nil {
		t.Fatal("服務從未放行")
	}

	// 不鎖死：重試產生新世代並照常走完整流程
	h.c.stage2Graph = &fakeGraph{name: "retry"}
	res, err := h.unseal(context.Background())
	if err != nil {
		t.Fatalf("應可重試: %v", err)
	}
	if res.Generation != 100 {
		t.Fatalf("重試 SHALL 產生新世代，預期 100 實得 %d", res.Generation)
	}
	if h.m.Snapshot().State != StateUnsealed {
		t.Fatal("重試後應成功發佈")
	}
}

// ---------------------------------------------------------------------------
// 格 6：段 2 逾時以外的失敗（含取消／panic）
// ---------------------------------------------------------------------------

func TestStage2FailureGoesFaultedWithCleanup(t *testing.T) {
	h := newHarness(t, nil)
	g := &fakeGraph{name: "partial"}
	h.c.stage2Graph = g
	h.c.stage2Err = errors.New("load 失敗")

	_, err := h.unseal(context.Background())
	mustCode(t, err, CodeInitFailed)
	mustCell(t, err, "6")

	if _, ok := h.j.find("outcome", OutcomeInitFailed); !ok {
		t.Fatal("段 2 失敗應寫 init_failed")
	}
	h.m.WaitCleanup()
	snap := h.m.Snapshot()
	if snap.State != StateSealedFaulted || snap.FaultCode != CodeInitFailed {
		t.Fatalf("應轉 sealed-faulted 並帶機器碼，實得 %+v", snap)
	}
	if snap.CleanupPending {
		t.Fatal("收束完成後 cleanup 應已清除")
	}
	if g.released.Load() != 1 {
		t.Fatalf("半建構服務圖應被釋放，實得 %d", g.released.Load())
	}
}

func TestStage2PanicGoesFaulted(t *testing.T) {
	h := newHarness(t, nil)
	h.c.stage2Panic = true

	_, err := h.unseal(context.Background())
	mustCell(t, err, "6")
	h.m.WaitCleanup()
	if got := h.m.Snapshot().State; got != StateSealedFaulted {
		t.Fatalf("段 2 panic 應轉 sealed-faulted，實得 %s", got)
	}
}

func TestStage2CancelGoesFaulted(t *testing.T) {
	h := newHarness(t, nil)
	h.c.stage2Block = make(chan struct{})
	h.c.stage2Started = make(chan struct{})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := h.unseal(ctx); done <- err }()
	<-h.c.stage2Started
	cancel()

	err := <-done
	mustCell(t, err, "6")
	if !h.c.stage2Cancel.Load() {
		t.Fatal("段 2 應於合作式檢查點觀察到取消")
	}
	h.m.WaitCleanup()
	if got := h.m.Snapshot().State; got != StateSealedFaulted {
		t.Fatalf("段 2 取消應轉 sealed-faulted，實得 %s", got)
	}
}

// ---------------------------------------------------------------------------
// 格 7：僅逾時 → 回 sourceState
// ---------------------------------------------------------------------------

func TestStage2TimeoutReturnsToSourceState(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Stage2Timeout = 30 * time.Millisecond })
	h.c.stage2Hard = make(chan struct{})

	_, err := h.unseal(context.Background())
	mustCode(t, err, CodeStage2Timeout)
	mustCell(t, err, "7")

	snap := h.m.Snapshot()
	if snap.State != StateSealed {
		t.Fatalf("自 sealed 進入者逾時應回 sealed，實得 %s", snap.State)
	}
	if !snap.CleanupPending || snap.CleanupReason != CodeStage2Timeout {
		t.Fatalf("逾時 SHALL 設 cleanup，實得 %+v", snap)
	}
	if h.m.limiter.GlobalFailures() != 0 {
		t.Fatal("逾時 SHALL NOT 計入材料失敗計數")
	}
	if h.m.TimeoutTotal() != 1 {
		t.Fatalf("逾時應另計次數，實得 %d", h.m.TimeoutTotal())
	}
	if _, ok := h.j.find("outcome", OutcomeTimeout); !ok {
		t.Fatal("逾時應寫 timeout")
	}
	close(h.c.stage2Hard)
	h.m.WaitCleanup()
}

func TestTimeoutFromFaultedKeepsFaultAndCode(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Stage2Timeout = 30 * time.Millisecond })
	h.driveToFaulted(t)
	h.c.stage2Hard = make(chan struct{})

	_, err := h.unseal(context.Background())
	mustCode(t, err, CodeStage2Timeout)

	snap := h.m.Snapshot()
	if snap.State != StateSealedFaulted {
		t.Fatalf("自 sealed-faulted 重試逾時後仍應為 sealed-faulted，實得 %s", snap.State)
	}
	if snap.FaultCode != CodeInitFailed {
		t.Fatalf("逾時不得抹除既有故障機器碼，實得 %q", snap.FaultCode)
	}
	close(h.c.stage2Hard)
	h.m.WaitCleanup()
}

// ---------------------------------------------------------------------------
// 格 8／格 9
// ---------------------------------------------------------------------------

func TestCleanupDoneClearsTokenAndUnblocksNextUnseal(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Stage2Timeout = 30 * time.Millisecond })
	h.c.stage2Hard = make(chan struct{})
	if _, err := h.unseal(context.Background()); CodeOf(err) != CodeStage2Timeout {
		t.Fatalf("預期逾時: %v", err)
	}
	if !h.m.Snapshot().CleanupPending {
		t.Fatal("應有待收束前代")
	}
	// 別代的收束回報不得清除本代 token
	if h.m.CompleteCleanup(999) {
		t.Fatal("不得清除不屬於該世代的 cleanup")
	}
	close(h.c.stage2Hard)
	h.m.WaitCleanup()

	if h.m.Snapshot().CleanupPending {
		t.Fatal("收束完成後 cleanup 應被清除")
	}
	h.c.stage2Hard = nil
	h.c.stage2Graph = &fakeGraph{name: "after-cleanup"}
	if _, err := h.unseal(context.Background()); err != nil {
		t.Fatalf("收束完成後應可再取得持有權: %v", err)
	}
}

func TestRestartReturnsToSealedWithoutPersistence(t *testing.T) {
	h := newHarness(t, nil)
	if _, err := h.unseal(context.Background()); err != nil {
		t.Fatalf("解封應成功: %v", err)
	}
	if h.m.Snapshot().State != StateUnsealed {
		t.Fatal("前置條件：應已解封")
	}
	// 「重啟」＝以同一組相依重新建構狀態機；無任何持久化來源可回復封印狀態
	fresh, err := New(Config{Journal: h.j, Verify: h.c.verify, Stage2: h.c.stage2fn})
	if err != nil {
		t.Fatalf("重建失敗: %v", err)
	}
	snap := fresh.Snapshot()
	if snap.State != StateSealed || snap.Generation != 0 || snap.Services != nil {
		t.Fatalf("重啟後應回 sealed，實得 %+v", snap)
	}
}

// ---------------------------------------------------------------------------
// 撕裂窗的結構性不可達
// ---------------------------------------------------------------------------

// TestMachineExposesNoSeparateServicesAccessor：閘與 handler SHALL 讀同一次
// 指標載入結果。若有第二個直接回傳 ServiceGraph 的存取器，「閘看到 unsealed、
// handler 拿到 nil」的撕裂窗就會重新出現。
func TestMachineExposesNoSeparateServicesAccessor(t *testing.T) {
	graphType := reflect.TypeOf((*ServiceGraph)(nil)).Elem()
	typ := reflect.TypeOf(&Machine{})
	found := false
	for i := 0; i < typ.NumMethod(); i++ {
		mt := typ.Method(i)
		if mt.Name == "Snapshot" {
			found = true
		}
		for j := 0; j < mt.Type.NumOut(); j++ {
			if mt.Type.Out(j) == graphType {
				t.Errorf("方法 %s 直接回傳 ServiceGraph，會製造第二次載入的撕裂窗", mt.Name)
			}
		}
	}
	if !found {
		t.Fatal("Machine 應提供 Snapshot 作為唯一狀態讀取入口")
	}
}
