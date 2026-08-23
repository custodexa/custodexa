package seal

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestConcurrentUnsealExactlyOneVerification：兩個同時且皆正確的解封請求，
// 恰一方取得持有權並執行驗證＋初始化全程，另一方在「任何驗證開始前」被拒。
//
// 本測試斷言的是驗證次數，而非「恰一方初始化」——後者無法排除「兩者都跑了
// 驗證、只是一方初始化」這個缺陷——CAS 取得持有權必須發生在任何驗證之前。
func TestConcurrentUnsealExactlyOneVerification(t *testing.T) {
	const n = 8
	h := newHarness(t, nil)
	h.c.verifyEnter = make(chan struct{})
	h.c.verifyRelease = make(chan struct{})

	results := make(chan error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := h.unseal(context.Background())
			results <- err
		}()
	}
	close(start)

	select {
	case <-h.c.verifyEnter:
	case <-time.After(5 * time.Second):
		t.Fatal("無人進入驗證")
	}
	// 持有者仍卡在驗證中；其餘 n-1 個請求應已全數被拒
	for i := 0; i < n-1; i++ {
		select {
		case err := <-results:
			mustCode(t, err, CodeUnsealInProgress)
		case <-time.After(5 * time.Second):
			t.Fatal("落敗的請求未在驗證開始前返回（可能有第二份驗證同時執行）")
		}
	}
	if got := h.c.verifyCalls.Load(); got != 1 {
		t.Fatalf("SHALL NOT 有第二份驗證同時執行：verify 被呼叫 %d 次", got)
	}

	close(h.c.verifyRelease)
	wg.Wait()
	if err := <-results; err != nil {
		t.Fatalf("持有者應成功: %v", err)
	}
	if got := h.c.stage2Calls.Load(); got != 1 {
		t.Fatalf("SHALL NOT 兩者都跑段 2 初始化：stage2 被呼叫 %d 次", got)
	}
	if h.j.count("rejected", RejectedConflict) != n-1 {
		t.Fatalf("被拒嘗試應逐一留痕，實得 %d", h.j.count("rejected", RejectedConflict))
	}
}

// TestConcurrentRetryUnderFaultedIsExclusive：sealed-faulted 下的並發重試
// 走同一道獨佔閘。
func TestConcurrentRetryUnderFaultedIsExclusive(t *testing.T) {
	const n = 6
	h := newHarness(t, nil)
	h.driveToFaulted(t)

	h.c.verifyEnter = make(chan struct{})
	h.c.verifyRelease = make(chan struct{})
	verifyBefore := h.c.verifyCalls.Load()

	results := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := h.unseal(context.Background())
			results <- err
		}()
	}
	select {
	case <-h.c.verifyEnter:
	case <-time.After(5 * time.Second):
		t.Fatal("無人進入驗證")
	}
	for i := 0; i < n-1; i++ {
		select {
		case err := <-results:
			mustCode(t, err, CodeUnsealInProgress)
		case <-time.After(5 * time.Second):
			t.Fatal("faulted 下的並發重試未受同一獨佔保護")
		}
	}
	if got := h.c.verifyCalls.Load() - verifyBefore; got != 1 {
		t.Fatalf("faulted 下仍應恰一方驗證，實得 %d", got)
	}
	close(h.c.verifyRelease)
	wg.Wait()
	<-results
}

// TestZombiePublishDiscardedAfterTimeout：逾時後才「成功」返回的舊 goroutine，
// 其 publish 必被 CAS 丟棄——服務不得被一個已被取代的世代發佈。
func TestZombiePublishDiscardedAfterTimeout(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Stage2Timeout = 30 * time.Millisecond })
	h.c.stage2Hard = make(chan struct{})
	h.c.stage2IgnoreCancel = true // 完全不理會取消的段 2
	g := &fakeGraph{name: "zombie"}
	h.c.stage2Graph = g

	_, err := h.unseal(context.Background())
	mustCode(t, err, CodeStage2Timeout)

	close(h.c.stage2Hard) // 殭屍此刻才「成功」返回
	h.m.WaitCleanup()

	snap := h.m.Snapshot()
	if snap.State != StateSealed {
		t.Fatalf("殭屍的發佈應被丟棄，狀態應仍為 sealed，實得 %s", snap.State)
	}
	if snap.Services != nil {
		t.Fatal("殭屍的服務圖不得被發佈")
	}
	if h.m.DiscardedTerminalEffects() == 0 {
		t.Fatal("被丟棄的終局副作用應被計數")
	}
	if g.released.Load() != 1 {
		t.Fatalf("殭屍的服務圖應被釋放，實得 %d", g.released.Load())
	}
	if snap.CleanupPending {
		t.Fatal("收束完成後 cleanup 應被清除")
	}
}

// TestZombieFaultedTransitionDiscardedAfterTimeout：逾時後才失敗的舊 goroutine
// 不得把狀態改成 sealed-faulted。
//
// 具體錯誤（若無柵欄）：逾時後管理員重試成功，此時舊 goroutine 才失敗並把狀態
// 打成 sealed-faulted，封印閘就對一個健康的服務全面回 503。
func TestZombieFaultedTransitionDiscardedAfterTimeout(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Stage2Timeout = 30 * time.Millisecond })
	h.c.stage2Hard = make(chan struct{})
	h.c.stage2Err = errors.New("段 2 於逾時之後才失敗")

	_, err := h.unseal(context.Background())
	mustCode(t, err, CodeStage2Timeout)
	discardBefore := h.m.DiscardedTerminalEffects()

	close(h.c.stage2Hard)
	h.m.WaitCleanup()

	snap := h.m.Snapshot()
	if snap.State != StateSealed {
		t.Fatalf("殭屍的 faulted 轉態應被丟棄，實得 %s", snap.State)
	}
	if snap.FaultCode != "" {
		t.Fatalf("不得留下殭屍的故障碼，實得 %q", snap.FaultCode)
	}
	if h.m.DiscardedTerminalEffects() <= discardBefore {
		t.Fatal("殭屍的 faulted 轉態應被計為丟棄")
	}
}

// TestStaleGenerationCannotFaultHealthyService：柵欄的直接驗證——
// 以一個過時世代的 attempt 嘗試 faulted 轉態，健康的 unsealed 服務不得被打倒。
// 這是縱深防護：正常路徑上 cleanup 前置已擋住「重試與殭屍並行」，
// 但柵欄本身仍必須獨立成立。
func TestStaleGenerationCannotFaultHealthyService(t *testing.T) {
	h := newHarness(t, nil)
	staleNode := h.m.node.Load()
	stale := &attempt{m: h.m, node: staleNode, gen: staleNode.generation}

	if _, err := h.unseal(context.Background()); err != nil {
		t.Fatalf("解封應成功: %v", err)
	}
	before := h.m.Snapshot()

	if stale.casCell(EventStage2Failure, func(n *sealNode) { n.faultCode = CodeInitFailed }) {
		t.Fatal("過時世代不得取得任何終局轉態")
	}
	if stale.casCell(EventStage2Published, func(n *sealNode) { n.services = &fakeGraph{} }) {
		t.Fatal("過時世代不得發佈")
	}
	after := h.m.Snapshot()
	if after.State != StateUnsealed || after.Services == nil || after.Generation != before.Generation {
		t.Fatalf("健康服務不得被過時世代改變，實得 %+v", after)
	}
	if h.m.DiscardedTerminalEffects() < 2 {
		t.Fatal("兩次過時的終局副作用皆應被計為丟棄")
	}
}

// TestNoTornWindowBetweenGateAndHandler：閘的狀態判定與 handler 的服務取用
// 讀同一次指標載入結果，故「閘看到 unsealed、handler 拿到 nil」不可達。
func TestNoTornWindowBetweenGateAndHandler(t *testing.T) {
	h := newHarness(t, nil)

	var torn atomic.Int64
	var sawUnsealed atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// 閘與 handler 共用的唯一讀取入口
				s := h.m.Snapshot()
				switch {
				case s.State == StateUnsealed && s.Services == nil:
					torn.Add(1)
				case s.State != StateUnsealed && s.Services != nil:
					torn.Add(1)
				case s.State == StateUnsealed:
					sawUnsealed.Add(1)
				}
			}
		}()
	}

	time.Sleep(5 * time.Millisecond)
	if _, err := h.unseal(context.Background()); err != nil {
		t.Fatalf("解封應成功: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	close(stop)
	wg.Wait()

	if torn.Load() != 0 {
		t.Fatalf("觀察到撕裂窗 %d 次", torn.Load())
	}
	// 正向案例：讀取者確實觀察到已發佈的狀態，否則上面的零撕裂是空真
	if sawUnsealed.Load() == 0 {
		t.Fatal("讀取者從未觀察到 unsealed，零撕裂的結論是空真")
	}
}

// TestBackoffRejectsRepeatedFailuresFromSameSource：per-source 退避的正向案例。
func TestBackoffRejectsRepeatedFailuresFromSameSource(t *testing.T) {
	h := newHarness(t, func(c *Config) {
		c.Limiter = NewLimiter(LimiterConfig{
			BaseBackoff: time.Hour, MaxBackoff: time.Hour, GlobalThreshold: 1000,
		})
	})
	h.c.verifyErr = errors.New("材料錯誤")
	if _, err := h.unseal(context.Background()); CodeOf(err) != CodeMaterialInvalid {
		t.Fatalf("預期材料失敗: %v", err)
	}
	verifyBefore := h.c.verifyCalls.Load()
	genBefore := h.m.Snapshot().Generation

	_, err := h.unseal(context.Background())
	mustCode(t, err, CodeBackoffActive)
	if h.c.verifyCalls.Load() != verifyBefore {
		t.Fatal("退避期的嘗試不得進行驗證")
	}
	if h.m.Snapshot().Generation != genBefore {
		t.Fatal("退避期的嘗試不得進入 CAS")
	}
	if h.j.count("rejected", RejectedBackoff) != 1 {
		t.Fatal("被退避拒絕的嘗試應留痕")
	}

	// 正向案例：換一個來源鍵仍可嘗試（證明退避確為 per-source 而非全域誤擋）
	if _, err := h.m.Unseal(context.Background(), UnsealRequest{
		Material: []byte("m"), SourceKey: "src-2", SourceDigest: "d",
	}); CodeOf(err) != CodeMaterialInvalid {
		t.Fatalf("另一來源應仍可嘗試，實得 %v", err)
	}
}
