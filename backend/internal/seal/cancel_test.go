package seal

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCheckCancelPassesWhileLive(t *testing.T) {
	if err := CheckCancel(context.Background()); err != nil {
		t.Fatalf("未取消時應通過，實得 %v", err)
	}
	if err := CheckCancelStep(context.Background(), "啟動排程器"); err != nil {
		t.Fatalf("未取消時應通過，實得 %v", err)
	}
}

func TestCheckCancelBlocksAfterCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := CheckCancel(ctx)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("取消後應回傳可辨識的取消錯誤，實得 %v", err)
	}
	err = CheckCancelStep(ctx, "啟動排程器")
	if err == nil || !strings.Contains(err.Error(), "啟動排程器") {
		t.Fatalf("步驟名應進入錯誤訊息，實得 %v", err)
	}
}

// TestStage2CancelledDoesNotStartSchedulerOrNotifier：合作式取消契約的行為驗證。
// 段 2 於每個具外部副作用的步驟之前檢查取消——取消後不得啟動排程器、
// 不得開始通知投遞、不得建立新的外部連線。
func TestStage2CancelledDoesNotStartSchedulerOrNotifier(t *testing.T) {
	type sideEffects struct {
		schedulerStarted atomic.Bool
		notifierStarted  atomic.Bool
		connOpened       atomic.Bool
	}

	// contractualStage2 是遵守合作式取消契約的段 2 範本
	build := func(se *sideEffects, gate <-chan struct{}) Stage2Func {
		return func(ctx context.Context, v VerifiedMaterial) (ServiceGraph, error) {
			if gate != nil {
				select {
				case <-gate:
				case <-ctx.Done():
				}
			}
			if err := CheckCancelStep(ctx, "建立外部連線"); err != nil {
				return nil, err
			}
			se.connOpened.Store(true)
			if err := CheckCancelStep(ctx, "開始通知投遞"); err != nil {
				return nil, err
			}
			se.notifierStarted.Store(true)
			if err := CheckCancelStep(ctx, "啟動排程器"); err != nil {
				return nil, err
			}
			se.schedulerStarted.Store(true)
			return &fakeGraph{name: "full"}, nil
		}
	}

	// 負面案例：取消後三項副作用皆不得發生
	var se sideEffects
	gate := make(chan struct{})
	h := newHarness(t, func(c *Config) { c.Stage2 = build(&se, gate) })
	started := make(chan struct{})
	h.c.verifyObserve = func() { close(started) }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := h.unseal(ctx); done <- err }()
	<-started
	time.Sleep(5 * time.Millisecond)
	cancel()
	if err := <-done; CellOf(err) != "6" && CellOf(err) != "4b" {
		t.Fatalf("取消應走格 4b 或格 6，實得 %v", err)
	}
	if se.connOpened.Load() || se.notifierStarted.Load() || se.schedulerStarted.Load() {
		t.Fatalf("取消後仍發生副作用: conn=%v notifier=%v scheduler=%v",
			se.connOpened.Load(), se.notifierStarted.Load(), se.schedulerStarted.Load())
	}
	h.m.WaitCleanup()

	// 正向案例：未取消時三項副作用都應發生，否則上面的「皆未發生」是空真
	var okSE sideEffects
	h2 := newHarness(t, func(c *Config) { c.Stage2 = build(&okSE, nil) })
	if _, err := h2.unseal(context.Background()); err != nil {
		t.Fatalf("未取消時應成功: %v", err)
	}
	if !okSE.connOpened.Load() || !okSE.notifierStarted.Load() || !okSE.schedulerStarted.Load() {
		t.Fatal("未取消時三項副作用都應發生")
	}
}

// TestTwoServiceGraphsNeverHoldResourcesSimultaneously：不放行兩份服務圖。
// 該保證 MUST 由 cleanup 的 CAS 前置承載，而非測試巧合——故本測試同時斷言
// 結構前置（acquireBlocker／遷移表）與行為結果（同時存活數恆 ≤ 1）。
func TestTwoServiceGraphsNeverHoldResourcesSimultaneously(t *testing.T) {
	var live atomic.Int64
	var peak atomic.Int64
	newGraph := func(name string) *fakeGraph {
		n := live.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		return &fakeGraph{name: name, onRelease: func() { live.Add(-1) }}
	}

	h := newHarness(t, func(c *Config) { c.Stage2Timeout = 30 * time.Millisecond })
	h.c.stage2Hard = make(chan struct{})
	h.c.stage2IgnoreCancel = true
	h.c.stage2Graph = newGraph("first")

	if _, err := h.unseal(context.Background()); CodeOf(err) != CodeStage2Timeout {
		t.Fatalf("預期逾時: %v", err)
	}

	// 結構前置：待收束時取得持有權在遷移表上無任何格可落
	if _, ok := Resolve(Situation{From: StateSealed, Event: EventUnsealRequest, HasCleanup: true, HolderAcquired: true}); ok {
		t.Fatal("待收束時取得持有權不得存在合法遷移格")
	}
	blocked := &sealNode{state: StateSealed, cleanup: &cleanupToken{generation: 1}}
	if code, ok := acquireBlocker(blocked); !ok || code != CodeCleanupPending {
		t.Fatalf("cleanup != nil SHALL 阻擋取得持有權，實得 %q/%v", code, ok)
	}

	// 行為：待收束期間的新解封被拒，第二份服務圖根本不會被建構
	if _, err := h.unseal(context.Background()); CodeOf(err) != CodeCleanupPending {
		t.Fatalf("待收束期間應被拒: %v", err)
	}
	if got := live.Load(); got != 1 {
		t.Fatalf("待收束期間不得出現第二份服務圖，存活數 %d", got)
	}

	close(h.c.stage2Hard)
	h.m.WaitCleanup()
	if got := live.Load(); got != 0 {
		t.Fatalf("收束後應無存活服務圖，實得 %d", got)
	}

	// 收束完成後才可再取得持有權
	h.c.stage2Hard = nil
	h.c.stage2IgnoreCancel = false
	h.c.stage2Graph = newGraph("second")
	if _, err := h.unseal(context.Background()); err != nil {
		t.Fatalf("收束完成後應可解封: %v", err)
	}
	if peak.Load() > 1 {
		t.Fatalf("兩份服務圖曾同時持有資源，峰值 %d", peak.Load())
	}
}

// ---------------------------------------------------------------------------
// ResourceBag
// ---------------------------------------------------------------------------

func TestResourceBagReleasesInReverseOrder(t *testing.T) {
	var order []string
	var bag ResourceBag
	for _, name := range []string{"a", "b", "c"} {
		n := name
		bag.AddFunc(n, func(ctx context.Context) error {
			order = append(order, n)
			return nil
		})
	}
	if bag.Len() != 3 {
		t.Fatalf("預期 3 項，實得 %d", bag.Len())
	}
	if err := bag.Release(context.Background()); err != nil {
		t.Fatalf("釋放不應失敗: %v", err)
	}
	if len(order) != 3 || order[0] != "c" || order[1] != "b" || order[2] != "a" {
		t.Fatalf("應以反序釋放，實得 %v", order)
	}
	if !bag.Released() {
		t.Fatal("應標記為已釋放")
	}
}

func TestResourceBagIsIdempotent(t *testing.T) {
	var calls int
	var bag ResourceBag
	bag.AddFunc("x", func(ctx context.Context) error { calls++; return nil })
	_ = bag.Release(context.Background())
	_ = bag.Release(context.Background())
	if calls != 1 {
		t.Fatalf("重複釋放不得重複執行，實得 %d 次", calls)
	}
}

func TestResourceBagContinuesAfterFailureAndPanic(t *testing.T) {
	var released []string
	var bag ResourceBag
	bag.AddFunc("first", func(ctx context.Context) error { released = append(released, "first"); return nil })
	bag.AddFunc("boom", func(ctx context.Context) error { panic("釋放時 panic") })
	bag.AddFunc("bad", func(ctx context.Context) error { return errors.New("關不掉") })
	bag.AddFunc("last", func(ctx context.Context) error { released = append(released, "last"); return nil })

	err := bag.Release(context.Background())
	if err == nil {
		t.Fatal("失敗與 panic 都應被聚合回報")
	}
	if !strings.Contains(err.Error(), "boom") || !strings.Contains(err.Error(), "bad") {
		t.Fatalf("錯誤應含失敗項名稱，實得 %v", err)
	}
	if len(released) != 2 || released[0] != "last" || released[1] != "first" {
		t.Fatalf("中途失敗不得中斷後續釋放，實得 %v", released)
	}
}

func TestResourceBagIgnoresNil(t *testing.T) {
	var bag ResourceBag
	bag.Add("nil", nil)
	bag.AddFunc("nilfn", nil)
	if bag.Len() != 0 {
		t.Fatalf("nil 項應被忽略，實得 %d", bag.Len())
	}
	if err := bag.Release(context.Background()); err != nil {
		t.Fatalf("空袋釋放不應失敗: %v", err)
	}
}
