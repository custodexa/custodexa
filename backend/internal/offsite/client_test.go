package offsite

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

// TestTransferTimeoutFloorNotLowered deadline 下限守衛（design §9：常數附守衛
// 防調得更緊）。下限被調低時，大檔上傳在慢速線路上會被自己的 deadline 砍斷、
// 進入永遠成功不了的重試循環。調高要重推導速率基準，不在本守衛射程。
func TestTransferTimeoutFloorNotLowered(t *testing.T) {
	if transferTimeoutFloor < 2*time.Minute {
		t.Fatalf("transferTimeoutFloor=%v 低於 2 分鐘下限：調低會使大檔在慢速線路上被自己的 deadline 砍斷", transferTimeoutFloor)
	}
	if transferRateBytesPerSec > 1<<20 {
		t.Fatalf("transferRateBytesPerSec=%d 高於 1 MiB/s 保守基準：等效於收緊 deadline，重推導須連同本守衛一起改", transferRateBytesPerSec)
	}
}

// TestTransferTimeoutDerivation 依大小推導：未知取下限、小檔取下限、
// 大檔依 size ÷ 1 MiB/s × 2。
func TestTransferTimeoutDerivation(t *testing.T) {
	cases := []struct {
		size int64
		want time.Duration
	}{
		{0, 2 * time.Minute},
		{-1, 2 * time.Minute},
		{10 << 20, 2 * time.Minute},                  // 10 MiB → 20s < 下限
		{1 << 30, time.Duration(1024) * time.Second * 2}, // 1 GiB → 2048s
	}
	for _, c := range cases {
		if got := transferTimeout(c.size); got != c.want {
			t.Errorf("transferTimeout(%d)=%v, want %v", c.size, got, c.want)
		}
	}
}

// TestFakeClientBlockingSlotHonorsDeadline 阻塞格實證 deadline 真的觸發
// （半開連線在逐操作 deadline 被截斷；FakeClient 的
// BlockUntilCtx 格＝<-ctx.Done() 實作，斷言回傳時間 < deadline＋容差）。
func TestFakeClientBlockingSlotHonorsDeadline(t *testing.T) {
	f := NewFakeClient("b")
	slot := f.Inject(&FaultSlot{Op: "head", Key: "k", BlockUntilCtx: true})
	t.Cleanup(func() {
		if slot.Fired() == 0 {
			t.Error("阻塞格從未被命中：測試沒走到注入點")
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := f.Head(ctx, ObjectRef{Key: "k"})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("阻塞至 ctx 結束的呼叫 MUST 回錯誤")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("錯誤應為 deadline 逾時，got %v", err)
	}
	// 外層 ctx 150ms 早於 Head 內部的 30s deadline：呼叫者的 ctx 一律被尊重
	if elapsed > 5*time.Second {
		t.Fatalf("阻塞呼叫耗時 %v，deadline 未生效", elapsed)
	}
}

// TestFakeClientFaultSlotKeyScoped 注入格只對命中本格 key 的呼叫注入
// （testing.md §7：不相干 key 的呼叫不得取得 credit），且回本格哨兵。
func TestFakeClientFaultSlotKeyScoped(t *testing.T) {
	f := NewFakeClient("b")
	sentinel := errors.New("slot-sentinel")
	slot := f.Inject(&FaultSlot{Op: "put", Key: "target", Err: sentinel})

	// 對照：不相干 key 的 Put 成功、不觸發注入
	if _, err := f.Put(context.Background(), "other", bytes.NewReader([]byte("x")), PutOpts{ContentLength: 1}); err != nil {
		t.Fatalf("不相干 key 的 Put 不應失敗: %v", err)
	}
	if slot.Fired() != 0 {
		t.Fatalf("注入格被不相干 key 命中 %d 次", slot.Fired())
	}
	// 命中：回本格哨兵
	_, err := f.Put(context.Background(), "target", bytes.NewReader([]byte("x")), PutOpts{ContentLength: 1})
	if !errors.Is(err, sentinel) {
		t.Fatalf("命中格應回本格哨兵，got %v", err)
	}
	if slot.Fired() != 1 {
		t.Fatalf("fired=%d, want 1", slot.Fired())
	}
}

// TestObjectKeyLayout key 組法。
func TestObjectKeyLayout(t *testing.T) {
	ended := time.Date(2026, 8, 31, 3, 4, 5, 0, time.UTC)
	cases := []struct{ got, want string }{
		{RecordingObjectKey("", 42, ended, "cast"), "recordings/2026/08/session-42.cast"},
		{RecordingObjectKey("corp", 42, ended, "guac"), "corp/recordings/2026/08/session-42.guac"},
		{RecordingObjectKey("corp/", 42, ended, "cast"), "corp/recordings/2026/08/session-42.cast"},
		{ExportObjectKey("", 7), "exports/job-7.zip"},
		{ExportObjectKey("corp", 7), "corp/exports/job-7.zip"},
		{ConnectionTestObjectKey("corp", 123), "corp/.custodexa-connection-test-123"},
		{ConnectionTestObjectKey("", 123), ".custodexa-connection-test-123"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("key=%q, want %q", c.got, c.want)
		}
	}
}

// TestObjectKeyMonthBucketUsesUTC 年月分桶固定 UTC：同一時刻在不同時區
// 不得落到不同月份桶（跨年邊界最會出事）。
func TestObjectKeyMonthBucketUsesUTC(t *testing.T) {
	// UTC 2025-12-31 23:30 ＝ 台北 2026-01-01 07:30
	taipei := time.FixedZone("Asia/Taipei", 8*3600)
	ended := time.Date(2026, 1, 1, 7, 30, 0, 0, taipei)
	if got := RecordingObjectKey("", 1, ended, "cast"); got != "recordings/2025/12/session-1.cast" {
		t.Fatalf("月份桶未固定 UTC：%q", got)
	}
}
