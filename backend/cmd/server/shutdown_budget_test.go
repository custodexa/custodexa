package main

import (
	"context"
	"testing"
	"time"
)

// TestResourceShutdownContextGuaranteesFloor 段 2 資源收束的預算獨立於監聽收束。
//
// 兩個方向缺一不可：監聽收束吃光預算時資源收束仍有保底（否則審計佇列一列都排不了）；
// 監聽提早收完時沿用原期限（否則正常路徑的關閉時長被無故縮短）。
func TestResourceShutdownContextGuaranteesFloor(t *testing.T) {
	now := time.Now()

	t.Run("監聽收束耗盡預算：資源收束仍取得保底", func(t *testing.T) {
		exhausted, cancel := context.WithDeadline(context.Background(), now.Add(-time.Second))
		defer cancel()
		<-exhausted.Done() // 前置條件：父 context 已過期

		rctx, rcancel := resourceShutdownContext(exhausted, now)
		defer rcancel()
		select {
		case <-rctx.Done():
			t.Fatal("資源收束 context 隨監聽收束一起過期——保底沒有生效")
		default:
		}
		d, ok := rctx.Deadline()
		if !ok || !d.Equal(now.Add(resourceShutdownFloor)) {
			t.Fatalf("期限應為 now＋保底 %v，得 %v（ok=%v）", resourceShutdownFloor, d, ok)
		}
	})

	t.Run("監聽提早收完：沿用原期限", func(t *testing.T) {
		original := now.Add(listenerShutdownTimeout)
		parent, cancel := context.WithDeadline(context.Background(), original)
		defer cancel()

		rctx, rcancel := resourceShutdownContext(parent, now)
		defer rcancel()
		d, ok := rctx.Deadline()
		if !ok || !d.Equal(original) {
			t.Fatalf("原期限尚有餘裕時應沿用 %v，得 %v（ok=%v）", original, d, ok)
		}
	})

	if listenerShutdownTimeout+resourceShutdownFloor >= 10*time.Second {
		t.Fatalf("兩段預算相加 %v 未留在容器編排預設的強制終止期限（10 秒）內",
			listenerShutdownTimeout+resourceShutdownFloor)
	}
}
