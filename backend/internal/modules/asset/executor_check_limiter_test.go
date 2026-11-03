package asset

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeLimiterClock struct{ t time.Time }

func (c *fakeLimiterClock) now() time.Time { return c.t }

func newTestLimiter(c executorCheckLimits) (*executorCheckLimiter, *fakeLimiterClock) {
	l := newExecutorCheckLimiterWith(c)
	clk := &fakeLimiterClock{t: time.Unix(1_800_000_000, 0)}
	l.now = clk.now
	return l, clk
}

func testLimits() executorCheckLimits {
	return executorCheckLimits{
		OperatorBurst: 3, OperatorRefill: 12 * time.Second,
		AssetBurst: 3, AssetRefill: 60 * time.Second,
		TargetBurst: 3, TargetRefill: 60 * time.Second,
		MaxInFlight: 4, MaxKeys: 4,
	}
}

func TestExecutorCheckLimiter(t *testing.T) {
	t.Run("操作者突發用盡拒絕且未消耗資產額度", func(t *testing.T) {
		l, _ := newTestLimiter(testLimits())
		for i := 0; i < 3; i++ {
			rel, ok := l.acquire(1, uint(100+i))
			require.True(t, ok)
			rel()
		}
		_, ok := l.acquire(1, 200)
		assert.False(t, ok)
		// 同一資產 200 未被扣額度：換一個操作者可連續取 3 次
		for i := 0; i < 3; i++ {
			rel, ok := l.acquire(2, 200)
			require.True(t, ok, "第 %d 次", i)
			rel()
		}
	})
	t.Run("同資產第二筆同時拒絕", func(t *testing.T) {
		l, _ := newTestLimiter(testLimits())
		rel, ok := l.acquire(1, 7)
		require.True(t, ok)
		_, ok2 := l.acquire(2, 7)
		assert.False(t, ok2)
		rel()
		rel2, ok3 := l.acquire(2, 7)
		assert.True(t, ok3, "release 後可再取得")
		rel2()
	})
	t.Run("全域滿拒絕、歸還後可取", func(t *testing.T) {
		c := testLimits()
		c.OperatorBurst = 50
		l, _ := newTestLimiter(c)
		var rels []func()
		for i := 0; i < 4; i++ {
			rel, ok := l.acquire(1, uint(10+i))
			require.True(t, ok)
			rels = append(rels, rel)
		}
		_, ok := l.acquire(1, 99)
		assert.False(t, ok)
		rels[0]()
		rel, ok := l.acquire(1, 99)
		assert.True(t, ok)
		rel()
		for _, r := range rels[1:] {
			r()
		}
	})
	t.Run("被拒的持續請求不延後回補", func(t *testing.T) {
		l, clk := newTestLimiter(testLimits())
		for i := 0; i < 3; i++ {
			rel, ok := l.acquire(1, uint(i+1))
			require.True(t, ok)
			rel()
		}
		for i := 0; i < 10; i++ {
			clk.t = clk.t.Add(time.Second)
			_, ok := l.acquire(1, 50)
			assert.False(t, ok)
		}
		clk.t = clk.t.Add(3 * time.Second) // 距首次取用共 13 秒，應已回補一枚
		rel, ok := l.acquire(1, 60)
		assert.True(t, ok)
		if ok {
			rel()
		}
	})
	t.Run("鍵表滿時淘汰最舊鍵不 panic", func(t *testing.T) {
		l, clk := newTestLimiter(testLimits())
		for i := 0; i < 20; i++ {
			clk.t = clk.t.Add(time.Millisecond)
			assert.NotPanics(t, func() {
				l.allowTarget(executorTargetKey("h", 22, string(rune('a'+i))))
			})
		}
		assert.LessOrEqual(t, len(l.target.buckets), 4)
	})
	t.Run("目標身分桶：不同資產鍵共用額度、大小寫視為同鍵、不同帳號名不共用", func(t *testing.T) {
		l, _ := newTestLimiter(testLimits())
		assert.True(t, l.allowTarget(executorTargetKey("HOST.example", 22, "cx")))
		assert.True(t, l.allowTarget(executorTargetKey("host.example", 22, "cx")))
		assert.True(t, l.allowTarget(executorTargetKey("host.example", 22, "cx")))
		assert.False(t, l.allowTarget(executorTargetKey("Host.Example", 22, "cx")), "第 4 次拒絕")
		assert.True(t, l.allowTarget(executorTargetKey("host.example", 22, "other")))
	})
	t.Run("併發取用不超過全域上限", func(t *testing.T) {
		c := testLimits()
		c.OperatorBurst = 1000
		c.MaxKeys = 1024
		l := newExecutorCheckLimiterWith(c)
		var wg sync.WaitGroup
		var mu sync.Mutex
		got := 0
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				if _, ok := l.acquire(1, uint(i+1)); ok {
					mu.Lock()
					got++
					mu.Unlock()
				}
			}(i)
		}
		wg.Wait()
		assert.Equal(t, 4, got)
	})
}
