package asset

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// 以堡壘機專用帳號登入目標機的頻率上限。目標機上會累加失敗登入計數的是「撥號位址＋帳號名」這個身分，
// 多筆資產指向同一台主機、或同一個專用帳號掛在多台時，逐資產計數會被繞過，所以另有以目標身分為鍵的令牌桶，
// 由專用帳號的盤點與測試登入共用同一個實例。被拒的嘗試不延後補充；鍵表有容量上限。

const (
	// executorTargetBurst 目標身分桶的突發量。
	executorTargetBurst = 3
	// executorTargetRefill 目標身分桶每回補一枚令牌的間隔。
	executorTargetRefill = 60 * time.Second
	// executorLimiterMaxKeys 每個桶表的鍵數上限，滿了淘汰最舊的鍵。
	executorLimiterMaxKeys = 4096
)

// executorTokenBucket 單一鍵的令牌桶狀態。
type executorTokenBucket struct {
	tokens   float64
	last     time.Time
	lastSeen time.Time
}

// tokenBucketTable 以鍵分桶的令牌桶表。
type tokenBucketTable struct {
	burst   float64
	refill  time.Duration
	maxKeys int
	buckets map[string]*executorTokenBucket
}

func newTokenBucketTable(burst int, refill time.Duration, maxKeys int) *tokenBucketTable {
	return &tokenBucketTable{burst: float64(burst), refill: refill, maxKeys: maxKeys, buckets: map[string]*executorTokenBucket{}}
}

// take 取一枚令牌；沒有時回 false，且不改動桶的補充起點（被拒的持續請求不延後回補）。
func (t *tokenBucketTable) take(key string, now time.Time) bool {
	b, ok := t.buckets[key]
	if !ok {
		if len(t.buckets) >= t.maxKeys {
			t.evictOldest()
		}
		b = &executorTokenBucket{tokens: t.burst, last: now}
		t.buckets[key] = b
	}
	b.lastSeen = now
	if elapsed := now.Sub(b.last); elapsed > 0 && t.refill > 0 {
		b.tokens += float64(elapsed) / float64(t.refill)
		if b.tokens > t.burst {
			b.tokens = t.burst
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (t *tokenBucketTable) evictOldest() {
	var oldestKey string
	var oldest time.Time
	first := true
	for k, b := range t.buckets {
		if first || b.lastSeen.Before(oldest) {
			oldestKey, oldest, first = k, b.lastSeen, false
		}
	}
	if !first {
		delete(t.buckets, oldestKey)
	}
}

// executorCheckLimits 測試登入的限流參數（全部可注入，測試不必靠長時間 sleep）。
type executorCheckLimits struct {
	OperatorBurst  int
	OperatorRefill time.Duration
	AssetBurst     int
	AssetRefill    time.Duration
	TargetBurst    int
	TargetRefill   time.Duration
	// MaxInFlight 全域同時執行的測試數上限。
	MaxInFlight int
	MaxKeys     int
}

func defaultExecutorCheckLimits() executorCheckLimits {
	return executorCheckLimits{
		OperatorBurst: 5, OperatorRefill: 12 * time.Second,
		AssetBurst: 3, AssetRefill: 60 * time.Second,
		TargetBurst: executorTargetBurst, TargetRefill: executorTargetRefill,
		MaxInFlight: 4, MaxKeys: executorLimiterMaxKeys,
	}
}

// executorCheckLimiter 專用帳號登入的頻率限制器：
// 測試登入走 acquire（每操作者 -> 每資產 -> 全域同時數），
// 測試登入與專用帳號盤點共用 allowTarget（目標身分桶）。
type executorCheckLimiter struct {
	mu       sync.Mutex
	now      func() time.Time
	operator *tokenBucketTable
	asset    *tokenBucketTable
	target   *tokenBucketTable

	assetBusy   map[uint]bool
	inFlight    int
	maxInFlight int
}

func newExecutorCheckLimiter() *executorCheckLimiter {
	return newExecutorCheckLimiterWith(defaultExecutorCheckLimits())
}

func newExecutorCheckLimiterWith(c executorCheckLimits) *executorCheckLimiter {
	return &executorCheckLimiter{
		now:         time.Now,
		operator:    newTokenBucketTable(c.OperatorBurst, c.OperatorRefill, c.MaxKeys),
		asset:       newTokenBucketTable(c.AssetBurst, c.AssetRefill, c.MaxKeys),
		target:      newTokenBucketTable(c.TargetBurst, c.TargetRefill, c.MaxKeys),
		assetBusy:   map[uint]bool{},
		maxInFlight: c.MaxInFlight,
	}
}

// acquire 依序取操作者令牌、資產（同時 1 筆加令牌）、全域名額。任一道拒絕即回 false。
// 同時登記（全域名額與資產忙碌旗標）只在三道都通過後才登記，所以被拒時沒有要歸還的。
// 令牌則是「前面道已扣就不退」：全域名額滿而被拒的嘗試，已扣的操作者與資產令牌不會退回，
// 與參照的 LDAP 限流器一致，讓同一操作者在全域滿載時連續重試也會被自身額度擋下。
// 被拒的嘗試不延後任何桶的回補。成功時呼叫端用完要呼叫 release。
func (l *executorCheckLimiter) acquire(operatorID, assetID uint) (release func(), ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if !l.operator.take(fmt.Sprintf("op:%d", operatorID), now) {
		return nil, false
	}
	if l.assetBusy[assetID] {
		return nil, false
	}
	if !l.asset.take(fmt.Sprintf("asset:%d", assetID), now) {
		return nil, false
	}
	if l.inFlight >= l.maxInFlight {
		return nil, false
	}
	l.inFlight++
	l.assetBusy[assetID] = true
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.inFlight--
			delete(l.assetBusy, assetID)
		})
	}, true
}

// allowTarget 取目標身分桶的一枚令牌；用盡回 false。
func (l *executorCheckLimiter) allowTarget(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.target.take(key, l.now())
}

// executorTargetKey 目標身分的鍵：撥號位址（主機小寫、埠）加專用帳號名。
func executorTargetKey(host string, port int, username string) string {
	return fmt.Sprintf("%s:%d|%s", strings.ToLower(strings.TrimSpace(host)), port, username)
}

// NewExecutorCheckLimiter 建立限流器（組裝根用；盤點與測試登入共用同一個）。
func NewExecutorCheckLimiter() *ExecutorCheckLimiter { return newExecutorCheckLimiter() }

// ExecutorCheckLimiter 組裝根持有的限流器型別別名。
type ExecutorCheckLimiter = executorCheckLimiter
