package offsite

import (
	"errors"
	"sync"
	"time"
)

// 連線測試的資源上限（沿 LDAP probe 的限流慣例）。
//
// # 為什麼測試端點需要限流
//
// 端點是管理員輸入的**任意主機**，而測試會真的對它發出連線。沒有上限時，一個
// admin session（或被劫持的 session）就能把本服務當成對外的探測與流量放大器；
// 就算沒有惡意，一個卡在逾時的端點也能讓數十個並行測試把連線與 goroutine 吃光。
//
// # 與 LDAP probe 的差異（誠實界定）
//
// LDAP 那一套另有「逐目標桶」與可注入的執行期資源（供測試調參）。此處**只有
// 兩道**：逐操作者的權杖桶與全域在途上限——object store 的 driver 自帶傳輸
// deadline（`client.go` 的 deadline 常數表），在途上限因此已能界定資源占用。
// 需要逐目標桶時再加，不預先造一個沒有消費者的維度。

// ErrOffsiteTestRateLimited 連線測試超出資源上限。
//
// **不揭露命中哪一道界線、不回 Retry-After**：那些數值會讓攻擊者精確地把流量
// 調到門檻之下持續消耗，而正當使用者只需要「稍後再試」。
var ErrOffsiteTestRateLimited = errors.New("離機儲存連線測試過於頻繁，請稍後再試")

const (
	// offsiteTestActorBurst 單一操作者的權杖上限
	offsiteTestActorBurst = 5
	// offsiteTestActorRefill 權杖補充間隔（每 12 秒補一顆＝穩態每分鐘 5 次）
	offsiteTestActorRefill = 12 * time.Second
	// offsiteTestMaxInFlight 全域同時進行中的測試數上限
	offsiteTestMaxInFlight = 2
)

// offsiteTestLimiter 逐操作者權杖桶＋全域在途上限。
type offsiteTestLimiter struct {
	mu       sync.Mutex
	tokens   map[string]int
	refilled map[string]time.Time
	inFlight int
	now      func() time.Time
}

func newOffsiteTestLimiter() *offsiteTestLimiter {
	return &offsiteTestLimiter{
		tokens: map[string]int{}, refilled: map[string]time.Time{}, now: time.Now,
	}
}

// acquire 取得一次測試的許可；回傳的 release 必須被呼叫（defer）。
func (l *offsiteTestLimiter) acquire(actorKey string) (release func(), ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	last, seen := l.refilled[actorKey]
	if !seen {
		l.tokens[actorKey] = offsiteTestActorBurst
		l.refilled[actorKey] = now
	} else if gained := int(now.Sub(last) / offsiteTestActorRefill); gained > 0 {
		t := l.tokens[actorKey] + gained
		if t > offsiteTestActorBurst {
			t = offsiteTestActorBurst
		}
		l.tokens[actorKey] = t
		l.refilled[actorKey] = now
	}
	if l.tokens[actorKey] <= 0 || l.inFlight >= offsiteTestMaxInFlight {
		return func() {}, false
	}
	l.tokens[actorKey]--
	l.inFlight++
	return func() {
		l.mu.Lock()
		l.inFlight--
		l.mu.Unlock()
	}, true
}
