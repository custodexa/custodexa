package identity

import (
	"sync"
	"time"
)

// LDAP 連線測試端點的資源上限。
//
// # 為什麼一個 admin-only 端點需要限流
//
// 單次測試最壞約 15 秒（dial／bind／search 各 5 秒），且**成功與失敗皆寫審計**。
// 無上限時，被劫持的 admin session 可同時耗盡三種資源：handler goroutine、
// 對外 LDAP socket，以及審計儲存——「全數審計」這道安全機制本身成為放大器。
//
// # 三道界線，缺一不可
//
//	per-actor → per-target → 全域 in-flight
//
//   - per-actor：單一操作者的節流。順序排第一，使被 actor 桶擋下的洪水
//     **不消耗 target 額度**（否則一個 admin 即可把某目標的額度打空，
//     其他 admin 連正常測試都做不了）。
//   - per-target：同一目錄位址的節流。admin 對「目標位址」有寫入權，
//     階梯回應天然是 open/closed oracle（誠實記載的殘餘面），
//     per-target 直接壓低掃描速率——這是 oracle 殘餘面的收斂手段之一。
//   - 全域 in-flight：速率上限擋不住「每個都很慢」造成的堆積（15 秒的阻塞
//     呼叫），故另設同時處理中的上限。
//
// 令牌桶語義沿 internal/api 的 oidcAbuseGuard 先例（含「被拒絕的嘗試不延後
// 補充時間」這條——否則持續送請求即可把窗口無限往後推，正當使用者永遠等不到
// 額度）。**不共用該實作**：它綁在 gin 的 *gin.Context 與 IP 取值語義上，
// 而本限流的鍵是已認證的 actor 與已正規化的目標端點，不是網路來源。
//
// 本結構為 in-memory、每副本各自限流——同 oidcAbuseGuard 的取捨：共享狀態需
// 外部存放，而其寫入正是本防護要保護的資源。

// ldapProbeLimits 限流參數（全部可注入，使測試不必依賴真實時間長 sleep）
type ldapProbeLimits struct {
	// ActorBurst 單一操作者可累積的測試次數
	ActorBurst float64
	// ActorRefill 每補回一次 actor 額度所需時間
	ActorRefill time.Duration
	// TargetBurst 單一目標端點可累積的測試次數
	TargetBurst float64
	// TargetRefill 每補回一次 target 額度所需時間
	TargetRefill time.Duration
	// MaxInFlight 全域同時執行中的測試數上限
	MaxInFlight int
	// MaxKeys actor／target 表各自的容量（無界鍵集合的記憶體保護）
	MaxKeys int
}

// defaultLDAPProbeLimits 預設參數。
//
// 量級以「admin 調設定時反覆按測試」為基準：5 次突發、每 12 秒回補一次
// （穩態約 5 次／分）足夠一輪除錯來回，卻使窮舉內網埠的成本高到無意義。
// 目標側放寬到 10／每 6 秒回補，讓多位 admin 同時對同一目錄除錯不互相擋。
func defaultLDAPProbeLimits() ldapProbeLimits {
	return ldapProbeLimits{
		ActorBurst:   5,
		ActorRefill:  12 * time.Second,
		TargetBurst:  10,
		TargetRefill: 6 * time.Second,
		MaxInFlight:  4,
		MaxKeys:      256,
	}
}

// 限流拒絕原因（**僅供伺服端 log**：對外一律收斂為單一「請稍後再試」語義，
// 回應不洩漏限流參數與命中哪一道——那些數值會讓攻擊者精確地把流量調到門檻
// 之下持續消耗）
const (
	ldapProbeLimitActor    = "actor"
	ldapProbeLimitTarget   = "target"
	ldapProbeLimitInFlight = "in_flight"
)

// ldapProbeBucket 令牌桶（以「上次補充時間＋餘額」表示，無背景 goroutine）
type ldapProbeBucket struct {
	tokens float64
	last   time.Time
}

// allow 消費一個令牌；額度不足回 false。
//
// **被拒絕的嘗試不更新補充時間**——先算補充再判定，判定失敗時 last 已前移但
// 額度未扣，故不存在「持續送請求把窗口往後推」的形態（同 oidcAbuseGuard）
func (b *ldapProbeBucket) allow(now time.Time, burst float64, refill time.Duration) bool {
	if b.last.IsZero() {
		b.tokens = burst
		b.last = now
	}
	if elapsed := now.Sub(b.last); elapsed > 0 {
		if refill > 0 {
			b.tokens += float64(elapsed) / float64(refill)
			if b.tokens > burst {
				b.tokens = burst
			}
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// ldapProbeLimiter 連線測試的三道資源界線
type ldapProbeLimiter struct {
	mu     sync.Mutex
	params ldapProbeLimits
	now    func() time.Time

	actors  map[string]*ldapProbeBucket
	targets map[string]*ldapProbeBucket
	// overflowActor／overflowTarget 表滿載後的共用桶：**不 fail-open**，
	// 也不無界成長（沿 oidcAbuseGuard 的 overflow 取捨）
	overflowActor  ldapProbeBucket
	overflowTarget ldapProbeBucket

	inFlight int
}

// newLDAPProbeLimiter 建立限流器；零值參數取預設
func newLDAPProbeLimiter(params ldapProbeLimits) *ldapProbeLimiter {
	d := defaultLDAPProbeLimits()
	if params.ActorBurst <= 0 {
		params.ActorBurst = d.ActorBurst
	}
	if params.ActorRefill <= 0 {
		params.ActorRefill = d.ActorRefill
	}
	if params.TargetBurst <= 0 {
		params.TargetBurst = d.TargetBurst
	}
	if params.TargetRefill <= 0 {
		params.TargetRefill = d.TargetRefill
	}
	if params.MaxInFlight <= 0 {
		params.MaxInFlight = d.MaxInFlight
	}
	if params.MaxKeys <= 0 {
		params.MaxKeys = d.MaxKeys
	}
	return &ldapProbeLimiter{
		params:  params,
		now:     time.Now,
		actors:  make(map[string]*ldapProbeBucket),
		targets: make(map[string]*ldapProbeBucket),
	}
}

// acquire 取得一次測試額度。
//
// 回傳的 release 須於測試結束後呼叫（並發計數歸還），且為冪等——呼叫端一律
// `defer release()`，重複歸還會使 in-flight 計數失真而讓上限失效。
// reason 僅在被拒時有值，供伺服端 log 判斷是哪一道界線命中
func (l *ldapProbeLimiter) acquire(actorKey, targetKey string) (release func(), reason string, ok bool) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	actor := l.bucketLocked(l.actors, &l.overflowActor, actorKey, now, l.params.ActorBurst, l.params.ActorRefill)
	if !actor.allow(now, l.params.ActorBurst, l.params.ActorRefill) {
		return nil, ldapProbeLimitActor, false
	}
	target := l.bucketLocked(l.targets, &l.overflowTarget, targetKey, now, l.params.TargetBurst, l.params.TargetRefill)
	if !target.allow(now, l.params.TargetBurst, l.params.TargetRefill) {
		return nil, ldapProbeLimitTarget, false
	}
	if l.inFlight >= l.params.MaxInFlight {
		return nil, ldapProbeLimitInFlight, false
	}
	l.inFlight++

	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			if l.inFlight > 0 {
				l.inFlight--
			}
			l.mu.Unlock()
		})
	}, "", true
}

// bucketLocked 取得（必要時建立）鍵對應的桶；表滿時先清掉已回滿的閒置條目，
// 仍滿則落到共用 overflow 桶
func (l *ldapProbeLimiter) bucketLocked(table map[string]*ldapProbeBucket, overflow *ldapProbeBucket,
	key string, now time.Time, burst float64, refill time.Duration) *ldapProbeBucket {
	if b, ok := table[key]; ok {
		return b
	}
	if len(table) >= l.params.MaxKeys {
		pruneLDAPProbeBuckets(table, now, burst, refill)
	}
	if len(table) >= l.params.MaxKeys {
		return overflow
	}
	b := &ldapProbeBucket{}
	table[key] = b
	return b
}

// pruneLDAPProbeBuckets 清掉額度已回滿的條目：它們與「不存在」等價，保留只是佔記憶體
func pruneLDAPProbeBuckets(table map[string]*ldapProbeBucket, now time.Time, burst float64, refill time.Duration) {
	for k, b := range table {
		refilled := b.tokens
		if elapsed := now.Sub(b.last); elapsed > 0 && refill > 0 {
			refilled += float64(elapsed) / float64(refill)
		}
		if refilled >= burst {
			delete(table, k)
		}
	}
}
