package api

import (
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/model"
)

// OIDC 公開端點的濫用防護（idp-oidc-integration 3.7a／design D13）。
//
// callback 與 exchange 皆為**未認證可達**且會觸發持久化副作用的端點：前者在
// state 查找階段即失敗（無須接觸 IdP、不受 flow state 容量限制），後者以隨機
// ticket 即可製造查詢與審計寫入。兩者原本都缺乏任何邊界，故此處施加三道：
//
//	per-IP 速率 → 全域速率 → 全域並發
//
// **兩層都要**的理由：per-IP 只在可信代理鏈已約定時才可信（未設 SEAL/TRUSTED_PROXIES
// 時 gin 信任任意 X-Forwarded-For），攻擊者輪換偽造標頭即可換到新的限流鍵；
// 全域上限不依賴任何客戶端可控輸入，是真正的保證。反之只有全域上限時，單一
// 來源即可耗盡全體額度，故 per-IP 仍須施加以提高成本。
//
// 失敗事件改採**聚合審計**：偵測訊號本身不得成為 DoS 載體。逐請求落審計時，
// 「持續送隨機 state」即等於「持續寫 DB」；聚合後同一（事件, IP, 時間窗）
// 至多一筆，筆數上界為 MaxAggregates × 每窗一筆。
//
// 本結構為 in-memory、**每副本各自限流**——多副本部署下實際額度為副本數的倍數。
// 此為刻意取捨：共享狀態需外部存放（Redis/DB），而其寫入正是本防護要保護的
// 資源。副本數為個位數時倍數效應可接受，且全域上限的量級即據此設定。
type sourceAbuseGuard struct {
	mu         sync.Mutex
	params     sourceGuardParams
	now        func() time.Time
	trustProxy bool
	sources    map[string]*tokenBucket
	overflow   tokenBucket // 來源表滿載後的共用桶（不 fail-open）
	global     tokenBucket
	inFlight   int
	agg        map[abuseAggKey]*abuseAggEntry
	sink       sourceAbuseAuditSink
}

// sourceGuardParams 限流參數。全部可注入，使測試不必依賴真實時間長 sleep
type sourceGuardParams struct {
	// PerIPBurst per-IP 可累積的請求額度上限
	PerIPBurst float64
	// PerIPRefill 每補回一個 per-IP 額度所需時間
	PerIPRefill time.Duration
	// GlobalBurst 全域可累積的請求額度上限
	GlobalBurst float64
	// GlobalRefill 每補回一個全域額度所需時間
	GlobalRefill time.Duration
	// MaxInFlight 全域同時處理中的請求數上限（callback 會發出對 IdP 的出站請求，
	// 速率上限擋不住「每個都很慢」造成的堆積）
	MaxInFlight int
	// MaxSources per-IP 表容量（無界來源集合的記憶體保護）
	MaxSources int
	// AggregateWindow 聚合審計的時間窗
	AggregateWindow time.Duration
	// MaxAggregates 聚合表容量
	MaxAggregates int
}

// defaultOIDCGuardParams 預設參數。
//
// 量級以「單一組織的正常 SSO 登入」為基準：per-IP 60 burst／60 次每分鐘涵蓋
// NAT 後整個辦公室同時上班登入；全域 600 burst／600 次每分鐘遠高於任何正常
// 尖峰，卻把最壞情況的 DB 讀取與出站請求壓在可預期的量級內。
func defaultOIDCGuardParams() sourceGuardParams {
	return sourceGuardParams{
		PerIPBurst:      60,
		PerIPRefill:     time.Second,
		GlobalBurst:     600,
		GlobalRefill:    100 * time.Millisecond,
		MaxInFlight:     32,
		MaxSources:      4096,
		AggregateWindow: time.Minute,
		MaxAggregates:   1024,
	}
}

// sourceAbuseAuditSink 聚合審計出口。抽成介面使「筆數有界」可被斷言——
// 真實審計服務是非同步的（worker＋channel＋flush），測試無從證明上界
type sourceAbuseAuditSink interface {
	LogAggregatedFailure(event, clientIP string, status model.AuditStatus, count int, firstAt, lastAt time.Time)
}

// abuseAggOverflowIP 聚合表滿載後的共用鍵。**不丟棄事件**：偵測訊號可以失去
// 來源解析度，但不該整段消失。
//
// 表容量因此是軟上限：實際條目數 ≤ MaxAggregates ＋ 事件種類數（每種一個
// overflow 鍵）。事件種類是程式碼裡的有限常數，故整體仍為常數級
const abuseAggOverflowIP = "(overflow)"

type abuseAggKey struct {
	event string
	ip    string
}

type abuseAggEntry struct {
	count     int
	first     time.Time
	last      time.Time
	windowEnd time.Time
}

// tokenBucket 令牌桶。以「上次補充時間＋餘額」表示，無背景 goroutine
type tokenBucket struct {
	tokens float64
	last   time.Time
}

// allow 消費一個令牌；額度不足回 false。
//
// 被拒絕的嘗試 SHALL NOT 延後補充時間——否則攻擊者持續送請求即可把窗口
// 無限往後推，正當使用者永遠等不到額度（seal limiter 的同型要求）
func (b *tokenBucket) allow(now time.Time, burst float64, refill time.Duration) bool {
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

// newSourceAbuseGuard 建立防護。sink 為 nil 時聚合仍計數但不落審計
func newSourceAbuseGuard(params sourceGuardParams, trustProxy bool, sink sourceAbuseAuditSink) *sourceAbuseGuard {
	d := defaultOIDCGuardParams()
	if params.PerIPBurst <= 0 {
		params.PerIPBurst = d.PerIPBurst
	}
	if params.PerIPRefill <= 0 {
		params.PerIPRefill = d.PerIPRefill
	}
	if params.GlobalBurst <= 0 {
		params.GlobalBurst = d.GlobalBurst
	}
	if params.GlobalRefill <= 0 {
		params.GlobalRefill = d.GlobalRefill
	}
	if params.MaxInFlight <= 0 {
		params.MaxInFlight = d.MaxInFlight
	}
	if params.MaxSources <= 0 {
		params.MaxSources = d.MaxSources
	}
	if params.AggregateWindow <= 0 {
		params.AggregateWindow = d.AggregateWindow
	}
	if params.MaxAggregates <= 0 {
		params.MaxAggregates = d.MaxAggregates
	}
	return &sourceAbuseGuard{
		params:     params,
		now:        time.Now,
		trustProxy: trustProxy,
		sources:    make(map[string]*tokenBucket),
		agg:        make(map[abuseAggKey]*abuseAggEntry),
		sink:       sink,
	}
}

// sourceIP 取限流鍵。
//
// **未設可信代理時一律採 socket peer IP 並忽略轉送標頭**：gin 在未呼叫
// SetTrustedProxies 時信任全部 X-Forwarded-For，此時以 ClientIP() 為鍵等同
// 讓攻擊者自選限流桶（每個請求換一個偽造標頭即得到全新額度），per-IP 這層
// 形同虛設。寧可讓同一代理後的使用者共用一個桶，也不提供可繞過的假防線
func (g *sourceAbuseGuard) sourceIP(c *gin.Context) string {
	return requestSourceIP(c, g.trustProxy)
}

// acquire 取得一次處理額度。回傳的 release 須於處理完成後呼叫（並發計數歸還）。
//
// 順序為 per-IP → 全域 → 並發：先扣 per-IP 使被 per-IP 擋下的洪水**不消耗
// 全域額度**，否則單一來源即可把全域額度打空而傷及其他使用者
func (g *sourceAbuseGuard) acquire(ip string) (release func(), ok bool) {
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()

	b := g.bucketForLocked(ip, now)
	if !b.allow(now, g.params.PerIPBurst, g.params.PerIPRefill) {
		return nil, false
	}
	if !g.global.allow(now, g.params.GlobalBurst, g.params.GlobalRefill) {
		return nil, false
	}
	if g.inFlight >= g.params.MaxInFlight {
		return nil, false
	}
	g.inFlight++

	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			if g.inFlight > 0 {
				g.inFlight--
			}
			g.mu.Unlock()
		})
	}, true
}

// bucketForLocked 取得（必要時建立）來源桶。表滿時先清掉已回滿的閒置條目，
// 仍滿則落到共用的 overflow 桶——不 fail-open，也不無界成長
func (g *sourceAbuseGuard) bucketForLocked(ip string, now time.Time) *tokenBucket {
	if b, ok := g.sources[ip]; ok {
		return b
	}
	if len(g.sources) >= g.params.MaxSources {
		g.pruneSourcesLocked(now)
	}
	if len(g.sources) >= g.params.MaxSources {
		return &g.overflow
	}
	b := &tokenBucket{}
	g.sources[ip] = b
	return b
}

// pruneSourcesLocked 清掉額度已回滿的條目：它們與「不存在」等價，
// 保留只是佔記憶體
func (g *sourceAbuseGuard) pruneSourcesLocked(now time.Time) {
	for k, b := range g.sources {
		refilled := b.tokens
		if elapsed := now.Sub(b.last); elapsed > 0 && g.params.PerIPRefill > 0 {
			refilled += float64(elapsed) / float64(g.params.PerIPRefill)
		}
		if refilled >= g.params.PerIPBurst {
			delete(g.sources, k)
		}
	}
}

// record 記錄一次失敗事件（聚合，不逐筆落審計）。
//
// 落審計的時機是「時間窗結束」——由後續事件或 flushExpired 觸發，故無背景
// goroutine。最後一個窗在無後續事件時會延後到下次事件才落，這是刻意的：
// 為了不留下 timer 而換得的延遲，對「洪水偵測」這個用途無害
func (g *sourceAbuseGuard) record(event, ip string) {
	now := g.now()
	g.mu.Lock()
	pending := g.sweepLocked(now)

	key := abuseAggKey{event: event, ip: ip}
	e, ok := g.agg[key]
	if !ok && len(g.agg) >= g.params.MaxAggregates {
		key = abuseAggKey{event: event, ip: abuseAggOverflowIP}
		e, ok = g.agg[key]
	}
	if ok {
		e.count++
		e.last = now
	} else {
		g.agg[key] = &abuseAggEntry{
			count: 1, first: now, last: now,
			windowEnd: now.Add(g.params.AggregateWindow),
		}
	}
	g.mu.Unlock()

	g.emit(pending)
}

// flushExpired 主動結清已到期的時間窗（測試與排程用）
func (g *sourceAbuseGuard) flushExpired() {
	now := g.now()
	g.mu.Lock()
	pending := g.sweepLocked(now)
	g.mu.Unlock()
	g.emit(pending)
}

// sweepLocked 取出已到期的聚合條目。**只取出、不落審計**——落審計會呼叫外部
// sink（可能寫 DB），持鎖跨越它會把限流路徑卡在儲存層延遲上
func (g *sourceAbuseGuard) sweepLocked(now time.Time) []abuseAggFlush {
	var out []abuseAggFlush
	for k, e := range g.agg {
		if now.Before(e.windowEnd) {
			continue
		}
		out = append(out, abuseAggFlush{key: k, entry: *e})
		delete(g.agg, k)
	}
	return out
}

type abuseAggFlush struct {
	key   abuseAggKey
	entry abuseAggEntry
}

func (g *sourceAbuseGuard) emit(pending []abuseAggFlush) {
	if g.sink == nil {
		return
	}
	for _, p := range pending {
		// 狀態語義由事件決定（oidcAggregateStatus）：憑證不成立記認證失敗、
		// 限流拒絕記授權拒絕
		g.sink.LogAggregatedFailure(p.key.event, p.key.ip, oidcAggregateStatus(p.key.event),
			p.entry.count, p.entry.first, p.entry.last)
	}
}
