package api

import (
	"bytes"
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// callback／exchange 濫用防護。
//
// 驗收的三個性質：per-IP 與**全域**兩層各自生效、未設可信代理時偽造
// X-Forwarded-For 不能換到新的限流桶、洪水下審計與 DB 存取有界。

// recordingAggSink 同步記錄聚合審計，使「筆數有界」可被斷言——
// 真實審計服務是非同步的（worker＋channel＋flush），無從證明上界
type recordingAggSink struct {
	mu      sync.Mutex
	entries []aggRecord
}

type aggRecord struct {
	event  string
	ip     string
	count  int
	status model.AuditStatus
}

func (r *recordingAggSink) LogAggregatedFailure(event, clientIP string, status model.AuditStatus,
	count int, firstAt, lastAt time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, aggRecord{event: event, ip: clientIP, count: count, status: status})
}

func (r *recordingAggSink) snapshot() []aggRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]aggRecord, len(r.entries))
	copy(out, r.entries)
	return out
}

// fakeClock 可注入時鐘：限流測試不得依賴真實時間 sleep（既慢又 flaky）
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// oidcAbuseTestEnv handler ＋ 真實 login service（sqlite）＋ DB 存取計數。
//
// 用真實 service 而非假物：4.15 要驗的是「DB 寫入有界」，替身會把待驗的
// 那條路徑整段換掉
type oidcAbuseTestEnv struct {
	handler *OIDCHandler
	router  *gin.Engine
	sink    *recordingAggSink
	clock   *fakeClock
	dbOps   *int64
}

func newOIDCAbuseTestEnv(t *testing.T, trustProxy bool, params sourceGuardParams) *oidcAbuseTestEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	// 純 Go driver 的每條連線是各自獨立的空 DB（ff51836 教訓）
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.OIDCFlowState{}, &model.OIDCLoginTicket{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var ops int64
	var opsMu sync.Mutex
	countOp := func(*gorm.DB) {
		opsMu.Lock()
		ops++
		opsMu.Unlock()
	}
	for name, cb := range map[string]func(*gorm.DB){
		"abuse:count_query":  countOp,
		"abuse:count_create": countOp,
		"abuse:count_update": countOp,
		"abuse:count_delete": countOp,
	} {
		var err error
		switch name {
		case "abuse:count_query":
			err = db.Callback().Query().After("gorm:query").Register(name, cb)
		case "abuse:count_create":
			err = db.Callback().Create().After("gorm:create").Register(name, cb)
		case "abuse:count_update":
			err = db.Callback().Update().After("gorm:update").Register(name, cb)
		case "abuse:count_delete":
			err = db.Callback().Delete().After("gorm:delete").Register(name, cb)
		}
		if err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
	}

	// providers／discovery／auth 於本檔的路徑上不被觸及：隨機 ticket 與 state
	// 都在第一次 DB 查找即失敗
	login := identity.NewOIDCLoginService(db, nil, nil, nil, nil)

	sink := &recordingAggSink{}
	clock := newFakeClock()
	h := NewOIDCHandler(nil, login, "https://bastion.example.com", nil)
	h.SetSourcePolicyReader(unrestrictedSourcePolicy())
	h.callbackGuard = newSourceAbuseGuard(params, trustProxy, sink)
	h.exchangeGuard = newSourceAbuseGuard(params, trustProxy, sink)
	h.callbackGuard.now = clock.Now
	h.exchangeGuard.now = clock.Now

	r := gin.New()
	if trustProxy {
		if err := r.SetTrustedProxies([]string{"192.0.2.10"}); err != nil {
			t.Fatalf("SetTrustedProxies: %v", err)
		}
	}
	r.GET("/auth/oidc/callback", h.Callback)
	r.POST("/auth/oidc/exchange", h.Exchange)

	return &oidcAbuseTestEnv{handler: h, router: r, sink: sink, clock: clock, dbOps: &ops}
}

// exchangeReq 以偽造的 X-Forwarded-For 發一次 exchange 請求，socket peer 固定
func (e *oidcAbuseTestEnv) exchangeReq(forwarded string, ticket string) int {
	body := bytes.NewBufferString(`{"ticket":"` + ticket + `","browser_secret":"s"}`)
	req := httptest.NewRequest(http.MethodPost, "/auth/oidc/exchange", body)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.10:54321"
	if forwarded != "" {
		req.Header.Set("X-Forwarded-For", forwarded)
	}
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	return w.Code
}

func (e *oidcAbuseTestEnv) callbackReq(forwarded, state string) int {
	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state="+state+"&code=c", nil)
	req.RemoteAddr = "192.0.2.10:54321"
	if forwarded != "" {
		req.Header.Set("X-Forwarded-For", forwarded)
	}
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	return w.Code
}

func (e *oidcAbuseTestEnv) ops() int64 {
	return *e.dbOps
}

// TestExchangeFloodForgedForwardedForCannotBypassPerIP 未設可信代理時，
// 偽造 X-Forwarded-For **不能**換到新的限流桶——限流鍵取 socket peer IP。
//
// 這是 4.15 的核心斷言：gin 在未呼叫 SetTrustedProxies 時信任任意轉送標頭，
// 若限流沿用 ClientIP()，攻擊者每個請求換一個標頭即得到全新額度
func TestExchangeFloodForgedForwardedForCannotBypassPerIP(t *testing.T) {
	const perIPBurst = 5
	env := newOIDCAbuseTestEnv(t, false, sourceGuardParams{
		PerIPBurst: perIPBurst, PerIPRefill: time.Second,
		GlobalBurst: 10000, GlobalRefill: time.Millisecond,
		MaxInFlight: 1000, AggregateWindow: time.Minute, MaxAggregates: 64,
	})

	const flood = 400
	accepted, throttled := 0, 0
	for i := 0; i < flood; i++ {
		switch env.exchangeReq("203.0.113."+strconv.Itoa(i%254+1), "bogus-ticket-"+strconv.Itoa(i)) {
		case http.StatusTooManyRequests:
			throttled++
		case http.StatusUnauthorized:
			accepted++
		default:
			t.Fatalf("第 %d 次請求得到非預期狀態碼", i)
		}
	}

	if accepted > perIPBurst {
		t.Fatalf("觸及 DB 的請求數 = %d，超過 per-IP 額度 %d（偽造標頭繞過了 per-IP 限流）", accepted, perIPBurst)
	}
	if throttled != flood-accepted {
		t.Fatalf("其餘請求應全數被限流：throttled=%d accepted=%d", throttled, accepted)
	}

	// DB 存取有界：只有通過限流的請求才會查 DB
	if ops := env.ops(); ops > int64(perIPBurst) {
		t.Fatalf("DB 存取次數 = %d，應 ≤ %d（洪水未被擋在 DB 之前）", ops, perIPBurst)
	}

	// 審計有界：400 次失敗聚合為（事件, IP, 時間窗）少數幾筆
	env.clock.advance(2 * time.Minute)
	env.handler.exchangeGuard.flushExpired()
	entries := env.sink.snapshot()
	if len(entries) > 2 {
		t.Fatalf("審計筆數 = %d，400 次失敗不得逐筆落審計", len(entries))
	}
	total := 0
	for _, e := range entries {
		total += e.count
		if e.ip != "192.0.2.10" {
			t.Errorf("聚合鍵的 IP = %q，應為 socket peer IP", e.ip)
		}
	}
	if total != flood {
		t.Fatalf("聚合計數合計 = %d，應涵蓋全部 %d 次失敗（聚合不得遺失事件）", total, flood)
	}
}

// TestExchangeFloodBoundedByGlobalLimitWhenProxyTrusted 可信代理已設定時，
// per-IP 限流被輪換來源打散——此時**全域上限**是唯一的保證。
//
// 突變自檢：拿掉 acquire() 裡的全域桶判定，本測試即轉紅
func TestExchangeFloodBoundedByGlobalLimitWhenProxyTrusted(t *testing.T) {
	const globalBurst = 12
	const maxAggregates = 8
	env := newOIDCAbuseTestEnv(t, true, sourceGuardParams{
		PerIPBurst: 1000, PerIPRefill: time.Millisecond,
		GlobalBurst: globalBurst, GlobalRefill: time.Minute,
		MaxInFlight: 1000, AggregateWindow: time.Minute, MaxAggregates: maxAggregates,
	})

	const flood = 300
	accepted := 0
	for i := 0; i < flood; i++ {
		// 每個請求換一個來源 IP：per-IP 這層永遠不會觸發
		if env.exchangeReq("203.0.113."+strconv.Itoa(i%254+1), "bogus-"+strconv.Itoa(i)) == http.StatusUnauthorized {
			accepted++
		}
	}
	if accepted > globalBurst {
		t.Fatalf("觸及 DB 的請求數 = %d，超過全域額度 %d（缺全域上限＝輪換來源即可無限打）", accepted, globalBurst)
	}
	if ops := env.ops(); ops > int64(globalBurst) {
		t.Fatalf("DB 存取次數 = %d，應 ≤ %d", ops, globalBurst)
	}

	// 來源被輪換時聚合鍵也隨之發散，故上界由**聚合表容量**給出
	//（滿載後併入 overflow 鍵）：筆數不隨洪水規模成長，事件也不遺失
	env.clock.advance(2 * time.Minute)
	env.handler.exchangeGuard.flushExpired()
	entries := env.sink.snapshot()
	// 上界＝MaxAggregates ＋ overflow 鍵（每個事件種類一個，此處為 throttled
	// 與 ticket_invalid 兩種）。關鍵是它是常數，不隨 flood 成長
	if len(entries) > maxAggregates+2 {
		t.Fatalf("審計筆數 = %d，應 ≤ %d（MaxAggregates ＋ 事件種類數）", len(entries), maxAggregates+2)
	}
	total := 0
	for _, e := range entries {
		total += e.count
	}
	if total != flood {
		t.Fatalf("聚合計數合計 = %d，應涵蓋全部 %d 次失敗", total, flood)
	}
}

// TestCallbackStateFloodAggregatedAndBounded callback 的 state 查找失敗是全流程
// 最便宜的洪水面（不接觸 IdP、不受 flow state 容量限制），其審計必須聚合
func TestCallbackStateFloodAggregatedAndBounded(t *testing.T) {
	const perIPBurst = 6
	env := newOIDCAbuseTestEnv(t, false, sourceGuardParams{
		PerIPBurst: perIPBurst, PerIPRefill: time.Second,
		GlobalBurst: 10000, GlobalRefill: time.Millisecond,
		MaxInFlight: 1000, AggregateWindow: time.Minute, MaxAggregates: 64,
	})

	const flood = 200
	throttled, redirected := 0, 0
	for i := 0; i < flood; i++ {
		switch env.callbackReq("198.51.100."+strconv.Itoa(i%254+1), "never-issued-"+strconv.Itoa(i)) {
		case http.StatusTooManyRequests:
			throttled++
		case http.StatusFound:
			redirected++
		default:
			t.Fatalf("第 %d 次 callback 得到非預期狀態碼", i)
		}
	}
	if redirected > perIPBurst {
		t.Fatalf("觸及 DB 的 callback 數 = %d，超過 per-IP 額度 %d", redirected, perIPBurst)
	}
	if throttled == 0 {
		t.Fatal("洪水應被限流攔截")
	}

	env.clock.advance(2 * time.Minute)
	env.handler.callbackGuard.flushExpired()
	entries := env.sink.snapshot()
	if len(entries) > 2 {
		t.Fatalf("審計筆數 = %d，state 查找失敗須聚合而非逐筆落庫", len(entries))
	}
	byEvent := map[string]int{}
	total := 0
	for _, e := range entries {
		byEvent[e.event] += e.count
		total += e.count
	}
	if byEvent[oidcEventCallbackStateInvalid] == 0 {
		t.Errorf("應有 %s 聚合事件，實得 %v", oidcEventCallbackStateInvalid, byEvent)
	}
	if byEvent[oidcEventCallbackThrottled] == 0 {
		t.Errorf("應有 %s 聚合事件，實得 %v", oidcEventCallbackThrottled, byEvent)
	}
	if total != flood {
		t.Fatalf("聚合計數合計 = %d，應涵蓋全部 %d 次失敗", total, flood)
	}
}

// TestGuardSourceIPHonoursTrustedProxyConfiguration 來源 IP 取用規則的直接斷言
func TestGuardSourceIPHonoursTrustedProxyConfiguration(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// 未設可信代理：忽略轉送標頭，取 socket peer IP。
	// 注意 gin 在此情境下的 ClientIP() 會回傳 203.0.113.99（信任全部轉送標頭），
	// 故本斷言同時證明「沒有沿用 ClientIP()」
	req0 := httptest.NewRequest(http.MethodGet, "/", nil)
	req0.RemoteAddr = "192.0.2.10:1111"
	req0.Header.Set("X-Forwarded-For", "203.0.113.99")
	req0.Header.Set("X-Real-IP", "203.0.113.98")
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = req0
	if got := c.ClientIP(); got != "203.0.113.99" {
		t.Fatalf("前提不成立：gin 未設可信代理時 ClientIP() = %q，預期採信偽造標頭", got)
	}
	untrusted := newSourceAbuseGuard(sourceGuardParams{}, false, nil)
	if got := untrusted.sourceIP(c); got != "192.0.2.10" {
		t.Fatalf("未設可信代理時 sourceIP = %q，應為 socket peer IP 192.0.2.10", got)
	}

	// 已設可信代理：走 gin 的 ClientIP()，採信轉送鏈
	trustedEngine := gin.New()
	if err := trustedEngine.SetTrustedProxies([]string{"192.0.2.10"}); err != nil {
		t.Fatalf("SetTrustedProxies: %v", err)
	}
	trusted := newSourceAbuseGuard(sourceGuardParams{}, true, nil)
	var got string
	trustedEngine.GET("/", func(c *gin.Context) { got = trusted.sourceIP(c) })
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.10:1111"
	req.Header.Set("X-Forwarded-For", "203.0.113.99")
	trustedEngine.ServeHTTP(httptest.NewRecorder(), req)
	if got != "203.0.113.99" {
		t.Fatalf("已設可信代理時 sourceIP = %q，應採信轉送鏈 203.0.113.99", got)
	}
}

// TestGuardTokenBucketRefillsWithInjectedClock 額度隨時間補回；
// 被拒絕的嘗試不得延後補充時間（否則持續送請求即可把窗口無限往後推）
func TestGuardTokenBucketRefillsWithInjectedClock(t *testing.T) {
	clock := newFakeClock()
	g := newSourceAbuseGuard(sourceGuardParams{
		PerIPBurst: 2, PerIPRefill: 10 * time.Second,
		GlobalBurst: 1000, GlobalRefill: time.Millisecond,
		MaxInFlight: 100,
	}, false, nil)
	g.now = clock.Now

	for i := 0; i < 2; i++ {
		if rel, ok := g.acquire("1.2.3.4"); !ok {
			t.Fatalf("第 %d 次應在額度內", i)
		} else {
			rel()
		}
	}
	if _, ok := g.acquire("1.2.3.4"); ok {
		t.Fatal("額度用盡後應被拒")
	}
	// 被拒的嘗試持續打不影響補充
	for i := 0; i < 50; i++ {
		g.acquire("1.2.3.4")
	}
	clock.advance(10 * time.Second)
	rel, ok := g.acquire("1.2.3.4")
	if !ok {
		t.Fatal("經過一個補充週期後應恢復額度")
	}
	rel()

	// 其他來源不受影響（per-IP 是分桶的）
	if rel, ok := g.acquire("5.6.7.8"); !ok {
		t.Fatal("其他來源不應被牽連")
	} else {
		rel()
	}
}

// TestGuardInFlightCapReleases 並發上限：未釋放時擋新請求，釋放後恢復
func TestGuardInFlightCapReleases(t *testing.T) {
	g := newSourceAbuseGuard(sourceGuardParams{
		PerIPBurst: 100, PerIPRefill: time.Millisecond,
		GlobalBurst: 100, GlobalRefill: time.Millisecond,
		MaxInFlight: 2,
	}, false, nil)

	r1, ok := g.acquire("1.1.1.1")
	if !ok {
		t.Fatal("第 1 個並發槽應可取得")
	}
	r2, ok := g.acquire("2.2.2.2")
	if !ok {
		t.Fatal("第 2 個並發槽應可取得")
	}
	if _, ok := g.acquire("3.3.3.3"); ok {
		t.Fatal("超過並發上限應被拒（速率額度尚有餘）")
	}
	r1()
	r3, ok := g.acquire("3.3.3.3")
	if !ok {
		t.Fatal("釋放後應可取得")
	}
	r3()
	r2()
	// 重複釋放不得使計數變負
	r1()
	if g.inFlight != 0 {
		t.Fatalf("全部釋放後 inFlight = %d，應為 0", g.inFlight)
	}
}

// TestGuardAggregateTableBounded 聚合表容量上限：來源無界時併入 overflow 鍵，
// 不無限成長也不整段丟棄事件
func TestGuardAggregateTableBounded(t *testing.T) {
	clock := newFakeClock()
	g := newSourceAbuseGuard(sourceGuardParams{
		AggregateWindow: time.Minute, MaxAggregates: 4,
	}, false, nil)
	g.now = clock.Now

	for i := 0; i < 500; i++ {
		g.record("evt", "10.0.0."+strconv.Itoa(i%250))
	}
	if n := len(g.agg); n > 5 {
		t.Fatalf("聚合表條目數 = %d，應受 MaxAggregates 約束", n)
	}
	total := 0
	for _, e := range g.agg {
		total += e.count
	}
	if total != 500 {
		t.Fatalf("聚合計數合計 = %d，應涵蓋全部 500 次事件", total)
	}
}

// TestGuardSourceTableBounded per-IP 表容量上限：滿載後落到共用桶，
// **不 fail-open**（否則來源輪換即等於關閉 per-IP 限流）
func TestGuardSourceTableBounded(t *testing.T) {
	clock := newFakeClock()
	g := newSourceAbuseGuard(sourceGuardParams{
		PerIPBurst: 1, PerIPRefill: time.Hour,
		GlobalBurst: 100000, GlobalRefill: time.Nanosecond,
		MaxInFlight: 100000, MaxSources: 8,
	}, false, nil)
	g.now = clock.Now

	accepted := 0
	for i := 0; i < 500; i++ {
		if rel, ok := g.acquire("10.1.0." + strconv.Itoa(i)); ok {
			accepted++
			rel()
		}
	}
	if n := len(g.sources); n > 8 {
		t.Fatalf("來源表條目數 = %d，應受 MaxSources 約束", n)
	}
	// 前 8 個各自成桶（各 1 次），其餘共用 overflow 桶（合計 1 次）
	if accepted > 9 {
		t.Fatalf("滿載後放行 %d 次，共用桶未生效（fail-open）", accepted)
	}
}
