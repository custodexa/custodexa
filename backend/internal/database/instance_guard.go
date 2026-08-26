package database

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gorm.io/gorm"
)

// 單實例開機守衛。
//
// 語義：**警告留痕＋操作者確認繼續即自負責任**——守衛防的是不知情，不是不發生。
//   - 啟動時以 postgres session 級 advisory lock 取得單實例互斥；鎖由一條**釘選連線**
//     持有（自連線池取出後終生不歸池），持鎖期＝行程生命期。
//   - 取不到鎖 → 有界重試 → 仍取不到即查持鎖者指紋，依 INSTANCE_GUARD_ACK
//     判定：未設或不符 → 回攔下錯誤（本實例不啟動、不 migration、不寫入）；
//     相符 → 允許啟動（狀態 overridden）並留審計事件、指標、橫幅。
//   - 執行期失鎖（watchdog 判定未持有或未知）→ **告知**（日誌／事件／指標／橫幅）
//     並每週期重取，**不 fencing、不退出、無重試上限**。
//
// 本檔：型別、可實例化的 InstanceGuard 物件、Acquire／Stop／Snapshot 與包級單例包裝。
// 鎖後端見 instance_guard_backend_pg.go／instance_guard_backend_sqlite.go；
// 指紋／ack／錯誤分類純函式見 instance_guard_fingerprint.go；
// watchdog 狀態機見 instance_guard_watchdog.go；事件緩衝見 instance_guard_events.go。

// InstanceGuardLockKey 單實例守衛的 advisory lock 鍵。
//
// 登記於 keyvault/key_manager_lock.go 的 keyspace 清單（0x0004）；撞號守衛
// TestInstanceGuardLockKeyDistinct 置於 cmd/server（infra 不得反向 import keyvault）。
// 在 pg_locks 的形狀：classid = 高 32 位、objid = 低 32 位、objsubid = 1
// （常數值已於 compose 內 postgres 16.15 以 `SELECT (x'6F746B65')::int, (x'6B000004')::int` 核對）。
const InstanceGuardLockKey int64 = 0x6F74_6B65_6B00_0004

// InstanceGuardApplicationName 釘選連線的 application_name（釘選後、取鎖前設定）。
// 既是持鎖者指紋的成分，也是對等偵測的辨識依據。
const InstanceGuardApplicationName = "custodexa-instance-guard"

// 生產預設值（可逆的實作細節；spec 只綁 watchdog 週期 ≤ 30 秒與重試總等待約 10 秒）。
const (
	instanceGuardDefaultWatchPeriod   = 15 * time.Second
	instanceGuardDefaultQueryTimeout  = 5 * time.Second
	instanceGuardDefaultRetryInterval = 2 * time.Second
	instanceGuardDefaultRetryAttempts = 5
	instanceGuardDefaultEventBuffer   = 16
)

// GuardState 守衛狀態機的態。
type GuardState string

const (
	GuardStateAcquiring  GuardState = "acquiring"
	GuardStateHeld       GuardState = "held"
	GuardStateOverridden GuardState = "overridden"
	GuardStateLost       GuardState = "lost"
	GuardStateStopping   GuardState = "stopping"
	GuardStateReleased   GuardState = "released"
)

// GuardReason 失鎖／未持鎖的原因，進日誌、事件、Snapshot 與 seal status 欄位。
type GuardReason string

const (
	GuardReasonNone          GuardReason = ""
	GuardReasonAckStartup    GuardReason = "ack_startup"
	GuardReasonContention    GuardReason = "contention"
	GuardReasonDBUnreachable GuardReason = "db_unreachable"
	GuardReasonPermanent     GuardReason = "permanent"
	GuardReasonUnknown       GuardReason = "unknown"
)

// GuardEvent 的事件名。
const (
	GuardEventOverridden = "overridden"
	GuardEventLost       = "lost"
	GuardEventRegained   = "regained"
)

// GuardInstance 本實例識別（進審計事件的 details）。
type GuardInstance struct {
	Hostname  string
	PID       int
	StartedAt time.Time
}

// HolderFingerprint 持鎖者指紋。
//
// Code 是 `application_name|pid|backend_start` 正規化字串 sha256 的前 12 碼，
// 也是 INSTANCE_GUARD_ACK 要比對的確認碼。NULL 欄以 "-" 代入。
// Source 標示指紋來源：pg_stat_activity（正常）、unavailable（查詢失敗的降級指紋）、
// sqlite（測試分支的固定形式）。
type HolderFingerprint struct {
	ApplicationName string
	PID             int64
	BackendStart    string
	Code            string
	Source          string
}

// 指紋來源常數。
const (
	FingerprintSourcePGStatActivity = "pg_stat_activity"
	FingerprintSourceUnavailable    = "unavailable"
	FingerprintSourceSQLite         = "sqlite"
)

// GuardSnapshot 守衛狀態的完整快照（Snapshot()）。
//
// 消費者：指標 collector（held／lost_total／overridden／peers）、seal status 的粗狀態欄、
// 管理者限定端點 GET /api/v1/instance-guard 的全貌。
type GuardSnapshot struct {
	State        GuardState
	Since        time.Time
	Reason       GuardReason
	Instance     GuardInstance
	DBSessionPID int
	Holder       *HolderFingerprint
	Ack          string
	LostTotal    uint64
	Peers        int
}

// GuardEvent 守衛事件：overridden／lost／regained。
type GuardEvent struct {
	Event        string
	Reason       GuardReason
	At           time.Time
	Instance     GuardInstance
	DBSessionPID int
	Holder       *HolderFingerprint
	Ack          string
	UnheldForMS  int64
	LostTotal    uint64
}

// InstanceGuardOptions 守衛物件的建構參數。零值＝生產預設。
//
// **不是組態**：除 Ack 由 INSTANCE_GUARD_ACK 供給外，只有測試與組裝根會填。
type InstanceGuardOptions struct {
	// Ack 操作者對本次衝突的確認碼（INSTANCE_GUARD_ACK）。前後空白會被去除，其餘精確比對。
	Ack string
	// ApplicationName 釘選連線的 application_name；空＝InstanceGuardApplicationName。
	ApplicationName string
	WatchPeriod     time.Duration
	QueryTimeout    time.Duration
	RetryInterval   time.Duration
	RetryAttempts   int
	// EventBufferLimit sink 注入前的事件緩衝上限；0＝預設 16。
	EventBufferLimit int
	// backend 覆寫鎖後端（**僅測試**）：nil＝依 dialect 建構。
	backend lockBackend
}

func (o InstanceGuardOptions) withDefaults() InstanceGuardOptions {
	o.Ack = strings.TrimSpace(o.Ack)
	if o.ApplicationName == "" {
		o.ApplicationName = InstanceGuardApplicationName
	}
	if o.WatchPeriod <= 0 {
		o.WatchPeriod = instanceGuardDefaultWatchPeriod
	}
	if o.QueryTimeout <= 0 {
		o.QueryTimeout = instanceGuardDefaultQueryTimeout
	}
	if o.RetryInterval <= 0 {
		o.RetryInterval = instanceGuardDefaultRetryInterval
	}
	if o.RetryAttempts <= 0 {
		o.RetryAttempts = instanceGuardDefaultRetryAttempts
	}
	if o.EventBufferLimit <= 0 {
		o.EventBufferLimit = instanceGuardDefaultEventBuffer
	}
	return o
}

// ErrInstanceGuardBlocked 攔下錯誤的哨兵（errors.Is 用）；訊息本體由 blockedMessage 產生。
var ErrInstanceGuardBlocked = errors.New("單實例鎖由另一個資料庫工作階段持有")

// lockBackend 鎖後端（內部介面）：pgLockBackend（真鎖）、sqliteLockBackend（行程互斥）、
// 測試自帶 fakeLockBackend 驅動狀態機。
type lockBackend interface {
	// tryLock 以 try 語義取鎖：got=false 為他人持鎖；err 為回應失敗（連線已丟棄）。
	tryLock(ctx context.Context) (got bool, err error)
	// isHeld 驗證本工作階段仍持有該鎖：直接查 pg_locks，不以 ping 代替。
	isHeld(ctx context.Context) (held bool, err error)
	// holderFingerprint 查持鎖者指紋；查詢失敗回降級指紋（不回 error）。
	// found=false 表示查得到但無人持鎖。
	holderFingerprint(ctx context.Context) (fp HolderFingerprint, found bool)
	// countPeers 計數同庫其他守衛版實例的連線（對等偵測）。
	countPeers(ctx context.Context) (int, error)
	// sessionPID 本實例釘選連線的 pg_backend_pid()；無連線時為 0。
	sessionPID() int
	// connected 釘選連線是否存在（lost 期間可能為 false）。
	connected() bool
	// reconnect 丟棄舊連線（若有）並重釘一條。
	reconnect(ctx context.Context) error
	// runsWatchdog 是否啟動背景 watchdog（sqlite 分支不啟動）。
	runsWatchdog() bool
	// close 釋放釘選連線；unlock 為真時先 best-effort 解鎖。
	close(ctx context.Context, unlock bool)
}

// InstanceGuard 可實例化的守衛物件。
//
// 狀態由 mu 保護；DB 查詢一律在鎖外執行、返回後重檢狀態（關閉序與 watchdog 才不會互相等待）。
type InstanceGuard struct {
	db   *gorm.DB
	opts InstanceGuardOptions

	mu          sync.Mutex
	state       GuardState
	since       time.Time
	reason      GuardReason
	instance    GuardInstance
	holder      *HolderFingerprint
	lostTotal   uint64
	peers       int
	unheldSince time.Time
	backend     lockBackend

	wdCancel context.CancelFunc
	wg       sync.WaitGroup
	stopOnce sync.Once

	events guardEventBuffer

	// 日誌節流（只在 watchdog goroutine 或 CheckNow 內存取）
	lastRetryableLog  time.Time
	lastPeerLog       time.Time
	lastOverriddenLog time.Time
	peerLogged        bool
}

// NewInstanceGuard 建立守衛物件；不做任何 I/O。
func NewInstanceGuard(db *gorm.DB, opts InstanceGuardOptions) *InstanceGuard {
	o := opts.withDefaults()
	g := &InstanceGuard{
		db:    db,
		opts:  o,
		state: GuardStateAcquiring,
	}
	g.events.limit = o.EventBufferLimit
	return g
}

// Acquire 取鎖：釘選連線 → 有界重試 → 耗盡即查持鎖者指紋並依確認碼判定。
//
// 回傳 nil 代表可以繼續啟動（held 或 overridden）；回傳 ErrInstanceGuardBlocked
// （帶完整攔下訊息）代表本實例不得啟動。
func (g *InstanceGuard) Acquire(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	hostname, _ := os.Hostname()
	now := time.Now().UTC()
	g.mu.Lock()
	g.instance = GuardInstance{Hostname: hostname, PID: os.Getpid(), StartedAt: now}
	g.mu.Unlock()

	backend, err := g.newBackend(ctx)
	if err != nil {
		return err
	}
	g.mu.Lock()
	g.backend = backend
	g.mu.Unlock()

	for attempt := 1; attempt <= g.opts.RetryAttempts; attempt++ {
		got, err := g.tryLockOnce(ctx, backend)
		if err != nil {
			// 鎖可能已在 DB 端授予而回應失敗：後端已丟棄該連線，不歸池
			return fmt.Errorf("取得單實例鎖失敗（已丟棄該連線以確保不殘留鎖）: %w", err)
		}
		if got {
			g.enterHeldAtStartup()
			return nil
		}
		if attempt < g.opts.RetryAttempts {
			log.Printf("[InstanceGuard] 等待既有實例釋放單實例鎖（第 %d/%d 次，%s 後重試）",
				attempt, g.opts.RetryAttempts, g.opts.RetryInterval)
			if err := sleepCtx(ctx, g.opts.RetryInterval); err != nil {
				backend.close(context.Background(), false)
				return fmt.Errorf("等待單實例鎖時啟動被取消: %w", err)
			}
		}
	}

	// 重試耗盡：同連線查持鎖者指紋，依 ack 判定
	fpCtx, cancelFP := g.queryCtx(ctx)
	fp, _ := backend.holderFingerprint(fpCtx)
	cancelFP()
	verdict := evaluateAck(g.opts.Ack, fp.Code, true)
	switch verdict {
	case ackMatch:
		g.enterOverriddenAtStartup(fp)
		return nil
	default:
		// 連線乾淨（DB 端明確未授予），正常關閉
		backend.close(context.Background(), false)
		g.mu.Lock()
		g.backend = nil
		g.state = GuardStateReleased
		g.mu.Unlock()
		return fmt.Errorf("%w\n%s", ErrInstanceGuardBlocked, blockedMessage(fp, verdict))
	}
}

// tryLockOnce 帶查詢逾時的單次取鎖。
func (g *InstanceGuard) tryLockOnce(ctx context.Context, backend lockBackend) (bool, error) {
	qctx, cancel := g.queryCtx(ctx)
	defer cancel()
	return backend.tryLock(qctx)
}

// enterHeldAtStartup 取鎖成功的收尾：狀態 held、啟動 watchdog、揭露未使用的 ack。
func (g *InstanceGuard) enterHeldAtStartup() {
	now := time.Now().UTC()
	g.mu.Lock()
	g.state = GuardStateHeld
	g.since = now
	g.reason = GuardReasonNone
	g.mu.Unlock()
	if evaluateAck(g.opts.Ack, "", false) == ackUnused {
		log.Printf("[InstanceGuard] INSTANCE_GUARD_ACK 已設定但本次未偵測到衝突，未使用；建議自環境移除（留在環境中的舊值是惰性的）")
	}
	g.startWatchdog()
}

// enterOverriddenAtStartup ack 相符的收尾：保留釘選連線、狀態 overridden、
// CRITICAL 日誌、overridden 事件（緩衝至 sink 注入後寫入）、啟動 watchdog 每週期重取。
func (g *InstanceGuard) enterOverriddenAtStartup(fp HolderFingerprint) {
	now := time.Now().UTC()
	holder := fp
	g.mu.Lock()
	g.state = GuardStateOverridden
	g.since = now
	g.unheldSince = now
	g.reason = GuardReasonAckStartup
	g.holder = &holder
	ev := g.eventLocked(GuardEventOverridden, GuardReasonAckStartup, now)
	g.mu.Unlock()
	log.Printf("[InstanceGuard] CRITICAL：以 INSTANCE_GUARD_ACK 啟動：單實例鎖仍由 %s 持有；本實例將照常執行 migration 與服務；此確認已記錄（actor=operator via env）",
		fp.readable())
	g.emit(ev)
	g.startWatchdog()
}

// newBackend 依 dialect 建構鎖後端；未知 dialect fail-close。
func (g *InstanceGuard) newBackend(ctx context.Context) (lockBackend, error) {
	if g.opts.backend != nil {
		return g.opts.backend, nil
	}
	if g.db == nil {
		return nil, errors.New("單實例守衛：資料庫連線尚未建立")
	}
	switch g.db.Dialector.Name() {
	case "postgres":
		b := &pgLockBackend{db: g.db, appName: g.opts.ApplicationName, queryTimeout: g.opts.QueryTimeout}
		if err := b.reconnect(ctx); err != nil {
			return nil, fmt.Errorf("釘選連線失敗（單實例鎖）: %w", err)
		}
		return b, nil
	case "sqlite":
		return &sqliteLockBackend{}, nil
	default:
		return nil, fmt.Errorf("不支援的資料庫 dialect %q：無跨實例單實例互斥實作，拒絕啟動", g.db.Dialector.Name())
	}
}

// Stop 關閉守衛（冪等）：stopping → 取消 watchdog → join → 釋放釘選連線 → released。
func (g *InstanceGuard) Stop() {
	g.stopOnce.Do(func() {
		g.mu.Lock()
		wasHeld := g.state == GuardStateHeld
		g.state = GuardStateStopping
		cancel := g.wdCancel
		g.mu.Unlock()

		if cancel != nil {
			cancel()
		}
		g.wg.Wait()

		g.mu.Lock()
		backend := g.backend
		g.backend = nil
		g.mu.Unlock()
		if backend != nil {
			ctx, cancelClose := context.WithTimeout(context.Background(), g.opts.QueryTimeout)
			backend.close(ctx, wasHeld)
			cancelClose()
		}

		g.mu.Lock()
		g.state = GuardStateReleased
		g.since = time.Now().UTC()
		g.mu.Unlock()
	})
}

// State 目前的守衛狀態。
func (g *InstanceGuard) State() GuardState {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.state
}

// Snapshot 守衛狀態的完整快照。
func (g *InstanceGuard) Snapshot() GuardSnapshot {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.snapshotLocked()
}

func (g *InstanceGuard) snapshotLocked() GuardSnapshot {
	s := GuardSnapshot{
		State:     g.state,
		Since:     g.since,
		Reason:    g.reason,
		Instance:  g.instance,
		Ack:       g.opts.Ack,
		LostTotal: g.lostTotal,
		Peers:     g.peers,
	}
	if g.backend != nil {
		s.DBSessionPID = g.backend.sessionPID()
	}
	if g.holder != nil {
		h := *g.holder
		s.Holder = &h
	}
	return s
}

// eventLocked 以目前狀態組事件（呼叫端持有 mu）。
func (g *InstanceGuard) eventLocked(name string, reason GuardReason, at time.Time) GuardEvent {
	ev := GuardEvent{
		Event:     name,
		Reason:    reason,
		At:        at,
		Instance:  g.instance,
		LostTotal: g.lostTotal,
	}
	if g.backend != nil {
		ev.DBSessionPID = g.backend.sessionPID()
	}
	switch name {
	case GuardEventOverridden:
		ev.Ack = g.opts.Ack
		if g.holder != nil {
			h := *g.holder
			ev.Holder = &h
		}
	case GuardEventLost:
		if reason == GuardReasonContention && g.holder != nil {
			h := *g.holder
			ev.Holder = &h
		}
	case GuardEventRegained:
		if !g.unheldSince.IsZero() {
			ev.UnheldForMS = at.Sub(g.unheldSince).Milliseconds()
		}
	}
	return ev
}

// queryCtx 為單次查詢套上逾時；呼叫端負責 cancel。
func (g *InstanceGuard) queryCtx(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, g.opts.QueryTimeout)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// ── 包級單例包裝（生產入口）────────────────────────────────────────────────

// instanceGuard 生產用的單一守衛實例。
//
// 包級而非掛在 stage1：database.Close() 是 main 正常返回時唯一必經的釋放點
// （main.go 的 defer database.Close()），掛在這裡才能在 sqlDB.Close() 之前釋放釘選連線。
// atomic.Pointer 使段 1 的寫入與指標 collector／handler 的讀取無資料競賽。
var instanceGuard atomic.Pointer[InstanceGuard]

// instanceGuardProcessMu sqlite 分支的行程層級 try 互斥：package 層級共用、
// TryLock 非阻塞——與 postgres 路徑同語義，不宣稱跨行程互斥。
// 亦承載持鎖者的 Acquire 時間，供 sqlite 固定形式指紋使用。
var instanceGuardProcessMu processGuardMutex

// AcquireInstanceLock 段 1 的生產入口：建立守衛、取鎖、登記為包級單例。
// 不是注入點（不以 Init／Set／Register 起頭）。
func AcquireInstanceLock(ctx context.Context, db *gorm.DB, ack string) error {
	g := NewInstanceGuard(db, InstanceGuardOptions{Ack: ack})
	if err := g.Acquire(ctx); err != nil {
		return err
	}
	instanceGuard.Store(g)
	return nil
}

// InstanceGuardSnapshot 包級單例的快照；守衛尚未建立時回零值（State 為空）。
func InstanceGuardSnapshot() GuardSnapshot {
	g := instanceGuard.Load()
	if g == nil {
		return GuardSnapshot{}
	}
	return g.Snapshot()
}

// SetInstanceGuardEventSink 注入事件 sink（段 2 組裝根）；守衛未建立時為 no-op。
func SetInstanceGuardEventSink(fn func(GuardEvent)) {
	if g := instanceGuard.Load(); g != nil {
		g.SetEventSink(fn)
	}
}

// releaseInstanceLock 釋放單實例鎖（冪等）；由 Close() 於 sqlDB.Close() 之前呼叫。
func releaseInstanceLock() {
	if g := instanceGuard.Load(); g != nil {
		g.Stop()
	}
}
