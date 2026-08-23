package seal

import (
	"sync"
	"sync/atomic"
	"time"
)

// LimiterConfig 為退避／冷卻參數。
type LimiterConfig struct {
	// BaseBackoff 為 per-source 第一次失敗後的退避基準
	BaseBackoff time.Duration
	// MaxBackoff 為 per-source 退避封頂——退避的成長 SHALL 有明確上限，
	// 使「等待即可再試」在任何攻擊強度下都成立
	MaxBackoff time.Duration
	// GlobalThreshold 為觸發全域冷卻的連續材料失敗次數；SHALL 明顯高於 per-source
	GlobalThreshold uint32
	// GlobalCooldown 為全域冷卻基準時長
	GlobalCooldown time.Duration
	// MaxGlobalCooldown 為全域冷卻封頂
	MaxGlobalCooldown time.Duration
	// MaxSources 為 per-source 表的容量上限（無界來源集合的記憶體保護）
	MaxSources int
	// TimeoutAlertThreshold 為逾時次數達此值時告警（逾時另計，不入失敗計數）
	TimeoutAlertThreshold uint64
}

// DefaultLimiterConfig 為預設參數。實際值由部署組態覆寫（後續接線批次）。
func DefaultLimiterConfig() LimiterConfig {
	return LimiterConfig{
		BaseBackoff:           2 * time.Second,
		MaxBackoff:            5 * time.Minute,
		GlobalThreshold:       20,
		GlobalCooldown:        time.Minute,
		MaxGlobalCooldown:     15 * time.Minute,
		MaxSources:            4096,
		TimeoutAlertThreshold: 3,
	}
}

// Limiter 是 per-source 失敗計數與退避的獨立限速結構。
//
// per-source 的失敗計數與退避 SHALL NOT 入 sealNode——它是無界的
// 來源集合，不得宣稱與 state／generation／services 在同一個 CAS 內更新
// （宣稱了也做不到，只會逼實作者造一個假的原子性）。
// 全域冷卻則相反：它是取得獨佔的前置條件，故 cooldownUntil 在 sealNode 內、
// 經同一道 CAS 更新；本結構只負責「算出」冷卻到期時間。
type Limiter struct {
	mu             sync.Mutex
	cfg            LimiterConfig
	sources        map[string]*sourceEntry
	globalFailures uint32
	timeoutTotal   atomic.Uint64
}

type sourceEntry struct {
	failures    uint32
	nextAllowed time.Time
}

// NewLimiter 建立限速結構。零值欄位以 DefaultLimiterConfig 補齊。
func NewLimiter(cfg LimiterConfig) *Limiter {
	d := DefaultLimiterConfig()
	if cfg.BaseBackoff <= 0 {
		cfg.BaseBackoff = d.BaseBackoff
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = d.MaxBackoff
	}
	if cfg.GlobalThreshold == 0 {
		cfg.GlobalThreshold = d.GlobalThreshold
	}
	if cfg.GlobalCooldown <= 0 {
		cfg.GlobalCooldown = d.GlobalCooldown
	}
	if cfg.MaxGlobalCooldown <= 0 {
		cfg.MaxGlobalCooldown = d.MaxGlobalCooldown
	}
	if cfg.MaxSources <= 0 {
		cfg.MaxSources = d.MaxSources
	}
	if cfg.TimeoutAlertThreshold == 0 {
		cfg.TimeoutAlertThreshold = d.TimeoutAlertThreshold
	}
	return &Limiter{cfg: cfg, sources: make(map[string]*sourceEntry)}
}

// AllowSource 判定該來源目前是否可嘗試。
//
// 被退避拒絕的嘗試 SHALL NOT 計入失敗計數、SHALL NOT 刷新或延長退避到期時間
// ——否則攻擊者可持續送請求把窗口無限往後推，等價於可持續 DoS。
// 本函式因此是純讀取，不改任何狀態。
func (l *Limiter) AllowSource(key string, now time.Time) (bool, time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.sources[key]
	if !ok || !now.Before(e.nextAllowed) {
		return true, time.Time{}
	}
	return false, e.nextAllowed
}

// RecordMaterialFailure 記錄一次材料驗證失敗（格 4）。
// 回傳「本次是否應武裝全域冷卻」及其到期時間；到期時間由呼叫端寫入 sealNode
// 的同一次 CAS（柵欄涵蓋全域冷卻）。
func (l *Limiter) RecordMaterialFailure(key string, now time.Time) (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.pruneLocked(now)
	e, ok := l.sources[key]
	if !ok {
		e = &sourceEntry{}
		l.sources[key] = e
	}
	e.failures++
	e.nextAllowed = now.Add(backoffFor(l.cfg.BaseBackoff, l.cfg.MaxBackoff, e.failures))

	l.globalFailures++
	if l.globalFailures < l.cfg.GlobalThreshold {
		return time.Time{}, false
	}
	over := l.globalFailures - l.cfg.GlobalThreshold + 1
	return now.Add(backoffFor(l.cfg.GlobalCooldown, l.cfg.MaxGlobalCooldown, over)), true
}

// RecordSuccess 於解封成功後把計數歸零。
func (l *Limiter) RecordSuccess(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.sources, key)
	l.globalFailures = 0
}

// RecordTimeout 記錄一次段 2 逾時。
//
// 逾時 SHALL NOT 計入材料失敗計數——材料是正確的，計入會讓連續逾時把正當管理員
// 推進冷卻。改為另計逾時次數，達門檻時回 alert=true 由呼叫端沿既有告警族發出。
func (l *Limiter) RecordTimeout() (total uint64, alert bool) {
	total = l.timeoutTotal.Add(1)
	return total, total >= l.cfg.TimeoutAlertThreshold
}

// TimeoutTotal 回傳累計逾時次數。
func (l *Limiter) TimeoutTotal() uint64 { return l.timeoutTotal.Load() }

// GlobalFailures 回傳目前的連續全域失敗計數（供 /seal/status 與測試）。
func (l *Limiter) GlobalFailures() uint32 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.globalFailures
}

// pruneLocked 在來源表逾量時清掉已過退避期的條目，界定無界來源集合的記憶體。
func (l *Limiter) pruneLocked(now time.Time) {
	if len(l.sources) <= l.cfg.MaxSources {
		return
	}
	for k, e := range l.sources {
		if !now.Before(e.nextAllowed) {
			delete(l.sources, k)
		}
	}
}

// backoffFor 以指數成長計算退避時長並封頂。
func backoffFor(base, max time.Duration, failures uint32) time.Duration {
	if failures == 0 {
		return 0
	}
	d := base
	for i := uint32(1); i < failures; i++ {
		if d >= max/2 {
			return max
		}
		d *= 2
	}
	if d > max {
		return max
	}
	return d
}
