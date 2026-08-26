package database

import (
	"context"
	"os"
	"sync"
	"time"
)

// sqliteLockBackend sqlite（僅單元測試）分支：行程層級共用的 try 互斥提供同語義
// （第二次取鎖被攔、訊息與 ack 路徑可離線測），不宣稱跨行程互斥、不啟動 watchdog。

// processGuardMutex 行程層級的 try 互斥，另記持鎖者的 Acquire 時間供固定形式指紋使用。
type processGuardMutex struct {
	lock        sync.Mutex
	meta        sync.Mutex
	holderStart time.Time
}

func (p *processGuardMutex) tryLock(start time.Time) bool {
	if !p.lock.TryLock() {
		return false
	}
	p.meta.Lock()
	p.holderStart = start
	p.meta.Unlock()
	return true
}

func (p *processGuardMutex) unlock() {
	p.meta.Lock()
	p.holderStart = time.Time{}
	p.meta.Unlock()
	p.lock.Unlock()
}

func (p *processGuardMutex) start() time.Time {
	p.meta.Lock()
	defer p.meta.Unlock()
	return p.holderStart
}

type sqliteLockBackend struct {
	mu      sync.Mutex
	holding bool
}

func (b *sqliteLockBackend) tryLock(context.Context) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.holding {
		return true, nil
	}
	if !instanceGuardProcessMu.tryLock(time.Now().UTC()) {
		return false, nil
	}
	b.holding = true
	return true, nil
}

func (b *sqliteLockBackend) isHeld(context.Context) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.holding, nil
}

// holderFingerprint 固定形式 `sqlite|<pid>|<持鎖者 Acquire 時間>`。
func (b *sqliteLockBackend) holderFingerprint(context.Context) (HolderFingerprint, bool) {
	start := instanceGuardProcessMu.start()
	return sqliteFingerprint(os.Getpid(), start), !start.IsZero()
}

func (b *sqliteLockBackend) countPeers(context.Context) (int, error) { return 0, nil }

func (b *sqliteLockBackend) sessionPID() int { return 0 }

func (b *sqliteLockBackend) connected() bool { return true }

func (b *sqliteLockBackend) reconnect(context.Context) error { return nil }

func (b *sqliteLockBackend) runsWatchdog() bool { return false }

func (b *sqliteLockBackend) close(context.Context, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.holding {
		instanceGuardProcessMu.unlock()
		b.holding = false
	}
}
