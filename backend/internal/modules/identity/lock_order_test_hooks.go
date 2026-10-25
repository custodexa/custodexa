package identity

import (
	"sync"

	"gorm.io/gorm"
)

// 鎖序測試掛點。生產恆為 nil，不由請求參數或環境變數控制；
// 只有測試會設定它，用來把兩筆交易固定在指定的取鎖停點上交錯。
// 掛點是包級共用狀態：使用它的鎖序測試不得呼叫 t.Parallel，也不得與其他設定同一掛點的測試並行。

// lockOrderHookState 保護通用停點函式的讀寫；seq 用來驗證還原順序。
var lockOrderHookState struct {
	mu  sync.RWMutex
	fn  func(point string, tx *gorm.DB, ids ...uint)
	seq uint64
}

// loadLockOrderHook 讀出目前的通用停點函式。呼叫點先取出再判斷、再呼叫同一個值，
// 判斷與呼叫之間不會被設定函式改掉。生產恆回 nil。
func loadLockOrderHook() func(point string, tx *gorm.DB, ids ...uint) {
	lockOrderHookState.mu.RLock()
	defer lockOrderHookState.mu.RUnlock()
	return lockOrderHookState.fn
}

// SetLockOrderHookForTest 設定通用停點函式並回傳還原函式；傳 nil 表示不掛。
// 供別包的測試（例如 session 套件）固定交錯，只設掛點、不帶任何其他行為。
// 還原必須依設定的相反順序（後設者先還原）；順序不符或重複還原會 panic，讓測試失敗。
func SetLockOrderHookForTest(h func(point string, tx *gorm.DB, ids ...uint)) (restore func()) {
	st := &lockOrderHookState
	st.mu.Lock()
	prevFn, prevSeq := st.fn, st.seq
	st.seq++
	mine := st.seq
	st.fn = h
	st.mu.Unlock()
	done := false
	return func() {
		st.mu.Lock()
		defer st.mu.Unlock()
		if done {
			panic("lock order hook: restore called twice")
		}
		if st.seq != mine {
			panic("lock order hook: restore out of order")
		}
		done = true
		st.fn, st.seq = prevFn, prevSeq
	}
}

// groupDeleteLockHookSet 群組刪除的兩個停點，供別包的測試設定；讀寫經 groupDeleteHookState 保護。
type groupDeleteLockHookSet struct {
	afterPrefetch      func()
	afterCascadeRevoke func()
}

var groupDeleteHookState struct {
	mu   sync.RWMutex
	hook groupDeleteLockHookSet
	seq  uint64
}

// loadGroupDeleteLockHooks 讀出目前的群組刪除停點；呼叫點先取出再判斷、再呼叫同一個值。
func loadGroupDeleteLockHooks() groupDeleteLockHookSet {
	groupDeleteHookState.mu.RLock()
	defer groupDeleteHookState.mu.RUnlock()
	return groupDeleteHookState.hook
}

// SetGroupDeleteLockHooksForTest 設定群組刪除的兩個停點並回傳還原函式；傳 nil 表示不掛。
// afterPrefetch 在成員預取之後、權限變更開始之前；afterCascadeRevoke 在級聯撤銷之後、逐人迴圈之前。
// 還原必須依設定的相反順序；順序不符或重複還原會 panic，讓測試失敗。
func SetGroupDeleteLockHooksForTest(afterPrefetch, afterCascadeRevoke func()) (restore func()) {
	st := &groupDeleteHookState
	st.mu.Lock()
	prevHook, prevSeq := st.hook, st.seq
	st.seq++
	mine := st.seq
	st.hook = groupDeleteLockHookSet{afterPrefetch: afterPrefetch, afterCascadeRevoke: afterCascadeRevoke}
	st.mu.Unlock()
	done := false
	return func() {
		st.mu.Lock()
		defer st.mu.Unlock()
		if done {
			panic("group delete lock hooks: restore called twice")
		}
		if st.seq != mine {
			panic("group delete lock hooks: restore out of order")
		}
		done = true
		st.hook, st.seq = prevHook, prevSeq
	}
}

// userMutexHookState 保護 SQLite 分支取得行程內使用者互斥鎖之前的計數掛點；
// 測試用來計算各入口取得該互斥鎖的次數。生產恆為 nil。
var userMutexHookState struct {
	mu  sync.RWMutex
	fn  func(userID uint)
	seq uint64
}

// loadUserMutexAcquireHook 讀出目前的取得次數掛點。
func loadUserMutexAcquireHook() func(userID uint) {
	userMutexHookState.mu.RLock()
	defer userMutexHookState.mu.RUnlock()
	return userMutexHookState.fn
}

// SetUserMutexAcquireHookForTest 設定取得次數掛點並回傳還原函式（還原順序驗證同上）。
func SetUserMutexAcquireHookForTest(fn func(userID uint)) (restore func()) {
	st := &userMutexHookState
	st.mu.Lock()
	prevFn, prevSeq := st.fn, st.seq
	st.seq++
	mine := st.seq
	st.fn = fn
	st.mu.Unlock()
	done := false
	return func() {
		st.mu.Lock()
		defer st.mu.Unlock()
		if done {
			panic("user mutex acquire hook: restore called twice")
		}
		if st.seq != mine {
			panic("user mutex acquire hook: restore out of order")
		}
		done = true
		st.fn, st.seq = prevFn, prevSeq
	}
}

// SetOIDCProviderPreWriteStopForTest 設定 provider 級序列化同步點的停點函式並回傳還原函式；
// 傳 nil 表示不掛。供別包（例如 session 套件）的測試把交易固定在「鎖內重讀通過之後、
// 實際寫入之前」，只設掛點、不帶任何其他行為。
func SetOIDCProviderPreWriteStopForTest(fn func(site string)) (restore func()) {
	prev := oidcProviderPreWriteHook
	oidcProviderPreWriteHook = fn
	return func() { oidcProviderPreWriteHook = prev }
}

// SetUserCredentialPreWriteStopForTest 設定使用者憑證同步點的停點函式並回傳還原函式；
// 傳 nil 表示不掛。用途同上。
func SetUserCredentialPreWriteStopForTest(fn func()) (restore func()) {
	prev := userCredentialPreWriteHook
	userCredentialPreWriteHook = fn
	return func() { userCredentialPreWriteHook = prev }
}
