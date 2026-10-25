package authz

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
