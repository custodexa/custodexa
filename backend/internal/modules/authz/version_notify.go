package authz

import (
	"sync"

	"gorm.io/gorm"
)

// 權限版本的提交後通知。
//
// 權限寫入與版本推進在呼叫端的同一交易內（AdvanceVersion）；有些行程內狀態（例如錄影票）
// 要在權限變更**提交之後**重新驗證持有者。本通知只在最外層交易成功提交之後觸發：權限寫入的
// 交易擁有者（identity 的鎖 helper 與直接持有交易的寫入者）在 Transaction 回 nil 後呼叫
// NotifyVersionCommittedAfter；交易內呼叫（db 本身是交易）不通知，由外層擁有者負責；
// 回滾不通知。監聽者自行讀目前版本，版本未變即不做事，所以多發一次無害。

var versionCommitListeners struct {
	mu  sync.RWMutex
	fns []func()
}

// RegisterVersionCommitListener 登記提交後通知的監聽者（組裝根呼叫）；回傳解除登記函式。
// 監聽者在提交者的 goroutine 內同步執行，不得取用權限寫入相關的鎖。
func RegisterVersionCommitListener(fn func()) (unregister func()) {
	versionCommitListeners.mu.Lock()
	defer versionCommitListeners.mu.Unlock()
	versionCommitListeners.fns = append(versionCommitListeners.fns, fn)
	idx := len(versionCommitListeners.fns) - 1
	return func() {
		versionCommitListeners.mu.Lock()
		defer versionCommitListeners.mu.Unlock()
		if idx < len(versionCommitListeners.fns) {
			versionCommitListeners.fns[idx] = nil
		}
	}
}

// NotifyVersionCommitted 通知全部監聽者（權限寫入已提交）。
func NotifyVersionCommitted() {
	versionCommitListeners.mu.RLock()
	fns := append([]func(){}, versionCommitListeners.fns...)
	versionCommitListeners.mu.RUnlock()
	for _, fn := range fns {
		if fn != nil {
			fn()
		}
	}
}

// NotifyVersionCommittedAfter 交易擁有者在 Transaction 回傳後呼叫：err 為 nil 且 db 不是交易
// （即剛才那筆就是最外層交易）時才通知。
func NotifyVersionCommittedAfter(db *gorm.DB, err error) {
	if err != nil || db == nil || inTransaction(db) {
		return
	}
	NotifyVersionCommitted()
}

func inTransaction(db *gorm.DB) bool {
	if db.Statement == nil || db.Statement.ConnPool == nil {
		return false
	}
	_, ok := db.Statement.ConnPool.(gorm.TxCommitter)
	return ok
}
