package sshproxy

import (
	"sync"

	"github.com/custodexa/backend/internal/dbconsole"
)

// admission 的計數範圍（拒絕審計的 scope 欄即取這兩個值）
const (
	consoleScopeUser   = "user"
	consoleScopeGlobal = "global"
)

// consoleAdmission 主控台會話的名額登記。
//
// **計數口徑是運行時的 in-process 表，不是 `sessions.status='active'` 列。**
// 理由是孤兒列：行程崩潰後那些列會留到收斂寬限期結束，若拿它們計數，使用者
// 會被自己的殘留會話擋在門外，而他沒有任何辦法自救——重開瀏覽器不會讓那些列
// 消失。單實例是產品前提，故 in-process 計數即全域計數。
//
// 名額於連線建立時佔用、連線關閉（任何原因）時釋放；acquire 與 release 必須
// 成對，故 acquire 成功時回傳的 release 是唯一的釋放途徑
type consoleAdmission struct {
	mu      sync.Mutex
	perUser map[uint]int
	total   int
}

func newConsoleAdmission() *consoleAdmission {
	return &consoleAdmission{perUser: make(map[uint]int)}
}

// consoleAdmissionDenial admission 被拒的事實（供拒絕審計逐欄填實）
type consoleAdmissionDenial struct {
	Scope   string
	Current int
	Limit   int
}

// acquire 佔一個名額。成功回傳 release（冪等）與 nil；
// 逾限回傳 nil 與拒絕事實。
//
// 兩個上限的檢查順序是「先個人後全域」：個人上限先到時，告訴使用者的是他自己
// 開太多，那是他能自己處理的；反過來報全域滿載只會讓他去找管理員
func (a *consoleAdmission) acquire(userID uint) (func(), *consoleAdmissionDenial) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if cur := a.perUser[userID]; cur >= dbconsole.MaxConcurrentSessionsPerUser {
		return nil, &consoleAdmissionDenial{Scope: consoleScopeUser,
			Current: cur, Limit: dbconsole.MaxConcurrentSessionsPerUser}
	}
	if a.total >= dbconsole.MaxConcurrentSessionsGlobal {
		return nil, &consoleAdmissionDenial{Scope: consoleScopeGlobal,
			Current: a.total, Limit: dbconsole.MaxConcurrentSessionsGlobal}
	}

	a.perUser[userID]++
	a.total++

	var once sync.Once
	return func() {
		once.Do(func() { a.release(userID) })
	}, nil
}

func (a *consoleAdmission) release(userID uint) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if cur := a.perUser[userID]; cur > 1 {
		a.perUser[userID] = cur - 1
	} else {
		delete(a.perUser, userID)
	}
	if a.total > 0 {
		a.total--
	}
}

// counts 目前的佔用數（測試與診斷用）
func (a *consoleAdmission) counts(userID uint) (user, total int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.perUser[userID], a.total
}
