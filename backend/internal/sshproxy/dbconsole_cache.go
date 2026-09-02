package sshproxy

import (
	"sync"

	"github.com/custodexa/backend/internal/dbconsole"
)

// consoleCachedUnit 一個執行單位留在伺服端的結果。
//
// **只留最近一次送出**：快取存在的唯一理由是讓匯出不必重新執行語句
// （重新執行會讓非冪等語句生效兩次，而且在審計上那是一次新的執行）。
// 留得更久沒有對應的使用者需求，卻讓每一場會話的記憶體佔用隨時間單調成長
type consoleCachedUnit struct {
	EventID  string
	Seq      int
	Database string
	Sets     []dbconsole.ResultSet
}

// consoleResultCache 會話的結果快取。
//
// 匯出端點自這裡取資料，而它的定址鍵是 `(event_id, set_index)`——
// 與審計列、轉錄行、即時訊息用的是同一個識別
type consoleResultCache struct {
	mu    sync.RWMutex
	units map[string]*consoleCachedUnit
}

func newConsoleResultCache() *consoleResultCache {
	return &consoleResultCache{units: make(map[string]*consoleCachedUnit)}
}

// reset 新的一次送出即清空。舊的事件識別自此對匯出而言不存在——
// 那正是六態收斂裡「事件識別非當前快取」那一態
func (c *consoleResultCache) reset() {
	c.mu.Lock()
	c.units = make(map[string]*consoleCachedUnit)
	c.mu.Unlock()
}

func (c *consoleResultCache) put(u *consoleCachedUnit) {
	c.mu.Lock()
	c.units[u.EventID] = u
	c.mu.Unlock()
}

func (c *consoleResultCache) get(eventID string) (*consoleCachedUnit, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	u, ok := c.units[eventID]
	return u, ok
}

// release 會話結束即釋放。匯出鈕在會話結束後停用正是因為這一步——
// 讓使用者收到一個沒有辦法解釋的 404 是更糟的選擇
func (c *consoleResultCache) release() {
	c.mu.Lock()
	c.units = nil
	c.mu.Unlock()
}
