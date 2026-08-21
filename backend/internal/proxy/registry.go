package proxy

import (
	"log"
	"sync"
)

// CloseFunc per-connection 的執行緒安全關閉回呼（break-glass-revocation F4）：
// 由各 bridge 於 Register 時提供——關閉通知的寫入必須與該連線資料橋接共用同一把
// 寫鎖（禁止對底層 WebSocket 併發寫），且按連線協議正確編碼（文字終端走自身
// 訊息協議、圖形通道走 Guacamole disconnect）。回呼必須冪等（bridge 側以
// once/closed 守衛），Registry 只保證同一 sessionID 至多呼叫一次。
type CloseFunc func() error

// ConnectionRegistry 管理所有活動連線的關閉回呼。
// F4 前身直接持有 *websocket.Conn 並裸寫 guac disconnect——繞過兩側 bridge 的
// 寫鎖（gorilla 併發寫 panic）且對 SSH 連線發錯協議，故改存回呼不存連線
type ConnectionRegistry struct {
	mu          sync.RWMutex
	connections map[uint]CloseFunc // SessionID -> 關閉回呼
}

// NewConnectionRegistry 創建連線註冊表
func NewConnectionRegistry() *ConnectionRegistry {
	return &ConnectionRegistry{
		connections: make(map[uint]CloseFunc),
	}
}

// Register 註冊一個新連線的關閉回呼
func (r *ConnectionRegistry) Register(sessionID uint, closeFn CloseFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.connections[sessionID] = closeFn
}

// Unregister 註銷連線
func (r *ConnectionRegistry) Unregister(sessionID uint) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.connections, sessionID)
}

// Close 關閉指定 SessionID 的連線：原子取出回呼（並發 Close 僅一方執行）後
// 於鎖外呼叫，避免回呼內的網路寫入持著註冊表鎖
func (r *ConnectionRegistry) Close(sessionID uint) error {
	r.mu.Lock()
	closeFn, exists := r.connections[sessionID]
	if exists {
		delete(r.connections, sessionID)
	}
	r.mu.Unlock()

	if !exists {
		return nil // 連線不存在，可能已經關閉
	}

	if err := closeFn(); err != nil {
		log.Printf("[Registry] 警告: 關閉連線失敗 (SessionID=%d): %v", sessionID, err)
		return err
	}
	log.Printf("[Registry] 連線已關閉 (SessionID=%d)", sessionID)
	return nil
}

// CloseAll 全量收線並清空註冊表（kek-provider-modularization D6.2.4）。
//
// 段 2 服務圖被丟棄時，其連線 goroutine 不會自己結束——逐一 Close 是唯一
// 收線途徑，缺此方法時「舊持有者釋放已建構資源」只能靠呼叫端自己遍歷，
// 而註冊表的鎖不對外，遍歷本身就不安全。
//
// 原子取出全部回呼後於鎖外呼叫（與 Close 同一策略）：回呼內含網路寫入，
// 持鎖呼叫會讓收線期間的任何 Register/Unregister 一併阻塞。
// 單項失敗不中斷後續——中途放棄會讓剩餘連線永久洩漏。
func (r *ConnectionRegistry) CloseAll() int {
	r.mu.Lock()
	pending := r.connections
	r.connections = make(map[uint]CloseFunc)
	r.mu.Unlock()

	closed := 0
	for sessionID, closeFn := range pending {
		if err := closeFn(); err != nil {
			log.Printf("[Registry] 警告: 全量收線時關閉失敗 (SessionID=%d): %v", sessionID, err)
			continue
		}
		closed++
	}
	if len(pending) > 0 {
		log.Printf("[Registry] 全量收線完成：共 %d 筆，成功 %d 筆", len(pending), closed)
	}
	return closed
}

// Count 返回目前活動連線數
func (r *ConnectionRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.connections)
}

// Has 回報指定 SessionID 是否有活連線登記（session-reconciliation 的
// 存活權威訊號：DB active 而 registry 無登記＝孤兒候選）
func (r *ConnectionRegistry) Has(sessionID uint) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.connections[sessionID]
	return exists
}
