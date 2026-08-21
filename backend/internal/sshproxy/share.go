package sshproxy

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// shareEntry 一筆會話分享（session-share D1）：記憶體存活，隨會話/重啟失效
type shareEntry struct {
	SessionID uint
	CreatedBy uint
	ExpiresAt time.Time
}

// ShareManager 分享碼管理：code → shareEntry，sessionID → code 反查（覆蓋舊碼用）
type ShareManager struct {
	mu     sync.Mutex
	byCode map[string]shareEntry
	bySess map[uint]string
}

// NewShareManager 建立分享管理器
func NewShareManager() *ShareManager {
	return &ShareManager{
		byCode: make(map[string]shareEntry),
		bySess: make(map[uint]string),
	}
}

// Create 為會話建立分享碼；同會話舊碼即刻失效（design D2）
func (m *ShareManager) Create(sessionID, createdBy uint, ttl time.Duration) (string, time.Time, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", time.Time{}, err
	}
	code := hex.EncodeToString(buf)
	expires := time.Now().Add(ttl)

	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.bySess[sessionID]; ok {
		delete(m.byCode, old)
	}
	m.byCode[code] = shareEntry{SessionID: sessionID, CreatedBy: createdBy, ExpiresAt: expires}
	m.bySess[sessionID] = code
	return code, expires, nil
}

// Revoke 撤銷會話的分享碼；回傳是否存在
func (m *ShareManager) Revoke(sessionID uint) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	code, ok := m.bySess[sessionID]
	if !ok {
		return false
	}
	delete(m.byCode, code)
	delete(m.bySess, sessionID)
	return true
}

// Resolve 驗證分享碼，有效則回傳 sessionID；過期碼順手清除
func (m *ShareManager) Resolve(code string) (uint, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.byCode[code]
	if !ok {
		return 0, false
	}
	if time.Now().After(entry.ExpiresAt) {
		delete(m.byCode, code)
		delete(m.bySess, entry.SessionID)
		return 0, false
	}
	return entry.SessionID, true
}
