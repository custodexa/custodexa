package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ObserverPurpose 觀看票證的用途。
//
// **同一個管理器內仍要分用途**：即時監看（稽核職能，限 admin／auditor）與分享
// 觀看（會話擁有者發碼、任何已登入者持碼加入）的准入條件完全不同，簽發時各自
// 判定。缺了本欄，一張分享票就能開監看——那等於讓任何登入者繞過角色限制看遍
// 進行中的連線。
type ObserverPurpose string

const (
	// ObserverPurposeMonitor 即時監看（`GET /sessions/:id/monitor`）
	ObserverPurposeMonitor ObserverPurpose = "monitor"
	// ObserverPurposeShare 分享觀看（`GET /sessions/share/:code/ws`）
	ObserverPurposeShare ObserverPurpose = "share"
)

// ObserverGrant 一次性觀看票證所攜帶的脈絡。
//
// # 為何與 ConnectGrant 分成兩個型別、兩個管理器
//
// 兩者的客體根本不同：連線票的客體是「資產＋帳號」，觀看票的客體是「進行中的
// 會話」或「分享碼」。合成一個型別就得讓四個客體欄位彼此互斥地留空，而
// 「終端票不得兌換成觀看、觀看票不得兌換成終端」只能靠兌換側自己記得比對用途欄
// ——漏比一次即是越權。分成兩個型別後，兩張票各自只有一個管理器認得，交叉兌換
// 是**編譯期不可能**，而不是一條需要有人記得的規則。
//
// 角色不進票證，理由同 ConnectGrant：角色一律於簽發與兌換各自現查。
type ObserverGrant struct {
	UserID  uint
	Purpose ObserverPurpose

	// SessionID 監看票的目標會話。分享票為 0——分享碼要到兌換時才解析，
	// 提前凍結目標會讓「簽票後分享被撤銷」的兌換仍然成立
	SessionID uint

	// ShareCode 分享票所對應的分享碼。監看票為空。
	// 兌換時與路徑上的碼比對：不比對的話，一張為 A 碼簽的票能加入 B 碼的會話
	ShareCode string

	// Username 觀察者的帳號名快照，供兌換點自寫的審計列填實。
	//
	// **與 ConnectGrant 不帶 Username 不衝突**：那裡的 username 是「憑證解封後
	// 要登入目標主機的帳號」，凍結進票證等於讓兌換側失去現查的機會；這裡的
	// username 是觀察者自己的登入名，本來就是溯源快照（審計表的 username 欄一向
	// 是快照，帳號日後改名不追溯）。不帶它就得在兌換點多查一次使用者表，
	// 而查不到時審計列會少掉稽核第一眼要看的那一欄。
	Username string

	// 認證脈絡：簽發階段自請求脈絡取得，兌換時寫入觀察者脈絡供
	// provider 停用收線與世代守衛使用。**這四欄不是授權快照**，授權一律現查。
	AuthMethod string
	ProviderID uint
	AuthEpoch  int
	CredEpoch  int

	// ExpiresAt 票證到期時刻，由簽發實作統一填寫（TTL 不進呼叫端）。
	ExpiresAt time.Time
}

// ErrObserverTicketCapacity 未兌換觀看票達上限，本次拒發。
// 與 ErrConnectTokenCapacity 分立：兩張表各自計數，觀看票被灌滿不該讓終端連線
// 拒發（反之亦然），而呼叫端要能分辨是哪一種容量事件。
var ErrObserverTicketCapacity = errors.New("未兌換的觀看票已達上限")

// ObserverTicketManager 一次性觀看票：兌換即焚（兌換成功的當下即失效，重放無效）。
// 生命週期、TTL 與容量上限比照 ConnectTokenManager（同一份常數），差別只在客體。
type ObserverTicketManager struct {
	mu      sync.Mutex
	tickets map[string]ObserverGrant
	// ttl 票證壽命；零值視為預設（見 NewObserverTicketManagerWithTTL）
	ttl time.Duration
}

// NewObserverTicketManager 建立管理器（TTL 同連線票）
func NewObserverTicketManager() *ObserverTicketManager {
	return NewObserverTicketManagerWithTTL(connectTokenTTL)
}

// NewObserverTicketManagerWithTTL 建立指定 TTL 的管理器。
//
// **TTL 可注入是為了讓「票過期」這條路徑測得到**：預設 60 秒，任何端到端測試都
// 等不起；而過期與偽票走的是不同的審計原因（`ticket_expired` 對
// `ticket_invalid`），把它留在只有單元測試碰得到的地方，等於讓兌換點對過期票的
// 處置沒有任何機器在盯。
func NewObserverTicketManagerWithTTL(ttl time.Duration) *ObserverTicketManager {
	return &ObserverTicketManager{tickets: make(map[string]ObserverGrant), ttl: ttl}
}

// IssueObserverTicket 簽發一次性觀看票（TTL 見建構子，預設 60 秒）。
//
// 逾時清理與容量判定同在簽發側（比照 ConnectTokenManager）：簽發不在熱路徑上，
// 兌換才是；故兌換維持 O(1)、不做全表掃描。
func (m *ObserverTicketManager) IssueObserverTicket(_ context.Context, grant ObserverGrant) (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := hex.EncodeToString(buf)

	ttl := m.ttl
	if ttl == 0 {
		ttl = connectTokenTTL
	}
	now := time.Now()
	grant.ExpiresAt = now.Add(ttl)

	m.mu.Lock()
	defer m.mu.Unlock()

	perUser := m.sweepExpiredLocked(now, grant.UserID)
	if perUser >= connectTokenPerUserCapacity {
		return "", fmt.Errorf("%w（使用者 %d 未兌換 %d 張）",
			ErrObserverTicketCapacity, grant.UserID, perUser)
	}
	if len(m.tickets) >= connectTokenCapacity {
		return "", fmt.Errorf("%w（全域 %d 張）", ErrObserverTicketCapacity, len(m.tickets))
	}

	m.tickets[token] = grant
	return token, nil
}

// sweepExpiredLocked 刪除全部逾時票，並回傳 userID 名下剩餘未逾時的張數。
// 呼叫端須持鎖
func (m *ObserverTicketManager) sweepExpiredLocked(now time.Time, userID uint) int {
	perUser := 0
	for tok, g := range m.tickets {
		if now.After(g.ExpiresAt) {
			delete(m.tickets, tok)
			continue
		}
		if g.UserID == userID {
			perUser++
		}
	}
	return perUser
}

// RedeemObserverTicketWithReason 驗證並消耗觀看票：成功與否一律自表中移除（一次性）。
// 回傳拒絕原因供審計；**對外回應仍收斂為同一則「token 無效」**——分流即票證存在性
// 探測面（理由與 RedeemConnectTokenWithReason 檔頭同）。
func (m *ObserverTicketManager) RedeemObserverTicketWithReason(_ context.Context, token string) (ObserverGrant, RedeemDenyReason) {
	m.mu.Lock()
	defer m.mu.Unlock()
	grant, ok := m.tickets[token]
	if !ok {
		return ObserverGrant{}, RedeemDenyInvalid
	}
	delete(m.tickets, token)
	if time.Now().After(grant.ExpiresAt) {
		return ObserverGrant{}, RedeemDenyExpired
	}
	return grant, RedeemDenyNone
}
