package api

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"sync"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/pkg/crypto"
)

// 錄影存取 token 的簽發、兌換與撤銷。
//
// **單行程限制（對抗審查 G-D，尚未解決）**：grants 與撤銷集合皆為行程內 map，
// 故撤銷只對「簽出該 token 的那一個副本」生效。多副本部署（負載平衡後有 2 個以上
// backend）時：
//
//	副本 A 簽出的錄影 token，管理者在副本 B 觸發的停用／解綁／provider 撤銷
//	掃不到它——該 token 仍可用到 TTL 自然到期。
//
// 影響面已被兩件事夾住，故列為已知限制而非阻斷缺陷：
//   - 時間上限 120 秒（recordingTokenTTL），且不可續期；
//   - 能力上限僅「讀取指定 session 的錄影檔」——token 不可用於登入、建立連線或
//     任何寫入操作（兌換點 StreamRecordingByToken 只走串流路徑）。
//
// 真正的修法是把 grant 移到共享儲存（DB 或 Redis）並讓撤銷成為一次寫入，
// 超出本 change 範圍。**在此之前，多副本部署 SHALL 於部署文件標註此殘留窗口**；
// 若無法接受，暫時的替代是讓錄影播放路由 session affinity 綁同一副本
// （撤銷仍只在該副本生效，但至少簽發與撤銷同址）。

// recordingTokenTTL 錄影存取 token 有效期：播放器載入 .cast 屬瞬時，短時效即足夠。
// 比照 connect-token 設計，但允許 TTL 內重用（HTTP Range / 重新載入會多次 fetch）。
const recordingTokenTTL = 120 * time.Second

// recordingGrant 錄影存取授權快照
type recordingGrant struct {
	UserID uint
	// Username 簽發者的使用者名稱快照。
	//
	// **為什麼身分要在簽發時就存進 grant**：兌換端點 `/recordings/stream` 註冊於
	// 未套 AuthMiddleware 的群組，兌換當下 gin context 內沒有任何身分——審計中介層
	// 因此整筆跳過（`middleware/audit_log.go:52-56`），取走錄影本體零留痕。
	// handler 自寫審計列時唯一可信的身分來源就是這份簽發時快照
	Username  string
	SessionID uint
	// ProviderID 簽發當下的認證 provider（0＝本地/LDAP）。
	// **採直接撤銷而非世代比對**：Resolve 是熱路徑（HTTP Range 會多次 fetch），
	// 每次都查 DB 比對世代並不划算；而 TTL 僅 120 秒，in-memory map 的遍歷成本極小
	ProviderID uint
	ExpiresAt  time.Time
	// RetrievalAudited 本 grant 的取證動作是否已留痕（見 MarkRetrievalAudited）。
	// 「一次取證」的邊界定在 grant 而非 HTTP 請求：播放器以 HTTP Range 分塊取流，
	// 一次調閱會打出多次請求，逐請求記列會讓審計量正比於傳輸分塊
	RetrievalAudited bool
}

// RecordingTokenManager 簽發短時效、不透明的錄影存取 token，用以取代
// 「把長效登入 JWT 放進播放 URL query」——JWT 會被 gin access log 完整記下。
// 此 token 不透明、僅授權讀取指定 session 的錄影，且短時效，洩漏面遠小於完整 JWT。
type RecordingTokenManager struct {
	mu     sync.Mutex
	grants map[string]recordingGrant
}

// NewRecordingTokenManager 建立管理器
func NewRecordingTokenManager() *RecordingTokenManager {
	return &RecordingTokenManager{grants: make(map[string]recordingGrant)}
}

// Issue 簽發綁定 (user, session) 的錄影 token。
// authCtx.ProviderID 為簽發者本次認證的 provider（0＝本地/LDAP），供撤銷時篩選。
//
// **於 capability lock 內簽發**（對抗審查 G-C，3.8b 通則的執行點）。原本簽發完全
// 不與撤銷序列化，留下這個交錯：
//
//	舊請求通過 AuthMiddleware → 暫停 → 管理者停用帳號／provider 並掃完整張表
//	→ 舊請求才寫入 map → 該 token 錯過掃描，可讀錄影達 120 秒。
//
// 為何不採「簽發時現查 DB 世代」的輕量方案：現查只把窗口從 120 秒縮到一次 DB
// 往返，並未關閉——讀到有效之後仍可能停在掃描之後才寫入 map。鎖內簽發則兩種
// 交錯都安全：簽發先取到鎖 → 寫入必早於撤銷（鎖外）掃描，會被掃到；撤銷先取到鎖
// → 世代已提交，鎖內重讀即拒。代價是每次簽發一次短交易，而簽發不是熱路徑
// （熱路徑是 Resolve，HTTP Range 會多次 fetch，它完全不碰 DB）。
//
// 借用 session.JoinWithGenerationGuard 的通用契約——「鎖內重讀前提 → 世代比對 →
// 非阻塞集合操作」——本方法正是該形狀；其命名偏向訂閱是歷史因素。
//
// 鎖序：capability lock → m.mu，**不得反向**。撤銷側（RevokeByUser／
// RevokeByProvider）只取 m.mu 且一律於 capability lock 之外呼叫，故無循環等待。
func (m *RecordingTokenManager) Issue(userID, sessionID uint, username string, authCtx crypto.AuthContext) (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := hex.EncodeToString(buf)
	grant := recordingGrant{
		UserID:     userID,
		Username:   username,
		SessionID:  sessionID,
		ProviderID: authCtx.ProviderID,
		ExpiresAt:  time.Now().Add(recordingTokenTTL),
	}

	if database.DB == nil {
		// 僅測試建構路徑可達（生產環境 DB 未初始化時整個應用無法運作）。
		// 比照 service 的世代閘：不靜默降級，每進程告警一次
		warnRecordingIssueGateDisabled()
		m.insert(token, grant)
		return token, nil
	}

	if _, err := session.JoinWithGenerationGuard(authCtx, userID, func() bool {
		m.insert(token, grant)
		return true
	}); err != nil {
		return "", err
	}
	return token, nil
}

// insert 寫入 grant 並順帶清掉逾時項（Issue 的鎖內動作，必須非阻塞）
func (m *RecordingTokenManager) insert(token string, grant recordingGrant) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked()
	m.grants[token] = grant
}

// recordingIssueGateWarnOnce 讓「DB 未注入→簽發序列化失效」的警告每進程只印一次
var recordingIssueGateWarnOnce sync.Once

func warnRecordingIssueGateDisabled() {
	recordingIssueGateWarnOnce.Do(func() {
		log.Println("[RecordingToken] 資料庫未初始化，簽發側世代閘與序列化不生效——" +
			"生產環境不應出現此訊息")
	})
}

// RevokeByUser 撤銷該使用者的全部錄影 token（帳號停用/刪除/外部化/解綁）。
//
// 缺這條時，「已撤銷憑證的人在 120 秒內仍能下載錄影」——錄影是最敏感的稽核資產，
// 那個窗口不可接受。**自動鎖定不得呼叫**（鎖定可由未認證第三方觸發）
func (m *RecordingTokenManager) RevokeByUser(userID uint) int {
	if userID == 0 {
		return 0
	}
	return m.revokeMatching(func(g recordingGrant) bool { return g.UserID == userID })
}

// RevokeByProvider 撤銷經指定 provider 認證者簽出的全部錄影 token
func (m *RecordingTokenManager) RevokeByProvider(providerID uint) int {
	if providerID == 0 {
		return 0 // 0 是「本地登入」的語義，不是萬用字元
	}
	return m.revokeMatching(func(g recordingGrant) bool { return g.ProviderID == providerID })
}

func (m *RecordingTokenManager) revokeMatching(match func(recordingGrant) bool) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for tok, g := range m.grants {
		if match(g) {
			delete(m.grants, tok)
			n++
		}
	}
	return n
}

// Resolve 驗證 token（TTL 內可重用，不於成功時移除）；逾時即移除並回 false
func (m *RecordingTokenManager) Resolve(token string) (recordingGrant, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	grant, ok := m.grants[token]
	if !ok {
		return recordingGrant{}, false
	}
	if time.Now().After(grant.ExpiresAt) {
		delete(m.grants, token)
		return recordingGrant{}, false
	}
	return grant, true
}

// MarkRetrievalAudited 把 grant 標記為「取證已留痕」，回傳**本次呼叫是否應寫審計列**。
//
// # 為什麼「一次取證」的邊界是 grant 而不是 HTTP 請求
//
// 播放器以 HTTP Range 分塊取流（`serveCastFile`／`serveGuacFile` 都走
// `http.ServeContent`），一次調閱會打出數次請求；`.guac` 圖形錄影的分塊尤其多。
// 若逐請求寫列：
//
//   - 審計量正比於傳輸分塊，「誰取走了這場錄影」這個訊號被自己的重複淹沒；
//   - 每個 Range 請求都多一次審計寫入，而 `Resolve` 這條熱路徑的設計前提正是
//     「完全不碰 DB」（見本檔頭部取捨），逐請求記列等於把該前提作廢。
//
// grant 是天然的取證邊界：它綁定單一 (使用者, 連線)、TTL 僅 120 秒且不可續期。
// 超過 TTL 還要繼續取流就必須重新簽發——而簽發本身已入審計，故長時間的調閱會
// 自然產生數筆各自有界的取證紀錄，不會被合併成一筆。
//
// **逾時競態一律偏向多記一列**：grant 可能在傳輸期間被 `cleanupLocked` 清掉，
// 此時無從得知是否已記過。漏一列＝取證無痕（本修法要消滅的正是這件事），
// 重複一列只是噪音，故 `!ok` 回 true。
func (m *RecordingTokenManager) MarkRetrievalAudited(token string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	grant, ok := m.grants[token]
	if !ok {
		return true
	}
	if grant.RetrievalAudited {
		return false
	}
	grant.RetrievalAudited = true
	m.grants[token] = grant
	return true
}

// cleanupLocked 清掉逾時項（呼叫端須持鎖）
func (m *RecordingTokenManager) cleanupLocked() {
	now := time.Now()
	for t, g := range m.grants {
		if now.After(g.ExpiresAt) {
			delete(m.grants, t)
		}
	}
}
