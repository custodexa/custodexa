package api

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"sync"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/pkg/crypto"
)

// 錄影存取 token 的簽發、兌換與撤銷。
//
// **單行程限制（尚未解決）**：grants 與撤銷集合皆為行程內 map，
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
	// Version 本 grant 最近一次判定（簽發或重驗）所依據的權限版本。觀察到更新的版本時，
	// 下一次取流必先重驗持有者的錄影檢視權
	Version int64
	// Gen 本 grant 判定（簽發或重驗）開始前已觀察到的「版本未確認」世代；落後於管理器目前的
	// 世代，表示判定之後曾有提交通知因讀不到權限版本而無法確認，下一次取流必先重驗
	Gen uint64
	// Facts 簽發時的權杖事實（主體種類、認證方式、憑證世代），重驗以同一組事實解析主體
	Facts authz.TokenFacts
}

// recordingIssueRoute 簽發錄影票的路由；簽發與重驗都以它的登錄項判定錄影檢視權。
const (
	recordingIssueMethod = "POST"
	recordingIssuePath   = "/api/v1/sessions/:id/recording/token"
)

// errRecordingIssueDenied 簽發時在鎖交易內重新判定，主體已無錄影檢視權。
type errRecordingIssueDenied struct{ decision authz.Decision }

func (e *errRecordingIssueDenied) Error() string { return "簽發錄影票時權限已不足" }

// recordingIssueDenial 簽發被鎖內判定拒絕時的路由判定結果（拒絕依據與路由層相同）。
func recordingIssueDenial(err error) (authz.Decision, bool) {
	var denied *errRecordingIssueDenied
	if errors.As(err, &denied) {
		return denied.decision, true
	}
	return authz.Decision{}, false
}

// recordingTokenHooks 交錯測試的同步點（生產為 nil）。
type recordingTokenHooks struct {
	// beforeJoin 路由已通過、進鎖交易之前
	beforeJoin func()
	// afterVersionRead 鎖交易內讀完權限版本、重新解析主體之前
	afterVersionRead func()
	// beforeApply 重驗讀完並判定、在 m.mu 內套用結果之前
	beforeApply func(token string)
}

// RecordingTokenManager 簽發短時效、不透明的錄影存取 token，用以取代
// 「把長效登入 JWT 放進播放 URL query」——JWT 會被 gin access log 完整記下。
// 此 token 不透明、僅授權讀取指定 session 的錄影，且短時效，洩漏面遠小於完整 JWT。
//
// # 權限變更後的主動撤銷
//
// grant 記下簽發時的權限版本。簽發在同一鎖交易內「先讀版本、再重新解析主體並以簽發路由
// 的登錄項判定」，判定不過不簽；票記錄的版本因此不晚於授權快照。權限寫入提交後，權限
// 模組通知本管理器（OnPermissionVersionCommitted），管理器把觀察版本推進到目前值並重驗
// 版本落後的持有者；Resolve 遇到版本落後的 grant 就地同步重驗。通知時讀不到版本則記下
// 「未確認」世代，判定早於它的票同樣在下一次取流重驗。重驗讀不到資料即刪除該票
// （fail-closed）；重驗結果不會覆蓋較新的版本，也不會復活已刪除的票。版本未變時 Resolve
// 不碰資料庫。
type RecordingTokenManager struct {
	mu     sync.Mutex
	grants map[string]recordingGrant
	// observed 已觀察到的權限版本（只增不減；m.mu 保護）
	observed int64
	// unconfirmed 「提交通知到達但讀不到權限版本」的累計次數（只增不減；m.mu 保護）。
	// 它記下「可能已變更」：讀版本失敗不能被當成「確定未變更」
	unconfirmed uint64
	hooks       recordingTokenHooks
	// versionOf／decide 權限版本讀取與錄影檢視權判定（測試可替換；預設讀 authz）
	versionOf func(db *gorm.DB) (int64, error)
	decide    func(db *gorm.DB, userID uint, facts authz.TokenFacts) (authz.Decision, error)
}

// NewRecordingTokenManager 建立管理器
func NewRecordingTokenManager() *RecordingTokenManager {
	return &RecordingTokenManager{
		grants:    make(map[string]recordingGrant),
		versionOf: authz.CurrentVersion,
		decide: func(db *gorm.DB, userID uint, facts authz.TokenFacts) (authz.Decision, error) {
			p, err := authz.ResolveUserOn(db, userID, facts)
			if err != nil {
				return authz.Decision{}, err
			}
			return authz.DecideRoute(recordingIssueMethod, recordingIssuePath, p), nil
		},
	}
}

// Issue 簽發綁定 (user, session) 的錄影 token。
// authCtx.ProviderID 為簽發者本次認證的 provider（0＝本地/LDAP），供撤銷時篩選。
//
// **於 capability lock 內簽發**。原本簽發完全
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
func (m *RecordingTokenManager) Issue(userID, sessionID uint, username string, authCtx crypto.AuthContext, facts authz.TokenFacts) (string, error) {
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
		Facts:      facts,
	}

	if database.DB == nil {
		// 僅測試建構路徑可達（生產環境 DB 未初始化時整個應用無法運作）。
		// 比照 service 的世代閘：不靜默降級，每進程告警一次；版本記 0、不做能力判定
		warnRecordingIssueGateDisabled()
		m.insert(token, grant)
		return token, nil
	}

	if hook := m.hooks.beforeJoin; hook != nil {
		hook()
	}
	// 同一鎖交易內：先讀權限版本、再重新解析主體並以簽發路由的登錄項判定，放行才寫入。
	// 票記錄的版本因此不晚於判定所依據的授權快照
	if _, err := session.JoinWithGenerationGuardTx(authCtx, userID, func(tx *gorm.DB) (bool, error) {
		// 世代快照必須早於版本讀取：讀取之後才失敗的通知，其標記要能讓這張票落後
		genAtRead := m.currentUnconfirmed()
		v, err := m.versionOf(tx)
		if err != nil {
			return false, err
		}
		if hook := m.hooks.afterVersionRead; hook != nil {
			hook()
		}
		d, err := m.decide(tx, userID, facts)
		if err != nil {
			return false, err
		}
		if !d.Allowed {
			return false, &errRecordingIssueDenied{decision: d}
		}
		grant.Version = v
		grant.Gen = genAtRead
		m.insert(token, grant)
		return true, nil
	}); err != nil {
		return "", err
	}
	return token, nil
}

func (m *RecordingTokenManager) currentUnconfirmed() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.unconfirmed
}

// insert 寫入 grant 並順帶清掉逾時項（Issue 的鎖內動作，必須非阻塞）
func (m *RecordingTokenManager) insert(token string, grant recordingGrant) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked()
	m.grants[token] = grant
	if grant.Version > m.observed {
		m.observed = grant.Version
	}
}

// OnPermissionVersionCommitted 權限寫入提交後的通知：觀察版本推進到目前值，重驗版本落後的
// 持有者。沒有 grant 時仍推進觀察版本：簽發途中（讀版本之後、寫入之前）提交的撤權，
// 其通知可能早於票寫入，要靠觀察版本讓該票下一次取流重驗。
func (m *RecordingTokenManager) OnPermissionVersionCommitted() {
	if database.DB == nil {
		return
	}
	v, err := m.versionOf(database.DB)
	if err != nil {
		// 讀不到版本：無法確認權限是否已變更。留下單調的「未確認」世代，
		// 所有判定早於此刻的票（含尚在簽發途中、稍後才寫入的票）下一次取流都要重驗
		log.Printf("[RecordingToken] 權限變更後讀取權限版本失敗，標記待重驗: %v", err)
		m.mu.Lock()
		m.unconfirmed++
		m.mu.Unlock()
		return
	}
	m.mu.Lock()
	if v > m.observed {
		m.observed = v
	}
	var stale []string
	for tok, g := range m.grants {
		if g.Version < m.observed || g.Gen < m.unconfirmed {
			stale = append(stale, tok)
		}
	}
	m.mu.Unlock()
	for _, tok := range stale {
		m.revalidate(tok)
	}
}

// revalidate 重驗一張票的持有者：先讀版本 v_r、再解析主體並判定，最後在 m.mu 內套用——
// grant 已不存在時不做事（不復活）；grant 版本已不舊於 v_r 時不做事（不倒退）；
// 放行即把 grant 版本改為 v_r；不放行或讀取失敗即刪除該票。
func (m *RecordingTokenManager) revalidate(token string) {
	m.mu.Lock()
	g, ok := m.grants[token]
	genSnap := m.unconfirmed
	m.mu.Unlock()
	if !ok {
		return
	}
	allowed := false
	vr, err := m.versionOf(database.DB)
	if err == nil {
		var d authz.Decision
		if d, err = m.decide(database.DB, g.UserID, g.Facts); err == nil {
			allowed = d.Allowed
		}
	}
	if err != nil {
		log.Printf("[RecordingToken] 重驗錄影票持有者失敗，撤銷該票: %v", err)
	}
	if hook := m.hooks.beforeApply; hook != nil {
		hook(token)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.grants[token]
	if !ok {
		return
	}
	if err == nil && cur.Version >= vr && cur.Gen >= genSnap {
		return
	}
	if err != nil || !allowed {
		delete(m.grants, token)
		return
	}
	if vr > cur.Version {
		cur.Version = vr
	}
	if genSnap > cur.Gen {
		cur.Gen = genSnap
	}
	m.grants[token] = cur
	if vr > m.observed {
		m.observed = vr
	}
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

// RevokeBySession 撤銷某會話的全部錄影 token（該會話的錄影被刪除之後）
func (m *RecordingTokenManager) RevokeBySession(sessionID uint) int {
	if sessionID == 0 {
		return 0
	}
	return m.revokeMatching(func(g recordingGrant) bool { return g.SessionID == sessionID })
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

// Resolve 驗證 token（TTL 內可重用，不於成功時移除）；逾時即移除並回 false。
// grant 版本落後於觀察版本時就地同步重驗一次（重驗讀不到即拒並刪除）；版本相同時不碰資料庫。
func (m *RecordingTokenManager) Resolve(token string) (recordingGrant, bool) {
	m.mu.Lock()
	grant, ok := m.grants[token]
	if !ok {
		m.mu.Unlock()
		return recordingGrant{}, false
	}
	if time.Now().After(grant.ExpiresAt) {
		delete(m.grants, token)
		m.mu.Unlock()
		return recordingGrant{}, false
	}
	stale := (grant.Version < m.observed || grant.Gen < m.unconfirmed) && database.DB != nil
	m.mu.Unlock()
	if !stale {
		return grant, true
	}
	m.revalidate(token)
	m.mu.Lock()
	defer m.mu.Unlock()
	grant, ok = m.grants[token]
	if !ok || grant.Version < m.observed || grant.Gen < m.unconfirmed {
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
