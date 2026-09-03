package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/custodexa/backend/pkg/gatewayapi"
)

// ConnectGrant 一次性連線授權快照，**即 `gatewayapi.ConnectGrant`**
// （型別別名）。
//
// 角色與連線授權/存取政策於簽發與兌換點各自 DB 現查——快照 SHALL NOT 攜帶角色，
// 使「憑角色快照判定 admin 特權」成為編譯期不可能。
// 該性質現由 `cmd/server/gatewayapi_purity_guard_test.go` 的 `gwExactFieldSets`
// 欄位白名單守住（任意命名的角色欄一律紅）。
//
// **別名而非各持一份**：兩份同形結構就有兩處可以各自增欄，白名單只守得住其中一份。
// 欄位語義（AccountID 0＝預設帳號、認證脈絡四欄不是授權快照）逐字見契約型別註解。
type ConnectGrant = gatewayapi.ConnectGrant

const connectTokenTTL = 60 * time.Second

// 未兌換 grant 的容量上限。
//
// grant 原本只有「以同一把 token 呼叫 Resolve」這一條移除路徑：已認證使用者
// 反覆簽發而從不兌換，map 即無界成長至記憶體耗盡。上限分兩層，缺一不可：
//
//	connectTokenPerUserCapacity  單一使用者的未兌換上限。**這層才是主防線**——
//	  只有全域上限時，一個已認證帳號灌滿全表就能讓其他所有人無法建立連線，
//	  等於把記憶體 DoS 換成可用性 DoS。正常使用者同時未兌換的 grant 是個位數
//	  （簽發後數秒內即兌換，TTL 僅 60 秒）。
//	connectTokenCapacity         全域上限，多帳號協同時的最後一道。
//	  4096 張 × 60 秒 TTL ≈ 每秒 68 條新連線持續不兌換，遠高於任何真實負載。
const (
	connectTokenPerUserCapacity = 32
	connectTokenCapacity        = 4096
)

// ErrConnectTokenCapacity 未兌換 grant 達上限，本次拒發。
//
// 呼叫端 SHALL 以此區分「暫時性容量拒絕」（503／稍後再試）與真正的內部錯誤，
// 兩者混為 500 會讓容量事件在告警裡淹沒於一般故障中
var ErrConnectTokenCapacity = errors.New("未兌換的連線 token 已達上限")

// ConnectTokenManager 一次性連線 token：兌換即焚（兌換成功的當下即失效，重放無效）。
// **`gatewayapi.TokenService` 的實作**。
type ConnectTokenManager struct {
	mu     sync.Mutex
	grants map[string]ConnectGrant
}

var _ gatewayapi.TokenService = (*ConnectTokenManager)(nil)

// NewConnectTokenManager 建立管理器
func NewConnectTokenManager() *ConnectTokenManager {
	return &ConnectTokenManager{grants: make(map[string]ConnectGrant)}
}

// IssueConnectToken 簽發一次性 token（60s TTL）。不收角色——角色於兌換點 DB 現查。
//
// **已改名**（原 `Issue`）：本型別即 `gatewayapi.TokenService` 的實作，
// 方法名與契約對齊。ctx 未被使用（純記憶體 map 操作、無 I/O），刻意保留參數
// 而不改契約——同 `gatewayapi.AsyncSink.Submit` 的既定紀律。
//
// **收結構而非位置參數**：原簽章是三個同型 uint，
// 加上認證脈絡後變成六個 uint 與一個字串，傳錯順序**不會編譯錯**——
// 把 providerID 傳成 assetID 的後果是連上錯誤的資產。結構強制具名。
// 呼叫端不需填 ExpiresAt，由本方法統一設定。
//
// **逾時清理與容量判定都在簽發側**（G-B）：簽發不在連線關鍵路徑上（使用者按下
// 連線到 WS 建立之間），一次 O(表大小) 的掃描（上限 4096 筆）成本可忽略；
// 兌換才是熱路徑，故 RedeemConnectToken 維持 O(1)、不做任何全表掃描。
// 也刻意不開背景 goroutine——多一條生命週期就多一處需要被關閉的資源。
func (m *ConnectTokenManager) IssueConnectToken(_ context.Context, grant ConnectGrant) (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := hex.EncodeToString(buf)

	now := time.Now()
	grant.ExpiresAt = now.Add(connectTokenTTL)

	m.mu.Lock()
	defer m.mu.Unlock()

	// 清理與計數同一趟：先掃掉逾時項再數，上限才是「未逾時的量」而非累計簽發量
	// （若先數後清，表被灌滿一次就永遠回不來，一次 DoS 造成永久停業）
	perUser := m.sweepExpiredLocked(now, grant.UserID)
	if perUser >= connectTokenPerUserCapacity {
		return "", fmt.Errorf("%w（使用者 %d 未兌換 %d 張）",
			ErrConnectTokenCapacity, grant.UserID, perUser)
	}
	if len(m.grants) >= connectTokenCapacity {
		return "", fmt.Errorf("%w（全域 %d 張）", ErrConnectTokenCapacity, len(m.grants))
	}

	m.grants[token] = grant
	return token, nil
}

// sweepExpiredLocked 刪除全部逾時 grant，並回傳 userID 名下**剩餘未逾時**的張數。
// 呼叫端須持鎖
func (m *ConnectTokenManager) sweepExpiredLocked(now time.Time, userID uint) int {
	perUser := 0
	for tok, g := range m.grants {
		if now.After(g.ExpiresAt) {
			delete(m.grants, tok)
			continue
		}
		if g.UserID == userID {
			perUser++
		}
	}
	return perUser
}

// RedeemConnectToken 驗證並消耗 token：成功與否一律自表中移除（一次性）。
// **熱路徑**：僅 O(1) 查表＋刪除，逾時清理一律在簽發側（見上）。
//
// **已改名**（原 `Resolve`）。第二回傳值維持 bool：票不存在／已兌換／已過期
// 三者一律收斂為同一則「token 無效」回應，分流即票證存在性探測面。
func (m *ConnectTokenManager) RedeemConnectToken(ctx context.Context, token string) (ConnectGrant, bool) {
	grant, reason := m.RedeemConnectTokenWithReason(ctx, token)
	return grant, reason == RedeemDenyNone
}

// RedeemDenyReason 兌換拒絕的**內部**原因。
//
// **對外回應仍收斂為同一則「token 無效」**——分流即票證存在性探測面，那條紀律
// 不變（見 RedeemConnectToken 檔頭）。審計是內部視角，兩者是不同的觀眾：稽核
// 必須分得出「拿著不存在的票反覆試」（探測訊號）與「票過期了」（使用者慢了
// 一步），把兩者寫成同一個字串等於把探測藏進日常噪音裡。
type RedeemDenyReason string

const (
	// RedeemDenyNone 兌換成立
	RedeemDenyNone RedeemDenyReason = ""
	// RedeemDenyMissing 請求根本沒帶票。**不由本型別的兌換方法產生**——沒有票就
	// 不會呼叫兌換，這一格由 handler 判定。定義在此是為了讓兩條兌換入口取用同一個
	// 字面量：各寫各的字串，稽核依 reason 分組時會多出一個只在某一側出現的值
	RedeemDenyMissing RedeemDenyReason = "ticket_missing"
	// RedeemDenyInvalid 票不存在或已被兌換過（一次性）
	RedeemDenyInvalid RedeemDenyReason = "ticket_invalid"
	// RedeemDenyExpired 票存在但已逾 TTL
	RedeemDenyExpired RedeemDenyReason = "ticket_expired"
	// RedeemDenyPurpose 票本身有效，但用途或客體與本次兌換的入口不符
	// （拿分享票開監看、拿為 A 碼簽的票加入 B 碼）。**不由兌換方法產生**——
	// 用途比對在 handler 手上（兌換側才知道自己是哪一支路由）。與
	// RedeemDenyInvalid 分成兩個值是因為兩者答的是不同問題：後者是「這張票不存在」
	// （多半是探測），前者是「票是真的、但被拿到別的門口用」（越權嘗試）
	RedeemDenyPurpose RedeemDenyReason = "ticket_purpose_mismatch"
)

// RedeemConnectTokenWithReason 同 RedeemConnectToken，另回傳拒絕原因供審計。
//
// **RedeemConnectToken 即以本方法實作**：兩條路徑共用同一份判定，不可能分化成
// 「回應說無效、審計說過期」。ctx 未被使用（純記憶體 map 操作），沿契約保留。
func (m *ConnectTokenManager) RedeemConnectTokenWithReason(_ context.Context, token string) (ConnectGrant, RedeemDenyReason) {
	m.mu.Lock()
	defer m.mu.Unlock()
	grant, ok := m.grants[token]
	if !ok {
		return ConnectGrant{}, RedeemDenyInvalid
	}
	delete(m.grants, token)
	if time.Now().After(grant.ExpiresAt) {
		return ConnectGrant{}, RedeemDenyExpired
	}
	return grant, RedeemDenyNone
}
