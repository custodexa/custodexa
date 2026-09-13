package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// 解封流程的授權脈絡（grant）。
//
// # 它是什麼、不是什麼
//
// grant 證明「送出這個請求的人，在不久之前通過了管理員帳號與密碼的驗證」。
// 它**不是**登入工作階段：不帶角色、不可用於任何業務端點、不進資料庫、不跨行程。
// 解封成功也不會把它升級成工作階段——操作者仍須經一般登入取得業務權限。
//
// # 為什麼在行程記憶體而不是 JWT 或資料庫
//
//   - JWT：簽出去就收不回來，而 grant 必須能在拓撲變動或權限變動時立刻失效。
//   - 資料庫：封存狀態下寫入面受限，且 grant 的壽命以分鐘計，落庫只會留下一張
//     需要清理的短命表。
//
// 行程重啟即全部失效，這是所欲的：重啟後系統回到已封存，本來就要重新驗證。
//
// # 儲存的是摘要而不是權杖本身
//
// 表內存 SHA-256 摘要，使「讀到這張表」不等於「拿到可用的 grant」。

// SealGrantTTL 解封授權脈絡的預設效期。
//
// 取 10 分鐘：夠一位管理者讀完拓撲、與部署紀錄核對、再取出憑證貼上；
// 又短到即使脈絡外洩也只有一個窄窗口。效期屆滿即要求重驗，不提供續期
// ——續期會讓「不久之前通過驗證」這個唯一的語義無限延伸。
const SealGrantTTL = 10 * time.Minute

// ErrSealGrantInvalid 脈絡不存在、已過期或已被撤銷。
var ErrSealGrantInvalid = errors.New("解封授權脈絡無效")

// SealGrant 一個已成立的授權脈絡。
type SealGrant struct {
	// UserID／Username 通過驗證的管理員（供審計；Username 非秘密）。
	UserID   uint
	Username string
	// ExpiresAt 效期屆滿時點。
	ExpiresAt time.Time
}

// SealGrantRevalidator 於**每次使用**重新確認該管理員仍具解封資格。
//
// **為什麼不能只靠簽發當下的判定**：脈絡的效期以分鐘計，而在那段窗口內帳號可能
// 被停用、被降權、被鎖定，或其憑證世代被推進（管理者主動使既簽憑證失效）。
// 規格明文要求「權限變動 SHALL 使該脈絡失效並要求重驗」，那句話只有在**取用時**
// 重新判定才成立。
//
// 以 func 注入而非介面：本套件只需要這一件事，宣告介面會把 identity 的型別
// 拉進 internal/api。實作為 identity.VerifySealAdminStillAuthorized。
type SealGrantRevalidator func(userID uint) error

// SealGrantStore 行程記憶體內的脈絡表。
type SealGrantStore struct {
	mu         sync.Mutex
	grants     map[string]SealGrant
	ttl        time.Duration
	now        func() time.Time
	revalidate SealGrantRevalidator
}

// SetRevalidator 注入「仍具資格嗎」的判定（未注入時不做重新判定）。
//
// **未注入不等於放行**：正式路徑一律注入（組裝根），未注入只出現在單元測試，
// 而那些測試各自守的是脈絡表本身的生命週期。
func (s *SealGrantStore) SetRevalidator(fn SealGrantRevalidator) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revalidate = fn
}

// NewSealGrantStore 建一個脈絡表；ttl <= 0 時取預設。
func NewSealGrantStore(ttl time.Duration) *SealGrantStore {
	if ttl <= 0 {
		ttl = SealGrantTTL
	}
	return &SealGrantStore{grants: map[string]SealGrant{}, ttl: ttl, now: time.Now}
}

// Issue 簽發一個脈絡，回傳權杖本體與屆期時點。
//
// 權杖只在此回傳一次；表內只留其摘要。
func (s *SealGrantStore) Issue(userID uint, username string) (string, time.Time, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		// CSPRNG 失敗即拒絕簽發：以任何可預測的值頂替等於把驗證這一步作廢。
		return "", time.Time{}, err
	}
	token := hex.EncodeToString(raw)
	expires := s.now().Add(s.ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	s.grants[grantKey(token)] = SealGrant{UserID: userID, Username: username, ExpiresAt: expires}
	return token, expires, nil
}

// Verify 檢查權杖並回傳其脈絡。過期者於此順手清除。
func (s *SealGrantStore) Verify(token string) (SealGrant, error) {
	if token == "" {
		return SealGrant{}, ErrSealGrantInvalid
	}
	key := grantKey(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[key]
	if !ok {
		return SealGrant{}, ErrSealGrantInvalid
	}
	if !s.now().Before(g.ExpiresAt) {
		delete(s.grants, key)
		return SealGrant{}, ErrSealGrantInvalid
	}
	// 權限變動即失效：停用、降權、鎖定、憑證世代被推進，都在此被擋下，
	// 且**順手把脈絡刪掉**——留著它只會讓下一次請求再判一次同樣的事。
	if s.revalidate != nil {
		if err := s.revalidate(g.UserID); err != nil {
			delete(s.grants, key)
			return SealGrant{}, ErrSealGrantInvalid
		}
	}
	return g, nil
}

// Revoke 撤銷一個脈絡（解封成功、或拓撲變動後要求重驗時呼叫）。
func (s *SealGrantStore) Revoke(token string) {
	if token == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.grants, grantKey(token))
}

// RevokeAll 撤銷全部脈絡。
//
// 解封成功後呼叫：新的世代已成立，任何在舊狀態下取得的核對結果都不該再能送出。
func (s *SealGrantStore) RevokeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.grants = map[string]SealGrant{}
}

// pruneLocked 清掉已過期的脈絡，界定表的大小。
func (s *SealGrantStore) pruneLocked() {
	now := s.now()
	for k, g := range s.grants {
		if !now.Before(g.ExpiresAt) {
			delete(s.grants, k)
		}
	}
}

// grantKey 權杖的儲存鍵（摘要，非權杖本身）。
func grantKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
