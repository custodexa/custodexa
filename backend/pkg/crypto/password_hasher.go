package crypto

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// === 密碼雜湊介面（password-hasher-interface）===
//
// 為什麼要有這層：密碼雜湊演算法原以 13 處直接呼叫 bcrypt 散在產品程式碼中，
// 使演算法無法更換；而更換的需求具體且方向互相衝突——場域要求 FIPS 140-3 合規
// （唯一核准的密碼派生函式是 PBKDF2），但抗離線暴力強度是
// Argon2id > bcrypt >> PBKDF2，換 PBKDF2 等於**為合規而降低安全性**。
// 故未來很可能需要兩者並存（依部署選擇），而非單向替換。
//
// **本檔不做演算法選擇**：bcrypt 仍是唯一實作，介面與遷移機制先就位。

// MaxInputUnlimited 表示該實作對輸入長度無上限（Argon2id／PBKDF2 屬此類）。
//
// 取負值哨兵而非 0 或 math.MaxInt：0 會與「不接受任何輸入」混淆，
// 而呼叫端做 `len(pw) > limit` 比較時，負值天然恆為 false，不需要特判。
const MaxInputUnlimited = -1

// bcrypt 的成本邊界。**不依賴標準庫做參數檢查**——實測 Go 1.26.6 的
// `crypto/pbkdf2` 參數檢查整段包在 `fips140only.Enforced()` 內，
// 而本產品因 TOTP 永久保留 SHA-1（該模式下 hmac 層直接 panic）永遠進不了
// `GODEBUG=fips140=only`，故標準庫在我方組態下是**零驗證**。此處自建守衛。
const (
	BcryptMinCost     = bcrypt.MinCost
	BcryptMaxCost     = bcrypt.MaxCost
	BcryptDefaultCost = bcrypt.DefaultCost

	// bcryptMaxInputBytes bcrypt 的輸入上限。**超出必須明確拒絕而非靜默截斷**：
	// 截斷會使兩個前 72 bytes 相同的密碼互相可登入。
	bcryptMaxInputBytes = 72

	// AlgorithmBcrypt bcrypt 的演算法識別字，取自雜湊字串前綴。
	AlgorithmBcrypt = "bcrypt"
)

// ErrPasswordMismatch 密碼與雜湊不符。**與「雜湊格式無法辨識」是不同的錯誤**：
// 前者記失敗嘗試、後者是資料問題，兩者的處置與告警層級不同。
var ErrPasswordMismatch = errors.New("密碼不符")

// ErrUnknownAlgorithm 雜湊字串的演算法無法辨識。
var ErrUnknownAlgorithm = errors.New("無法辨識的密碼雜湊演算法")

// Hasher 密碼雜湊的**寫入面**。
//
// password 收 `[]byte` 而非 string：既有的 zeroize 邊界要求可覆寫的緩衝，
// string 不可變故無法抹除。
type Hasher interface {
	// ID 演算法識別字，與 AlgorithmID 對雜湊字串前綴的判別結果一致。
	ID() string
	// Hash 產生雜湊。輸入超過 MaxInputBytes 時 MUST 回錯，不得靜默截斷。
	Hash(password []byte) (string, error)
	// MaxInputBytes 輸入長度上限；無上限回 MaxInputUnlimited。
	MaxInputBytes() int
	// Cost 相對成本，供認證端點的併發上限推導（取代寫死的常數）。
	Cost() int
}

// Verifier 密碼雜湊的**讀取面**。
//
// Verify 只回 `error` 而不回 `(bool, error)`：現存 7 處驗證點全部是
// `if err := …; err != nil` 的形狀，維持同一形狀使「檢查 bool 卻忽略 err」
// 這種寫法根本寫不出來。
type Verifier interface {
	// Verify 驗證密碼。
	//   - 相符回 nil
	//   - 不符回 ErrPasswordMismatch（可用 errors.Is 比對）
	//   - hash 為空回錯（契約，見下）
	//   - 演算法無法辨識回 ErrUnknownAlgorithm
	//
	// **空 hash 恆為失敗是契約而非實作副作用**：不變式「密碼為空者必為外部化帳號」
	// （identity/oidc_invariant_matrix_test.go）目前靠 bcrypt 恰好對空 hash 回錯而成立。
	// 換一個實作若對空 hash 回 nil，該不變式會**靜默失效**，
	// 使 LDAP／OIDC 影子帳號可用空密碼從本地路徑登入。
	Verify(hash string, password []byte) error
	// NeedsRehash 回報該雜湊是否應在登入成功後升級為當前演算法／參數。
	// 空 hash 回 false——那是外部化帳號，不該被寫入本地密碼。
	NeedsRehash(hash string) bool
}

// AlgorithmID 由雜湊字串的開頭 token 判別演算法。
//
// **絕不新增演算法欄位**：`external_credential` 已為欄位漂移付過學費——
// 欄位與實際內容可能不同步，而雜湊字串本身是自描述的單一事實源。
func AlgorithmID(hash string) string {
	switch {
	case strings.HasPrefix(hash, "$2a$"),
		strings.HasPrefix(hash, "$2b$"),
		strings.HasPrefix(hash, "$2y$"):
		return AlgorithmBcrypt
	default:
		return ""
	}
}

// SupportedAlgorithms 目前可驗證的全部演算法。
//
// **誠實邊界（獨立驗收 2026-08-19 訂正）**：本函式目前在 `pkg/crypto` 之外
// **零產品消費者**——legacy 掃描（`database/seed.go`）走的是 `Verify` 的前綴分派，
// 那條路徑本身就自動涵蓋所有已實作的演算法，不需要查這張清單。
// 故本函式現階段的作用是**登記處與文件**，不是掃描的實際依據。
// 對應的守衛 `TestVerifierRecognisesAllSupportedAlgorithms` 也只驗單向
// （當前實作在清單內），**抓不到「新增了實作卻忘了登記」**——
// 要抓那個方向需要反向枚舉，目前只有一個實作故未做。
func SupportedAlgorithms() []string {
	return []string{AlgorithmBcrypt}
}

// BcryptHasher bcrypt 實作。值不可變，參數在建構子驗證。
type BcryptHasher struct {
	cost int
}

// NewBcryptHasherChecked 建立 bcrypt 實作，成本不合法即回錯。
//
// **參數守衛置於建構子**：不合法參數 MUST 使實作無法被建構，
// 接既有 `config.Validate*` 的 fail-close 模板——讓錯誤在啟動時炸掉，
// 而不是在某次登入時才顯現。
func NewBcryptHasherChecked(cost int) (*BcryptHasher, error) {
	if cost < BcryptMinCost || cost > BcryptMaxCost {
		return nil, fmt.Errorf("bcrypt cost %d 超出合法範圍 [%d, %d]",
			cost, BcryptMinCost, BcryptMaxCost)
	}
	return &BcryptHasher{cost: cost}, nil
}

// NewBcryptHasher 同上，但成本不合法時 panic。
//
// 僅供**編譯期已知為合法**的呼叫點使用（測試、以常數建構的產線初始化）。
// 執行期取得的成本一律走 NewBcryptHasherChecked。
func NewBcryptHasher(cost int) *BcryptHasher {
	h, err := NewBcryptHasherChecked(cost)
	if err != nil {
		panic(err)
	}
	return h
}

// ID 實作 Hasher。
func (h *BcryptHasher) ID() string { return AlgorithmBcrypt }

// MaxInputBytes 實作 Hasher。bcrypt 有 72 位元組的硬上限。
func (h *BcryptHasher) MaxInputBytes() int { return bcryptMaxInputBytes }

// Cost 實作 Hasher。
func (h *BcryptHasher) Cost() int { return h.cost }

// Hash 實作 Hasher。超過上限明確回錯，不靜默截斷。
func (h *BcryptHasher) Hash(password []byte) (string, error) {
	if len(password) > bcryptMaxInputBytes {
		return "", fmt.Errorf("密碼長度 %d 位元組超過 bcrypt 上限 %d",
			len(password), bcryptMaxInputBytes)
	}
	out, err := bcrypt.GenerateFromPassword(password, h.cost)
	if err != nil {
		return "", fmt.Errorf("密碼雜湊失敗: %w", err)
	}
	return string(out), nil
}

// defaultHasher 產線的預設寫入實作。
//
// **以套件級單例提供而非各處自建**：各處自建會讓「當前演算法／參數」散成多份，
// NeedsRehash 的判定就會依呼叫端而異——遷移於是變成不確定行為。
var defaultHasher = NewBcryptHasher(BcryptDefaultCost)

// DefaultPasswordHasher 產線的密碼雜湊寫入面（單一事實源）。
func DefaultPasswordHasher() Hasher { return defaultHasher }

// DefaultPasswordVerifier 產線的密碼雜湊讀取面（單一事實源）。
func DefaultPasswordVerifier() Verifier { return NewPasswordVerifier(defaultHasher) }

// passwordVerifier 依雜湊字串前綴分派到對應演算法。
//
// 本 change 只有 bcrypt 一個實作；日後新增時在 Verify 的 switch 增一個分支即可，
// **登入路徑不需要再動**——那正是抽這層介面的目的。
type passwordVerifier struct {
	current Hasher
}

// NewPasswordVerifier 建立驗證器。current 為目前的寫入實作，用於 NeedsRehash 判定。
func NewPasswordVerifier(current Hasher) Verifier {
	return &passwordVerifier{current: current}
}

// Verify 實作 Verifier。
func (v *passwordVerifier) Verify(hash string, password []byte) error {
	// 空 hash 恆為失敗（契約，見 Verifier 的說明）。
	// 放在最前面且不分派：不論哪個演算法，空字串都不是有效雜湊。
	if hash == "" {
		return fmt.Errorf("%w: 雜湊為空（此帳號無本地密碼）", ErrUnknownAlgorithm)
	}

	switch AlgorithmID(hash) {
	case AlgorithmBcrypt:
		if err := bcrypt.CompareHashAndPassword([]byte(hash), password); err != nil {
			if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
				return ErrPasswordMismatch
			}
			// 雜湊本身壞掉（長度不符、cost 無效…）：是資料問題不是密碼錯，
			// 不可回 ErrPasswordMismatch，否則會被當成使用者打錯密碼而掩蓋。
			return fmt.Errorf("%w: %v", ErrUnknownAlgorithm, err)
		}
		return nil
	default:
		return fmt.Errorf("%w: 前綴無法辨識", ErrUnknownAlgorithm)
	}
}

// NeedsRehash 實作 Verifier。
func (v *passwordVerifier) NeedsRehash(hash string) bool {
	// 空 hash＝外部化帳號，不該被寫入本地密碼。
	if hash == "" {
		return false
	}
	// 演算法不同於當前寫入實作 → 需升級。
	alg := AlgorithmID(hash)
	if alg == "" || alg != v.current.ID() {
		// 無法辨識的雜湊不觸發重雜湊：那是資料問題，
		// 交由 Verify 回錯處理，不在登入成功路徑上悄悄覆寫。
		return alg != "" && alg != v.current.ID()
	}
	// 同演算法但參數較舊 → 需升級。
	if alg == AlgorithmBcrypt {
		cost, err := bcrypt.Cost([]byte(hash))
		if err != nil {
			return false
		}
		return cost < v.current.Cost()
	}
	return false
}
