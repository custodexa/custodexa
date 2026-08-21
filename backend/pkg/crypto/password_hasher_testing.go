package crypto

// === 測試專用的雜湊建構（password-hasher-interface 2.2）===
//
// **為什麼需要這個**：產品參數（bcrypt cost=10）每次雜湊約 70ms，
// 測試碼有 39 處自行產生雜湊，全用產品參數會讓測試變得極慢。
// 既有測試因此直接呼叫 `bcrypt.GenerateFromPassword(pw, bcrypt.MinCost)`——
// 那繞過了介面，於是**換演算法時這些測試仍在驗舊演算法的行為**。
//
// 此處提供介面內的等價入口：測試取得的是 `Hasher`／`Verifier`，
// 換演算法時只要 `NewTestPasswordHasher` 換一行，所有使用它的測試自動跟上。
//
// **不放在 _test.go**：跨套件的測試（identity、api、sshproxy…）都要用，
// 而 `_test.go` 的內容不會被其他套件看見。

// NewTestPasswordHasher 測試專用的雜湊實作：**最低成本，只求快**。
//
// SHALL NOT 用於產品路徑——最低成本的雜湊對離線暴力破解幾乎沒有抵抗力。
// 產品路徑一律走 `DefaultPasswordHasher()`；
// `internal/guards/passwordhash` 的守衛確保產品碼不會直接建構演算法實作。
func NewTestPasswordHasher() Hasher {
	return NewBcryptHasher(BcryptMinCost)
}

// NewTestPasswordVerifier 對應的驗證器（判定「是否需要升級」時以測試實作為當前參數）。
func NewTestPasswordVerifier() Verifier {
	return NewPasswordVerifier(NewTestPasswordHasher())
}

// MustHashForTest 以測試參數產生雜湊；失敗即 panic。
//
// 測試碼的固件建構（seed 一個帶密碼的使用者）用它取代
// `bcrypt.GenerateFromPassword(pw, bcrypt.MinCost)`——
// 呼叫端因而不需要 import 任何演算法函式庫，換演算法時也不必逐檔改。
func MustHashForTest(password string) string {
	h, err := NewTestPasswordHasher().Hash([]byte(password))
	if err != nil {
		panic("測試密碼雜湊失敗: " + err.Error())
	}
	return h
}
