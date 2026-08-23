package crypto

import (
	"errors"
	"strings"
	"testing"
)

// === 密碼雜湊介面===
//
// 本 change **不選演算法**：完成後 bcrypt 仍是唯一實作，介面與遷移機制就位。
// 抽介面的動機是「演算法無法更換」這個事實本身——場域要求 FIPS 140-3 合規
// （唯一核准的密碼派生函式是 PBKDF2），而抗離線暴力強度 Argon2id > bcrypt >> PBKDF2，
// 故未來很可能需要兩者並存而非單向替換。

// TestBcryptHasherRoundTrip 產生的雜湊必須能被驗證器接受，錯誤密碼必須被拒。
func TestBcryptHasherRoundTrip(t *testing.T) {
	h := NewBcryptHasher(BcryptMinCost)

	hash, err := h.Hash([]byte("correct-horse-battery"))
	if err != nil {
		t.Fatalf("Hash 失敗: %v", err)
	}
	if hash == "" {
		t.Fatal("Hash 回傳空字串")
	}

	v := NewPasswordVerifier(h)
	if err := v.Verify(hash, []byte("correct-horse-battery")); err != nil {
		t.Errorf("正確密碼被拒: %v", err)
	}
	if err := v.Verify(hash, []byte("wrong-password")); err == nil {
		t.Error("錯誤密碼竟通過驗證")
	}
}

// TestVerifyEmptyHashAlwaysFails 空字串雜湊必須恆為驗證失敗。
//
// **這條是契約，不是實作副作用。** 現行不變式「密碼為空者必為外部化帳號」
// （`identity/oidc_invariant_matrix_test.go`）目前靠 bcrypt 的副作用成立——
// `CompareHashAndPassword("", pw)` 恰好回錯。換一個實作若對空 hash 回 nil，
// 該不變式會**靜默失效**，使外部化帳號（LDAP／OIDC 影子帳號）可用空密碼本地登入。
// 故此處把它釘成介面契約並獨立測試。
func TestVerifyEmptyHashAlwaysFails(t *testing.T) {
	v := NewPasswordVerifier(NewBcryptHasher(BcryptMinCost))

	cases := []struct {
		name     string
		password []byte
	}{
		{"空密碼", []byte("")},
		{"nil 密碼", nil},
		{"任意密碼", []byte("anything")},
		{"看似雜湊的密碼", []byte("$2a$10$abcdefghijklmnopqrstuv")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := v.Verify("", c.password); err == nil {
				t.Errorf("空雜湊竟通過驗證（密碼 = %q）——外部化帳號可被本地登入", c.password)
			}
		})
	}
}

// TestVerifyUnknownAlgorithmFailsClosed 無法辨識的雜湊格式必須回錯，不得 panic、不得通過。
func TestVerifyUnknownAlgorithmFailsClosed(t *testing.T) {
	v := NewPasswordVerifier(NewBcryptHasher(BcryptMinCost))

	cases := []string{
		"$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$hash", // 尚未實作的演算法
		"$pbkdf2-sha256$29000$salt$hash",                  // 同上
		"plaintext-not-a-hash",
		"$",
		"$2a$",             // 前綴對但內容殘缺
		"not$2a$anywhere",  // token 不在開頭
	}
	for _, hash := range cases {
		t.Run(hash, func(t *testing.T) {
			err := v.Verify(hash, []byte("whatever"))
			if err == nil {
				t.Errorf("無法辨識的雜湊 %q 竟通過驗證", hash)
			}
		})
	}
}

// TestHasherIDFromHashPrefix 演算法判別**只看雜湊字串開頭的 token**。
//
// 絕不新增演算法欄位——`external_credential` 已為欄位漂移付過學費：
// 欄位與實際內容可能不同步，而雜湊字串本身是自描述的單一事實源。
func TestHasherIDFromHashPrefix(t *testing.T) {
	h := NewBcryptHasher(BcryptMinCost)
	if h.ID() == "" {
		t.Fatal("Hasher.ID() 為空")
	}

	hash, err := h.Hash([]byte("pw"))
	if err != nil {
		t.Fatalf("Hash 失敗: %v", err)
	}
	// bcrypt 的雜湊字串以 $2a$／$2b$／$2y$ 起頭
	if !strings.HasPrefix(hash, "$2") {
		t.Errorf("bcrypt 雜湊前綴異常: %q", hash)
	}
	if got := AlgorithmID(hash); got != h.ID() {
		t.Errorf("AlgorithmID(%q) = %q, want %q", hash, got, h.ID())
	}
}

// TestBcryptMaxInputBytes bcrypt 的 72 位元組上限必須由介面回報，不得由呼叫端寫死。
//
// 政策層與 i18n 文案原本字面寫死「約 72 個英數字元」，換演算法後那個數字就錯了。
func TestBcryptMaxInputBytes(t *testing.T) {
	h := NewBcryptHasher(BcryptMinCost)
	if got := h.MaxInputBytes(); got != 72 {
		t.Errorf("bcrypt MaxInputBytes() = %d, want 72", got)
	}

	// 超過上限的輸入必須被明確拒絕，而不是靜默截斷。
	// 靜默截斷的後果：兩個前 72 bytes 相同的密碼會互相可登入。
	long := []byte(strings.Repeat("a", 73))
	if _, err := h.Hash(long); err == nil {
		t.Error("超過 72 bytes 的密碼竟被接受——靜默截斷會使不同密碼互相可登入")
	}
}

// TestMaxInputBytesCanExpressUnlimited 介面須能表達「無上限」（未來的 Argon2id／PBKDF2）。
func TestMaxInputBytesCanExpressUnlimited(t *testing.T) {
	if MaxInputUnlimited >= 0 {
		t.Errorf("MaxInputUnlimited = %d，應為負值哨兵以與真實上限區分", MaxInputUnlimited)
	}
}

// TestNewBcryptHasherRejectsInvalidCost 參數守衛置於建構子：不合法參數 MUST 使實作無法建構。
//
// **不可依賴標準庫的檢查**——實測 Go 1.26.6 的 `crypto/pbkdf2` 參數檢查整段包在
// `fips140only.Enforced()` 內，而本產品因 TOTP 保留 SHA-1 永遠進不了該模式，
// 故標準庫在我方組態下是**零驗證**。此處自建。
func TestNewBcryptHasherRejectsInvalidCost(t *testing.T) {
	cases := []struct {
		name string
		cost int
	}{
		{"低於 bcrypt 下限", 3},
		{"零值", 0},
		{"負值", -1},
		{"高於 bcrypt 上限", 32},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, err := NewBcryptHasherChecked(c.cost)
			if err == nil {
				t.Errorf("cost=%d 竟建構成功（Hasher=%v）——參數守衛失效", c.cost, h)
			}
			if h != nil {
				t.Errorf("cost=%d 建構失敗但回傳非 nil 的 Hasher，呼叫端可能誤用", c.cost)
			}
		})
	}
}

// TestNeedsRehashDetectsCostChange 以較舊參數產生的雜湊須被標記為應升級。
//
// 這是漸進遷移的觸發點：登入成功時（唯一明文在手的時機）順手升級。
// 本 change 只有 bcrypt 一個實作，故以不同 cost 模擬「舊參數」。
func TestNeedsRehashDetectsCostChange(t *testing.T) {
	old := NewBcryptHasher(BcryptMinCost)
	oldHash, err := old.Hash([]byte("pw"))
	if err != nil {
		t.Fatalf("Hash 失敗: %v", err)
	}

	// 目前實作的成本高於產生該雜湊時
	current := NewBcryptHasher(BcryptMinCost + 1)
	v := NewPasswordVerifier(current)

	if !v.NeedsRehash(oldHash) {
		t.Error("較低 cost 的雜湊未被標記為需升級——漸進遷移不會發生")
	}

	currentHash, err := current.Hash([]byte("pw"))
	if err != nil {
		t.Fatalf("Hash 失敗: %v", err)
	}
	if v.NeedsRehash(currentHash) {
		t.Error("當前參數的雜湊被誤判為需升級——每次登入都會重雜湊")
	}
}

// TestNeedsRehashOnEmptyHashIsFalse 空雜湊（外部化帳號）不得被視為需要升級。
//
// 若回 true，登入路徑會嘗試為一個**本來就不該有本地密碼**的帳號寫入雜湊，
// 破壞「密碼為空者必為外部化帳號」的不變式。
func TestNeedsRehashOnEmptyHashIsFalse(t *testing.T) {
	v := NewPasswordVerifier(NewBcryptHasher(BcryptMinCost))
	if v.NeedsRehash("") {
		t.Error("空雜湊被判為需升級——會為外部化帳號寫入本地密碼")
	}
}

// TestVerifierRecognisesAllSupportedAlgorithms legacy 掃描必須涵蓋全部支援的演算法。
//
// 理由：僅比對當前演算法會讓舊雜湊的帳號逃過 `admin123` 掃描，
// 而那正是**最可能中招**的帳號——久未登入故未遷移。
// 本 change 只有 bcrypt，但 `SupportedAlgorithms` 必須存在且被掃描端使用，
// 使日後新增實作時掃描自動涵蓋，而不是漏掉。
func TestVerifierRecognisesAllSupportedAlgorithms(t *testing.T) {
	algs := SupportedAlgorithms()
	if len(algs) == 0 {
		t.Fatal("SupportedAlgorithms() 為空——legacy 掃描將無所依據")
	}
	h := NewBcryptHasher(BcryptMinCost)
	found := false
	for _, a := range algs {
		if a == h.ID() {
			found = true
		}
	}
	if !found {
		t.Errorf("SupportedAlgorithms() = %v，未含當前實作 %q", algs, h.ID())
	}
}

// TestVerifyErrorIsComparable 驗證失敗的錯誤須可被呼叫端辨識（區分「密碼錯」與「雜湊壞」）。
//
// 登入路徑要能分辨：密碼不符 → 記失敗嘗試；雜湊無法辨識 → 是資料問題，
// 兩者的處置與告警層級不同。
func TestVerifyErrorIsComparable(t *testing.T) {
	v := NewPasswordVerifier(NewBcryptHasher(BcryptMinCost))
	hash, err := NewBcryptHasher(BcryptMinCost).Hash([]byte("pw"))
	if err != nil {
		t.Fatalf("Hash 失敗: %v", err)
	}

	if err := v.Verify(hash, []byte("wrong")); !errors.Is(err, ErrPasswordMismatch) {
		t.Errorf("密碼不符的錯誤 = %v, want 可用 errors.Is 比對 ErrPasswordMismatch", err)
	}
	if err := v.Verify("garbage", []byte("pw")); errors.Is(err, ErrPasswordMismatch) {
		t.Error("雜湊格式錯誤被誤報為密碼不符——資料問題會被當成使用者打錯密碼")
	}
}
