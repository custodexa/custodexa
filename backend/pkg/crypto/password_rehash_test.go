package crypto

import (
	"testing"
)

// === 漸進遷移的判定契約===
//
// 本檔釘的是**判定**——
// NeedsRehash 決定「要不要升級」，判錯的兩個方向後果都不小：
//   - 該升級卻回 false → 遷移永遠不發生，介面白抽了
//   - 不該升級卻回 true → 每次登入都重雜湊，徒增成本且製造無謂的寫入
//
// **寫入行為**（真的落到 DB 了嗎、並發改密會不會被蓋掉）在
// `internal/modules/identity/auth_password_rehash_test.go`。
// 註：本檔原有一句註解宣稱該測試已存在，但**當時它並不存在**——
// 那是不實記載，經獨立驗收（2026-08-19）點名後才補上實作。

// TestNeedsRehashMatrix 以矩陣釘住判定，避免日後新增演算法時漏掉某一格。
func TestNeedsRehashMatrix(t *testing.T) {
	low := NewBcryptHasher(BcryptMinCost)
	high := NewBcryptHasher(BcryptMinCost + 2)

	lowHash, err := low.Hash([]byte("pw"))
	if err != nil {
		t.Fatalf("低成本 Hash 失敗: %v", err)
	}
	highHash, err := high.Hash([]byte("pw"))
	if err != nil {
		t.Fatalf("高成本 Hash 失敗: %v", err)
	}

	cases := []struct {
		name    string
		current Hasher
		hash    string
		want    bool
		why     string
	}{
		{"舊參數（成本較低）須升級", high, lowHash, true,
			"這是遷移的主要觸發情境——參數調高後既有帳號應逐步跟上"},
		{"當前參數不須升級", high, highHash, false,
			"若回 true，每次登入都會重雜湊"},
		{"成本高於當前不降級", low, highHash, false,
			"不得把已較強的雜湊降回較弱參數"},
		{"空雜湊不升級", high, "", false,
			"空＝外部化帳號，升級等於為它寫入本地密碼，破壞不變式"},
		{"無法辨識的雜湊不升級", high, "garbage-not-a-hash", false,
			"那是資料問題，不該在登入成功路徑上悄悄覆寫"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := NewPasswordVerifier(c.current).NeedsRehash(c.hash)
			if got != c.want {
				t.Errorf("NeedsRehash = %v, want %v（%s）", got, c.want, c.why)
			}
		})
	}
}

// TestRehashPreservesVerifiability 升級後的雜湊必須仍能驗證同一個密碼。
//
// 這條看似顯然，但它擋的是「升級時把明文與雜湊對錯」這類搬移錯誤——
// 一旦發生，使用者下次登入就會被自己的密碼擋在門外，且無法自行恢復。
func TestRehashPreservesVerifiability(t *testing.T) {
	const password = "user-real-password"

	old := NewBcryptHasher(BcryptMinCost)
	oldHash, err := old.Hash([]byte(password))
	if err != nil {
		t.Fatalf("Hash 失敗: %v", err)
	}

	current := NewBcryptHasher(BcryptMinCost + 2)
	v := NewPasswordVerifier(current)

	// 舊雜湊仍可驗證（否則既有使用者立刻全部登不進來）
	if err := v.Verify(oldHash, []byte(password)); err != nil {
		t.Fatalf("舊雜湊無法驗證: %v", err)
	}
	if !v.NeedsRehash(oldHash) {
		t.Fatal("舊雜湊未被標記為需升級")
	}

	// 模擬登入路徑的升級動作
	newHash, err := current.Hash([]byte(password))
	if err != nil {
		t.Fatalf("重雜湊失敗: %v", err)
	}
	if newHash == oldHash {
		t.Error("重雜湊後與原雜湊相同——升級沒有實際發生")
	}
	if err := v.Verify(newHash, []byte(password)); err != nil {
		t.Errorf("升級後的雜湊無法驗證原密碼: %v——使用者會被自己的密碼擋在門外", err)
	}
	if err := v.Verify(newHash, []byte("wrong")); err == nil {
		t.Error("升級後的雜湊竟接受錯誤密碼")
	}
	if v.NeedsRehash(newHash) {
		t.Error("升級後仍被標記為需升級——會每次登入都重雜湊")
	}
}

// TestNoBatchRehashEntryPoint 本套件 SHALL NOT 提供批次重新雜湊的入口。
//
// 批次重雜湊在密碼學上不可實作（需要明文，而系統沒有明文），
// **留一個空殼入口比沒有更糟**——呼叫端會以為遷移已經處理掉了。
// 此處以「介面不提供該形態的方法」作為機器可見的表達：
// Hasher 只能對單一明文產生雜湊，Verifier 只能驗證，兩者都拿不到批次入口。
func TestNoBatchRehashEntryPoint(t *testing.T) {
	var h Hasher = NewBcryptHasher(BcryptMinCost)
	var v Verifier = NewPasswordVerifier(h)

	// 這兩個型別斷言若有一天成立，表示有人加了批次入口。
	type batchRehasher interface {
		RehashAll() error
	}
	if _, ok := h.(batchRehasher); ok {
		t.Error("Hasher 出現 RehashAll——批次重雜湊在密碼學上做不到，空殼入口會誤導呼叫端")
	}
	if _, ok := v.(batchRehasher); ok {
		t.Error("Verifier 出現 RehashAll——同上")
	}
}
