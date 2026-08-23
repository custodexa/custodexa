package crypto

import (
	"fmt"
	"testing"
	"time"
)

// === 認證端點的成本量測===
//
// 併發上限不可憑推估設值。本檔量測單次雜湊的實際耗時，
// 供 `MaxInFlight` 的推導有可指認的數字依據。
//
// **量測時的負載口徑必須一併記錄**——本專案有前例：並行跑測試會嚴重扭曲耗時。
// 執行方式：`go test ./pkg/crypto/ -run TestMeasure -v`（單獨跑，不與其他包並行）。

// TestMeasurePasswordHashCost 量測產品參數下單次雜湊與驗證的耗時。
//
// 不是斷言型測試（硬體不同數字必不同），而是**產生決策依據的量測**：
// 以 `-v` 執行後把數字記進 tasks，供上限推導引用。
func TestMeasurePasswordHashCost(t *testing.T) {
	if testing.Short() {
		t.Skip("量測型測試，-short 下略過")
	}

	h := DefaultPasswordHasher()
	const password = "measure-cost-password"

	// 產生一次，作為驗證的輸入
	hash, err := h.Hash([]byte(password))
	if err != nil {
		t.Fatalf("Hash 失敗: %v", err)
	}

	const rounds = 5

	var hashTotal time.Duration
	for i := 0; i < rounds; i++ {
		start := time.Now()
		if _, err := h.Hash([]byte(password)); err != nil {
			t.Fatalf("Hash 失敗: %v", err)
		}
		hashTotal += time.Since(start)
	}

	v := NewPasswordVerifier(h)
	var verifyTotal time.Duration
	for i := 0; i < rounds; i++ {
		start := time.Now()
		if err := v.Verify(hash, []byte(password)); err != nil {
			t.Fatalf("Verify 失敗: %v", err)
		}
		verifyTotal += time.Since(start)
	}

	hashAvg := hashTotal / rounds
	verifyAvg := verifyTotal / rounds

	t.Logf("=== 產品參數 cost=%d，取樣 %d 次 ===", h.Cost(), rounds)
	t.Logf("單次 Hash   平均 %v", hashAvg)
	t.Logf("單次 Verify 平均 %v", verifyAvg)

	// 依端點的實際雜湊次數推導成本
	//   登入：1 次 Verify
	//   改密：2 次 Verify（驗舊 ＋ 比對現行）＋ N 次歷史比對 ＋ 1 次 Hash
	for _, historyCount := range []int{0, 4, 100} {
		changeCost := verifyAvg*time.Duration(2+historyCount) + hashAvg
		ratio := float64(changeCost) / float64(verifyAvg)
		t.Logf("改密（password_history_count=%3d）：約 %v，為登入的 %.1f 倍",
			historyCount, changeCost, ratio)
	}

	fmt.Printf("MEASURE hash_avg=%v verify_avg=%v cost=%d\n", hashAvg, verifyAvg, h.Cost())
}
