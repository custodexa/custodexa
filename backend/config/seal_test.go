package config

import (
	"math"
	"testing"
	"time"
)

// 解封端點速率參數的 fail-close 驗收（kek-provider-modularization D6.4）。
//
// 這些旋鈕唯一的作用是限制未認證端點的嘗試速率。零、負值、max < base 與溢位
// 的寫法效果都是**把保護關掉**，且都不會有任何執行期症狀——沒有守衛時，
// 一個打錯的環境變數就等於悄悄停用退避／冷卻。

// validSealConfig 是通過驗證的基準組態（各案例只改一個欄位）。
func validSealConfig() SealConfig {
	return SealConfig{
		BackoffBase:       2 * time.Second,
		BackoffMax:        300 * time.Second,
		CooldownThreshold: 20,
		Cooldown:          60 * time.Second,
		CooldownMax:       900 * time.Second,
	}
}

func TestSealConfigValidateAcceptsDefaults(t *testing.T) {
	if err := validSealConfig().Validate(); err != nil {
		t.Fatalf("預設組態竟被拒: %v", err)
	}
	// LoadSeal 的預設值必須自身合法——否則未設任何 env 的部署會拒絕啟動。
	t.Setenv("SEAL_UNSEAL_BACKOFF_BASE_SECONDS", "")
	if err := LoadSeal().Validate(); err != nil {
		t.Fatalf("LoadSeal 的內建預設值不合法: %v", err)
	}
}

// 「冷卻門檻為負」不再列於下方案例：門檻已是 uint32，負值於欄位層無法表達。
// 該案例移到 TestSealConfigLoadRejectsOutOfRangeThreshold 的 env 層——負值只可能從 env 進來。
func TestSealConfigValidateRejectsDisablingValues(t *testing.T) {
	cases := map[string]func(*SealConfig){
		"退避基準為零":    func(c *SealConfig) { c.BackoffBase = 0 },
		"退避基準為負":    func(c *SealConfig) { c.BackoffBase = -time.Second },
		"退避封頂為零":    func(c *SealConfig) { c.BackoffMax = 0 },
		"退避封頂低於基準":  func(c *SealConfig) { c.BackoffMax = time.Second },
		"冷卻為零":      func(c *SealConfig) { c.Cooldown = 0 },
		"冷卻封頂低於基準":  func(c *SealConfig) { c.CooldownMax = time.Second },
		"冷卻門檻為零":    func(c *SealConfig) { c.CooldownThreshold = 0 },
		"冷卻門檻大到不可能": func(c *SealConfig) { c.CooldownThreshold = math.MaxUint32 },
		"退避基準超過上限":  func(c *SealConfig) { c.BackoffBase = 48 * time.Hour },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := validSealConfig()
			mutate(&c)
			if err := c.Validate(); err == nil {
				t.Fatalf("%s 竟通過驗證——保護可被一個打錯的環境變數關掉", name)
			}
		})
	}
}

// TestSealConfigLoadRejectsOutOfRangeSeconds env 的極端值不得被靜默夾取或溢位成合法值。
//
// `time.Duration(secs) * time.Second` 在 secs 超過約 9.2e9 時回繞：
// 「把冷卻設成天文數字」與「把冷卻關掉」因此在型別上不可分辨。故秒數在轉為
// Duration **之前**就要受界，且越界一律走 Validate 的 fail-close，不夾取。
func TestSealConfigLoadRejectsOutOfRangeSeconds(t *testing.T) {
	for _, v := range []string{"0", "-5", "999999999999999999"} {
		t.Run("SEAL_UNSEAL_COOLDOWN_SECONDS="+v, func(t *testing.T) {
			t.Setenv("SEAL_UNSEAL_COOLDOWN_SECONDS", v)
			c := LoadSeal()
			if err := c.Validate(); err == nil {
				t.Fatalf("越界秒數 %q 轉出的 Cooldown=%v 竟通過驗證", v, c.Cooldown)
			}
		})
	}
}

// TestSealConfigLoadRejectsOutOfRangeThreshold 冷卻門檻的越界 env 一律 fail-close。
//
// 門檻欄位已是 uint32，負值與超出 32 位元的寫法在讀取期就無法成為一個值——
// 但那不表示它們可以被靜默替換成內建預設：一個打錯的門檻若看起來生效，
// 部署方會以為自己調過全域冷卻，而實際跑的是別的數字。故此類 env 走與
// 「顯式寫零」相同的 fail-close 路徑。
func TestSealConfigLoadRejectsOutOfRangeThreshold(t *testing.T) {
	for _, v := range []string{"0", "-1", "abc", "4294967296", "1048577"} {
		t.Run("SEAL_UNSEAL_COOLDOWN_THRESHOLD="+v, func(t *testing.T) {
			t.Setenv("SEAL_UNSEAL_COOLDOWN_THRESHOLD", v)
			c := LoadSeal()
			if err := c.Validate(); err == nil {
				t.Fatalf("越界門檻 %q 轉出的 CooldownThreshold=%d 竟通過驗證", v, c.CooldownThreshold)
			}
		})
	}
}
