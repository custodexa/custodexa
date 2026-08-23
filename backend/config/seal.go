package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// SealConfig B 模式解封端點的部署組態。
//
// **本組態不含任何金鑰材料**：B 模式的 KEK 只由解封 API 進入記憶體，
// 故此處一律是速率、來源與監聽面的旋鈕，SHALL NOT 新增任何承載材料的鍵。
// journal 落點亦不在此——它沿用 AUDIT_LOG_PATH 所在目錄、不新增 env 鍵。
type SealConfig struct {
	// BackoffBase per-source 第一次失敗後的退避基準
	BackoffBase time.Duration
	// BackoffMax per-source 退避封頂：退避的成長 SHALL 有明確上限，
	// 使「等待即可再試」在任何攻擊強度下都成立
	BackoffMax time.Duration
	// CooldownThreshold 觸發全域冷卻的連續材料失敗次數（SHALL 明顯高於 per-source）。
	//
	// **型別與限速器同為 uint32**：非負由型別自證，接線處因此不需要任何縮窄轉換。
	// 縮窄轉換是這個旋鈕唯一的溢位入口——一個負的或超出 32 位元的值轉過去會成為
	// 極大門檻，而「門檻大到永遠觸發不到」與「把全域冷卻關掉」在執行期無從分辨。
	CooldownThreshold uint32
	// Cooldown 全域冷卻基準時長
	Cooldown time.Duration
	// CooldownMax 全域冷卻封頂
	CooldownMax time.Duration

	// TrustedProxies 可信代理清單（IP 或 CIDR）。
	// **未設定時 per-IP 退避 SHALL 保守降級為全域退避**：無可信代理鏈
	// 約定時，限速鍵可被轉送標頭污染而誤歸戶或繞過，寧可影響可用性也不提供
	// 可繞過的假防線。
	TrustedProxies []string

	// UnsealBindAddr 解封端點的獨立監聽位址（空＝與主服務共用監聽）。
	UnsealBindAddr string
	// UnsealAllowedCIDRs 解封端點允許的來源網段（空＝不限制）。
	UnsealAllowedCIDRs []string
}

// 退避／冷卻參數的合法值域。
//
// 上限存在的理由不是「這麼久沒意義」，而是**溢位**：env 是任意整數，
// `time.Duration(secs) * time.Second` 在 secs 超過 ~9.2e9 時會回繞為負值或
// 一個看似合理的小正值，於是「把冷卻設成天文數字」與「把冷卻關掉」
// 在型別上不可分辨。故秒數在轉為 Duration **之前**就先受界。
const (
	sealParamMinSeconds = 1
	sealParamMaxSeconds = 24 * 60 * 60
	// sealCooldownThresholdMax 冷卻門檻上限。門檻的非負性已由 uint32 型別保證，
	// 故上限擋的是另一件事：一個大到永遠觸發不到的門檻與寫零同效——都是把全域
	// 冷卻關掉，且都沒有執行期症狀。故此鍵須受界而非只擋零。
	sealCooldownThresholdMax = 1 << 20
)

// sealInvalidDuration 是「env 值不在合法秒數值域」的哨兵。
//
// **不靜默夾取**：夾取會讓打錯的參數看起來生效，而這些參數的作用正是限制
// 攻擊者的嘗試速率——一個看似生效實則被改寫的防護，比沒有防護更危險。
const sealInvalidDuration = time.Duration(-1)

// sealInvalidThreshold 是「env 值無法解析為合法門檻」的哨兵。
//
// 取零是因為零必然落在合法值域之外：於是「打錯的門檻」與「顯式寫零」走同一條
// fail-close 路徑。理由同 sealInvalidDuration——退回內建預設會讓部署方以為自己
// 調過這個旋鈕，而它的作用正是限制未認證端點的嘗試速率。
const sealInvalidThreshold uint32 = 0

// LoadSeal 讀取封印端點組態。
//
// 全部鍵皆有安全預設，未設定即為「不限制來源、共用監聽、內建退避參數」——
// 產品必須提供這些控制（含網段繫結），是否啟用由部署方決定。
//
// 本函式只負責讀取與轉換，**不 fail-close**：合法性由 Validate 於啟動期集中
// 判定（見 runStage1），使「組態不合法」只有一個出口與一種處置。
func LoadSeal() SealConfig {
	return SealConfig{
		BackoffBase:        sealDurationFromEnv("SEAL_UNSEAL_BACKOFF_BASE_SECONDS", 2),
		BackoffMax:         sealDurationFromEnv("SEAL_UNSEAL_BACKOFF_MAX_SECONDS", 300),
		CooldownThreshold:  sealThresholdFromEnv("SEAL_UNSEAL_COOLDOWN_THRESHOLD", 20),
		Cooldown:           sealDurationFromEnv("SEAL_UNSEAL_COOLDOWN_SECONDS", 60),
		CooldownMax:        sealDurationFromEnv("SEAL_UNSEAL_COOLDOWN_MAX_SECONDS", 900),
		TrustedProxies:     parseCSV(getEnv("TRUSTED_PROXIES", "")),
		UnsealBindAddr:     getEnv("SEAL_UNSEAL_BIND_ADDR", ""),
		UnsealAllowedCIDRs: parseCSV(getEnv("SEAL_UNSEAL_ALLOWED_CIDRS", "")),
	}
}

// sealDurationFromEnv 讀秒數並轉為 Duration；超出值域者回哨兵值交由 Validate 處置。
func sealDurationFromEnv(key string, def int) time.Duration {
	secs := getEnvInt(key, def)
	if secs < sealParamMinSeconds || secs > sealParamMaxSeconds {
		return sealInvalidDuration
	}
	return time.Duration(secs) * time.Second
}

// sealThresholdFromEnv 讀冷卻門檻；無法解析為 32 位元非負整數者回哨兵值交由 Validate 處置。
//
// **直接以 ParseUint(_, 10, 32) 受界，而非 Atoi 後轉型**：Atoi 產出的是架構相依的
// int，要落到限速器的 uint32 必經一次縮窄轉換，負值與超出 32 位元的值會在那次
// 轉換裡回繞成一個看似合理的大門檻。改由解析器把值域寫進型別，越界即是解析失敗，
// 於是整條鏈（env → 欄位 → 限速器）沒有任何一處需要縮窄。
func sealThresholdFromEnv(key string, def uint32) uint32 {
	raw := getEnv(key, "")
	if raw == "" {
		return def
	}
	v, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return sealInvalidThreshold
	}
	return uint32(v)
}

// Validate 於啟動期驗證退避／冷卻參數，任一項不合法即 fail-close。
//
// **為何是 fail-close 而非取預設值**：這些旋鈕唯一的作用是限制未認證端點的
// 嘗試速率。悄悄以預設值頂替一個打錯的值，等於讓部署方以為自己調過參數；
// 而「零／負值／max < base」這幾種寫法的實際效果都是把保護關掉。
func (s SealConfig) Validate() error {
	for _, c := range []struct {
		key string
		d   time.Duration
	}{
		{"SEAL_UNSEAL_BACKOFF_BASE_SECONDS", s.BackoffBase},
		{"SEAL_UNSEAL_BACKOFF_MAX_SECONDS", s.BackoffMax},
		{"SEAL_UNSEAL_COOLDOWN_SECONDS", s.Cooldown},
		{"SEAL_UNSEAL_COOLDOWN_MAX_SECONDS", s.CooldownMax},
	} {
		if c.d < sealParamMinSeconds*time.Second || c.d > sealParamMaxSeconds*time.Second {
			return fmt.Errorf("%s 不合法（須為 %d..%d 秒；零、負值與溢位值皆等同關閉保護）",
				c.key, sealParamMinSeconds, sealParamMaxSeconds)
		}
	}
	if s.BackoffMax < s.BackoffBase {
		return fmt.Errorf("SEAL_UNSEAL_BACKOFF_MAX_SECONDS(%v) 小於 SEAL_UNSEAL_BACKOFF_BASE_SECONDS(%v)：退避封頂低於基準等同無退避",
			s.BackoffMax, s.BackoffBase)
	}
	if s.CooldownMax < s.Cooldown {
		return fmt.Errorf("SEAL_UNSEAL_COOLDOWN_MAX_SECONDS(%v) 小於 SEAL_UNSEAL_COOLDOWN_SECONDS(%v)：冷卻封頂低於基準等同無冷卻",
			s.CooldownMax, s.Cooldown)
	}
	if s.CooldownThreshold < 1 || s.CooldownThreshold > sealCooldownThresholdMax {
		return fmt.Errorf("SEAL_UNSEAL_COOLDOWN_THRESHOLD(%d) 不合法（須為 1..%d；零、負值與超出 32 位元的寫法在讀取期即歸零，一律於此拒絕而不退回預設）",
			s.CooldownThreshold, sealCooldownThresholdMax)
	}
	return nil
}

// TrustedProxyConfigured 是否已顯式約定可信代理鏈。
func (s SealConfig) TrustedProxyConfigured() bool { return len(s.TrustedProxies) > 0 }

// ParseAllowedCIDRs 解析允許網段。
//
// 單一項目解析失敗即整體 fail-close：把「打錯的網段」靜默忽略，等於把一道
// 顯式啟用的來源限制悄悄關掉——那是最不該靜默的一類設定錯誤。
// 裸 IP 亦接受，補為 /32（IPv4）或 /128（IPv6）。
func (s SealConfig) ParseAllowedCIDRs() ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(s.UnsealAllowedCIDRs))
	for _, raw := range s.UnsealAllowedCIDRs {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}
		if !strings.Contains(item, "/") {
			ip := net.ParseIP(item)
			if ip == nil {
				return nil, fmt.Errorf("SEAL_UNSEAL_ALLOWED_CIDRS 含無法解析的項目 %q", item)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			item = fmt.Sprintf("%s/%d", item, bits)
		}
		_, n, err := net.ParseCIDR(item)
		if err != nil {
			return nil, fmt.Errorf("SEAL_UNSEAL_ALLOWED_CIDRS 含無法解析的項目 %q: %w", raw, err)
		}
		out = append(out, n)
	}
	return out, nil
}
