package sourceip

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// 來源位址政策的**單一解析與比對實作**。
//
// 使用者管理的清單驗證、登入／刷新／簽發／兌換各判定點、管理端的判定端點與
// 稽核工作台的位址正規化全部經由本檔；不得在其他包另寫第二套解析——IPv6 縮寫、
// zone、IPv4-mapped 與遮罩正規化的行為在兩套實作之間必然分歧，而分歧的後果是
// 「前端說可以、後端說不行」或「這個判定點放行、那個判定點拒絕」。
//
// 本檔只有純函式，不讀請求、不讀標頭、不碰資料庫；來源位址仍由本包 From／Of 取得。

// MaxPrefixes 每位使用者允許網段的項目上限（去重後計算）。
const MaxPrefixes = 32

// 有效涵蓋狀態：依清單**實際放行的範圍**判定，不依陣列是否為空。
const (
	// StatusUnrestricted 清單為空＝不限制來源。
	StatusUnrestricted = "unrestricted"
	// StatusEffectivelyUnrestricted 清單含全域前綴（0.0.0.0/0 或 ::/0），
	// 該位址家族全部放行——列表若標成「已限定」會把放行呈為受限。
	StatusEffectivelyUnrestricted = "effectively_unrestricted"
	// StatusRestricted 清單非空且不含全域前綴。
	StatusRestricted = "restricted"
)

// 位址家族標記（隨 effectively_unrestricted 附帶，指出哪一族被全放行）。
const (
	FamilyV4 = "v4"
	FamilyV6 = "v6"
)

// 單項驗證結果的機器碼（判定端點逐項回覆；VALIDATION_* 對外碼由 apierror 承載）。
const (
	// ItemInvalid 無法解析為 IPv4／IPv6 位址或 CIDR。
	ItemInvalid = "invalid"
	// ItemTooMany 去重後超過 MaxPrefixes 的項目。
	ItemTooMany = "too_many"
)

// 拒絕原因碼（只進審計，不對外回顯）。
const (
	// ReasonSourceNotAllowed 來源位址不在清單內，或清單非空而來源無法解析。
	ReasonSourceNotAllowed = "source_not_allowed"
	// ReasonPolicyUnreadable 政策不可用：使用者列讀不到，或儲存的清單字串無法解析。
	// 與來源拒絕分開，讓稽核能把「被擋」歸因到「政策壞了」而非「來源不對」。
	ReasonPolicyUnreadable = "source_policy_unreadable"
)

// 政策不可用的成因類別（審計 details 的 cause 欄）。
const (
	CauseReadError  = "read_error"
	CauseParseError = "parse_error"
)

var (
	// ErrPrefixInvalid 清單含無法解析的項目（任一項失敗即整體拒絕，不靜默丟棄）。
	ErrPrefixInvalid = errors.New("允許網段含無法解析的項目")
	// ErrTooManyPrefixes 去重後超過上限。
	ErrTooManyPrefixes = errors.New("允許網段超過上限")
)

// Item 清單中單一項目的驗證結果。
type Item struct {
	Input      string `json:"input"`
	Normalized string `json:"normalized,omitempty"`
	ErrorCode  string `json:"error_code,omitempty"`
}

// Canonical 把位址字串正規化為標準文字形式：去 zone、IPv4-mapped IPv6 還原為 IPv4。
// 解析失敗回 ("", false)。位址樞紐與位址篩選的輸入、基準表寫入、CIDR 比對前一律經此。
func Canonical(s string) (string, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return "", false
	}
	return addr.WithZone("").Unmap().String(), true
}

// canonicalAddr 同 Canonical，回傳結構化位址供比對。
func canonicalAddr(s string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.WithZone("").Unmap(), true
}

// normalizePrefix 單項正規化：裸位址補 /32（IPv4）或 /128（IPv6）；CIDR 取遮罩後的
// 網路位址；IPv4-mapped IPv6 前綴（含 ::ffff:0:0/96 以內者）還原為對應的 IPv4 前綴。
func normalizePrefix(raw string) (netip.Prefix, bool) {
	item := strings.TrimSpace(raw)
	if item == "" {
		return netip.Prefix{}, false
	}
	if !strings.Contains(item, "/") {
		addr, ok := canonicalAddr(item)
		if !ok {
			return netip.Prefix{}, false
		}
		return netip.PrefixFrom(addr, addr.BitLen()), true
	}
	p, err := netip.ParsePrefix(item)
	if err != nil {
		return netip.Prefix{}, false
	}
	addr := p.Addr().WithZone("")
	bits := p.Bits()
	if addr.Is4In6() {
		// ::ffff:a.b.c.d/N 的後 32 位就是 IPv4：N ≥ 96 才對應到一個 IPv4 前綴，
		// 否則它涵蓋的不只 IPv4-mapped 空間，保留為 IPv6 前綴
		if bits >= 96 {
			addr = addr.Unmap()
			bits -= 96
		}
	}
	return netip.PrefixFrom(addr, bits).Masked(), true
}

// Inspect 逐項驗證並正規化清單。
//
// 回傳值：去重排序後的前綴、其字串形式、逐項結果、整體是否合法。任一項無法解析
// 或去重後超過上限即 valid=false（合法項目仍在 items 內回報其正規化形式，供介面
// 就近提示）。順序穩定：以正規化字串排序，使同一集合在任何輸入順序下存成同一份。
func Inspect(list []string) (prefixes []netip.Prefix, normalized []string, items []Item, valid bool) {
	valid = true
	items = make([]Item, 0, len(list))
	seen := map[string]netip.Prefix{}
	for _, raw := range list {
		it := Item{Input: raw}
		p, ok := normalizePrefix(raw)
		if !ok {
			it.ErrorCode = ItemInvalid
			valid = false
			items = append(items, it)
			continue
		}
		it.Normalized = p.String()
		seen[it.Normalized] = p
		items = append(items, it)
	}
	normalized = make([]string, 0, len(seen))
	for s := range seen {
		normalized = append(normalized, s)
	}
	sort.Strings(normalized)
	if len(normalized) > MaxPrefixes {
		valid = false
		// 超額的項目逐項標記：以正規化後的序位判定，使「哪幾項是多出來的」可重現
		over := map[string]bool{}
		for _, s := range normalized[MaxPrefixes:] {
			over[s] = true
		}
		for i := range items {
			if items[i].ErrorCode == "" && over[items[i].Normalized] {
				items[i].ErrorCode = ItemTooMany
			}
		}
	}
	prefixes = make([]netip.Prefix, 0, len(normalized))
	for _, s := range normalized {
		prefixes = append(prefixes, seen[s])
	}
	return prefixes, normalized, items, valid
}

// ParsePrefixes 解析清單；任一項失敗或超過上限即整體回錯（fail-close）。
func ParsePrefixes(list []string) ([]netip.Prefix, error) {
	prefixes, normalized, items, valid := Inspect(list)
	if valid {
		return prefixes, nil
	}
	for _, it := range items {
		if it.ErrorCode == ItemInvalid {
			return nil, fmt.Errorf("%w: %q", ErrPrefixInvalid, it.Input)
		}
	}
	return nil, fmt.Errorf("%w（%d > %d）", ErrTooManyPrefixes, len(normalized), MaxPrefixes)
}

// Allowed 來源是否落於清單內。清單為空＝不限（true）；清單非空而來源無法解析＝拒絕
// （false）——一道顯式啟用的限制不該因取不到來源而靜默失效。IPv4-mapped 來源先
// 還原為 IPv4，使 IPv4 前綴能命中。
func Allowed(ip string, prefixes []netip.Prefix) bool {
	if len(prefixes) == 0 {
		return true
	}
	addr, ok := canonicalAddr(ip)
	if !ok {
		return false
	}
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// CoverageStatus 依清單的有效涵蓋計算狀態與被全放行的位址家族。
func CoverageStatus(prefixes []netip.Prefix) (status string, families []string) {
	if len(prefixes) == 0 {
		return StatusUnrestricted, nil
	}
	v4, v6 := false, false
	for _, p := range prefixes {
		if p.Bits() != 0 {
			continue
		}
		if p.Addr().Is4() {
			v4 = true
		} else {
			v6 = true
		}
	}
	if !v4 && !v6 {
		return StatusRestricted, nil
	}
	if v4 {
		families = append(families, FamilyV4)
	}
	if v6 {
		families = append(families, FamilyV6)
	}
	return StatusEffectivelyUnrestricted, families
}

// SplitStored 把資料庫的逗號分隔字串拆成清單（空字串＝空清單）。
func SplitStored(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []string{}
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// JoinStored 把正規化清單組回資料庫的逗號分隔字串。
func JoinStored(normalized []string) string {
	return strings.Join(normalized, ",")
}

// Verdict 一次判定的結果。
//
// Reason 與 Cause 只進審計；對外回應由各判定點收斂為其既有形狀。
// Policy 為判定當下的清單快照（正規化字串），供審計列記錄判定依據。
type Verdict struct {
	Allowed bool
	Reason  string
	Cause   string
	Policy  []string
}

// Evaluate 以儲存字串與讀取結果對來源作一次完整判定。
//
// readErr 非 nil（使用者列讀不到）→ 拒絕，原因政策不可讀／read_error；
// 儲存字串解析失敗 → 拒絕，原因政策不可讀／parse_error；
// 空字串 → 不限，放行；其餘依 Allowed 判定。政策壞掉不得視為空清單放行。
func Evaluate(raw string, readErr error, ip string) Verdict {
	if readErr != nil {
		return Verdict{Reason: ReasonPolicyUnreadable, Cause: CauseReadError}
	}
	list := SplitStored(raw)
	if len(list) == 0 {
		return Verdict{Allowed: true}
	}
	prefixes, normalized, _, valid := Inspect(list)
	if !valid {
		return Verdict{Reason: ReasonPolicyUnreadable, Cause: CauseParseError}
	}
	if !Allowed(ip, prefixes) {
		return Verdict{Reason: ReasonSourceNotAllowed, Policy: normalized}
	}
	return Verdict{Allowed: true, Policy: normalized}
}
