package api

import (
	"testing"
)

// === 認證端點的併發上限依實際雜湊成本設定===
//
// 缺陷：`MaxInFlight = 16` 只掛在 `/auth/login`，而登入每次只做 **1 次**雜湊；
// 真正昂貴的 `/auth/change-password` 每次做 **2 + N + 1** 次（驗舊、比對現行、
// 逐筆比對最近 N 筆歷史、產生新雜湊），**卻完全沒有併發上限**。
//
// 成本結構（單位＝一次雜湊；**倍率可攜、絕對毫秒不可攜**，見下）：
//   - 預設 `password_history_count=4` → 7 單位，約登入的 7 倍
//   - 政策上界 24（2026-08-19 由 100 調降）→ 27 單位，約登入的 27 倍
//
// 兩次獨立量測在不同負載下得到同一組倍率而絕對值差 2.6 倍
// （原量測 Hash 68ms／Verify 78ms；獨立驗收 Hash 121ms／Verify 205ms）。
// 倍率恆落在 (2+N, 3+N) 是數學性質，故結論可攜——引用時用單位數，不要引毫秒。
//
// 三問：今天存在（不需新功能即可觸發）／B 類（只需一個已認證的一般帳號，
// 用產品正常暴露的端點）／後果是可用性而非留痕繞過——「今天存在 ＋ B」仍為必修。

// TestChangePasswordHasLowerInFlightThanLogin 改密的併發上限必須**低於**登入。
//
// 這是本 change 的核心斷言：兩個端點的每請求成本差 7 倍以上，
// 給它們相同的上限等於讓昂貴的那個吃掉數倍的 CPU 預算。
func TestChangePasswordHasLowerInFlightThanLogin(t *testing.T) {
	login := defaultLoginGuardParams()
	change := defaultChangePasswordGuardParams()

	if change.MaxInFlight >= login.MaxInFlight {
		t.Errorf("改密 MaxInFlight = %d，未低於登入的 %d——"+
			"改密每請求的雜湊成本是登入的約 7 倍（預設）至約 27 倍（政策上界 24）",
			change.MaxInFlight, login.MaxInFlight)
	}
	if change.MaxInFlight < 1 {
		t.Errorf("改密 MaxInFlight = %d，低於 1 等於關閉該功能", change.MaxInFlight)
	}
}

// TestLoginInFlightUnchanged 登入端點的上限不得因本次改動而退化。
//
// 原值 16 是既有行為，本 change 只把它的**來源**從寫死常數改為成本推導，
// 不改變數值——行為變更要是一等公民，不能混在重構裡悄悄發生。
func TestLoginInFlightUnchanged(t *testing.T) {
	if got := defaultLoginGuardParams().MaxInFlight; got != 16 {
		t.Errorf("登入 MaxInFlight = %d, want 16（本 change 只改推導來源，不改數值）", got)
	}
}

// TestHashInFlightBudgetScalesWithCost 上限必須隨每請求成本反向縮放。
//
// 若不隨成本縮放，換演算法（例如 Argon2id 每次額外吃記憶體）之後，
// 這個上限的依據就消失了——原本的常數註解直接寫死「bcrypt」正是此問題。
func TestHashInFlightBudgetScalesWithCost(t *testing.T) {
	cases := []struct {
		name  string
		units int
		want  int
		why   string
	}{
		{"登入（1 單位）", 1, 16, "維持既有行為"},
		{"改密（7 單位，預設歷史 4 筆）", 7, 2, "16/7 取整"},
		{"極貴端點（20 單位）", 20, 1, "下限 1：再貴也要能處理請求，否則等於關閉功能"},
		{"零值防禦", 0, 16, "視為 1 單位，不得除以零"},
		{"負值防禦", -5, 16, "同上"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hashInFlightBudget(c.units); got != c.want {
				t.Errorf("hashInFlightBudget(%d) = %d, want %d（%s）",
					c.units, got, c.want, c.why)
			}
		})
	}
}

// TestBudgetIsMonotonicInCost 成本越高，允許的並發必須越低（或持平），絕不反向。
//
// 用性質而非個別數值來釘，避免日後調整預算時要逐格改測試——
// 但「更貴卻允許更多並發」這種錯誤仍會被抓到。
func TestBudgetIsMonotonicInCost(t *testing.T) {
	prev := hashInFlightBudget(1)
	for units := 2; units <= 40; units++ {
		got := hashInFlightBudget(units)
		if got > prev {
			t.Errorf("成本 %d 單位的上限 %d 高於成本 %d 單位的 %d——更貴的端點卻允許更多並發",
				units, got, units-1, prev)
		}
		if got < 1 {
			t.Errorf("成本 %d 單位的上限 %d < 1，等於關閉功能", units, got)
		}
		prev = got
	}
}

// TestChangePasswordGuardIsWired handler 建構後改密 guard 必須存在。
//
// **這條防的是「參數訂好了但沒掛上」**——那會讓所有成本推導變成純裝飾，
// 而測試若只驗 params 就完全看不出來。
func TestChangePasswordGuardIsWired(t *testing.T) {
	h := NewAuthHandler(nil, nil)
	if h.changePasswordGuard == nil {
		t.Fatal("changePasswordGuard 未注入——成本推導的參數沒有被任何東西使用")
	}
	if h.loginGuard == nil {
		t.Fatal("loginGuard 未注入")
	}

	// guard 的實際上限須與 params 一致（防止注入時傳錯 params）
	if got, want := h.changePasswordGuard.params.MaxInFlight,
		defaultChangePasswordGuardParams().MaxInFlight; got != want {
		t.Errorf("changePasswordGuard.MaxInFlight = %d, want %d——注入時傳了錯的 params", got, want)
	}
	if got, want := h.loginGuard.params.MaxInFlight,
		defaultLoginGuardParams().MaxInFlight; got != want {
		t.Errorf("loginGuard.MaxInFlight = %d, want %d", got, want)
	}
}

// TestChangePasswordGuardBlocksExcess 超過上限的並行請求必須被拒而非全部放行。
//
// 直接對 guard 施壓：取滿額度後再取一個應失敗；釋放一個後應能再取。
func TestChangePasswordGuardBlocksExcess(t *testing.T) {
	g := newSourceAbuseGuard(defaultChangePasswordGuardParams(), false, nil)
	limit := defaultChangePasswordGuardParams().MaxInFlight

	var releases []func()
	for i := 0; i < limit; i++ {
		release, ok := g.acquire("192.0.2.10")
		if !ok {
			t.Fatalf("第 %d 個請求（上限 %d 內）竟被拒", i+1, limit)
		}
		releases = append(releases, release)
	}

	if _, ok := g.acquire("192.0.2.10"); ok {
		t.Errorf("超過上限 %d 的請求竟被放行——併發保護未生效", limit)
	}

	// 釋放一個之後應可再取（額度是可回收的，不是一次性耗盡）
	releases[0]()
	release, ok := g.acquire("192.0.2.10")
	if !ok {
		t.Error("釋放額度後仍無法取得——額度未被回收，端點會逐漸鎖死")
	} else {
		release()
	}
	for _, r := range releases[1:] {
		r()
	}
}
