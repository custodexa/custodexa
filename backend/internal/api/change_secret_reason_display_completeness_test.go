package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// 改密結果原因碼（`model.ChangeSecretReasons()`）的三語完備性守衛。
//
// **為何既有守衛擋不住**：i18n.spec.js 只比對「三份 locale 的鍵集合是否相等」，
// 而漏譯的典型形態是後端新增一個原因碼、三語**同時**都沒有——集合仍相等、全綠。
// 實際後果是 ChangeSecretPlans.vue 的 `reasonText()` 走 `te(key)` 失敗分支，
// 三語使用者一律看到裸機器碼（`CHANGE_SECRET_REMOTE_REJECTED`）而非文案。
//
// 本族是**高成長值域**：改密每擴一個協議／一條失敗路徑就多一批碼
// （SSH 金鑰路徑一次就加了 6 個），故值得一支反向守衛而非只靠人工同步。
//
// 方向與 key_env_display_completeness_test.go 相同：從後端字面出發比對 locale。
// 差別是本族後端已有 `ChangeSecretReasons()` 封閉集合函式，不需 AST 掃描
// （該函式自身的完備性由 model 層既有守衛把關）。

// changeSecretReasonNS locale 中的巢狀 namespace 路徑
var changeSecretReasonNS = []string{"changeSecretPlans", "reason"}

// minChangeSecretReasons 後端碼數下限（防「集合空掉＝無違規」的假綠）。
// 2026-08-13 現況 28 個，門檻取 24 保留餘裕
const minChangeSecretReasons = 24

// changeSecretReasonLocale 讀出 locale 的 changeSecretPlans.reason 子樹。
// 巢狀讀取自行實作而不共用 keyEnvLocaleNamespace：後者只認頂層扁平 namespace
func changeSecretReasonLocale(t *testing.T, dir, locale string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, locale+".json"))
	if err != nil {
		t.Fatalf("讀 %s locale 失敗: %v", locale, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("解析 %s locale 失敗: %v", locale, err)
	}
	node := any(doc)
	for _, seg := range changeSecretReasonNS {
		m, ok := node.(map[string]any)
		if !ok {
			t.Fatalf("%s 的 %v 路徑中斷於 %q：改密頁將整欄顯示裸機器碼", locale, changeSecretReasonNS, seg)
		}
		node, ok = m[seg]
		if !ok {
			t.Fatalf("%s 缺 %v（斷在 %q）：改密頁將整欄顯示裸機器碼", locale, changeSecretReasonNS, seg)
		}
	}
	body, ok := node.(map[string]any)
	if !ok {
		t.Fatalf("%s 的 %v 不是物件", locale, changeSecretReasonNS)
	}
	out := map[string]string{}
	for k, v := range body {
		s, _ := v.(string)
		out[k] = s
	}
	return out
}

// diffChangeSecretReasons 比對「後端碼清單」與「單一 locale 的譯文表」。
//
// 抽成純函式是為了讓偵測力本身可被測試（合成輸入自證，不碰真實 locale——
// locale 為多人共寫檔，突變還原會覆蓋他人改動）
func diffChangeSecretReasons(codes []string, got map[string]string) (missing, stale []string) {
	known := map[string]bool{}
	for _, c := range codes {
		known[c] = true
		if v, ok := got[c]; !ok || v == "" {
			missing = append(missing, c)
		}
	}
	for k := range got {
		if !known[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	return missing, stale
}

// TestChangeSecretReasonCodesTranslated 後端每個原因碼在三語皆有譯文。
func TestChangeSecretReasonCodesTranslated(t *testing.T) {
	codes := model.ChangeSecretReasons()
	if len(codes) < minChangeSecretReasons {
		t.Fatalf("只取到 %d 個原因碼（現況至少 %d）：值域來源已失真，本守衛正在放行一切",
			len(codes), minChangeSecretReasons)
	}
	dir := keyEnvLocaleDir(t)
	for _, locale := range keyEnvLocales {
		got := changeSecretReasonLocale(t, dir, locale)
		missing, stale := diffChangeSecretReasons(codes, got)
		for _, c := range missing {
			t.Errorf("%s 的 changeSecretPlans.reason 缺 %q：該語系使用者在改密頁看到裸機器碼", locale, c)
		}
		for _, c := range stale {
			t.Errorf("%s 的 changeSecretPlans.reason 登記了 %q 但後端已無此碼：譯文腐爛，請刪除該條目", locale, c)
		}
	}
	if !t.Failed() {
		t.Logf("改密原因碼 %d 個，三語皆有譯文", len(codes))
	}
}

// TestChangeSecretReasonDiffDetectsBothDirections 比對器的偵測力自證（合成輸入）。
//
// 沒有這一支，上面那支的綠只證明「現況沒違規」，不證明「有違規時會紅」
func TestChangeSecretReasonDiffDetectsBothDirections(t *testing.T) {
	codes := []string{"CHANGE_SECRET_REMOTE_REJECTED", "CHANGE_SECRET_VERIFY_FAILED"}

	// 方向一：後端有而 locale 缺（三語同缺＝對齊守衛全綠的那個形態）
	missing, stale := diffChangeSecretReasons(codes,
		map[string]string{"CHANGE_SECRET_REMOTE_REJECTED": "Remote rejected"})
	if len(missing) != 1 || missing[0] != "CHANGE_SECRET_VERIFY_FAILED" {
		t.Fatalf("漏譯未被偵測：missing=%v", missing)
	}
	if len(stale) != 0 {
		t.Fatalf("誤報腐爛：stale=%v", stale)
	}

	// 方向二：locale 有而後端已無
	missing, stale = diffChangeSecretReasons(codes, map[string]string{
		"CHANGE_SECRET_REMOTE_REJECTED": "a", "CHANGE_SECRET_VERIFY_FAILED": "b",
		"CHANGE_SECRET_RETIRED": "c"})
	if len(stale) != 1 || stale[0] != "CHANGE_SECRET_RETIRED" {
		t.Fatalf("腐爛條目未被偵測：stale=%v", stale)
	}
	if len(missing) != 0 {
		t.Fatalf("誤報漏譯：missing=%v", missing)
	}

	// 空字串譯文等同缺譯
	missing, _ = diffChangeSecretReasons(codes, map[string]string{
		"CHANGE_SECRET_REMOTE_REJECTED": "a", "CHANGE_SECRET_VERIFY_FAILED": ""})
	if len(missing) != 1 || missing[0] != "CHANGE_SECRET_VERIFY_FAILED" {
		t.Fatalf("空字串譯文未被當成缺譯：missing=%v", missing)
	}
}
