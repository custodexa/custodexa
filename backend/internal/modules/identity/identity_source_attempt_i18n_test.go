package identity_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/modules/identity"
)

// 面板「最近一次登入」的白話原因由前端依機器碼查三語文案。後端新增一個原因碼或
// 白名單子碼而三語沒有跟上時，畫面會落到裸鍵或空白，管理者看不到原因——本測試把
// 後端的列舉當基準，逐碼確認三語都有非空譯文。

const attemptLocaleEnv = "APIERROR_LOCALE_DIR"
const attemptLocaleRel = "frontend/src/i18n/locales"

var attemptLocales = []string{"zh-TW", "en-US", "ja-JP"}

// attemptLocaleDir 定位三語 locale 目錄：env 覆寫優先，否則自 cwd 逐層上溯
func attemptLocaleDir(t *testing.T) string {
	t.Helper()
	if d := os.Getenv(attemptLocaleEnv); d != "" {
		return d
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("取工作目錄失敗: %v", err)
	}
	for dir := wd; ; {
		cand := filepath.Join(dir, filepath.FromSlash(attemptLocaleRel))
		if st, err := os.Stat(cand); err == nil && st.IsDir() {
			return cand
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skipf("locale 目錄不可達（%s 未設且自 %s 上溯找不到 %s）：跳過而非假綠",
		attemptLocaleEnv, wd, attemptLocaleRel)
	return ""
}

// attemptLocaleNode 取 identitySources.preflight.attempt 子樹
func attemptLocaleNode(t *testing.T, dir, locale string) map[string]any {
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
	for _, seg := range []string{"identitySources", "preflight", "attempt"} {
		m, ok := node.(map[string]any)
		if !ok {
			t.Fatalf("%s 缺 identitySources.preflight.attempt（斷在 %s）", locale, seg)
		}
		node = m[seg]
	}
	m, ok := node.(map[string]any)
	if !ok {
		t.Fatalf("%s 缺 identitySources.preflight.attempt", locale)
	}
	return m
}

// missingAttemptKeys 回傳 node 下 group 子樹中缺少或為空字串的碼
func missingAttemptKeys(node map[string]any, group []string, codes []string) []string {
	cur := any(node)
	for _, seg := range group {
		m, _ := cur.(map[string]any)
		cur = m[seg]
	}
	sub, _ := cur.(map[string]any)
	var missing []string
	for _, code := range codes {
		s, _ := sub[code].(string)
		if strings.TrimSpace(s) == "" {
			missing = append(missing, strings.Join(append(append([]string{}, group...), code), "."))
		}
	}
	return missing
}

func TestAttemptReasonTranslated(t *testing.T) {
	// 防空集合假綠：列舉被誤清空時本測試會無條件通過
	if len(identity.AttemptReasonCodes) < 21 ||
		len(identity.AttemptRulesNoncompliantDetails) < 7 ||
		len(identity.AttemptProviderErrorDetails) < 9 {
		t.Fatalf("原因碼列舉少於設計數量：reason=%d rules=%d provider=%d",
			len(identity.AttemptReasonCodes), len(identity.AttemptRulesNoncompliantDetails),
			len(identity.AttemptProviderErrorDetails))
	}
	dir := attemptLocaleDir(t)
	for _, locale := range attemptLocales {
		node := attemptLocaleNode(t, dir, locale)
		var missing []string
		missing = append(missing, missingAttemptKeys(node, []string{"reason"}, identity.AttemptReasonCodes)...)
		missing = append(missing, missingAttemptKeys(node,
			[]string{"detail", "admission_rules_noncompliant"}, identity.AttemptRulesNoncompliantDetails)...)
		missing = append(missing, missingAttemptKeys(node,
			[]string{"detail", "provider_error"}, identity.AttemptProviderErrorDetails)...)
		if len(missing) > 0 {
			t.Errorf("%s 缺少或為空的譯文（identitySources.preflight.attempt.*）：%s",
				locale, strings.Join(missing, ", "))
		}
	}
}
