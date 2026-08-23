package apierror

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// localeDir locates the frontend three-language locale directory.
//
// The APIERROR_LOCALE_DIR override MUST stay: the backend test container mounts
// the locale directory read-only and points this variable at it (see
// docker-compose.dev.yml). Only the host fallback is decoupled.
//
// **The fallback no longer counts `..` levels from this test file**:
// that was tied to how deep this package sits,
// so moving the package one level down would silently point at a non-existent
// directory. It now anchors on the go.mod module root and goes up exactly one
// level (backend/ → repo root), asserting the marker exists — an unreadable
// subject means no guard at all, so it Fatals rather than skipping.
func localeDir(t *testing.T) string {
	t.Helper()
	if d := os.Getenv("APIERROR_LOCALE_DIR"); d != "" {
		return d
	}
	parent := filepath.Dir(backendRoot())
	dir := filepath.Join(parent, filepath.FromSlash(apierrorLocaleRel))
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("locale fallback 目錄不存在（%s）：專案根定位失效，"+
			"守衛讀不到被驗證對象即等於沒有守衛（故 Fatal 而非 skip）: %v", dir, err)
	}
	return dir
}

// apierrorLocaleRel locale 目錄相對專案根（backend 的上一層）的路徑。
const apierrorLocaleRel = "frontend/src/i18n/locales"

// minAPIErrorLocaleKeys 單一 locale 檔的 apiError 鍵數下限（防空集合假綠）。
// 2026-08-09 三語各實測 514 鍵（見 TestCodeTranslationsComplete 的 t.Logf），門檻取 460。
const minAPIErrorLocaleKeys = 460

func loadAPIError(t *testing.T, dir, locale string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, locale+".json"))
	if err != nil {
		t.Fatalf("read %s locale: %v", locale, err)
	}
	var doc struct {
		APIError map[string]string `json:"apiError"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s locale: %v", locale, err)
	}
	return doc.APIError
}

var locales = []string{"zh-TW", "en-US", "ja-JP"}

// unescapeVueI18nAt 還原 vue-i18n 的 `@` 轉義後再比對 zh 逐字一致性。
//
// vue-i18n 把 `@` 視為 linked message 起手（`@:key`／`@.modifier:key`），訊息內
// 出現裸 `@` 會在 render 期拋 Invalid linked format 並中斷整個元件渲染，故 locale
// 端必須寫成 `{'@'}`。後端 registry 的 ZhFallback 是給非前端消費者的 wire fallback，
// 不該帶前端模板語法——兩者語義相同、表示不同，守衛比對語義而非位元組。
//
// 僅還原此一轉義：其餘 `{...}` 為參數佔位，由 placeholdersOf 另行逐一比對。
func unescapeVueI18nAt(s string) string {
	return strings.ReplaceAll(s, "{'@'}", "@")
}

func placeholdersOf(s string) map[string]bool {
	set := map[string]bool{}
	for _, m := range placeholderRe.FindAllStringSubmatch(s, -1) {
		set[m[1]] = true
	}
	return set
}

func equalStringSets(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestCodeTranslationsComplete is the hard constraint that keeps a registered
// error code from ever reaching a user untranslated: every registered code MUST
// have a non-empty translation in all three languages, with no orphan apiError
// keys (bijection). It also pins
// registry.ZhFallback == apiError.zh-TW[code] so the wire fallback and the code
// render never drift.
func TestCodeTranslationsComplete(t *testing.T) {
	dir := localeDir(t)
	byLocale := map[string]map[string]string{}
	for _, l := range locales {
		byLocale[l] = loadAPIError(t, dir, l)
		if n := len(byLocale[l]); n < minAPIErrorLocaleKeys {
			t.Fatalf("%s 只載到 %d 個 apiError 鍵（下限 %d，locale 目錄 %s）："+
				"載入範圍已失真，正向（三語非空）與反向（孤兒鍵）兩側都會在空集合下假綠",
				l, n, minAPIErrorLocaleKeys, dir)
		}
		t.Logf("locale %s apiError 鍵數=%d（下限 %d）", l, len(byLocale[l]), minAPIErrorLocaleKeys)
	}

	codes := AllCodes()

	// forward: every registered code has a non-empty key in every language, its
	// zh matches the registry template, and all three languages carry the same
	// {placeholder} set (so a dropped/renamed {min} etc. cannot slip through).
	for _, code := range codes {
		for _, l := range locales {
			v, ok := byLocale[l][string(code)]
			if !ok || v == "" {
				t.Errorf("code %q missing/empty in %s apiError", code, l)
			}
		}
		d, _ := DescriptorOf(code)
		if zh := unescapeVueI18nAt(byLocale["zh-TW"][string(code)]); zh != d.ZhFallback {
			t.Errorf("code %q: zh drift — registry %q vs apiError.zh-TW %q", code, d.ZhFallback, zh)
		}
		want := placeholdersOf(d.ZhFallback)
		for _, l := range locales {
			if got := placeholdersOf(byLocale[l][string(code)]); !equalStringSets(got, want) {
				t.Errorf("code %q: %s placeholders %v != template %v", code, l, keysOf(got), keysOf(want))
			}
		}
	}

	// reverse: no orphan apiError keys outside the registry
	registered := map[string]bool{}
	for _, code := range codes {
		registered[string(code)] = true
	}
	for _, l := range locales {
		for key := range byLocale[l] {
			if !registered[key] {
				t.Errorf("orphan apiError key %q in %s (not in registry)", key, l)
			}
		}
	}

	// same-value heuristic (3.4): flag codes whose en-US/ja-JP text is byte-identical
	// to zh-TW — a signal that the zh was copied instead of translated. Codes whose
	// value is legitimately identical across languages go in sameValueAllowlist.
	for _, code := range codes {
		zh := byLocale["zh-TW"][string(code)]
		for _, l := range []string{"en-US", "ja-JP"} {
			if byLocale[l][string(code)] == zh && !sameValueAllowlist[string(code)] {
				t.Errorf("code %q: %s text identical to zh-TW (%q) — likely untranslated copy; translate it or add to sameValueAllowlist", code, l, zh)
			}
		}
	}
}

// sameValueAllowlist lists codes whose translation is legitimately identical to
// zh-TW across languages (e.g. pure symbols/identifiers). Empty until a real case appears.
var sameValueAllowlist = map[string]bool{}
