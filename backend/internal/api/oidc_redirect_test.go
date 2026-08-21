package api

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// 登入後重導向目標的清洗（idp-oidc-integration tasks 4.3，spec「開放重導向被拒」）。
//
// 這是登入流程唯一接受使用者提供之 URL 的地方。它同時要擋住 scheme-relative、
// 絕對 URL、反斜線與多重編碼，並把目標限制在前端既有路由內。

func TestSanitizeRedirectNextAcceptsKnownRoutes(t *testing.T) {
	cases := []string{
		"/", "/dashboard", "/assets", "/sessions/42", "/terminal/7",
		"/my-connections", "/oidc-providers", "/sessions/42/monitor",
		"/dashboard?tab=recent", "/assets#top",
	}
	for _, in := range cases {
		if got := sanitizeRedirectNext(in); got != in {
			t.Errorf("sanitizeRedirectNext(%q) = %q, want 原值保留", in, got)
		}
	}
}

func TestSanitizeRedirectNextRejectsOpenRedirect(t *testing.T) {
	// 每一項都是實際被利用過的開放重導向形式；退回預設路徑而非報錯，
	// 因為使用者的登入不該因為一個壞掉的 next 參數而失敗
	cases := map[string]string{
		"絕對 URL":                "https://evil.example.com/",
		"scheme-relative":       "//evil.example.com/",
		"scheme-relative 帶路徑":   "//evil.example.com/dashboard",
		"反斜線變形":                 "/\\evil.example.com",
		"反斜線 scheme-relative":   "\\\\evil.example.com",
		"單次編碼的 scheme-relative": "%2f%2fevil.example.com",
		"雙重編碼":                  "%252f%252fevil.example.com",
		"javascript scheme":     "javascript:alert(1)",
		"data scheme":           "data:text/html,<script>alert(1)</script>",
		"相對路徑（無前導斜線）":           "dashboard",
		"帶使用者資訊的絕對 URL":         "https://user:pw@evil.example.com/",
		"空字串":                   "",
		"僅空白":                   "   ",
	}
	for name, in := range cases {
		if got := sanitizeRedirectNext(in); got != "/" {
			t.Errorf("%s: sanitizeRedirectNext(%q) = %q, want 退回 \"/\"", name, in, got)
		}
	}
}

func TestSanitizeRedirectNextRejectsUnknownRoute(t *testing.T) {
	// 同源相對路徑但不在路由枚舉內：尤其是後端表面不該成為登入後落點
	cases := []string{
		"/api/v1/users", "/api", "/not-a-route", "/../etc/passwd", "/%2e%2e/admin",
		// dot-segment 包裝：第一段是合法的 dashboard，瀏覽器卻會正規化成
		// /api/v1/users——枚舉只看第一段，不擋 dot-segment 即可被任意繞過
		"/dashboard/../../api/v1/users",
		"/dashboard/..%2f..%2fapi/v1/users",
		"/dashboard/./../api",
		"/assets/../not-a-route",
	}
	for _, in := range cases {
		if got := sanitizeRedirectNext(in); got != "/" {
			t.Errorf("sanitizeRedirectNext(%q) = %q, want 退回 \"/\"（不在路由枚舉內）", in, got)
		}
	}
}

func TestSanitizeRedirectNextRejectsOverlong(t *testing.T) {
	long := "/dashboard/" + strings.Repeat("a", 300)
	if got := sanitizeRedirectNext(long); got != "/" {
		t.Errorf("超長路徑應退回預設，實得 %q", got)
	}
}

func TestIsSHA256Hex(t *testing.T) {
	// 瀏覽器綁定值的形狀驗證：只驗非空會讓任意字串成為合法綁定
	valid := strings.Repeat("a1B2", 16) // 64 字元
	if !isSHA256Hex(valid) {
		t.Errorf("%q 應為合法 SHA256 十六進位", valid)
	}
	invalid := []string{
		"", "   ", "short", strings.Repeat("a", 63), strings.Repeat("a", 65),
		strings.Repeat("g", 64), // 非十六進位字元
		strings.Repeat("a", 63) + " ",
	}
	for _, s := range invalid {
		if isSHA256Hex(s) {
			t.Errorf("%q 不應通過形狀驗證", s)
		}
	}
}

// routePathRe 擷取 frontend/src/router/index.js 的 `path: <字串>` 宣告。
// 單引號、雙引號與樣板字面皆涵蓋——只認單引號時，前端改用其他引號形式會使
// 該路由被靜默漏掉而假綠（守衛本身失效比沒有守衛更糟）
var routePathRe = regexp.MustCompile("path:\\s*['\"`]([^'\"`]*)['\"`]")

func TestFrontendRouteSegmentsNoDrift(t *testing.T) {
	// 後端的路由枚舉與前端 router 雙向比對。前端新增路由時本測試會紅——
	// 這是刻意的：靜默漂移的表現是「SSO 登入後被莫名丟回首頁」，極難診斷
	// 容器內經 docker-compose.dev.yml 唯讀掛入 testdata/router；host 直跑時走相對路徑。
	// **找不到即 Fatal 而非 Skip**：可跳過的守衛等於沒有守衛。
	// **掃整個目錄而非 index.js 單檔**：路由日後拆檔時，只讀單檔的守衛不會紅，
	// 而使用者仍會被丟回首頁——正是它宣稱要防的失效模式
	raw, err := readRouterSources("testdata/router")
	if err != nil {
		raw, err = readRouterSources("../../../frontend/src/router")
	}
	if err != nil {
		t.Fatalf("讀取前端 router 失敗——容器內需 docker-compose.dev.yml 的 "+
			"testdata/router 唯讀掛載，host 直跑需 frontend/ 在相對位置: %v", err)
	}

	want := map[string]bool{}
	for _, m := range routePathRe.FindAllStringSubmatch(string(raw), -1) {
		p := m[1]
		if strings.HasPrefix(p, ":pathMatch") || strings.Contains(p, "pathMatch") {
			continue // 萬用捕捉路由不是可導向的具體目標
		}
		seg := firstPathSegment(p)
		if strings.HasPrefix(seg, ":") {
			continue // 動態參數不成為第一段（實際路由皆有具名前綴）
		}
		want[seg] = true
	}
	if len(want) < 10 {
		t.Fatalf("自 router 解析到的路由段僅 %d 個，解析很可能已失效（regexp 需更新）", len(want))
	}

	missing := diffKeys(want, frontendRouteSegments)
	stale := diffKeys(frontendRouteSegments, want)
	if len(missing) > 0 {
		t.Errorf("前端新增了路由但後端枚舉未同步，請把這些段加入 frontendRouteSegments: %v", missing)
	}
	if len(stale) > 0 {
		t.Errorf("後端枚舉含前端已不存在的路由段，請移除: %v", stale)
	}
}

// readRouterSources 遞迴讀取路由目錄下的所有 .js/.ts，串成一份來源。
// 排除 __tests__ 等測試目錄——那裡的假路由不是真實路由宣告
func readRouterSources(dir string) ([]byte, error) {
	var buf []byte
	found := false
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), "__") || d.Name() == "node_modules" {
				return fs.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(d.Name())
		if ext != ".js" && ext != ".ts" {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		buf = append(buf, b...)
		buf = append(buf, '\n')
		found = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fs.ErrNotExist
	}
	return buf, nil
}

func diffKeys(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
