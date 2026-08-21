package asset

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// SD-15：標籤正規化的行為表守衛——**service 側**（modular-architecture W7 7.8）。
//
// 對照 `backend/testdata/tag_normalization_cases.txt`（唯一預期來源）。
//
// **原本是雙面守衛**：對側是 `internal/database` 的 migration 端測試，比對的是
// 「存量清洗 SQL」與「寫入路徑 Go 實作」兩份規則有沒有漂移。存量清洗 migration
// 隨 migration-baseline-compression 退場後只剩一份規則，對照面消失，
// 但共用預期表與本側的 canonical 行為斷言原樣保留——正規化的規則本身仍然是
// 「寫入時就要對」的產品行為，不隨清洗腳本一起消失。

// tagCasesModulePath 掃描根的身分錨點：go.mod 的 module 行必須完全等於此值。
const tagCasesModulePath = "github.com/custodexa/backend"

// tagCasesRel 預期表相對 module 根的路徑（兩側共用，改路徑須兩側同步）。
const tagCasesRel = "testdata/tag_normalization_cases.txt"

// minTagNormalizationCases 案例數下限（防「檔被清空即零違規」的空集合假綠）。
const minTagNormalizationCases = 8

// tagCase 一筆預期
type tagCase struct {
	Raw  string
	Want string
}

// loadTagNormalizationCases 讀共用預期表。找不到／案例太少一律 t.Fatal，不 skip。
func loadTagNormalizationCases(t *testing.T, moduleRoot func(*testing.T) string) []tagCase {
	t.Helper()
	path := filepath.Join(moduleRoot(t), tagCasesRel)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("讀取共用預期表 %s 失敗：兩份正規化規則的等價比對無從進行（守衛拒絕在無基準下通過）: %v", path, err)
	}
	var out []tagCase
	for i, line := range strings.Split(string(body), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		parts := strings.Split(line, " => ")
		if len(parts) != 2 {
			t.Fatalf("預期表第 %d 行格式錯誤（須為 `raw => want`）: %q", i+1, line)
		}
		out = append(out, tagCase{Raw: unescapeTagCase(parts[0]), Want: unescapeTagCase(parts[1])})
	}
	if len(out) < minTagNormalizationCases {
		t.Fatalf("預期表只有 %d 筆案例（下限 %d）：比對面已失真", len(out), minTagNormalizationCases)
	}
	return out
}

// unescapeTagCase 還原 `\s`（空白）與 `\e`（空字串）跳脫——
// 前後空白與空結果在純文字表裡無法直接書寫。
func unescapeTagCase(s string) string {
	if s == `\e` {
		return ""
	}
	return strings.ReplaceAll(s, `\s`, " ")
}

// tagCasesModuleRoot 由本測試檔位置向上找 go.mod 並核對 module 行
// （不用 cwd 相對或固定層數 `..`：那與本 package 的樹深綁死，W1 1.20）。
func tagCasesModuleRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller 取本檔路徑失敗，掃描根無從定位")
	}
	dir := filepath.Dir(self)
	for {
		if body, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
			want := "module " + tagCasesModulePath
			for _, line := range strings.Split(string(body), "\n") {
				if strings.TrimSpace(line) == want {
					return dir
				}
			}
			t.Fatalf("在 %s 找到 go.mod，但 module 行不是 %q：掃描根定位錨點失效",
				filepath.Join(dir, "go.mod"), tagCasesModulePath)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("自 %s 向上找不到 go.mod（module %s）：掃描根無從定位",
				filepath.Dir(self), tagCasesModulePath)
		}
		dir = parent
	}
}

// TestTagNormalizationParityServiceSide service 端 `normalizeTagList` 對照共用預期表。
func TestTagNormalizationParityServiceSide(t *testing.T) {
	cases := loadTagNormalizationCases(t, tagCasesModuleRoot)
	for _, c := range cases {
		got := strings.Join(normalizeTagList(c.Raw), ",")
		if got != c.Want {
			t.Errorf("normalizeTagList(%q) = %q, 共用預期表要求 %q\n"+
				"兩份規則（service 寫入路徑／migration 存量清洗）已漂移："+
				"存量資料會停在舊規則的正規形而新寫入是新規則的正規形，"+
				"而兩側的既有單測各自照樣綠（SD-15／backlog B-8）", c.Raw, got, c.Want)
		}
	}
	// 冪等性（兩份規則都自陳冪等；破了會讓「跑第二次結果不同」這種難查的問題出現）
	for _, c := range cases {
		once := strings.Join(normalizeTagList(c.Raw), ",")
		twice := strings.Join(normalizeTagList(once), ",")
		if once != twice {
			t.Errorf("normalizeTagList 不冪等：%q → %q → %q", c.Raw, once, twice)
		}
	}
}
