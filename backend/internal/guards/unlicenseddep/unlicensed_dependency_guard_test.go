package unlicenseddep

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// forbiddenDep 一筆禁止復活的第三方依賴。
type forbiddenDep struct {
	// modulePath 為 module 路徑；比對時亦涵蓋其所有子套件（前綴 + "/"）。
	modulePath string
	// reason 說明為什麼不得使用——沒有理由的禁令會在下一次有人趕時間時被刪掉。
	reason string
	// replacement 指向自家的替代實作，讓踩到守衛的人知道該往哪走。
	replacement string
}

// forbiddenDeps 禁止清單。
//
// 只放「授權上不可用」的套件，不放「我們不喜歡」的套件：判準必須客觀，
// 否則清單會膨脹成品味之爭，最後整條守衛失去權威。
var forbiddenDeps = []forbiddenDep{
	{
		modulePath: "github.com/LeeEirc/terminalparser",
		reason: "無授權（repo 內沒有 LICENSE，作者未宣告任何授權條款）——" +
			"未授權即預設保留全部權利，商業散布本產品時它是一顆法務未爆彈。",
		replacement: "internal/vtscreen（terminal-screen-parser-inhouse 自行實作的終端螢幕解析器）",
	},
}

// minScannedGoFiles 掃描到的 .go 檔數下限（防假綠第一道）。
//
// **空掃描＝零違規＝綠，是本守衛最危險的失效形態**：掃描根算錯、walk 提早 return、
// 或副檔名判斷寫錯，都會讓守衛安靜地什麼都沒檢查。現況 876 檔，取 700 為保守下界。
const minScannedGoFiles = 700

// positiveControlFile／positiveControlImport 防假綠第二道（正向對照）。
//
// 檔數下限只證明「走到了很多檔案」，不證明「import 真的被讀出來」——
// 一個恆回傳空 import 清單的抽取器同樣會全綠。故要求在這個具名檔案上
// **實際看到**這個具名 import；看不到就代表抽取路徑壞了，此時的零違規不成立。
// 選 go-runewidth 是因為它正是本次自 indirect 提升為 direct 的那一個，
// 兩件事會一起壞、也會一起被發現。
const (
	positiveControlFile   = "internal/vtscreen/screen.go"
	positiveControlImport = "github.com/mattn/go-runewidth"
)

// goImportIndex 為一次全樹掃描的結果。
type goImportIndex struct {
	// imports：import 路徑 → 出現該 import 的檔案（相對 module 根，slash 分隔）
	imports map[string][]string
	// files 掃描到的 .go 檔數
	files int
}

// scanGoImports 走訪整棵原始碼樹，抽出每個 .go 檔的 import 路徑。
//
// 刻意用 `go/parser` 的 ImportsOnly 而不是純文字 grep：
// grep 會把註解、設計文件引用、本守衛自己的清單一起算成違規，
// 逼人為了轉綠而刪掉說明文字——那是把守衛做成噪音的標準路徑。
// 禁的是「程式碼真的引用了它」，不是「這個字串出現過」。
func scanGoImports(t *testing.T, root string) goImportIndex {
	t.Helper()
	idx := goImportIndex{imports: map[string][]string{}}
	fset := token.NewFileSet()

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// 版控與相依快取不是我們的原始碼；vendor 若存在也不由本守衛管
			switch d.Name() {
			case ".git", "node_modules", "vendor":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)

		file, parseErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if parseErr != nil {
			// 剖析失敗＝這個檔案的 import 沒被檢查過，不得當作「沒有違規」帶過
			t.Errorf("剖析 %s 失敗，其 import 未被檢查（殘缺掃描上的「零違規」不成立）：%v", rel, parseErr)
			return nil
		}
		idx.files++
		for _, spec := range file.Imports {
			p, unquoteErr := strconv.Unquote(spec.Path.Value)
			if unquoteErr != nil {
				t.Errorf("%s 的 import 路徑 %s 無法解析：%v", rel, spec.Path.Value, unquoteErr)
				continue
			}
			idx.imports[p] = append(idx.imports[p], rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("走訪原始碼樹 %s 失敗：%v", root, err)
	}
	return idx
}

// TestNoUnlicensedDependencyInGoModAndSum 斷言禁止清單上的 module 不在 go.mod／go.sum。
//
// go.sum 與 go.mod 都要驗：只驗 go.mod 的話，`go mod tidy` 尚未跑過的中間狀態
// （require 已刪、雜湊還在）會被判為乾淨，而那份 go.sum 仍然指名了該套件。
func TestNoUnlicensedDependencyInGoModAndSum(t *testing.T) {
	root := unlicensedDepModuleRoot(t)

	for _, name := range []string{"go.mod", "go.sum"} {
		body, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("讀取 %s 失敗：%v", name, err)
		}
		// 防假綠：檔案讀成空的同樣會「沒有違規」
		if len(body) == 0 {
			t.Fatalf("%s 是空的：掃描目標失真，此時的零違規不成立", name)
		}

		for _, dep := range forbiddenDeps {
			var hits []string
			for i, line := range strings.Split(string(body), "\n") {
				trimmed := strings.TrimSpace(line)
				// 註解行不算違規：go.mod 內本來就寫得下「為什麼某個依賴被移除」，
				// 把說明也判成違規只會逼人刪掉說明來轉綠。
				// require 指令不可能是註解行，故這個豁免不會漏掉真正的復活。
				if strings.HasPrefix(trimmed, "//") {
					continue
				}
				if strings.Contains(line, dep.modulePath) {
					hits = append(hits, fmt.Sprintf("    %s:%d: %s", name, i+1, trimmed))
				}
			}
			if len(hits) > 0 {
				t.Errorf("%s 又出現了無授權依賴 %s\n%s\n  禁用理由：%s\n  改用：%s\n"+
					"  修法：移除該 require 後於容器內跑 `go mod tidy`",
					name, dep.modulePath, strings.Join(hits, "\n"), dep.reason, dep.replacement)
			}
		}
	}
}

// TestNoUnlicensedDependencyImportedInTree 斷言全樹沒有任何 .go 檔 import 禁止清單上的套件。
//
// 與 go.mod 那一條不重疊：import 先於 require 出現（有人貼上一段舊碼、還沒跑 tidy），
// 此時 go.mod 仍乾淨而原始碼已經引用了它；反之刪光 import 卻忘了 tidy 則相反。
// 兩端各守一邊，才涵蓋整條復活路徑。
func TestNoUnlicensedDependencyImportedInTree(t *testing.T) {
	root := unlicensedDepModuleRoot(t)
	idx := scanGoImports(t, root)

	if idx.files < minScannedGoFiles {
		t.Fatalf("只掃到 %d 個 .go 檔（下限 %d）：掃描範圍失真，此時的零違規不成立",
			idx.files, minScannedGoFiles)
	}
	if got := idx.imports[positiveControlImport]; !containsFile(got, positiveControlFile) {
		t.Fatalf("正向對照失敗：%s 未被記錄為 import 了 %s（實得 %v）\n"+
			"  這代表 import 抽取路徑壞了，不是「沒有違規」",
			positiveControlFile, positiveControlImport, got)
	}
	t.Logf("掃描 %d 個 .go 檔、%d 個相異 import 路徑；正向對照 %s → %s 命中",
		idx.files, len(idx.imports), positiveControlFile, positiveControlImport)

	for _, dep := range forbiddenDeps {
		var hits []string
		for path, files := range idx.imports {
			if path != dep.modulePath && !strings.HasPrefix(path, dep.modulePath+"/") {
				continue
			}
			sorted := append([]string(nil), files...)
			sort.Strings(sorted)
			hits = append(hits, fmt.Sprintf("    %s ← %s", path, strings.Join(sorted, ", ")))
		}
		if len(hits) > 0 {
			sort.Strings(hits)
			t.Errorf("原始碼樹又 import 了無授權依賴 %s\n%s\n  禁用理由：%s\n  改用：%s",
				dep.modulePath, strings.Join(hits, "\n"), dep.reason, dep.replacement)
		}
	}
}

// TestForbiddenDepsEntriesAreUsable 防止清單腐爛成沒有射程的死條文。
func TestForbiddenDepsEntriesAreUsable(t *testing.T) {
	if len(forbiddenDeps) == 0 {
		t.Fatal("禁止清單是空的：本守衛此刻什麼都沒守")
	}
	seen := map[string]bool{}
	for _, dep := range forbiddenDeps {
		switch {
		case strings.TrimSpace(dep.modulePath) == "":
			t.Error("禁止清單有條目缺少 modulePath")
		case seen[dep.modulePath]:
			t.Errorf("禁止清單重複登記 %s", dep.modulePath)
		case strings.TrimSpace(dep.reason) == "":
			t.Errorf("%s 沒有寫禁用理由：說不出為什麼禁，下一個趕時間的人就會把它刪掉", dep.modulePath)
		case strings.TrimSpace(dep.replacement) == "":
			t.Errorf("%s 沒有寫替代方案：踩到守衛卻不知道該往哪走，只會逼人繞過守衛", dep.modulePath)
		}
		seen[dep.modulePath] = true
	}
}

func containsFile(files []string, want string) bool {
	for _, f := range files {
		if f == want {
			return true
		}
	}
	return false
}
