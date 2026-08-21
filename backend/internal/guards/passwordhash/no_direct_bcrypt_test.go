// Package passwordhash 守衛：產品程式碼不得直接呼叫密碼雜湊演算法函式庫。
//
// 抽出 `pkg/crypto` 的 Hasher／Verifier 之後，若有人在別處直接 import bcrypt，
// 那一處就換不掉演算法——而換演算法正是抽這層介面的唯一動機。
// 「請大家都走介面」寫在文件裡等於沒寫（goal-charter §7：誠實邊界要機器可見），
// 故以掃描釘死。
package passwordhash

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// forbiddenImports 密碼雜湊演算法的函式庫。新增演算法實作時一併登記。
var forbiddenImports = []string{
	"golang.org/x/crypto/bcrypt",
	"golang.org/x/crypto/argon2",
	"golang.org/x/crypto/pbkdf2",
	"crypto/pbkdf2",
	"golang.org/x/crypto/scrypt",
}

// allowedFiles 唯一得以直接 import 的位置＝`pkg/crypto` 的實作檔本身。
//
// **射程刻意只排除實作檔，不排除整個 pkg/crypto 目錄**：
// 若日後有人在 pkg/crypto 下新增一個繞過介面的 helper，這個守衛仍要抓到。
var allowedFiles = map[string]bool{
	filepath.Join("pkg", "crypto", "password_hasher.go"): true,
}

// TestNoDirectPasswordHashImport 掃描全部**非測試**的產品程式碼。
//
// 為什麼排除測試檔：測試需要以低成本參數快速產生雜湊，
// 且測試不構成產品的可換演算法射程。但**產品碼一處都不准**。
func TestNoDirectPasswordHashImport(t *testing.T) {
	root := repoBackendRoot(t)

	var violations []string
	scanned := 0

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// 掃描射程外：相依套件、建置產物、暫存
			switch info.Name() {
			case "vendor", "node_modules", ".git", "tmp":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		if allowedFiles[rel] {
			return nil
		}

		scanned++
		f, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if parseErr != nil {
			return parseErr
		}
		for _, imp := range f.Imports {
			p, uErr := strconv.Unquote(imp.Path.Value)
			if uErr != nil {
				continue
			}
			for _, bad := range forbiddenImports {
				if p == bad {
					violations = append(violations,
						rel+" 直接 import "+bad)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("掃描失敗: %v", err)
	}

	// 掃描下限：射程若因搬檔而掃空，這個守衛會靜默地永遠通過。
	// 訂在一個遠低於現況、但高於「幾乎沒掃到」的值。
	const minScanned = 200
	if scanned < minScanned {
		t.Fatalf("只掃到 %d 個產品 .go 檔（下限 %d）——射程可能已失效，"+
			"守衛會靜默通過。請確認掃描根與排除規則", scanned, minScanned)
	}

	if len(violations) > 0 {
		t.Errorf("產品程式碼直接使用密碼雜湊函式庫（%d 處），"+
			"這些位置換不掉演算法，須改經 pkg/crypto 的 Hasher／Verifier：\n  %s",
			len(violations), strings.Join(violations, "\n  "))
	}
	t.Logf("已掃描 %d 個產品 .go 檔，允許清單 %d 筆", scanned, len(allowedFiles))
}

// repoBackendRoot 由本測試檔位置往上找到 backend 根（含 go.mod 者）。
func repoBackendRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("取得工作目錄失敗: %v", err)
	}
	for i := 0; i < 10; i++ {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("找不到含 go.mod 的 backend 根目錄")
	return ""
}

// TestAllowedFilesExist 允許清單裡的檔案必須真的存在。
//
// **這條防的是允許清單的靜默失效**：檔案被改名或刪除後，清單裡的路徑就永遠不會命中，
// 而守衛看起來還是綠的——實際上該檔若重新出現在別處就抓不到了。
func TestAllowedFilesExist(t *testing.T) {
	root := repoBackendRoot(t)
	for rel := range allowedFiles {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			t.Errorf("允許清單的 %s 不存在（%v）——清單已與現況脫節，守衛射程有洞", rel, err)
		}
	}
}

var _ = ast.Print // 保留 go/ast 依賴的顯式引用，避免 import 被自動移除
