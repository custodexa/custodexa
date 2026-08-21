package sshproxy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// 無碼錯誤幀守衛（backend-i18n-unification D7 收尾）
//
// 語義：MsgError／MsgNotice 幀必須帶 apierror registry 碼，因此只能由
// EncodeErrorMessage／EncodeCodedErrorMessage／EncodeNoticeMessage 產生。
// `EncodeMessage(MsgError, "認證失敗")` 這條路徑會產出無 Code 欄的幀，
// 前端無從查譯——D7 的收口就從這一行漏光。
//
// 為什麼需要 AST 守衛而非只靠執行期檢查：EncodeMessage 的執行期防護
// （message.go）只在該行真的被跑到時才報，且失敗表現是「使用者什麼都沒收到」。
// 靜態掃描讓它在 CI 就紅，是「長久守衛不可被繞過」的那一半。
//
// 兩者不可互相取代，也不可只留一個：
//   - 執行期：擋得住編譯期看不見的 MessageType 變數；
//   - 靜態：擋得住「寫了但沒被測試覆蓋到」的死角。
// ---------------------------------------------------------------------------

// codedFrameScanDirs 是本守衛的掃描範圍（相對 backend/）。
// internal/proxy 目前不引用 sshproxy 的編碼函式，納入是為了「日後搬過去也照抓」。
var codedFrameScanDirs = []string{"internal/sshproxy", "internal/proxy"}

// codedFrameTypes 是必須帶碼的幀型別常數名。
var codedFrameTypes = map[string]bool{"MsgError": true, "MsgNotice": true}

// minCodedFrameScannedFiles 防假綠：掃描範圍被誤縮時測試會綠得毫無意義。
// 兩套件實測 20 檔（非測試碼），門檻取 15。
const minCodedFrameScannedFiles = 15

// codedFrameModulePath 掃描根的身分錨點：go.mod 的 module 行必須完全等於此值。
const codedFrameModulePath = "github.com/custodexa/backend"

// codedFrameBackendRoot 定位 backend module 根。
//
// **不用固定層數 `..`**（modular-architecture W1 1.20）：`Dir(caller)/../..`
// 與「本 package 住在樹的第幾層」綁死，package 下移一層就指向 internal/，
// 掃描根隨之失真而守衛在錯的子樹上掃出零違規。改以「向上找 go.mod 並核對
// module 行」為身分錨點；錨點失效即 panic，不回傳可疑路徑。
func codedFrameBackendRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("runtime.Caller 取本檔路徑失敗，掃描根無從定位")
	}
	dir := filepath.Dir(file)
	for {
		if body, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
			want := "module " + codedFrameModulePath
			for _, line := range strings.Split(string(body), "\n") {
				if strings.TrimSpace(line) == want {
					return dir
				}
			}
			panic("在 " + dir + "/go.mod 的 module 行不是 \"" + want +
				"\"：掃描根定位錨點失效，守衛可能正在掃錯的樹")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			panic("自 " + filepath.Dir(file) + " 向上找不到 go.mod（module " +
				codedFrameModulePath + "）：掃描根無從定位")
		}
		dir = parent
	}
}

// codedFrameTypeName 回傳運算式所指的幀型別常數名（`MsgError` 或
// `sshproxy.MsgError` 兩種寫法），非識別字形態回空字串。
func codedFrameTypeName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return v.Sel.Name
	}
	return ""
}

// isEncodeMessageCall 回報 call 是否為 EncodeMessage（含 sshproxy.EncodeMessage）。
func isEncodeMessageCall(call *ast.CallExpr) bool {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name == "EncodeMessage"
	case *ast.SelectorExpr:
		return fun.Sel.Name == "EncodeMessage"
	}
	return false
}

// scanUncodedErrorFrames 回傳檔內所有 `EncodeMessage(MsgError|MsgNotice, ...)`
// 的位置（rel:line 形式）。
func scanUncodedErrorFrames(fset *token.FileSet, f *ast.File, rel string) []string {
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isEncodeMessageCall(call) || len(call.Args) == 0 {
			return true
		}
		name := codedFrameTypeName(call.Args[0])
		if codedFrameTypes[name] {
			out = append(out, rel+":"+strconv.Itoa(fset.Position(call.Pos()).Line)+" ("+name+")")
		}
		return true
	})
	return out
}

// collectCodedFrameFiles 回傳 dirs 下所有非測試 .go（相對 root，斜線分隔）。
func collectCodedFrameFiles(root string, dirs []string) ([]string, error) {
	var out []string
	for _, d := range dirs {
		abs := filepath.Join(root, filepath.FromSlash(d))
		err := filepath.Walk(abs, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				if name := info.Name(); path != abs && (name == "testdata" || name == "vendor") {
					return filepath.SkipDir
				}
				return nil
			}
			name := info.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				return nil
			}
			rel, rerr := filepath.Rel(root, path)
			if rerr != nil {
				return rerr
			}
			out = append(out, filepath.ToSlash(rel))
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(out)
	return out, nil
}

// TestNoUncodedErrorFrames 是「MsgError／MsgNotice 幀不得繞過碼化編碼器」的長久守衛。
func TestNoUncodedErrorFrames(t *testing.T) {
	root := codedFrameBackendRoot()

	files, err := collectCodedFrameFiles(root, codedFrameScanDirs)
	if err != nil {
		t.Fatalf("collect scan files: %v", err)
	}
	if len(files) < minCodedFrameScannedFiles {
		t.Errorf("掃描檔數 %d < 下限 %d——掃描範圍設定可能被誤縮，本測試已失去意義",
			len(files), minCodedFrameScannedFiles)
	}

	fset := token.NewFileSet()
	var violations []string
	for _, rel := range files {
		f, perr := parser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(rel)), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", rel, perr)
		}
		violations = append(violations, scanUncodedErrorFrames(fset, f, rel)...)
	}

	if len(violations) > 0 {
		t.Errorf("偵測到 %d 處以 EncodeMessage 產生的無碼錯誤／通知幀：\n  %s\n"+
			"MsgError 請改用 EncodeErrorMessage/EncodeCodedErrorMessage，MsgNotice 請用 EncodeNoticeMessage（D7）。",
			len(violations), strings.Join(violations, "\n  "))
	}
}

// TestCodedFrameScanDirsAreReal 釘掃描範圍確實存在。
func TestCodedFrameScanDirsAreReal(t *testing.T) {
	root := codedFrameBackendRoot()
	for _, d := range codedFrameScanDirs {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(d))); err != nil {
			t.Errorf("掃描目錄不存在: %s (%v)", d, err)
		}
	}
}

// TestUncodedErrorFrameDetector 正向控制：偵測器對每種繞法都抓得到，
// 對合法寫法不誤報。樣本移除後主守衛的「零違規」即為假綠。
func TestUncodedErrorFrameDetector(t *testing.T) {
	const src = `package sample

func f() {
	EncodeMessage(MsgData, "ok")                 // OK：不帶碼的幀本來就走這裡
	EncodeMessage(MsgResize, "{}")               // OK
	EncodeCodedErrorMessage(apierror.CodeX)      // OK：碼化編碼器
	EncodeNoticeMessage(apierror.CodeY, nil)     // OK
	EncodeMessage(MsgError, "認證失敗")           // 紅 1：無碼錯誤幀
	EncodeMessage(MsgNotice, "已阻斷")            // 紅 2：無碼通知幀
	sshproxy.EncodeMessage(sshproxy.MsgError, "跨套件寫法") // 紅 3
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "sample.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := scanUncodedErrorFrames(fset, f, "sample.go")
	if len(got) != 3 {
		t.Fatalf("偵測數 = %d %v, want 3", len(got), got)
	}
	for _, g := range got {
		if !strings.Contains(g, "MsgError") && !strings.Contains(g, "MsgNotice") {
			t.Errorf("錯誤訊息未標明幀型別: %s", g)
		}
	}

	// 反向：只有合法寫法時必須零違規（避免偵測器一律紅的假敏感）。
	cleanFset := token.NewFileSet()
	clean, err := parser.ParseFile(cleanFset,
		"clean.go", "package s\nfunc g() { EncodeMessage(MsgData, \"x\") }\n", 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if n := scanUncodedErrorFrames(cleanFset, clean, "clean.go"); len(n) != 0 {
		t.Errorf("合法寫法被誤報: %v", n)
	}
}
