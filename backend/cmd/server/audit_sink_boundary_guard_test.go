package main

// 收口邊界的三道守衛。
//
// 這三件事都屬於「**做了以後很難看得出來被改掉**」的類別：
//
//	4.5  三個 GORM hook 刻意維持直寫。日後有人「順手收口」把它們改走 sink，
//	     model 就得持一個包級全域 sink——設計上明確拒絕過的形態
//	     （可被漏接成 nil no-op 的全域旗標，`model/audit_log.go:164-183` 自陳）。
//	     改完之後所有測試照樣綠。
//	4.6  DirectSink 是唯一繞過 AuditLogEnabled 的落地面。它一旦被當成「比較好寫的
//	     sink」擴散使用，等於在受管路徑旁邊開了一條無管制的第三條寫入通道。
//	4.7  sink 未注入即拒絕啟動。這一行若被刪掉或降級為 log，症狀是「審計靜默消失
//	     而系統看起來正常」，且測試更綠。
//
// 掃描根一律以 go.mod 的 module 身分為錨點（沿用 auditPointModuleRoot），
// 不用 cwd 相對或固定層數。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// t3HookMethods 三個真 GORM hook（manifest AP-23／24／25）。
var t3HookMethods = map[string]bool{"AfterCreate": true, "AfterUpdate": true, "AfterDelete": true}

// t3HookFile 三個 hook 的所在檔（相對 module 根）。
const t3HookFile = "internal/model/asset_audit.go"

// TestT3HooksStayDetachedDirectWrites 4.5：三個 hook 維持現況直寫，且維持脫離呼叫方交易。
//
// 兩條斷言：
//  1. 每個 hook 的函式體內必須有 `Session(&gorm.Session{NewDB: true})` 的寫入——
//     這是它們「刻意脫離呼叫方交易」的唯一語法載體（manifest §4.2 訂正）。
//     它若消失，hook 會變成參與呼叫方交易，資產寫入的失敗語義整組改變。
//  2. `internal/model` SHALL NOT import 任何 sink 包。收口需要 model 認識 sink，
//     禁掉 import 就是禁掉那條路。
func TestT3HooksStayDetachedDirectWrites(t *testing.T) {
	root := auditPointModuleRoot(t)
	path := filepath.Join(root, t3HookFile)
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("解析 %s 失敗（守衛不在殘缺 AST 上作判定）: %v", t3HookFile, err)
	}

	found := map[string]bool{}
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Recv == nil || !t3HookMethods[fd.Name.Name] || fd.Body == nil {
			continue
		}
		found[fd.Name.Name] = true
		if !bodyHasDetachedCreate(fd.Body) {
			t.Errorf("%s.%s 內找不到 Session(&gorm.Session{NewDB: true}) 的寫入："+
				"三個 GORM hook 刻意脫離呼叫方交易（manifest AP-23…25 訂正），"+
				"改為參與呼叫方交易是行為變更，且不會有任何測試轉紅",
				t3HookFile, fd.Name.Name)
		}
	}
	if len(found) != len(t3HookMethods) {
		t.Fatalf("在 %s 只找到 %d 個 hook（期望 %d 個：%v）——"+
			"hook 被改名或搬家時本守衛會掃空而假綠", t3HookFile, len(found), len(t3HookMethods), found)
	}
}

func bodyHasDetachedCreate(body *ast.BlockStmt) bool {
	hit := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Session" || len(call.Args) != 1 {
			return true
		}
		// 引數必須是 &gorm.Session{NewDB: true} 形態
		unary, ok := call.Args[0].(*ast.UnaryExpr)
		if !ok || unary.Op != token.AND {
			return true
		}
		lit, ok := unary.X.(*ast.CompositeLit)
		if !ok {
			return true
		}
		for _, el := range lit.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != "NewDB" {
				continue
			}
			if v, ok := kv.Value.(*ast.Ident); ok && v.Name == "true" {
				hit = true
			}
		}
		return true
	})
	return hit
}

// forbiddenModelSinkImports model 包不得認識的 sink 包。
var forbiddenModelSinkImports = []string{
	"internal/modules/audit",
	"pkg/gatewayapi",
}

// TestModelPackageHasNoSinkImport 4.5 的第二半：堵死「model 持包級全域 sink」那條路。
func TestModelPackageHasNoSinkImport(t *testing.T) {
	root := auditPointModuleRoot(t)
	dir := filepath.Join(root, "internal", "model")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("讀取 internal/model 失敗: %v", err)
	}
	scanned := 0
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("解析 %s 失敗: %v", e.Name(), err)
		}
		scanned++
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbiddenModelSinkImports {
				if strings.Contains(p, bad) {
					t.Errorf("internal/model/%s import 了 %s：model 一旦認識 sink，"+
						"「三個 hook 改走全域 sink」就成為可行的下一步——"+
						"那是明確拒絕過的形態（可被漏接成 nil no-op 的全域旗標）",
						e.Name(), p)
				}
			}
		}
	}
	// 掃描檔數下限：model 包現況 40+ 檔；掃空即零違規是最危險的假綠形態
	if scanned < 20 {
		t.Fatalf("只掃到 %d 個 model 檔（下限 20）：掃描根失真，本守衛的「零違規」不成立", scanned)
	}
}

// directSinkAllowedConstructionFiles 允許建構 DirectSink 的檔（相對 module 根）。
//
// **只有組裝根**：DirectSink 繞過 AuditLogEnabled，是 C-plain 兩點（AP-04／AP-28）
// 的專用落地面。任何服務或 handler 自行 `NewDirectSink(db)` 就是繞過組裝根另開一條
// 無管制的寫入通道；要新增使用者必須在此列名，而那一行在 PR diff 裡必須被質問。
var directSinkAllowedConstructionFiles = map[string]bool{
	"cmd/server/stage2.go": true,
}

// TestDirectSinkIsConstructedOnlyAtAssemblyRoot 4.6：DirectSink 不得擴散使用。
func TestDirectSinkIsConstructedOnlyAtAssemblyRoot(t *testing.T) {
	root := auditPointModuleRoot(t)
	hits := scanCallsByName(t, root, "NewDirectSink")
	if len(hits) == 0 {
		t.Fatal("全庫掃不到任何 audit.NewDirectSink 呼叫：C-plain 兩點的落地面已消失，" +
			"或掃描失真——兩者都不該靜默通過")
	}
	for _, h := range hits {
		if strings.HasSuffix(h.file, "_test.go") {
			continue // 測試自建替身不受此限
		}
		if !directSinkAllowedConstructionFiles[h.file] {
			t.Errorf("%s:%d 建構了 DirectSink：它繞過 AuditLogEnabled，"+
				"只允許組裝根建構（現況 %v）。新增使用者 SHALL 先在 "+
				"directSinkAllowedConstructionFiles 列名並說明為何該點不受開關管制",
				h.file, h.line, directSinkAllowedConstructionFiles)
		}
	}
}

// TestAssemblyChecksAuditSinksAtStartup 4.7／5.4：組裝根確實有 sink 注入自檢。
//
// 斷言 stage2.go 同時呼叫 requireAuditTxSink、requireAuditAsyncSinks 與
// requireAlertSink，且**三者都在自己的
// `if err != nil { return fail(...) }` 形態內**——只呼叫不看回傳值等於沒檢查。
func TestAssemblyChecksAuditSinksAtStartup(t *testing.T) {
	root := auditPointModuleRoot(t)
	for _, name := range []string{"requireAuditTxSink", "requireAuditAsyncSinks", "requireAlertSink"} {
		hits := scanCallsByName(t, root, name)
		found := false
		for _, h := range hits {
			if h.file == "cmd/server/stage2.go" && h.insideIfErr {
				found = true
			}
		}
		if !found {
			t.Errorf("cmd/server/stage2.go 沒有「%s(...) 的結果進入 if err != nil 分支」的呼叫："+
				"sink 未注入時必須拒絕啟動（比照 InitAuditIntegrityVersioned），"+
				"SHALL NOT 降級為靜默略過或只記 log", name)
		}
	}
}

type callHit struct {
	file        string
	line        int
	insideIfErr bool
}

// scanCallsByName 全 module 掃某個函式名的呼叫點（含「是否位於 if err != nil 的 init 中」）。
func scanCallsByName(t *testing.T, root, name string) []callHit {
	t.Helper()
	var out []callHit
	scanned := 0
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if auditPointSkipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("解析 %s 失敗（守衛不在殘缺 AST 上作判定）: %v", rel, perr)
		}
		scanned++
		ast.Inspect(f, func(n ast.Node) bool {
			ifs, ok := n.(*ast.IfStmt)
			inIf := false
			if ok && ifs.Init != nil {
				if callsNamed(ifs.Init, name) {
					inIf = true
					out = append(out, callHit{file: rel, line: fset.Position(ifs.Pos()).Line, insideIfErr: true})
				}
			}
			if inIf {
				return true
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if calleeIdentName(call.Fun) == name {
				out = append(out, callHit{file: rel, line: fset.Position(call.Pos()).Line})
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("走訪 module 失敗: %v", err)
	}
	if scanned < minScannedGoFiles {
		t.Fatalf("只掃到 %d 個 .go 檔（下限 %d）：掃描根失真", scanned, minScannedGoFiles)
	}
	return out
}

func callsNamed(stmt ast.Stmt, name string) bool {
	hit := false
	ast.Inspect(stmt, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && calleeIdentName(call.Fun) == name {
			hit = true
		}
		return true
	})
	return hit
}

func calleeIdentName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}
