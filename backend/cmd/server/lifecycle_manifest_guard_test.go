package main

// lifecycle manifest 雙向完備性守衛（modular-architecture W1 任務 1.4）。
//
// **為什麼需要它**：Phase B 要把 223 檔的扁平 `internal/service` 拆成 7 個 Go
// package。拆包會改變「包級變數初始化 → init() → 組裝根的注入／註冊 → 啟動步驟
// → 停止／reset／zeroize」這條時序鏈，而現有的 build／test／路由 golden **全部
// 證明不了啟停等價**——測試各自建構自己的 DB 與服務，不走真實啟動路徑。順序在
// 搬遷中被改掉的症狀是隱性的：某段窗口的審計未蓋章、關閉時金鑰未清零、注入失敗
// 未回滾。故先把「現實中有哪些具時序語義的項目」凍結成 manifest，再以本守衛雙向釘住：
//
//	方向 1（manifest → 現實）：manifest 每一列的錨點鍵必須在程式碼中真的存在。
//	方向 2（現實 → manifest）：程式碼中每一個該類項目都必須在 manifest 內。
//
// 反向斷言是關鍵（比照 internal/service/post_unseal_guard_test.go:213-216 的紀律）：
// 只驗方向 1 的守衛在「程式碼新增了未登記的全域／hook」時仍然全綠，而那正是
// 搬遷期最容易發生的事。
//
// **與 manifest-audit-points.md 的分工**：審計 manifest 登記「審計列的**寫入點**」
// （在誰的交易內、走哪個 sink 變體）；本 manifest 登記同一批符號的「**註冊時序**」
// 面向（何時被注入、相對誰必須先／後、釋放時的反序位置）。兩者互補不重複——
// 例如 `model.SetAuditCreateHooks` 在審計 manifest 是「蓋章與 tee 的掛載點」，
// 在本 manifest 是「必須早於任何會寫審計列的步驟、且釋放時必須先解 hook 再解單例」。
//
// **掃描式守衛的兩個假綠孔已顯式堵上**（R4 實證既有守衛踩過）：
//   - 掃描根不用「本檔目錄往上跳 N 層」推算，改以 go.mod 的 module 行當身分錨點；
//   - 載入包數、掃描檔數、各類項目數皆有下限，且 `len(pkg.Errors) > 0` 一律 t.Fatal
//     ——否則搬檔後掃描範圍靜默縮小，守衛會在空集合下全綠。
//
// **manifest 的 file:line 欄不受守衛對帳**（guard-scan-cost-reduction B 段撤除
// TestLifecycleManifestAnchorsMatchSourceLines）。三個理由：manifest 位於
// openspec/changes/archive/ 之下，逐行對帳等於要求持續改寫已歸檔的歷史紀錄；
// file:line 是純定位資訊，不承載代碼表達不了的人工決定（manifest 真正無可取代的
// 是「順序敏感理由」欄）；specs/module-boundaries 全文未要求逐行對帳。
// 該欄自此僅供讀碼入口參考，**可能過期**。列的語義仍由錨點鍵（檔＋符號名）承載，
// 那一側由本檔的雙向完備性守衛獨立釘住，未受影響。

import (
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"

	"golang.org/x/tools/go/packages"
)

// ── 受管常數 ──────────────────────────────────────────────────────────────

// lifecycleModulePath 掃描根的身分錨點：go.mod 的 module 行必須完全等於此值。
const lifecycleModulePath = "github.com/custodexa/backend"

// lifecycleManifestRel manifest 相對 change 目錄的路徑。
//
// **單一來源、不留副本**：權威檔在 repo 根的 openspec/ 下；docker 掛載點、host 直跑與
// 歸檔後（任意日期前綴）三種佈局的解析統一由 `openspecManifestPath` 承擔，見
// `openspec_manifest_path_test.go` 的檔頭說明（含「找不到即 Fatal」「找到複本即 Fatal」
// 兩條刻意保留的 fail-close）。
const lifecycleManifestRel = "research/manifest-lifecycle.md"

// minLifecyclePackages `packages.Load("./...")` 的載入包數下限。
// 現況 26 個包；取 24 為保守下界。**遷移只會增加包（internal/modules/*），
// 不會減少**，故此下限在十波期間恆有效；掉到下限以下代表掃描範圍失真。
const minLifecyclePackages = 24

// minLifecycleScannedFiles 非測試 .go 檔的掃描下限（現況 291，取 250）。
const minLifecycleScannedFiles = 250

// minLifecycleGlobals 個別登記的包級全域下限（現況 134，取 110）。
const minLifecycleGlobals = 110

// minLifecycleHookSites 組裝根注入／註冊呼叫點下限（現況 44，取 35）。
const minLifecycleHookSites = 35

// minLifecycleFieldInjections 組裝根裸欄位注入（`inject:`）的筆數下限（現況 11，取 8）。
// 這一類**整批消失**（例如判準被放寬到零命中、或組裝根改用複合字面量建元件）不會
// 讓任何逐項比對轉紅——反向斷言只看「現實有的都登記了」，空集合恆滿足。故另設下限。
const minLifecycleFieldInjections = 8

// minLifecycleStartupSteps 段 2 啟動步驟的**字面量** mark() 呼叫點下限
// （現況 30；另 5 項由排程器迴圈以 mark(s.name) 追加，執行期共 35，見
// TestLifecycleManifestStartupMatchesServiceInventory）。取 25 為下界。
const minLifecycleStartupSteps = 25

// lifecycleAssemblyPkgs 「組裝根」的包路徑：注入／註冊呼叫點只在此範圍內登記。
// 具名而非以目錄前綴推算——組裝根搬家時要當場失敗，不是靜靜地少驗一個包。
var lifecycleAssemblyPkgs = map[string]bool{
	lifecycleModulePath + "/cmd/server": true,
}

// lifecycleHookCalleeExclusions 形態像注入、實際不是的呼叫（逐條附理由）。
// 這是燒盡制清單：新增排除項 SHALL 附理由，否則等於默許守衛涵蓋面縮水。
var lifecycleHookCalleeExclusions = map[string]string{
	"SetTrustedProxies": "gin 內建的 engine 設定（cmd/server/main.go、stage1.go），非服務注入",
	"SetMode":           "gin 內建的執行模式設定（gin.SetMode），非服務注入",
	"RegisterRoutes":    "路由註冊，已由 TestRouteRegistrationConfinedToRegisterRoutes 與路由 golden 專責守衛",
	"WithTimeout":       "context 標準庫的衍生 context（cmd/server/main.go:211），非服務注入",
	"WithCancel":        "context 標準庫的衍生 context，非服務注入",
	"WithDeadline":      "context 標準庫的衍生 context，非服務注入",
	"WithValue":         "context 標準庫的衍生 context，非服務注入",
}

// ── 現實側：資料型別 ──────────────────────────────────────────────────────

type lcItem struct {
	Key  string // 錨點鍵，與 manifest 第 2 欄同格式
	File string // 相對 module 根，slash 分隔
	Line int
	Desc string // 錯誤訊息用的補充描述
}

type lcScan struct {
	Items       []lcItem       // 需逐項登記者（var／init／hook／singleton）
	ClassCounts map[string]int // 摺疊類別（class:*）的實際筆數
	Ordered     map[string][]lcItem
	Packages int
	Files    int
	// Err 掃描失敗的原因（載入錯誤、包數低於下限、pkg.Errors 非空）。
	//
	// **為什麼失敗不在掃描函式內直接 t.Fatalf**：掃描結果由本包五支守衛共用單次
	// 載入，而 sync.Once 內拿到的 `t` 屬於第一個進入的測試。在其中 Fatal 只會讓
	// 那一支紅，其餘四支拿到零值 lcScan 並在空集合上全綠——守衛數量與錯誤訊息
	// 看起來都正常，射程卻是零。故失敗寫進本欄，由每個呼叫者各自 Fatal。
	Err error
}

// ── 掃描根定位 ────────────────────────────────────────────────────────────

// lifecycleModuleRoot 由本測試檔位置向上找 go.mod，並核對 module 行。
// 不用「Dir(Caller)/../..」的層數推算：那在守衛檔搬家時會靜默指到別處（R4 F-掃描根）。
func lifecycleModuleRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller 取本檔路徑失敗，掃描根無從定位")
	}
	dir := filepath.Dir(self)
	for {
		gomod := filepath.Join(dir, "go.mod")
		if body, err := os.ReadFile(gomod); err == nil {
			want := "module " + lifecycleModulePath
			for _, line := range strings.Split(string(body), "\n") {
				if strings.TrimSpace(line) == want {
					return dir
				}
			}
			t.Fatalf("在 %s 找到 go.mod，但 module 行不是 %q：掃描根定位錨點失效，守衛可能正在掃錯的樹",
				gomod, lifecycleModulePath)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("自 %s 向上找不到 go.mod（module %s）：掃描根無從定位", filepath.Dir(self), lifecycleModulePath)
		}
		dir = parent
	}
}

// lifecycleManifestPath 解析 manifest 路徑（docker 掛載點／host repo 根／歸檔後任意日期前綴）。
// **一律不 Skip**：找不到即 Fatal——「守衛沒跑」與「守衛通過」必須可分辨。
func lifecycleManifestPath(t *testing.T, root string) string {
	t.Helper()
	return openspecManifestPath(t, root, openspecChangeDirName, lifecycleManifestRel)
}

// ── 現實側：掃描 ──────────────────────────────────────────────────────────

var (
	lifecycleScanOnce  sync.Once
	lifecycleScanCache lcScan
)

// scanLifecycle 取（並快取）全樹掃描結果，本包五支守衛共用。
//
// 快取的理由是成本：帶完整型別資訊的全 module packages.Load 單次約 40 秒
// （guard-scan-cost-reduction 基準量測），掃五次是純重複——五支守衛看的是
// 同一棵樹的同一份事實，沒有任何一支會改動它。
//
// 快取也讓五支守衛必然看到**同一份**輸入：否則「登記項不存在」與「實際項未登記」
// 可能建立在兩次不同的掃描上，兩邊的錯誤訊息會互相矛盾。
//
// 失敗處理見 lcScan.Err 的說明——不在 Once 內 Fatal。
func scanLifecycle(t *testing.T, root string) lcScan {
	t.Helper()
	lifecycleScanOnce.Do(func() { lifecycleScanCache = runLifecycleScan(root) })
	if lifecycleScanCache.Err != nil {
		t.Fatalf("%v", lifecycleScanCache.Err)
	}
	return lifecycleScanCache
}

// runLifecycleScan 實際執行一次全樹掃描。
//
// 不接 *testing.T：本函式在 sync.Once 內執行，任何 t 都只屬於第一個進入者。
// 下限斷言與 pkg.Errors 檢查一律改為寫入 lcScan.Err——**這兩道防假綠管線的
// 判準值與時機不變**，只是每包執行一次而非五次。
func runLifecycleScan(root string) lcScan {
	fail := func(format string, args ...any) lcScan {
		return lcScan{Err: fmt.Errorf(format, args...)}
	}
	fset := token.NewFileSet()
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedSyntax | packages.NeedTypes | packages.NeedImports | packages.NeedDeps,
		Dir:   root,
		Fset:  fset,
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return fail("packages.Load 失敗（守衛無法在無視野下宣稱通過）: %v", err)
	}
	if len(pkgs) < minLifecyclePackages {
		return fail("只載入 %d 個包（下限 %d）：掃描範圍已失真，守衛將在近乎空集合下假綠",
			len(pkgs), minLifecyclePackages)
	}
	// pkg.Errors 非空即失敗：帶著載入／型別錯誤的樹，其 AST 可能殘缺，
	// 掃不到的項目會被當成「現實中不存在」而讓反向斷言假綠。
	for _, p := range pkgs {
		if len(p.Errors) > 0 {
			return fail("包 %s 有 %d 個載入／型別錯誤（首個：%v）：守衛拒絕在殘缺的 AST 上作判定",
				p.PkgPath, len(p.Errors), p.Errors[0])
		}
	}

	s := lcScan{
		ClassCounts: map[string]int{},
		Ordered:     map[string][]lcItem{},
		Packages:    len(pkgs),
	}
	rel := func(abs string) string {
		r, err := filepath.Rel(root, abs)
		if err != nil {
			return abs
		}
		return filepath.ToSlash(r)
	}

	for _, p := range pkgs {
		isAssembly := lifecycleAssemblyPkgs[p.PkgPath]
		for _, f := range p.Syntax {
			path := fset.Position(f.Pos()).Filename
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			rf := rel(path)
			s.Files++
			scanFileDecls(&s, fset, f, rf)
			if isAssembly {
				scanAssemblyFile(&s, fset, f, rf)
			}
		}
	}

	sort.Slice(s.Items, func(i, j int) bool {
		if s.Items[i].File != s.Items[j].File {
			return s.Items[i].File < s.Items[j].File
		}
		return s.Items[i].Line < s.Items[j].Line
	})
	return s
}

// scanFileDecls 收「包級全域」「init()」「單例式 Init／Reset／Zeroize 函式宣告」三類。
func scanFileDecls(s *lcScan, fset *token.FileSet, f *ast.File, rf string) {
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			line := fset.Position(d.Pos()).Line
			name := d.Name.Name
			if d.Recv == nil && name == "init" {
				s.Items = append(s.Items, lcItem{
					Key: "init:" + rf + ":init", File: rf, Line: line, Desc: "init()",
				})
				continue
			}
			if isLifecycleFuncName(name) {
				recv := recvTypeName(d)
				key := "singleton:" + rf + ":" + name
				desc := "func " + name
				if recv != "" {
					key = "singleton:" + rf + ":" + recv + "." + name
					desc = "func (" + recv + ") " + name
				}
				s.Items = append(s.Items, lcItem{Key: key, File: rf, Line: line, Desc: desc})
			}
		case *ast.GenDecl:
			if d.Tok != token.VAR {
				continue
			}
			for _, spec := range d.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, n := range vs.Names {
					line := fset.Position(n.Pos()).Line
					var val ast.Expr
					if len(vs.Values) == len(vs.Names) {
						val = vs.Values[i]
					} else if len(vs.Values) == 1 {
						val = vs.Values[0]
					}
					if cls := collapseClassOf(rf, n.Name, val); cls != "" {
						s.ClassCounts[cls]++
						continue
					}
					s.Items = append(s.Items, lcItem{
						Key: "var:" + rf + ":" + n.Name, File: rf, Line: line, Desc: "var " + n.Name,
					})
				}
			}
		}
	}
}

// isLifecycleFuncName 具生命週期語義的函式名判準（單例建立／解除／材料歸零）。
func isLifecycleFuncName(name string) bool {
	switch {
	case strings.HasPrefix(name, "Init") && hasUpperAfter(name, len("Init")):
		return true
	case strings.HasPrefix(name, "Reset") && hasUpperAfter(name, len("Reset")):
		return true
	case strings.HasSuffix(name, "ForRelease"):
		return true
	}
	return false
}

func hasUpperAfter(s string, i int) bool {
	return len(s) > i && s[i] >= 'A' && s[i] <= 'Z'
}

func recvTypeName(d *ast.FuncDecl) string {
	if d.Recv == nil || len(d.Recv.List) == 0 {
		return ""
	}
	switch e := d.Recv.List[0].Type.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.StarExpr:
		if id, ok := e.X.(*ast.Ident); ok {
			return id.Name
		}
	}
	return "?"
}

// collapseClassOf 判定包級全域是否屬於「同質摺疊類別」。
//
// 摺疊而非逐條登記的三類都不承載時序語義，且數量大到逐條登記會淹沒真正的
// 時序項；但**每一類在 manifest 內都有一列 `class:*` 並帶筆數下限**，故類別
// 整批消失（＝掃描範圍縮水）仍會轉紅。
func collapseClassOf(file, name string, val ast.Expr) string {
	if name == "_" {
		return "class:blank"
	}
	call, ok := val.(*ast.CallExpr)
	if !ok {
		return ""
	}
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if x, ok := sel.X.(*ast.Ident); ok {
			if (x.Name == "errors" && sel.Sel.Name == "New") || (x.Name == "fmt" && sel.Sel.Name == "Errorf") {
				return "class:sentinel"
			}
		}
	}
	if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "register" &&
		strings.HasPrefix(file, "internal/apierror/") {
		return "class:apierror-code"
	}
	return ""
}

// scanAssemblyFile 收組裝根特有的五類：注入／註冊呼叫點、**裸欄位注入**、啟動步驟、
// 釋放登記、關閉步驟。
//
// 本函式的 `ast.Inspect` 只認 `*ast.CallExpr` 與 `*ast.CompositeLit`，故
// `handler.Field = service` 這種**不經任何函式呼叫**的注入原本整類在射程外
// （實證：拆掉 `sshHandler.AccessPolicy = accessPolicyService` 後 `./cmd/server`
// 全綠）。裸欄位注入改由 scanAssemblyFieldInjections 承接。
func scanAssemblyFile(s *lcScan, fset *token.FileSet, f *ast.File, rf string) {
	scanAssemblyFieldInjections(s, fset, f, rf)
	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			line := fset.Position(node.Pos()).Line
			switch fun := node.Fun.(type) {
			case *ast.SelectorExpr:
				callee := fun.Sel.Name
				if callee == "AddFunc" && len(node.Args) > 0 {
					if lit := stringLit(node.Args[0]); lit != "" {
						s.Ordered["release"] = append(s.Ordered["release"], lcItem{
							Key: "release:" + rf + ":" + lit, File: rf, Line: line, Desc: lit,
						})
					}
					return true
				}
				if isHookCallee(callee) {
					s.Items = append(s.Items, lcItem{
						Key:  "hook:" + rf + ":" + exprName(fun.X) + "." + callee,
						File: rf, Line: line, Desc: exprName(fun.X) + "." + callee,
					})
				}
			case *ast.Ident:
				if fun.Name == "mark" && len(node.Args) > 0 {
					// 非字面量引數（`mark(s.name)`，現況唯一一處是排程器群的迴圈）不入
					// 有序序列：步驟名在執行期才決定，取不到可比對的字面量。那一群步驟的
					// 登記序改由 lifecycle_startup_shutdown_test.go 的
					// expectedReleaseRegistration 逐位釘住。
					if lit := stringLit(node.Args[0]); lit != "" {
						s.Ordered["step"] = append(s.Ordered["step"], lcItem{
							Key: "step:" + lit, File: rf, Line: line, Desc: lit,
						})
					}
					return true
				}
				if isHookCallee(fun.Name) {
					s.Items = append(s.Items, lcItem{
						Key:  "hook:" + rf + ":" + fun.Name,
						File: rf, Line: line, Desc: fun.Name,
					})
				}
			}
		case *ast.CompositeLit:
			id, ok := node.Type.(*ast.Ident)
			if !ok || id.Name != "shutdownStep" || len(node.Elts) == 0 {
				return true
			}
			if lit := stringLit(node.Elts[0]); lit != "" {
				s.Ordered["shutdown"] = append(s.Ordered["shutdown"], lcItem{
					Key: "shutdown:" + lit, File: rf, Line: fset.Position(node.Pos()).Line, Desc: lit,
				})
			}
		}
		return true
	})
}

// scanAssemblyFieldInjections 收「組裝根對自建元件的裸欄位注入」（`inject:`）。
//
// **界定問題**：`x.F = y` 在一個檔案裡有很多形態，絕大多數不是注入——方法內對
// receiver 欄位賦值（`s.journal = j`）、對組態結構賦值（`c.AllowCredentials = true`）、
// 對圖狀態記錄（`g.auditService = …`）、對
// 切片元素欄位賦值（`starts[0].start = …`）。全收會製造數十列與時序無關的登記，
// 而**淹沒的 manifest 等於沒有 manifest**（沒人會逐列讀它，漂移就無人察覺）。
//
// 故判準是三個條件的合取，每一條都對應「組裝根注入」這件事的一個結構特徵：
//
//	1. `=` 而非 `:=`／`+=`——注入是「補上依賴」，不是宣告或累加；
//	2. 左值是 `base.Field` 且 `base` 是**純識別字**、`Field` 為**匯出欄位**——
//	   排除 `starts[0].start` 這類容器元素，以及未匯出的內部狀態記錄（`g.built`、
//	   `s.journal`）：未匯出欄位只能由同包寫，本質上不是跨層注入面；
//	3. `base` 是**同一函式內由建構子 `New*` 建出的區域變數**——即「組裝根親手建了
//	   這個元件，現在正在把它的依賴接齊」。這一條把 receiver、參數、以及
//	   複合字面量建出的第三方組態結構（`cors.Config{…}`、`&identity.OIDCEgressPolicy{…}`）
//	   全數排除，而它們正是雜訊的來源。
//
// **殘留缺口（明說而非假裝沒有）**：以複合字面量建出的自家元件（`h := &api.Foo{}`
// 後接 `h.Dep = svc`）不在射程內。本樹現況零此形態；若日後出現，補的是條件 3
// 的建構判準（isConstructorCall），不是把整條規則放寬到「所有欄位賦值」。
// 另有 minLifecycleFieldInjections 下限守著「整類靜默歸零」。
func scanAssemblyFieldInjections(s *lcScan, fset *token.FileSet, f *ast.File, rf string) {
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		built := constructedLocals(fn.Body)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || as.Tok != token.ASSIGN {
				return true
			}
			for _, lhs := range as.Lhs {
				sel, ok := lhs.(*ast.SelectorExpr)
				if !ok {
					continue
				}
				base, ok := sel.X.(*ast.Ident)
				if !ok || !built[base.Name] {
					continue
				}
				if !hasUpperAfter(sel.Sel.Name, 0) {
					continue
				}
				name := base.Name + "." + sel.Sel.Name
				s.Items = append(s.Items, lcItem{
					Key:  "inject:" + rf + ":" + name,
					File: rf, Line: fset.Position(as.Pos()).Line, Desc: name + " = …（裸欄位注入）",
				})
			}
			return true
		})
	}
}

// constructedLocals 收本函式體內以 `:=` 自建構子建出的區域變數名。
// 多回傳值（`svc, err := pkg.NewX(...)`）以第 0 個左值對應唯一的右值呼叫。
func constructedLocals(body *ast.BlockStmt) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || as.Tok != token.DEFINE {
			return true
		}
		for i, lhs := range as.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok {
				continue
			}
			var rhs ast.Expr
			switch {
			case len(as.Rhs) == len(as.Lhs):
				rhs = as.Rhs[i]
			case len(as.Rhs) == 1 && i == 0:
				rhs = as.Rhs[0]
			}
			if rhs != nil && isConstructorCall(rhs) {
				out[id.Name] = true
			}
		}
		return true
	})
	return out
}

// isConstructorCall 判定運算式是否為 `New*` 建構子呼叫，含 `pkg.NewX(...)`、
// `NewX(...)` 與鏈式 `pkg.NewX(...).WithY(...)`。
// 刻意**不**認 `gin.New()`／`errors.New()`：`hasUpperAfter` 要求 `New` 之後還有
// 大寫字母，故裸 `New` 不成立——那類回傳的是框架物件與哨兵，不是本樹的元件。
func isConstructorCall(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return strings.HasPrefix(fun.Name, "New") && hasUpperAfter(fun.Name, len("New"))
	case *ast.SelectorExpr:
		if strings.HasPrefix(fun.Sel.Name, "New") && hasUpperAfter(fun.Sel.Name, len("New")) {
			return true
		}
		return isConstructorCall(fun.X)
	}
	return false
}

// isHookCallee 注入／註冊呼叫點的 callee 名判準。
//
// **前綴集合是涵蓋面本身，不是風格偏好**：H-42c（`WithWatermarks`）與 H-41c
// （裸欄位賦值）兩次都是「注入形態落在判準外 ⇒ 拆掉它零測試轉紅」，前一次的修法
// 是改程式碼去遷就判準（改名為 `SetWatermarks`、改為 setter）。改程式碼只關掉當下
// 那一個孔，下一個人寫下一個 `WithX` 又會漏，故此處改為擴充判準本身。
//
// 收錄的四組「把依賴接上去」慣用前綴：`Set`／`Init`／`Register`／`Reset`（原有）、
// 以及 `With`／`Use`（流暢式選項與策略切換，現實各 1 例）、`Attach`／`Bind`
// （同語義的近鄰慣用語，現實 0 例——**先收錄比事後補收錄安全**：多收的代價是
// 一列 manifest 登記或一條附理由的排除項，漏收的代價是整類注入無人看守）。
// 未收錄 `Enable`／`Configure`／`Mount`：那三個在本樹的語義偏「設定與路由掛載」，
// 且 `Mount` 與已由路由 golden 專責的註冊域重疊。
func isHookCallee(name string) bool {
	if _, excluded := lifecycleHookCalleeExclusions[name]; excluded {
		return false
	}
	for _, p := range []string{"Set", "Init", "Register", "Reset", "With", "Use", "Attach", "Bind"} {
		if strings.HasPrefix(name, p) && hasUpperAfter(name, len(p)) {
			return true
		}
	}
	return strings.HasSuffix(name, "ForRelease")
}

func stringLit(e ast.Expr) string {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	return strings.Trim(lit.Value, "`\"")
}

func exprName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprName(v.X) + "." + v.Sel.Name
	case *ast.CallExpr:
		return exprName(v.Fun) + "()"
	case *ast.StarExpr:
		return "*" + exprName(v.X)
	case *ast.IndexExpr:
		return exprName(v.X) + "[]"
	}
	return "?"
}

// ── manifest 側：解析 ─────────────────────────────────────────────────────

type lcRow struct {
	ID      string
	Key     string
	Item    string
	Loc     string
	Kind    string
	Module  string
	Wave    string
	Reason  string
	DocLine int
}

var lcKeyPrefixes = []string{"var:", "init:", "hook:", "inject:", "singleton:", "step:", "release:", "shutdown:", "class:"}

// parseLifecycleManifest 解析 manifest 的全部登記列。
//
// 判準為「第 2 欄是受管前綴的錨點鍵」——表頭、分隔列、散文與附錄表格因此自然被
// 排除，不需要維護一份「哪些表要解析」的清單（那份清單本身就是漂移來源）。
func parseLifecycleManifest(t *testing.T, path string) []lcRow {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("讀取 lifecycle manifest %s 失敗（守衛不得在缺檔時跳過）: %v", path, err)
	}
	var rows []lcRow
	for i, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "|") {
			continue
		}
		cols := splitTableRow(trimmed)
		if len(cols) < 8 {
			continue
		}
		key := cols[1]
		managed := false
		for _, p := range lcKeyPrefixes {
			if strings.HasPrefix(key, p) {
				managed = true
				break
			}
		}
		if !managed {
			continue
		}
		row := lcRow{
			ID: cols[0], Key: key, Item: cols[2], Loc: cols[3], Kind: cols[4],
			Module: cols[5], Wave: cols[6], Reason: cols[7], DocLine: i + 1,
		}
		if row.ID == "" || row.Reason == "" {
			t.Errorf("manifest L%d：ID 或順序敏感理由為空（%s）——理由欄不得空泛或留白", row.DocLine, key)
		}
		rows = append(rows, row)
	}
	return rows
}

func splitTableRow(line string) []string {
	parts := strings.Split(strings.Trim(line, "|"), "|")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

// ── 守衛 ──────────────────────────────────────────────────────────────────

// TestLifecycleManifestIsBidirectionallyComplete 逐項類（var／init／hook／singleton）雙向完備。
//
// 以**多重集合**比對而非集合：同一檔內同名 callee 可以合法出現多次
// （例：`model.SetAuditCreateHooks` 在 stage2.go 出現兩次——註冊與解除），
// 兩次語義不同且都具時序敏感性，故必須各佔 manifest 一列；筆數變動同樣要轉紅。
func TestLifecycleManifestIsBidirectionallyComplete(t *testing.T) {
	root := lifecycleModuleRoot(t)
	scan := scanLifecycle(t, root)
	rows := parseLifecycleManifest(t, lifecycleManifestPath(t, root))

	if scan.Files < minLifecycleScannedFiles {
		t.Fatalf("只掃到 %d 個非測試 .go 檔（下限 %d）：掃描範圍失真", scan.Files, minLifecycleScannedFiles)
	}

	realCount := map[string]int{}
	realFirst := map[string]lcItem{}
	nGlobals, nHooks, nInjects := 0, 0, 0
	for _, it := range scan.Items {
		realCount[it.Key]++
		if _, ok := realFirst[it.Key]; !ok {
			realFirst[it.Key] = it
		}
		switch {
		case strings.HasPrefix(it.Key, "var:"):
			nGlobals++
		case strings.HasPrefix(it.Key, "hook:"):
			nHooks++
		case strings.HasPrefix(it.Key, "inject:"):
			nInjects++
		}
	}
	if nGlobals < minLifecycleGlobals {
		t.Fatalf("只掃到 %d 個個別登記的包級全域（下限 %d）：摺疊規則或掃描範圍已失真", nGlobals, minLifecycleGlobals)
	}
	if nHooks < minLifecycleHookSites {
		t.Fatalf("只掃到 %d 個組裝根注入／註冊呼叫點（下限 %d）：組裝根定位或排除清單已失真",
			nHooks, minLifecycleHookSites)
	}
	if nInjects < minLifecycleFieldInjections {
		t.Fatalf("只掃到 %d 個組裝根裸欄位注入（下限 %d）：注入判準（scanAssemblyFieldInjections）"+
			"或組裝根定位已失真，該類將在空集合下假綠", nInjects, minLifecycleFieldInjections)
	}

	docCount := map[string]int{}
	docFirst := map[string]lcRow{}
	for _, r := range rows {
		if strings.HasPrefix(r.Key, "step:") || strings.HasPrefix(r.Key, "release:") ||
			strings.HasPrefix(r.Key, "shutdown:") || strings.HasPrefix(r.Key, "class:") {
			continue
		}
		docCount[r.Key]++
		if _, ok := docFirst[r.Key]; !ok {
			docFirst[r.Key] = r
		}
	}

	// 方向 1：manifest → 現實
	var stale []string
	for key, n := range docCount {
		got := realCount[key]
		if got == 0 {
			stale = append(stale, fmt.Sprintf("%s（manifest L%d）", key, docFirst[key].DocLine))
			continue
		}
		if got != n {
			stale = append(stale, fmt.Sprintf("%s：manifest 登記 %d 列、現實 %d 處（manifest L%d）",
				key, n, got, docFirst[key].DocLine))
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("[manifest→現實] 下列 %d 項登記與現實不符：\n  %s\n"+
			"符號被刪除／改名／搬包時 SHALL 同步更新 manifest 的錨點鍵與所在波次（tasks 2.6 形態）",
			len(stale), strings.Join(stale, "\n  "))
	}

	// 方向 2：現實 → manifest（關鍵方向）
	var missing []string
	for key, n := range realCount {
		if docCount[key] == n {
			continue
		}
		if docCount[key] == 0 {
			it := realFirst[key]
			missing = append(missing, fmt.Sprintf("%s（%s:%d %s）", key, it.File, it.Line, it.Desc))
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("[現實→manifest] 下列 %d 個具時序語義的項目未登記於 lifecycle manifest：\n  %s\n"+
			"新增包級全域／init()／組裝根注入點／單例 Init/Reset/Zeroize SHALL 同步登記，"+
			"並寫明「若順序反了會發生什麼」。未登記者在拆包時沒有任何東西擋著它被重排。",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// minLifecycleUniqueIDs manifest 受管列的 ID 數下限（現況 302，取 260）。
// 唯一性斷言在空集合上恆成立，故另設下限：解析失真時要當場紅，不是靜靜地驗零列。
const minLifecycleUniqueIDs = 260

// TestLifecycleManifestIDsAreUnique manifest 的 ID 欄必須全域唯一。
//
// **為什麼需要**：ID 是這份 manifest 對外的引用把手——散文、其他列的「同 G-127 型」
// 交叉引用、change 的 tasks 與 PR 討論都靠它指認某一列。ID 撞號時所有這些引用都變成
// 二義的：讀者以為在看白名單那一列，實際落在保留鍵那一列，而兩列的安全語義毫不相干。
// 撞號在 HEAD 已經發生過（`checkpointUpdatableColumns` 與 `dataRetentionKeys` 同為
// G-127，兩者由同一個 change 的不同組別各自新增），且沒有任何東西擋著它。
//
// 錨點鍵的多重集合比對不涵蓋這件事：它比的是第 2 欄，ID 在第 1 欄，撞號完全不影響它。
func TestLifecycleManifestIDsAreUnique(t *testing.T) {
	root := lifecycleModuleRoot(t)
	rows := parseLifecycleManifest(t, lifecycleManifestPath(t, root))

	if len(rows) < minLifecycleUniqueIDs {
		t.Fatalf("manifest 只解析到 %d 列受管列（下限 %d）：解析器或檔案已失真，"+
			"唯一性斷言將在近乎空集合上假綠", len(rows), minLifecycleUniqueIDs)
	}

	seen := map[string][]lcRow{}
	for _, r := range rows {
		seen[r.ID] = append(seen[r.ID], r)
	}
	var dup []string
	for id, rs := range seen {
		if len(rs) < 2 {
			continue
		}
		var where []string
		for _, r := range rs {
			where = append(where, fmt.Sprintf("L%d %s", r.DocLine, r.Key))
		}
		sort.Strings(where)
		dup = append(dup, fmt.Sprintf("%s ×%d：%s", id, len(rs), strings.Join(where, " ／ ")))
	}
	sort.Strings(dup)
	if len(dup) > 0 {
		t.Errorf("manifest 有 %d 個重複的 ID：\n  %s\n"+
			"ID 是本檔對外的引用把手（散文交叉引用、tasks、PR 討論都以它指認某一列），"+
			"撞號會讓所有引用二義化——讀者以為在看 A 列，實際落在語義毫不相干的 B 列。\n"+
			"新增列時 SHALL 取一個未使用的新號（不得沿用同批工作的號碼），"+
			"而不是把兩列併成一個號。",
			len(dup), strings.Join(dup, "\n  "))
	}
	t.Logf("lifecycle manifest ID 唯一性：%d 列、%d 個 ID", len(rows), len(seen))
}

// TestLifecycleManifestCollapsedClassesHaveFloor 摺疊類別的筆數下限。
//
// 摺疊類別（error 哨兵／apierror 碼／空白識別字）逐條登記無助於時序判讀，但
// **整批消失＝掃描範圍縮水**，那正是假綠的來源。故各自在 manifest 佔一列並帶下限。
func TestLifecycleManifestCollapsedClassesHaveFloor(t *testing.T) {
	root := lifecycleModuleRoot(t)
	scan := scanLifecycle(t, root)
	rows := parseLifecycleManifest(t, lifecycleManifestPath(t, root))

	floors := map[string]int{}
	for _, r := range rows {
		if !strings.HasPrefix(r.Key, "class:") {
			continue
		}
		var n int
		if _, err := fmt.Sscanf(r.Item, "%d", &n); err != nil {
			t.Fatalf("manifest L%d：摺疊類別 %s 的「項目」欄須以筆數下限開頭（實得 %q）", r.DocLine, r.Key, r.Item)
		}
		floors[r.Key] = n
	}
	if len(floors) == 0 {
		t.Fatal("manifest 未登記任何 class:* 摺疊類別：摺疊規則失去下限保護，整批消失時守衛會假綠")
	}
	for cls, got := range scan.ClassCounts {
		floor, ok := floors[cls]
		if !ok {
			t.Errorf("[現實→manifest] 摺疊類別 %s（現實 %d 筆）未登記於 manifest", cls, got)
			continue
		}
		if got < floor {
			t.Errorf("摺疊類別 %s 實得 %d 筆，低於 manifest 登記的下限 %d：掃描範圍縮水或該類被整批移除",
				cls, got, floor)
		}
	}
	for cls := range floors {
		if _, ok := scan.ClassCounts[cls]; !ok {
			t.Errorf("[manifest→現實] manifest 登記的摺疊類別 %s 在現實中零命中", cls)
		}
	}
}

// TestLifecycleManifestOrderedSequencesMatch 三條有序序列逐位對齊。
//
// 這是本守衛真正釘住「順序」的一項：啟動步驟、釋放登記、關閉步驟三者的**順序本身**
// 就是契約（ResourceBag 以 LIFO 釋放，故登記序決定釋放序），manifest 的列序必須與
// 程式碼的出現序逐位相同。任何搬遷造成的重排會在此當場失敗，而不是在某個窗口
// 靜靜地少蓋一個章或少歸零一段金鑰。
func TestLifecycleManifestOrderedSequencesMatch(t *testing.T) {
	root := lifecycleModuleRoot(t)
	scan := scanLifecycle(t, root)
	rows := parseLifecycleManifest(t, lifecycleManifestPath(t, root))

	for _, kind := range []string{"step", "release", "shutdown"} {
		var want, got []string
		for _, r := range rows {
			if strings.HasPrefix(r.Key, kind+":") {
				want = append(want, r.Key)
			}
		}
		for _, it := range scan.Ordered[kind] {
			got = append(got, it.Key)
		}
		if len(got) == 0 {
			t.Fatalf("現實側掃到 0 個 %s 項：掃描器或組裝根已失真，序列比對將在空集合下假綠", kind)
		}
		if kind == "step" {
			// 啟動步驟：字面量 mark() 只有 30 處，排程器群另以迴圈 mark(s.name)
			// 追加 5 項，故 manifest 的 35 列與字面量序列不是等長關係。此處斷言
			// 「字面量序列是 manifest 序列的**有序子序列**」——重排任何一個字面量
			// 步驟都會使子序列比對失敗；那 5 個迴圈項則由 stage2ServiceInventory
			// 的逐位等值比對（下一個測試）涵蓋，兩者合起來覆蓋全部 35 項。
			if len(got) < minLifecycleStartupSteps {
				t.Fatalf("段 2 啟動步驟只掃到 %d 個字面量 mark()（下限 %d）", len(got), minLifecycleStartupSteps)
			}
			j := 0
			for _, w := range want {
				if j < len(got) && got[j] == w {
					j++
				}
			}
			if j != len(got) {
				t.Errorf("段 2 啟動步驟的字面量序列不是 manifest 序列的有序子序列"+
					"（對齊到第 %d／%d 項，卡在 %q）：步驟被重排或 manifest 未同步。\n  manifest=%v\n  現實字面量=%v\n"+
					"順序即契約：注入晚於使用者即是「某段窗口未生效」，而那不會有任何編譯或測試失敗",
					j, len(got), got[min(j, len(got)-1)], want, got)
			}
			continue
		}
		if len(want) != len(got) {
			t.Errorf("%s 序列長度不符：manifest %d 項、現實 %d 項\n  manifest=%v\n  現實=%v",
				kind, len(want), len(got), want, got)
			continue
		}
		for i := range want {
			if want[i] != got[i] {
				t.Errorf("%s 序列第 %d 位不符：manifest=%q、現實=%q（%s:%d）\n"+
					"順序即契約：釋放以 LIFO 進行，登記序被重排等同於釋放序被重排",
					kind, i+1, want[i], got[i], scan.Ordered[kind][i].File, scan.Ordered[kind][i].Line)
			}
		}
	}
}

// TestLifecycleManifestStartupMatchesServiceInventory 啟動步驟序 ⇄ stage2ServiceInventory。
//
// `stage2ServiceInventory` 已由既有守衛與 appGraph.ServiceNames() 逐項比對
// （stage2.go:48/123），本測試把 manifest 接上同一條鏈：manifest 的 step 序
// SHALL 逐位等於清單。三方對齊之後，manifest 不是平行維護的文件，而是
// 「執行期真的按此順序建構」的可執行斷言的一環。
//
// 註：`mark()` 的字面量呼叫點有 30 處，但排程器群以迴圈 mark(s.name) 追加 5 項，
// 故執行期為 35 項——清單比對涵蓋迴圈那 5 項，字面量序列比對涵蓋其餘。
func TestLifecycleManifestStartupMatchesServiceInventory(t *testing.T) {
	root := lifecycleModuleRoot(t)
	rows := parseLifecycleManifest(t, lifecycleManifestPath(t, root))

	var want []string
	for _, r := range rows {
		if strings.HasPrefix(r.Key, "step:") {
			want = append(want, strings.TrimPrefix(r.Key, "step:"))
		}
	}
	if len(want) != len(stage2ServiceInventory) {
		t.Fatalf("manifest 的啟動步驟 %d 項 ≠ stage2ServiceInventory 的 %d 項\n  manifest=%v\n  清單=%v",
			len(want), len(stage2ServiceInventory), want, stage2ServiceInventory)
	}
	for i := range want {
		if want[i] != stage2ServiceInventory[i] {
			t.Errorf("啟動步驟第 %d 位不符：manifest=%q、stage2ServiceInventory=%q",
				i+1, want[i], stage2ServiceInventory[i])
		}
	}
}

// TestLifecycleScanDump 現實側清單傾印（維護用，不承擔守衛責任）。
//
// `LIFECYCLE_DUMP=1 go test ./cmd/server -run TestLifecycleScanDump -v` 列出掃到的
// 全部項目，供新增／位移後重建 manifest 表格。
func TestLifecycleScanDump(t *testing.T) {
	if os.Getenv("LIFECYCLE_DUMP") != "1" {
		t.Skip("設 LIFECYCLE_DUMP=1 以傾印 lifecycle 清單（維護工具，守衛責任由上列測試承擔）")
	}
	root := lifecycleModuleRoot(t)
	scan := scanLifecycle(t, root)
	fmt.Printf("PKGS\t%d\tFILES\t%d\n", scan.Packages, scan.Files)
	for cls, n := range scan.ClassCounts {
		fmt.Printf("CLASS\t%s\t%d\n", cls, n)
	}
	for _, it := range scan.Items {
		fmt.Printf("ITEM\t%s\t%s:%d\t%s\n", it.Key, it.File, it.Line, it.Desc)
	}
	for _, kind := range []string{"step", "release", "shutdown"} {
		for i, it := range scan.Ordered[kind] {
			fmt.Printf("ORD\t%s\t%d\t%s\t%s:%d\n", kind, i+1, it.Key, it.File, it.Line)
		}
	}
}
