// Package offsitedelete 承載「offsite driver 的 Delete 唯一呼叫點」靜態守衛
// （防誤接雙層之 (b)；spec「遠端治理責任邊界」scenario
// 「刪除方法誤接被守衛擋下」）。
//
// # 守什麼
//
// 產品對遠端物件**不刪除**：保留清理只清本機，遠端到期清理由
// 部署方的 bucket lifecycle 承擔。driver 的 Delete 方法存在（未來擴充點、契約
// 測試涵蓋），但全產品非測試碼中它的唯一合法呼叫點＝測試連線清理自己的探測物
// （internal/offsite/testconnection.go 的 RunConnectionTest）。日後任何正式路徑
// 接上 Delete，本守衛即紅——除非連同下方登記一起改（即顯式決策）。
//
// # 怎麼判
//
// 全 module 型別掃描（沿 internal/guards/txtaking 的 packages.Load 形態）：
// 找出所有對「internal/offsite 包內宣告、名為 Delete」的方法呼叫——涵蓋
// Client 介面呼叫與 s3Client／gcsClient／FakeClient 具體型別呼叫；呼叫點所在檔
// 必須落在允許清單內。行為層的另一半（保留清理路徑對 fake 斷言零 Delete 呼叫）
// 由 worker 與 retention 的行為測試承擔。
//
// # 擋不住的事（誠實界定）
//
// 有 commit 權者可以刪掉本檔；也可以繞過 driver 直接以原生 SDK 對儲存端發
// DeleteObject——本守衛只覆蓋經 Client 契約的刪除通道。後者由 code review 與
// 「offsite 之外不 import 儲存 SDK」的相依慣例承擔，不在本守衛射程。
package offsitedelete

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// offsitePkgPath driver 契約的宿主包。
const offsitePkgPath = "github.com/custodexa/backend/internal/offsite"

// allowedDeleteCallFiles Delete 呼叫點的允許清單（相對 module 根）。
//
// **燒盡方向**：新增一列＝把一條正式路徑接上遠端刪除，屬遠端治理
// 責任邊界的變更，必須連同規格一起改，不是修測試。
var allowedDeleteCallFiles = map[string]string{
	"internal/offsite/testconnection.go": "測試連線清理自己的探測物（第 1 段）——" +
		"產品自己寫入的探測物，被 bucket 保留擋下時收斂 warn，不計入產品追蹤。",
}

// guardModulePath 掃描根核對錨點。
const guardModulePath = "github.com/custodexa/backend"

// guardModuleRoot 由本檔位置向上找 go.mod 並核對 module 行
// （慣例同 txtaking/doc_modroot_test.go：不以層數推算，防搬檔靜默指錯樹）。
func guardModuleRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller 取本檔路徑失敗，掃描根無從定位")
	}
	dir := filepath.Dir(self)
	for {
		gomod := filepath.Join(dir, "go.mod")
		if body, err := os.ReadFile(gomod); err == nil {
			want := "module " + guardModulePath
			for _, line := range strings.Split(string(body), "\n") {
				if strings.TrimSpace(line) == want {
					return dir
				}
			}
			t.Fatalf("在 %s 找到 go.mod，但 module 行不是 %q：掃描根定位錨點失效", gomod, guardModulePath)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("自 %s 向上找不到 go.mod（module %s）", filepath.Dir(self), guardModulePath)
		}
		dir = parent
	}
}

// minScanPackages packages.Load 的載入下限（txtaking 現況 32、取 24 同一保守下界）。
const minScanPackages = 24

// TestOffsiteDeleteCallSitesAreRegistered 全 module 非測試碼中，
// offsite Delete 方法的呼叫點必須逐一落在允許清單內；允許清單列的檔案
// 必須真的有呼叫點（防清單越留越寬）；且至少掃到一個呼叫點（偵測器健康——
// TestConnection 自己就呼叫 Delete，零命中＝掃描器失明而非「沒人呼叫」）。
func TestOffsiteDeleteCallSitesAreRegistered(t *testing.T) {
	root := guardModuleRoot(t)
	fset := token.NewFileSet()
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo |
			packages.NeedImports | packages.NeedDeps,
		Dir:   root,
		Fset:  fset,
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		t.Fatalf("packages.Load 失敗（守衛無法在無視野下宣稱通過）: %v", err)
	}
	if len(pkgs) < minScanPackages {
		t.Fatalf("只載入 %d 個包（下限 %d）：掃描範圍已失真", len(pkgs), minScanPackages)
	}
	for _, p := range pkgs {
		if len(p.Errors) > 0 {
			t.Fatalf("包 %s 有 %d 個載入／型別錯誤（首個：%v）：守衛拒絕在殘缺的 AST 上作判定",
				p.PkgPath, len(p.Errors), p.Errors[0])
		}
	}

	rel := func(abs string) string {
		r, err := filepath.Rel(root, abs)
		if err != nil {
			return abs
		}
		return filepath.ToSlash(r)
	}

	callSites := map[string][]string{} // file → []file:line
	scannedFiles := 0
	for _, p := range pkgs {
		if p.TypesInfo == nil {
			continue
		}
		for _, f := range p.Syntax {
			path := fset.Position(f.Pos()).Filename
			if strings.HasSuffix(path, "_test.go") {
				continue // 測試碼可自由呼叫（FakeClient 斷言、契約測試）
			}
			rf := rel(path)
			scannedFiles++
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Delete" {
					return true
				}
				if !isOffsiteDeleteMethod(p.TypesInfo, sel) {
					return true
				}
				site := rf + ":" + fmt.Sprint(fset.Position(call.Pos()).Line)
				callSites[rf] = append(callSites[rf], site)
				return true
			})
		}
	}
	if scannedFiles < 250 {
		t.Fatalf("只掃了 %d 個非測試檔（下限 250）：掃描面已失真", scannedFiles)
	}

	// 呼叫點必登記
	var violations []string
	for file, sites := range callSites {
		if _, ok := allowedDeleteCallFiles[file]; !ok {
			violations = append(violations, strings.Join(sites, ", "))
		}
	}
	sort.Strings(violations)
	if len(violations) > 0 {
		t.Errorf("以下呼叫點把正式路徑接上了 offsite driver 的 Delete：\n  %s\n"+
			"產品對遠端物件不刪除（遠端到期清理由部署方的 bucket lifecycle 承擔）。"+
			"要新增合法呼叫點＝責任邊界變更，須連同 design/spec 與本檔 allowedDeleteCallFiles 一起改。",
			strings.Join(violations, "\n  "))
	}

	// 登記檔必須真的有呼叫點（防清單越留越寬）
	var stale []string
	for file := range allowedDeleteCallFiles {
		if len(callSites[file]) == 0 {
			stale = append(stale, file)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("允許清單登記的檔案在現實中已無 Delete 呼叫點（移除須顯式更新清單）：\n  %s",
			strings.Join(stale, "\n  "))
	}

	// 偵測器健康：TestConnection 必然貢獻至少一個呼叫點
	total := 0
	for _, sites := range callSites {
		total += len(sites)
	}
	if total == 0 {
		t.Fatal("全樹掃不到任何 offsite Delete 呼叫點：偵測器已失明" +
			"（TestConnection 自己就呼叫 Delete），「零未登記呼叫」不構成證據")
	}
	t.Logf("offsite Delete 掃描：%d 包／%d 非測試檔／呼叫點 %d 個（全部落在允許清單）",
		len(pkgs), scannedFiles, total)
}

// isOffsiteDeleteMethod selector 指向的是否為 offsite 包內宣告的 Delete 方法
// （Client 介面方法，或 s3Client／gcsClient／FakeClient 等具體型別的方法——
// 以「方法宣告所在包」判定，涵蓋兩種呼叫形態；不看識別字拼法）。
func isOffsiteDeleteMethod(info *types.Info, sel *ast.SelectorExpr) bool {
	fn, ok := info.Uses[sel.Sel].(*types.Func)
	if !ok {
		return false
	}
	return fn.Pkg() != nil && fn.Pkg().Path() == offsitePkgPath
}
