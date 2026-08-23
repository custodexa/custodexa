package main

// 來源位址單一取法的 AST 守衛。
//
// # 守的是什麼
//
// 審計列的 `client_ip` 一旦取自 `c.ClientIP()`，在**未設 TRUSTED_PROXIES** 的部署下
// 就由請求方的轉送標頭決定（gin 未呼叫 SetTrustedProxies 時信任全部代理）。零憑證可達的三處先修掉，
// 其餘 33 處隨後收口。這類偏差的共同形態是：
// **改回去以後所有測試照樣綠**，審計列上仍有一個看起來很正常的 IP。
//
// # 為什麼判準是「全庫禁用」而不是「審計寫入路徑禁用」
//
// 「哪些呼叫點算審計寫入路徑」沒有機械判準——`ClientIP` 會經過參數、結構欄位、
// service 呼叫層層傳遞（`groupService.Create(..., ip)`、`contractSubject(ip)`、
// `createSession(..., ip)`），要判定某個呼叫點的值最終有沒有流進審計列，等於做
// 跨包污點分析；而任何近似判定都會留下「這處不算審計路徑」的爭辯空間，那正是
// 人工清單的入口。**全庫禁用＋單一豁免**沒有這個空間：判準是「檔案路徑是不是
// 那唯一一份實作」，新增的呼叫點一律轉紅，不需要任何人記得去登記什麼。
//
// 豁免表刻意只有一項，且新增豁免必須改這個檔——它是被審視的動作，不是填表。
//
// # 第二道：不得繞過本函式自己讀轉送標頭
//
// 只禁 `c.ClientIP()` 的話，`c.GetHeader("X-Forwarded-For")` 是等價的繞道（同樣
// 由請求方控制）。故另禁六個轉送標頭名以**字串字面量**形式出現在產品碼——AST 掃
// BasicLit，註解裡的說明不受影響（本檔與 sourceip 包的說明文字即大量提及它們）。

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// sourceIPSoleImplFile 全庫唯一允許呼叫 `ClientIP()` 的檔（相對 module 根）。
//
// **不是「允許清單」而是「那一份實作的位置」**：這裡多一個條目，就等於承認同一條
// 紀律又分了一次家。要改動它請連同 internal/sourceip 的包註解一起改。
const sourceIPSoleImplFile = "internal/sourceip/sourceip.go"

// forwardedIPHeaders 由請求方控制、可用來冒充來源位址的標頭名。
//
// 前三個是 gin `RemoteIPHeaders` 與 `Forwarded` 標準；後三個是 CDN／WAF 慣例——
// 產品碼一旦自己讀其中任何一個當來源，就繞過了 internal/sourceip 的判定。
var forwardedIPHeaders = []string{
	"x-forwarded-for",
	"x-real-ip",
	"forwarded",
	"true-client-ip",
	"cf-connecting-ip",
	"x-client-ip",
}

// TestClientIPHasSingleImplementation 產品碼中 `ClientIP()` 只准出現在唯一實作內。
//
// 掃描範圍＝module 根下全部非測試 `.go`（含 cmd／config／internal／pkg）。**不排除
// 任何子樹**：排除規則本身就是下一個缺口——當初的三處分家實作分別住在
// api／middleware 兩個包，任何「只掃 internal/api」的守衛都看不到它們。
//
// 測試檔不掃：`_test.go` 內的 `c.ClientIP()` 多半正是在斷言「gin 預設會採信標頭」
// 這件事（見 internal/api/oidc_abuse_guard_test.go），禁掉它等於禁掉反向證明。
func TestClientIPHasSingleImplementation(t *testing.T) {
	root := auditPointModuleRoot(t)
	sole := filepath.FromSlash(sourceIPSoleImplFile)

	var offenders []string
	soleSeen := false
	walkGoSources(t, root, func(rel string, fset *token.FileSet, f *ast.File) {
		hits := 0
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "ClientIP" || len(call.Args) != 0 {
				return true
			}
			hits++
			if rel != sole {
				offenders = append(offenders,
					fmt.Sprintf("%s:%d", rel, fset.Position(call.Pos()).Line))
			}
			return true
		})
		if rel == sole && hits > 0 {
			soleSeen = true
		}
	})

	if !soleSeen {
		t.Fatalf("%s 內找不到任何 ClientIP() 呼叫——唯一實作被搬家或改名時本守衛會掃空而假綠；"+
			"請同步更新 sourceIPSoleImplFile", sourceIPSoleImplFile)
	}
	if len(offenders) > 0 {
		t.Errorf("下列產品碼直接呼叫 ClientIP()（共 %d 處）：%v\n"+
			"來源位址一律走 internal/sourceip（未設 TRUSTED_PROXIES 時不採信轉送標頭）："+
			"直接呼叫在未設可信代理的部署下，等於讓請求方自選審計列上的來源位址，"+
			"而這種偏差不會讓任何行為測試轉紅",
			len(offenders), offenders)
	}
}

// TestForwardedHeadersNotReadDirectly 產品碼不得自己讀轉送標頭。
//
// 這是上一條的繞道封堵：`c.GetHeader("X-Forwarded-For")` 拿到的值與 `c.ClientIP()`
// 同樣由請求方控制，卻不會被上一條掃到。判準取「字串字面量」而非呼叫形態——
// 讀法可以有很多種（GetHeader／Request.Header.Get／Header.Values／map 索引），
// 標頭名卻總得寫出來。
func TestForwardedHeadersNotReadDirectly(t *testing.T) {
	root := auditPointModuleRoot(t)
	sole := filepath.FromSlash(sourceIPSoleImplFile)

	var offenders []string
	walkGoSources(t, root, func(rel string, fset *token.FileSet, f *ast.File) {
		if rel == sole {
			return
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			val := strings.ToLower(strings.Trim(lit.Value, "`\""))
			for _, h := range forwardedIPHeaders {
				if val == h {
					offenders = append(offenders,
						fmt.Sprintf("%s:%d %s", rel, fset.Position(lit.Pos()).Line, lit.Value))
				}
			}
			return true
		})
	})

	if len(offenders) > 0 {
		t.Errorf("下列產品碼出現轉送標頭字面量：%v\n"+
			"這些標頭由請求方控制，讀它們取來源位址與直接呼叫 ClientIP() 等價；"+
			"來源位址一律走 internal/sourceip（該包由 gin 的可信代理鏈判定是否採信）",
			offenders)
	}
}

// walkGoSources 走訪 module 根下全部非測試 `.go` 並解析。
//
// 解析失敗一律 Fatal：守衛不在殘缺 AST 上作判定（沿用 audit_sink_boundary 的紀律）。
// 跳過 vendor 與隱藏目錄；`testdata` 亦跳過（那是資料不是產品碼）。
func walkGoSources(t *testing.T, root string, visit func(rel string, fset *token.FileSet, f *ast.File)) {
	t.Helper()
	scanned := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (name == "vendor" || name == "testdata" ||
				strings.HasPrefix(name, ".")) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("解析 %s 失敗（守衛不在殘缺 AST 上作判定）: %v", rel, perr)
		}
		scanned++
		visit(rel, fset, f)
		return nil
	})
	if err != nil {
		t.Fatalf("走訪 %s 失敗: %v", root, err)
	}
	if scanned < 100 {
		t.Fatalf("只掃到 %d 個產品碼檔案——掃描根或過濾條件失效，守衛正在對空氣作判定", scanned)
	}
}
