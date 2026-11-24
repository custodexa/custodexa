package audit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// 交叉核對守衛：非測試程式中，對通道的 HTTP 送出只能發生在三條既定路徑——持久投遞程序、
// 測試發送、稽核失效的直接送出退路。產生點一律經排入介面，不得自行呼叫送出函式。
//
// 判準：本套件非測試檔中，對送出原語（deliverOnce、sendRenderedBody、sendToDestination）的呼叫，
// 以及 http.Client 的 Do 呼叫（以「唯一參數不是函式字面量」與 sync.Once.Do 區分），所在的函式
// 必須在 directSendAllowed 之內。

// directSendPrimitives 送出原語。
var directSendPrimitives = map[string]bool{"deliverOnce": true, "sendRenderedBody": true, "sendToDestination": true}

// directSendAllowed 可以呼叫送出原語或 http.Client.Do 的函式（名稱 → 所屬路徑）。
var directSendAllowed = map[string]string{
	"attemptSend":               "持久投遞程序的單筆送出",
	"postRendered":              "持久投遞程序的單筆送出（通道目的地與已解析位址的個人訊息共用）",
	"lookupSlackUser":           "個人訊息與傳給我自己的帳號查詢（以電子郵件查平台帳號，不送通知內容）",
	"SendTestNotificationShape": "測試發送（同步單次、不排入）",
	"directSendOne":             "稽核失效一族的直接送出退路",
	"deliverOnce":               "送出原語本身",
	"sendRenderedBody":          "送出原語本身",
	"sendToDestination":         "送出原語本身",
}

type directSendSite struct {
	Site string
	Func string
	Call string
}

// scanDirectSends 掃描 dir 下非測試 Go 檔，回傳不在允許函式內的送出呼叫。
func scanDirectSends(t *testing.T, dir string) (bad []directSendSite, total int) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("解析 %s 失敗: %v", name, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				label := ""
				switch fun := call.Fun.(type) {
				case *ast.Ident:
					if directSendPrimitives[fun.Name] {
						label = fun.Name
					}
				case *ast.SelectorExpr:
					if fun.Sel.Name == "Do" && len(call.Args) == 1 {
						if _, isFunc := call.Args[0].(*ast.FuncLit); !isFunc {
							label = "http.Client.Do"
						}
					}
				}
				if label == "" {
					return true
				}
				total++
				if _, ok := directSendAllowed[fn.Name.Name]; !ok {
					p := fset.Position(call.Pos())
					bad = append(bad, directSendSite{Site: name + ":" + strconv.Itoa(p.Line), Func: fn.Name.Name, Call: label})
				}
				return true
			})
		}
	}
	sort.Slice(bad, func(i, j int) bool { return bad[i].Site < bad[j].Site })
	return bad, total
}

func TestNoDirectSendOutsideDeliveryPaths(t *testing.T) {
	bad, total := scanDirectSends(t, ".")
	// 掃描下限：三條路徑的送出點與原語本身的 Do 呼叫至少 6 處，少於此即掃描失效
	if total < 6 {
		t.Fatalf("只掃到 %d 處送出呼叫，掃描失效", total)
	}
	for _, s := range bad {
		t.Errorf("%s：函式 %s 直接呼叫 %s，繞過排入介面；產生點一律經 EnqueueInTx／EnqueueStandalone（稽核失效一族經 EnqueueAuditFailureNotice）", s.Site, s.Func, s.Call)
	}
}

// TestDirectSendGuardSensitivity 守衛自檢：在產生點加回直接呼叫 deliverOnce，守衛要指出位置。
func TestDirectSendGuardSensitivity(t *testing.T) {
	dir := t.TempDir()
	src := "package audit\n\nfunc (s *AccessRequestService) notify() {\n\t_, _ = deliverOnce(nil, nil, nil)\n}\n\n" +
		"func directSendOne() {\n\t_, _ = sendRenderedBody(nil, ChannelDestination{}, nil)\n}\n\n" +
		"func loop() {\n\tonce.Do(func() {})\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	bad, total := scanDirectSends(t, dir)
	if total != 2 || len(bad) != 1 || bad[0].Site != "x.go:4" || bad[0].Func != "notify" {
		t.Fatalf("守衛應只指出 x.go:4 的 notify，實得 total=%d bad=%v", total, bad)
	}
}
