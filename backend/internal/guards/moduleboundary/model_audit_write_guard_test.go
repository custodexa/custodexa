package moduleboundary

// `internal/model` 的審計寫入面禁令（modular-architecture Phase B / W6 任務 6.2）。
//
// **擋的是什麼**：W6 把 T-2 的 11 個產生點自 `model.RecordAssetAccountChange`／
// `RecordAssetChange`／`RecordAssetNodeChange` 收口到 `audit/port.WriteInTx`，
// 那三個函式隨之自 `internal/model` 刪除。**復辟的形態不是有人硬要繞過守衛，
// 而是「下一個要在交易內記一筆審計的人，照著 model 裡現成的 hook 再寫一個
// helper」**——那正是「正常開發會意外發生」的錯誤（tasks.md 檔頭的加守衛判準），
// 且一旦發生，asset／identity 的審計寫入會再度對 audit 模組隱形。
//
// **為何判「AuditLog 字面量」而不是「識別字叫 Record*Change」**：識別字禁令只擋
// 得住同名復辟，改個名字就繞過；而任何在 model 層落地審計列的路徑**必然**要
// 建構一個 `AuditLog`。判字面量所以不依賴命名習慣。
//
// **與 4.5 `TestT3HooksStayDetachedDirectWrites` 的分工**：那一格釘住「三個 hook
// 仍以 `Session(NewDB:true)` 脫離呼叫方交易」（＝它們刻意不 fail-close）；
// 本格釘住「model 裡除了那三個 hook 之外沒有第四個審計產生點」。
// 前者管既有三點的語義，後者管總數，兩者缺一不可。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// modelAuditWriteAllowlist `internal/model` 中允許建構 AuditLog 的函式。
//
// 三個 T-3 GORM hook（tasks.md 4.5 裁決維持現況直寫，理由見 backlog B-1：
// model 不可 import 模組，改走 sink 需再造一個可漏接的包級全域）。
// **新增一列 SHALL 附理由並經審查**——這份清單是「model 層審計入口」的全集。
var modelAuditWriteAllowlist = map[string]string{
	"(*Asset).AfterCreate": "T-3：資產建立 hook，刻意脫離呼叫方交易（B-1）",
	"(*Asset).AfterUpdate": "T-3：資產更新 hook，同上",
	"(*Asset).AfterDelete": "T-3：資產刪除 hook，同上",
}

// minModelScannedFiles `internal/model` 非測試檔數下限（現況 37，取 30 為下界）。
// 掃空即「零違規」，那是最危險的通過形態。
const minModelScannedFiles = 30

// TestModelPackageHasNoNewAuditWriter model 層的審計產生點不得超出 T-3 三個 hook。
func TestModelPackageHasNoNewAuditWriter(t *testing.T) {
	root := lifecycleModuleRoot(t)
	dir := filepath.Join(root, "internal", "model")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("讀取 %s 失敗（掃描根失真，守衛不得宣稱通過）: %v", dir, err)
	}
	fset := token.NewFileSet()
	scanned := 0
	found := map[string][]string{} // 函式 → file:line
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		scanned++
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("解析 %s 失敗：守衛拒絕在殘缺的 AST 上作判定: %v", name, err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			owner := funcQualifiedName(fn)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				cl, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				id, ok := cl.Type.(*ast.Ident)
				if !ok || id.Name != "AuditLog" {
					return true
				}
				found[owner] = append(found[owner],
					name+":"+itoa(fset.Position(cl.Pos()).Line))
				return true
			})
		}
	}
	if scanned < minModelScannedFiles {
		t.Fatalf("只掃到 %d 個 internal/model 非測試檔（下限 %d）：掃描面已失真",
			scanned, minModelScannedFiles)
	}
	// 掃空防護：三個 hook 必須被看見，否則「零違規」只是偵測器壞了
	for want := range modelAuditWriteAllowlist {
		if len(found[want]) == 0 {
			t.Errorf("[偵測器健康] 允許清單登記的 %s 未被掃到任何 AuditLog 建構："+
				"要嘛該 hook 已被移除（此時 SHALL 同步刪除登記列），要嘛偵測器失效而本守衛已成恆綠", want)
		}
	}
	var extra []string
	for owner, sites := range found {
		if _, ok := modelAuditWriteAllowlist[owner]; ok {
			continue
		}
		extra = append(extra, owner+"（"+strings.Join(sites, "、")+"）")
	}
	sort.Strings(extra)
	if len(extra) > 0 {
		t.Fatalf("`internal/model` 出現 %d 個未登記的審計產生點：\n  %s\n"+
			"W6 6.2 已把 T-2 的三個 model 層落地函式收口到 audit/port.WriteInTx。"+
			"交易內要記審計，SHALL 在**擁有該業務語義的模組**內建構事件並經 port.WriteInTx 落地"+
			"（範例：internal/modules/asset/asset_audit_events.go）；在 model 層直寫會讓該筆寫入"+
			"對 audit 模組與 manifest 完全隱形。",
			len(extra), strings.Join(extra, "\n  "))
	}
}

// funcQualifiedName 把函式宣告轉成 `(*T).Method` 或 `Func` 形式。
func funcQualifiedName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	switch rt := fn.Recv.List[0].Type.(type) {
	case *ast.StarExpr:
		if id, ok := rt.X.(*ast.Ident); ok {
			return "(*" + id.Name + ")." + fn.Name.Name
		}
	case *ast.Ident:
		return "(" + rt.Name + ")." + fn.Name.Name
	}
	return fn.Name.Name
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
