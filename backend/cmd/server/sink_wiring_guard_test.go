package main

// 接線完整性守衛。
//
// # 這道守衛補的是哪一種漏
//
// `requireAuditTxSink`／`requireAuditAsyncSinks`／`requireAlertSink` 檢的是組裝根手上
// **那個變數是不是 nil**，不是**那個變數有沒有被接到消費端**。兩者之間隔著一行普通的
// 賦值，而那一行沒有任何測試釘住：
//
//	sshHandler.AlertSink = alertSink        ← 換成 `_ = alertSink`
//	  → go build ./... 過
//	  → cmd/server（含全部啟動自檢守衛）／internal/sshproxy／internal/modules/audit 三包全綠
//	  → 生產後果：阻斷告警不入庫、不通知、不 tee，只剩一行 log（比單純漏 tee 更重）
//
// 實跑證實了上述形態。這是**通用形態**而非單一案例：每個新增的 sink 都會
// 產生一組「自檢過的變數」與「消費端欄位」，兩者之間的那一行永遠是無守衛的單點。
//
// # 為何是登記表而非硬編碼
//
// 本檔的判定資料全在 `sinkWiringRegistry`：新增一個 `require*` 自檢卻不登記它的消費端，
// 由 `TestSinkWiringRegistryCoversEveryStartupGuard` 轉紅（登記表對現實的反向完備）；
// 既有 sink 的某個消費端被拆線，由 `TestRequiredSinksAreWiredToConsumers` 指名轉紅。
// 後續只需在登記表加一列，不需要改判定邏輯。
//
// # 守衛的界限（誠實界定）
//
// 本守衛做的是**語法層**判定：「組裝根裡存在一處把該變數交給指名消費端的賦值／傳入」。
// 它保證不了「消費端拿到之後真的用它」——那要型別資訊與資料流分析。它擋的是
// 「接線那一行被刪掉／被改成別的值／被 `_ =` 吃掉」這一類**沉默拆線**，
// 而那正是實跑證實可以全綠溜過的形態。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sinkConsumerKind 接線在語法上的三種載體。
type sinkConsumerKind string

const (
	// consumerFieldAssign 消費端欄位賦值：`sshHandler.AlertSink = alertSink`
	consumerFieldAssign sinkConsumerKind = "欄位賦值"
	// consumerCallArg 建構子／設值方法傳入：`audit.InitAlertMatcher(db, alertSink)`
	consumerCallArg sinkConsumerKind = "建構子傳入"
	// consumerStructField 結構字面量欄位注入：`routeServices{auditTxSink: auditTxSink}`
	consumerStructField sinkConsumerKind = "結構欄位注入"
)

// sinkConsumer 一個必須存在的消費端接線。
//
// target 的寫法依 kind 而定：
//   - consumerFieldAssign：`接收者.欄位`（僅支援單層選擇子，組裝根現況全是這個形態）
//   - consumerCallArg：被呼叫函式／方法名（不含包限定詞）
//   - consumerStructField：結構字面量的欄位名
type sinkConsumer struct {
	kind   sinkConsumerKind
	target string
	why    string
}

// sinkWiring 一個「啟動自檢過的依賴」與它必須接到的消費端。
type sinkWiring struct {
	// guard 對應的啟動自檢函式名（audit_sinks.go 內的 require*）。
	guard string
	// variable 組裝根中承載該依賴的變數名。自檢必須以它為引數——
	// 變數改名而登記表沒跟上時，本欄使守衛轉紅而非靜默指向不存在的東西。
	variable string
	// consumers 缺一即紅的消費端接線。
	consumers []sinkConsumer
}

// sinkWiringRegistry 接線登記表。
//
// **新增 `require*` 自檢時 SHALL 一併在此登記其消費端**，否則
// TestSinkWiringRegistryCoversEveryStartupGuard 轉紅。登記的消費端是
// 「拆掉即造成該類證據沉默消失」的那些，不是該變數的全部出現處——
// 登記全部出現處只會讓正當重構噪音化，並不提高矯正力。
var sinkWiringRegistry = []sinkWiring{
	{
		guard:    "requireAuditTxSink",
		variable: "auditTxSink",
		consumers: []sinkConsumer{
			{
				kind: consumerCallArg, target: "NewLDAPDirectoryService",
				why: "TxSink 的第一個消費者：LDAP 目錄設定的交易內審計由此落地",
			},
			{
				kind: consumerCallArg, target: "RegisterLDAPSeedMigration",
				why: "AP-51：seed 的插列＋審計＋marker 同事務，拆線即 seed 無痕",
			},
			{
				kind: consumerStructField, target: "auditTxSink",
				why: "routeServices 注入：節點樹與使用者群組刪除留痕的唯一出口",
			},
		},
	},
	{
		guard:    "requireAuditAsyncSinks",
		variable: "auditService",
		consumers: []sinkConsumer{
			{
				kind: consumerStructField, target: "auditService",
				why: "routeServices 注入：AuditLogMiddleware 與全部 handler 的審計出口",
			},
			{
				kind: consumerCallArg, target: "SetAuditSink",
				why: "外部身分管理四操作的審計出口，拆線即該四操作無痕",
			},
		},
	},
	{
		guard:    "requireAuditAsyncSinks",
		variable: "auditDirectSink",
		consumers: []sinkConsumer{
			{
				kind: consumerFieldAssign, target: "connHandler.AuditSink",
				why: "AP-28 檔案上傳審計：每條圖形連線的 FileTap 由此取得投遞面",
			},
			{
				kind: consumerStructField, target: "auditDirectSink",
				why: "AP-04 k8s 檔案操作：經 routeServices 傳到 assetHandler",
			},
		},
	},
	{
		guard:    "requireAlertSink",
		variable: "alertSink",
		consumers: []sinkConsumer{
			{
				kind: consumerFieldAssign, target: "sshHandler.AlertSink",
				why: "阻斷路徑：每條會話的 commandBlocker 由此取得落地面。" +
					"拆線即阻斷告警不入庫、不通知、不 tee——已實證的假綠形態",
			},
			{
				kind: consumerCallArg, target: "InitAlertMatcher",
				why: "比對路徑：alertMatcher 的落地面，拆線即比對告警改走無出口的路徑",
			},
		},
	},
}

// assemblyRootFiles 組裝根（cmd/server）的非測試檔 AST。
type assemblyRootFiles struct {
	fset  *token.FileSet
	files []*ast.File
	names []string
}

// minAssemblyRootFiles 組裝根非測試檔數下限（現況 7 檔）：掃空即零違規是最危險的假綠形態。
const minAssemblyRootFiles = 5

func parseAssemblyRoot(t *testing.T) *assemblyRootFiles {
	t.Helper()
	dir := filepath.Join(auditPointModuleRoot(t), "cmd", "server")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("讀取組裝根 cmd/server 失敗: %v", err)
	}
	out := &assemblyRootFiles{fset: token.NewFileSet()}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(out.fset, filepath.Join(dir, e.Name()), nil, parser.ParseComments)
		if perr != nil {
			t.Fatalf("解析 cmd/server/%s 失敗（守衛不在殘缺 AST 上作判定）: %v", e.Name(), perr)
		}
		out.files = append(out.files, f)
		out.names = append(out.names, e.Name())
	}
	if len(out.files) < minAssemblyRootFiles {
		t.Fatalf("組裝根只掃到 %d 個非測試 .go 檔（下限 %d）：掃描根失真，本守衛的「零違規」不成立",
			len(out.files), minAssemblyRootFiles)
	}
	return out
}

// TestRequiredSinksAreWiredToConsumers 自檢過的每個 sink 都必須接到登記的消費端。
//
// 「自檢通過」與「接線存在」是兩件事——前者只證明組裝根手上那個變數不是 nil。
func TestRequiredSinksAreWiredToConsumers(t *testing.T) {
	root := parseAssemblyRoot(t)
	if len(sinkWiringRegistry) == 0 {
		t.Fatal("接線登記表為空：本守衛失去全部射程（登記表被清空時 SHALL 轉紅而非零違規通過）")
	}
	for _, w := range sinkWiringRegistry {
		if len(w.consumers) == 0 {
			t.Errorf("%s／%s 登記了零個消費端：登記一個沒有消費端的依賴等於沒登記",
				w.guard, w.variable)
			continue
		}
		if !guardChecksVariable(root, w.guard, w.variable) {
			t.Errorf("組裝根找不到 %s(… %s …) 的呼叫：登記表宣稱該變數受此自檢保護，"+
				"但現實已不是如此（變數改名／自檢被拆／登記表過期都會走到這裡）",
				w.guard, w.variable)
			continue
		}
		for _, c := range w.consumers {
			if consumerWired(root, w.variable, c) {
				continue
			}
			t.Errorf("組裝根少了一條接線：%s 的「%s → %s」不存在。\n"+
				"　　該接線的作用：%s\n"+
				"　　注意 %s 通過**不代表**接線存在——它檢的是變數是否為 nil，"+
				"不是變數有沒有被交給消費端；把接線改成 `_ = %s` 之下自檢照樣通過。\n"+
				"　　若接線是正當地搬到別處，SHALL 更新 sinkWiringRegistry 的 target 而非刪除本格",
				w.variable, c.kind, c.target, c.why, w.guard, w.variable)
		}
	}
}

// TestSinkWiringRegistryCoversEveryStartupGuard 登記表與現實的雙向完備。
//
// 三格：
//  1. 每個 require* 自檢都必須在登記表中有至少一列（新增自檢不登記＝紅）。
//  2. 登記表列的自檢都必須真實存在（登記表過期＝紅）。
//  3. 每個 require* 呼叫的每個識別字引數都必須已登記（在既有自檢上多掛一個
//     未登記的 sink＝紅，這是 requireAuditAsyncSinks 這種可變參數自檢的漏法）。
func TestSinkWiringRegistryCoversEveryStartupGuard(t *testing.T) {
	root := parseAssemblyRoot(t)
	declared := declaredRequireFuncs(root)
	if len(declared) == 0 {
		t.Fatal("組裝根掃不到任何 require* 啟動自檢函式：掃描失真或自檢已整組消失，" +
			"兩者都不該靜默通過")
	}

	registered := map[string]map[string]bool{}
	for _, w := range sinkWiringRegistry {
		if registered[w.guard] == nil {
			registered[w.guard] = map[string]bool{}
		}
		registered[w.guard][w.variable] = true
	}

	for name := range declared {
		if _, ok := registered[name]; !ok {
			t.Errorf("%s 是啟動自檢但未在 sinkWiringRegistry 登記接線："+
				"自檢只證明變數非 nil，接線是否存在無人可擋。"+
				"新增 require* 時 SHALL 一併登記其消費端", name)
		}
	}
	for guard, vars := range registered {
		if !declared[guard] {
			t.Errorf("sinkWiringRegistry 列了 %s，但組裝根沒有這個自檢函式："+
				"登記表已與現實脫節（自檢被改名或刪除時 SHALL 轉紅而非靜默失效）", guard)
			continue
		}
		for _, arg := range guardArguments(root, guard) {
			if !vars[arg] {
				t.Errorf("%s 的引數 %q 未登記接線：在既有自檢上多掛一個 sink 卻不登記，"+
					"等於讓它的接線回到無人可擋的狀態", guard, arg)
			}
		}
	}
}

// declaredRequireFuncs 組裝根非測試檔中宣告的 require* 函式名。
func declaredRequireFuncs(root *assemblyRootFiles) map[string]bool {
	out := map[string]bool{}
	for _, f := range root.files {
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || !strings.HasPrefix(fd.Name.Name, "require") {
				continue
			}
			out[fd.Name.Name] = true
		}
	}
	return out
}

// guardArguments 某個自檢函式在組裝根被呼叫時傳入的識別字引數（去重）。
func guardArguments(root *assemblyRootFiles, guard string) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range root.files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || calleeIdentName(call.Fun) != guard {
				return true
			}
			for _, a := range call.Args {
				id, ok := a.(*ast.Ident)
				if !ok || seen[id.Name] {
					continue
				}
				seen[id.Name] = true
				out = append(out, id.Name)
			}
			return true
		})
	}
	return out
}

// guardChecksVariable 該自檢是否確實以該變數為引數被呼叫。
func guardChecksVariable(root *assemblyRootFiles, guard, variable string) bool {
	for _, arg := range guardArguments(root, guard) {
		if arg == variable {
			return true
		}
	}
	return false
}

// consumerWired 組裝根中是否存在「把 variable 交給 c 所指消費端」的接線。
func consumerWired(root *assemblyRootFiles, variable string, c sinkConsumer) bool {
	hit := false
	for _, f := range root.files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.AssignStmt:
				if c.kind != consumerFieldAssign {
					return true
				}
				for i, lhs := range node.Lhs {
					if i >= len(node.Rhs) || selectorText(lhs) != c.target {
						continue
					}
					if id, ok := node.Rhs[i].(*ast.Ident); ok && id.Name == variable {
						hit = true
					}
				}
			case *ast.CallExpr:
				if c.kind != consumerCallArg || calleeIdentName(node.Fun) != c.target {
					return true
				}
				for _, a := range node.Args {
					if id, ok := a.(*ast.Ident); ok && id.Name == variable {
						hit = true
					}
				}
			case *ast.CompositeLit:
				if c.kind != consumerStructField {
					return true
				}
				for _, el := range node.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, ok := kv.Key.(*ast.Ident)
					if !ok || key.Name != c.target {
						continue
					}
					if id, ok := kv.Value.(*ast.Ident); ok && id.Name == variable {
						hit = true
					}
				}
			}
			return true
		})
	}
	return hit
}

// selectorText 單層選擇子的文字形態（`sshHandler.AlertSink`）；非該形態回空字串。
func selectorText(e ast.Expr) string {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	x, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	return x.Name + "." + sel.Sel.Name
}
