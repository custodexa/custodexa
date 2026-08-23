package main

import (
	"context"
	"fmt"
	"go/ast"
	"sort"
	"strings"
	"testing"

	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 指令告警落地面的收口守衛。
//
// # 本檔守的是什麼
//
// 要防的形態不是「有人寫錯欄位」，而是**同一張表有第二條寫入路徑，而那條路徑
// 少做了一件事**（syslog 離機轉發）。修法是把入庫、通知與 tee 收成單一落地面
// （internal/modules/audit/alert_sink.go 的 alertRecorder），於是「漏 tee」不再是
// 一個可以忘記做的動作，而是必須繞過整個落地面才做得到。
//
// 這件事只有在「沒有第二條寫入路徑」成立時才有效，而那是一句需要有人記得去 grep 的
// 宣稱——除非把它機器化。本檔即為機器化：
//
//	TestCommandAlertRowsAreWrittenOnlyByAlertSink  誰可以構造 command_alerts 列
//	TestChangeSecretAlertFailureStaysOffAlertSink  誰**不得**被順手收口（幽靈告警）
//	TestAlertSinkIsConstructedOnlyAtAssemblyRoot   落地面本身只有一個建構點
//
// 三者都以 module 根為掃描錨點（非 cwd／非層數推算）並帶掃描檔數下限，
// 檔案搬包後射程不會靜默縮水。

// commandAlertLiteralAllowlist 允許出現 `model.CommandAlert{…}` 的檔（相對 module 根）
// 及其理由。**燒盡制**：新增一列等於宣告「這裡也能生出一筆告警列」，
// 那一行必須在 PR diff 裡被質問。
var commandAlertLiteralAllowlist = map[string]string{
	"internal/modules/audit/alert_sink.go": "唯一落地面（alertRowOf）：入庫＋通知＋syslog tee 三件事的收口處，" +
		"「漏 tee」的結構性解法本體",
	"internal/modules/audit/alert_notifier.go":        "SendTestNotification 的測試 payload：只序列化後送 webhook，不入庫（無 GORM 寫入）",
	"internal/modules/audit/command_alert_service.go": "`Model(&model.CommandAlert{})` 查詢／審閱更新的型別標記，非資料列",
	"internal/modules/audit/daily_review_service.go":  "同上，未審閱計數查詢的型別標記",
	"internal/modules/audit/timeline_service.go": "同上（auditor-workbench）：`Model(&model.CommandAlert{})` " +
		"是 fetchAlerts 取窗與 countSource 計數的**查詢型別標記**，兩處皆只 Find／Count，" +
		"函式內零 GORM 寫入呼叫——工作台是唯讀聚合面，本來就不該生出告警列，" +
		"故「這一筆為何不需要 tee」的答案是：它根本不是一筆列。層 2 的無寫入斷言即此宣稱的機器化",
	"internal/modules/audit/audit_export_report.go": "同上：" +
		"`Model(&model.CommandAlert{})` 是事件報告匯出取窗的**查詢型別標記**，" +
		"writeReportAlerts 只 Find 後寫進 CSV，函式內零 GORM 寫入呼叫——" +
		"匯出是把既有告警**讀出去**，本來就不該生出告警列。層 2 的無寫入斷言即此宣稱的機器化",
	"internal/modules/asset/change_secret_runner.go": "改密失敗借道告警**通知**通道：" +
		"不入庫、不 tee，且 SHALL NOT 併入 AlertSink——併入會產生無對應規則的幽靈告警列",
	"internal/modules/asset/change_secret_retry_runner.go": "同上：候選憑證逾期放棄重試時的通知。" +
		"與 change_secret_runner.go 走同一條借道，" +
		"理由與邊界完全相同——不入庫、不 tee、不併入 AlertSink",
}

// commandAlertWriteFile 唯一可以把 command_alerts 列寫進 DB 的檔。
const commandAlertWriteFile = "internal/modules/audit/alert_sink.go"

// minCommandAlertLiteralSites 現況實測 10 處（alert_sink 1／alert_notifier 1／
// command_alert_service 2／daily_review_service 1／timeline_service 2／
// audit_export_report 1／change_secret_runner 1／change_secret_retry_runner 1）。
// 下限擋的是「掃描根失真 → 零命中 → 零違規」這個最危險的假綠形態。
const minCommandAlertLiteralSites = 5

type commandAlertSite struct {
	File string
	Line int
	Fn   string
	// WritesToDB 該 CompositeLit 所在函式內是否有 GORM 寫入呼叫
	WritesToDB bool
	WriteCall  string
}

// TestCommandAlertRowsAreWrittenOnlyByAlertSink 5.6：`command_alerts` 無第二處直寫。
//
// 判定分兩層，缺一都會留下「漏 tee」的復發空間：
//
//	層 1（構造）：`model.CommandAlert{…}` 只准出現在登記過的檔——擋的是「在新的地方
//	              長出一條寫入路徑」。
//	層 2（落地）：登記檔中除落地面外，其所在函式 SHALL NOT 含 GORM 寫入呼叫——
//	              擋的是「已登記的檔（例如借道通知的那個）某天順手加一行 Create」。
//
// **誠實界定**：本守衛是語法層判定，涵蓋的是「以 `model.CommandAlert` 複合字面量
// 構造的列」。以原生 SQL（`db.Exec("INSERT INTO command_alerts …")`）或 map 形態寫入
// 不在射程內——現況生產碼零筆該形態，`TestCommandAlertsHaveNoRawSQLInsert` 一併釘住。
func TestCommandAlertRowsAreWrittenOnlyByAlertSink(t *testing.T) {
	sites, scanned := scanCommandAlertSites(t)
	if scanned < minScannedGoFiles {
		t.Fatalf("只掃到 %d 個非測試 .go 檔（下限 %d）：掃描根或走訪邏輯已失真",
			scanned, minScannedGoFiles)
	}
	if len(sites) < minCommandAlertLiteralSites {
		t.Fatalf("只掃到 %d 處 model.CommandAlert 複合字面量（下限 %d）："+
			"掃描失真時「零違規」不成立，本守衛拒絕在空集合上宣告通過",
			len(sites), minCommandAlertLiteralSites)
	}

	seen := map[string]bool{}
	for _, s := range sites {
		seen[s.File] = true
		if _, ok := commandAlertLiteralAllowlist[s.File]; !ok {
			t.Errorf("%s:%d（%s）構造了 model.CommandAlert：\n"+
				"  command_alerts 的寫入 SHALL 只經 %s 的落地面——"+
				"那裡才同時做入庫、通知與 syslog 離機轉發。\n"+
				"  繞過它的後果就是漏掉 tee：安全事件只留本機一份，"+
				"而離機轉發存在的理由正是「本機資料庫可能被竄改或清除」。\n"+
				"  真的需要新的構造點時 SHALL 先在 commandAlertLiteralAllowlist 列名並寫明"+
				"「這一筆為何不需要 tee」。",
				s.File, s.Line, s.Fn, commandAlertWriteFile)
			continue
		}
		if s.File == commandAlertWriteFile {
			continue
		}
		if s.WritesToDB {
			t.Errorf("%s:%d（%s）在同一函式內有 GORM 寫入呼叫 %s：\n"+
				"  本檔登記於白名單的理由是「不入庫」（%s）。一旦它真的寫入，"+
				"就是第二條繞過 syslog tee 的路徑，離機證據又缺一整類。",
				s.File, s.Line, s.Fn, s.WriteCall, commandAlertLiteralAllowlist[s.File])
		}
	}

	// 反向：白名單不得留下已不存在的列（否則守衛的涵蓋面會隨著檔案消失而悄悄縮水，
	// 而白名單看起來仍然「有在管」）
	var stale []string
	for file := range commandAlertLiteralAllowlist {
		if !seen[file] {
			stale = append(stale, file)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("commandAlertLiteralAllowlist 有 %d 列已無對應構造點：%s\n"+
			"  檔案搬包或該構造點被刪除時 SHALL 同步移除白名單列——"+
			"殘留列會讓「白名單＝實際構造點集合」這個前提悄悄失效",
			len(stale), strings.Join(stale, "、"))
	}
}

// baselineSchemaFiles baseline 的 schema 定義檔（相對 module 根）。
//
// **為何需要這份具名清單**：壓縮前，
// `command_alerts` 的全部 DDL 都在宣告 `RunMigrations` 的那一個檔裡，故「migration 檔」
// 這個結構性定位同時界定了 schema 定義的所在。壓縮後 baseline 的 47 張表 DDL
// 超過單檔行數上限而必須切多檔，`RunMigrations` 仍只在 migrations.go 宣告，
// 但 `command_alerts` 的建表與索引落在 baseline_schema_audit.go——
// 那個檔會被本守衛判成「migration 檔以外的原生 SQL」。
//
// **不用萬用字元、不整包豁免**：判準的失敗方向必須是大聲失敗。清單漏列一個
// baseline 檔＝該檔被判違規（測試紅），不是靜默放行；清單列了不存在的檔
// ＝下方的存在性檢查直接 Fatal（防「檔案改名後豁免對象憑空消失，而清單看起來
// 仍然有在管」）。
var baselineSchemaFiles = map[string]string{
	"internal/database/baseline_schema_identity.go": "baseline schema：身分與認證域",
	"internal/database/baseline_schema_asset.go":    "baseline schema：資產與憑證域",
	"internal/database/baseline_schema_authz.go":    "baseline schema：授權與申請流程域",
	"internal/database/baseline_schema_audit.go":    "baseline schema：會話與審計域（command_alerts 的建表與索引在此）",
	"internal/database/baseline_schema_platform.go": "baseline schema：平台服務域",
	"internal/database/baseline_seed.go":            "baseline 種子：內建告警規則（alert_rules）",
}

// TestCommandAlertsHaveNoRawSQLInsert 補上語法層判定的已知缺口：原生 SQL 寫入。
//
// 現況生產碼對 `command_alerts` 的原生 SQL 只出現在 schema 定義檔（建表／索引）。
// 任何 INSERT INTO command_alerts 的字串一旦出現在 schema 定義面以外，
// 就是繞過落地面的第二條路徑。
func TestCommandAlertsHaveNoRawSQLInsert(t *testing.T) {
	root := auditPointModuleRoot(t)
	files, scanned := parseModuleFiles(t, root)
	if scanned < minScannedGoFiles {
		t.Fatalf("只掃到 %d 個非測試 .go 檔（下限 %d）：掃描根已失真", scanned, minScannedGoFiles)
	}

	// 具名清單的存在性：列了卻掃不到，代表檔案改名／搬家而清單沒跟上。
	// 此時豁免對象憑空消失，而清單看起來仍然有在管——必須大聲失敗。
	present := map[string]bool{}
	for _, pf := range files {
		present[pf.Rel] = true
	}
	var absent []string
	for f := range baselineSchemaFiles {
		if !present[f] {
			absent = append(absent, f)
		}
	}
	sort.Strings(absent)
	if len(absent) > 0 {
		t.Fatalf("baselineSchemaFiles 有 %d 個檔在掃描結果中不存在：%s\n"+
			"  schema 定義檔搬家或改名時 SHALL 同步更新本清單——"+
			"殘留列會讓「清單＝schema 定義面」這個前提悄悄失效",
			len(absent), strings.Join(absent, "、"))
	}
	// **以「誰宣告 RunMigrations」定位 migration 檔，不以路徑字串定位**：
	// 原本判 `pf.Rel == "internal/repository/migrations.go"`。後來把 `internal/repository`
	// 改名為 `internal/database`，那個字串從此匹配不到任何檔——**這正是「字串型守衛在
	// 改名當下失效」的教科書形態**（sealjournal 已實證過一次）。本例的失效方向恰好是
	// 誤報（migration 的建表 SQL 會被判違規）而非恆綠，但修法一樣不能是「把字串改成新名字」：
	// 下一次改名照壞。migration 檔的身分＝它宣告了 migration 執行入口 `RunMigrations`，
	// 那個事實不隨包名或目錄移動。
	migrationFile := ""
	for _, pf := range files {
		for _, d := range pf.File.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Name == nil || fn.Name.Name != "RunMigrations" {
				continue
			}
			if migrationFile != "" && migrationFile != pf.Rel {
				t.Fatalf("找到多個宣告 RunMigrations 的檔（%s 與 %s）："+
					"migration 入口不唯一時本守衛的豁免對象無從確定", migrationFile, pf.Rel)
			}
			migrationFile = pf.Rel
		}
	}
	if migrationFile == "" {
		t.Fatal("全庫找不到宣告 RunMigrations 的檔：migration 入口的定位失效，" +
			"本守衛將把建表 SQL 一律誤判為違規（或在別處被順手放寬），拒絕在此前提下通過")
	}

	checked := 0
	for _, pf := range files {
		ast.Inspect(pf.File, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Value == "" {
				return true
			}
			v := strings.ToLower(lit.Value)
			if !strings.Contains(v, "command_alerts") {
				return true
			}
			checked++
			if !strings.Contains(v, "insert into") {
				return true
			}
			if pf.Rel == migrationFile {
				return true // 建表與資料修補屬 migration 職責（結構性定位，見上）
			}
			if _, ok := baselineSchemaFiles[pf.Rel]; ok {
				return true // schema 定義面（具名清單，見 baselineSchemaFiles）
			}
			t.Errorf("%s:%d 以原生 SQL INSERT command_alerts：SHALL 改經 %s 的落地面，"+
				"否則入庫成功但通知與 syslog 離機轉發雙缺",
				pf.Rel, pf.Fset.Position(lit.Pos()).Line, commandAlertWriteFile)
			return true
		})
	}
	if checked == 0 {
		t.Fatal("全庫掃不到任何提及 command_alerts 的字串字面量：" +
			"連 migration 的建表語句都掃不到，代表掃描已失真，本守衛的通過不成立")
	}
}

// TestChangeSecretAlertFailureStaysOffAlertSink 5.5：改密失敗借道**不得**併入落地面。
//
// `ChangeSecretRunner.alertFailure` 復用 CommandAlert 的**通知**格式把改密失敗推給
// webhook，它沒有對應的告警規則、也不該出現在告警清單裡。看到它「也在處理 CommandAlert」
// 而順手改走 AlertSink，會在 command_alerts 產生一批 rule_id=0 的幽靈列——
// 審閱流程要處置它們、PCI 10.4.1 的未審閱計數要算它們，而它們根本不是指令告警。
func TestChangeSecretAlertFailureStaysOffAlertSink(t *testing.T) {
	const target = "internal/modules/asset/change_secret_runner.go"
	root := auditPointModuleRoot(t)
	files, _ := parseModuleFiles(t, root)

	var fn *ast.FuncDecl
	var pf *parsedFile
	for _, f := range files {
		if f.Rel != target {
			continue
		}
		pf = f
		ast.Inspect(f.File, func(n ast.Node) bool {
			d, ok := n.(*ast.FuncDecl)
			if ok && d.Name != nil && d.Name.Name == "alertFailure" && d.Body != nil {
				fn = d
			}
			return true
		})
	}
	if pf == nil {
		t.Fatalf("找不到 %s：檔案搬包時 SHALL 同步更新本守衛的目標路徑，"+
			"否則它會在「找不到就通過」之下恆綠", target)
	}
	if fn == nil {
		t.Fatalf("%s 內找不到 alertFailure：函式改名或消失時本守衛必須被重新檢視，"+
			"不得靜默通過", target)
	}

	sawEnqueue := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "Enqueue":
			sawEnqueue = true
		case "RecordAlert", "RecordAlerts":
			t.Errorf("%s:%d alertFailure 呼叫了 %s：改密失敗借道的是告警**通知**通道，"+
				"併入 AlertSink 會在 command_alerts 產生無對應規則的幽靈列",
				target, pf.Fset.Position(call.Pos()).Line, sel.Sel.Name)
		}
		return true
	})
	if !sawEnqueue {
		t.Errorf("%s 的 alertFailure 不再呼叫 Enqueue：本守衛的前提（它走通知通道而非落地面）"+
			"已不成立，SHALL 重新檢視這條路徑要往哪裡去，不得讓守衛在前提消失後繼續假綠", target)
	}
}

// alertSinkAllowedConstructionFiles 允許建構 AlertSink 實作的檔（相對 module 根）。
//
// **只有組裝根**：任何服務自行 `audit.NewAlertRecorder(db)` 都會繞過
// `requireAlertSink` 的啟動自檢——自檢檢查的是組裝根手上那一份，
// 別處自建的那份未注入也不會有人發現。
var alertSinkAllowedConstructionFiles = map[string]bool{
	"cmd/server/stage2.go": true,
}

// TestAlertSinkIsConstructedOnlyAtAssemblyRoot 5.4：落地面只有一個生產建構點。
func TestAlertSinkIsConstructedOnlyAtAssemblyRoot(t *testing.T) {
	root := auditPointModuleRoot(t)
	hits := scanCallsByName(t, root, "NewAlertRecorder")
	if len(hits) == 0 {
		t.Fatal("全庫掃不到任何 audit.NewAlertRecorder 呼叫：告警落地面已消失，或掃描失真" +
			"——兩者都不該靜默通過")
	}
	for _, h := range hits {
		if strings.HasSuffix(h.file, "_test.go") {
			continue // 測試自建替身不受此限
		}
		if !alertSinkAllowedConstructionFiles[h.file] {
			t.Errorf("%s:%d 建構了 AlertSink：它是 command_alerts 的唯一落地面，"+
				"只允許組裝根建構並在建構後立即 requireAlertSink 自檢（現況 %v）",
				h.file, h.line, alertSinkAllowedConstructionFiles)
		}
	}
}

// nilAlertSink 型別化的 nil（Go 的 typed-nil 陷阱：`var s *x; var i AlertSink = s`
// 之下 `i != nil` 為真，但任何方法呼叫都打在 nil 接收器上）。
type nilAlertSink struct{}

func (*nilAlertSink) RecordAlert(context.Context, gatewayapi.CommandAlert) error    { return nil }
func (*nilAlertSink) RecordAlerts(context.Context, []gatewayapi.CommandAlert) error { return nil }

// TestRequireAlertSinkRejectsMissing 5.4：未注入即啟動失敗（含 typed-nil）。
//
// 三格：可用的 sink 放行（**成功對照**——否則「都被拒絕」也會讓下面兩格通過）、
// 裸 nil 拒絕、typed-nil 拒絕。
func TestRequireAlertSinkRejectsMissing(t *testing.T) {
	if err := requireAlertSink(&nilAlertSink{}); err != nil {
		t.Fatalf("對照組：可用的 sink 不該被拒絕，實得 %v", err)
	}
	if err := requireAlertSink(nil); err == nil {
		t.Error("裸 nil sink 通過了自檢：未注入 SHALL 使啟動失敗，" +
			"SHALL NOT 降級為 no-op 而使阻斷告警靜默消失")
	}
	var typedNil *nilAlertSink
	if err := requireAlertSink(typedNil); err == nil {
		t.Error("typed-nil sink 通過了自檢：`sink == nil` 對它為假，" +
			"必須靠 reflect 判定，否則第一次寫告警時才會 panic")
	}
}

// scanCommandAlertSites 掃全 module 非測試碼的 `model.CommandAlert{…}` 構造點。
func scanCommandAlertSites(t *testing.T) ([]commandAlertSite, int) {
	t.Helper()
	root := auditPointModuleRoot(t)
	files, scanned := parseModuleFiles(t, root)

	var out []commandAlertSite
	for _, pf := range files {
		// 先建「函式 → 是否含 GORM 寫入呼叫」的索引，供層 2 判定
		type fnInfo struct {
			name      string
			writeCall string
		}
		var stack []*ast.FuncDecl
		fnWrites := map[*ast.FuncDecl]string{}
		for _, decl := range pf.File.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			stack = append(stack, fd)
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if gormWriteMethods[sel.Sel.Name] {
					if _, dup := fnWrites[fd]; !dup {
						fnWrites[fd] = sel.Sel.Name
					}
				}
				return true
			})
		}

		for _, fd := range stack {
			var info fnInfo
			info.name = fd.Name.Name
			info.writeCall = fnWrites[fd]
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				cl, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				sel, ok := cl.Type.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				x, ok := sel.X.(*ast.Ident)
				if !ok || x.Name != "model" || sel.Sel.Name != "CommandAlert" {
					return true
				}
				out = append(out, commandAlertSite{
					File:       pf.Rel,
					Line:       pf.Fset.Position(cl.Pos()).Line,
					Fn:         fmt.Sprintf("func %s", info.name),
					WritesToDB: info.writeCall != "",
					WriteCall:  info.writeCall,
				})
				return true
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out, scanned
}
