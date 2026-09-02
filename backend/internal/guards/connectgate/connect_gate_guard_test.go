package connectgate

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 兩階段閘序守衛（收緊版）
//
// 三條不變式，缺一即紅：
//
//  1. **憑證解封出口只允許出現在兩階段之間的那個固定位置**——連線入口的
//     `AuthorizePreResolve` 與 `AuthorizeResolvedAccount` 之間。提前解封＝在授權未完成前
//     就把明文憑證取出來，即使後續拒絕也已違反連線收口紅線（conventions §2）。
//     白名單早期只要求「夾在 Authorize 之間」，後來收緊成這個固定位置。
//  2. **判定類方法不得在閘序宣告之外直呼**——閘序的唯一事實來源是 `connect_gates.go`
//     的 []Gate 順序；在 handler 裡多加一個 if 會讓閘序表看不到它，等價表也就對不上。
//  3. **兩份白名單的每一條都必須在現實中被用到**——條目對應的呼叫消失後，那條豁免
//     等於為將來的回填預先開好洞。單向守衛（只驗「違規在不在清單內」）擋不住這種腐化。
//
// 前兩條都以 **AST ＋ 結構性錨點** 判定（不比對行號：行號會被任何無關編輯推移，
// 那種守衛只會製造假紅或在搬檔後靜默失效）。

const gateGuardModulePath = "github.com/custodexa/backend"

// gateUnsealOutlets 明文憑證解封出口。兩個都要列：`GetSftpPassword` 曾經全案漏列。
var gateUnsealOutlets = map[string]bool{
	"GetWithCredentialsForAccount": true,
	"GetSftpPassword":              true,
}

// gateJudgmentCalls 連線閘序的判定類方法：它們的呼叫位置即閘的位置
var gateJudgmentCalls = map[string]bool{
	"CurrentConnectRole":                 true,
	"CurrentConnectRoleAndSourcePolicy":  true,
	"SourceOutcome":                      true,
	"VerifyCredentialGenerationByUserID": true,
	"VerifyAccountBinding":               true,
	"AuthorizeConnectAccount":            true,
	"CheckPermission":                    true,
	"CheckConnect":                       true,
	"ProbeWritable":                      true,
	"ResolveAccountIdentity":             true,
}

// gateUnsealAllowlist 解封出口的具名例外（鍵＝`相對路徑#所在函式`，值＝理由）。
//
// **每條都必須有理由，缺理由即紅**：這份清單就是「憑證在哪些地方會變成明文」的
// 完整答案，沒有第二份。
var gateUnsealAllowlist = map[string]string{
	"internal/sshproxy/handler.go#HandleSSH": "SSH 兌換入口的固定解封點；另受 betweenStages 位置斷言約束",
	"internal/sshproxy/dbconsole_handler.go#HandleDBConsole": "查詢主控台兌換入口的固定解封點，" +
		"位置與 HandleSSH 同構（兩階段之間）；閘序表逐字共用，只多兩道主控台專屬閘",
	"internal/sshproxy/dbconsole_handler.go#switchByReconnect": "PostgreSQL 切庫＝關閉並重連，" +
		"而重連是一次新的連線建立：**重跑整段閘序後**才解封。不重跑等於以一張已兌換的票" +
		"再開一條連線，授權在這段期間可能已被撤銷。解封位置同樣夾在兩階段之間",
	"internal/proxy/handler.go#HandleConnect": "guacd 兌換入口的固定解封點（GetWithCredentialsForAccount）；" +
		"同函式另有 GetSftpPassword＝VNC SFTP 側車憑證，位置在 AuthorizeResolvedAccount 之後" +
		"（授權已完成才解封，不違反收口方向）",
	"internal/modules/session/sftp_service.go#connect": "資料面（StageData）的 SFTP 短連線，" +
		"不屬那三處兩階段化的連線入口，其本身尚未兩階段化。" +
		"該路徑的授權由呼叫端 handler 完成",
	"internal/modules/asset/asset_service.go#GetWithCredentialsDefault": "asset 模組內部委派" +
		"（預設帳號捷徑，解封出口自身的實作側，非新的解封面）",
	"internal/modules/asset/change_secret_runner.go#runTarget": "改密 runner 的目標帳號憑證解封" +
		"（走帶 accountID 的 GetWithCredentialsForAccount，因改密是帳號級的操作）。" +
		"**不屬那三處兩階段化的連線入口**：" +
		"它不是使用者發起的連線兌換，而是系統排程對目標機的維運操作，沒有前端、沒有 " +
		"connect-token、沒有兩階段授權面可夾；其授權面是「整組端點 admin only」。" +
		"解封出的明文只用於本行程內的 SSH 客戶端，不進任何子程序的 argv 或環境。",
}

// gateJudgmentAllowlist 判定類方法在閘序宣告之外的具名例外。
//
// **登記＝放行，不是擋回填**：多登一條就是預先開一個洞。故本清單受
// `gateAssertAllowlistFullyUsed` 的反向完備性約束——條目在現實中沒有對應呼叫即紅，
// 陳舊豁免不得永久躺著（比照 ratchet 守衛的第三方向與觸點守衛）。
var gateJudgmentAllowlist = map[string]string{
	"internal/sshproxy/handler.go#connectPermissionOutcome": "G-I5／G-S9 兩道閘共用的判定實作，" +
		"由閘序以 Gate.Eval 委派；checkPermission 亦以它實作，兩條路徑不可能分化",
	"internal/sshproxy/handler.go#HandleCreateConnectToken": "簽發側兩階段之間的『帳號身分解析』步驟" +
		"（ResolveAccountIdentity，只解析 username 不解封憑證），位置等同兌換側的解封點",
}

// gateAssertAllowlistFullyUsed 反向完備性：白名單的每一條都必須在現實中被用到。
//
// 只驗「違規是否在清單內」是**單向**守衛——它擋得住新增的違規，擋不住清單自身腐化：
// 條目對應的呼叫被刪掉後，那條豁免會永久躺著，等於為將來的回填預先開好洞
// （`internal/proxy/handler.go#HandleConnect` 原是零違規的預先豁免，
// 註解卻自稱「擋回填」，方向相反）。
func gateAssertAllowlistFullyUsed(t *testing.T, kind string, allowlist map[string]string, used map[string]bool) {
	t.Helper()
	for key := range allowlist {
		if !used[key] {
			t.Errorf("%s白名單條目 %s 在現實中沒有對應呼叫（陳舊豁免＝預先開好的洞）："+
				"該處已無違規時應**刪除條目**，而非留著；登記等於放行，不是擋回填", kind, key)
		}
	}
}

// gateScanPackages 判定類方法守衛的射程（連線入口所在的兩個交付層 package）
var gateScanPackages = []string{"internal/sshproxy", "internal/proxy"}

func gateModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("取得工作目錄失敗: %v", err)
	}
	for {
		if body, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
			want := "module " + gateGuardModulePath
			for _, line := range strings.Split(string(body), "\n") {
				if strings.TrimSpace(line) == want {
					return dir
				}
			}
			t.Fatalf("在 %s 找到 go.mod 但 module 行不是 %q：掃描根錨點失效", dir, gateGuardModulePath)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("向上找不到 go.mod（module %s）：掃描根無從定位", gateGuardModulePath)
		}
		dir = parent
	}
}

// gateCall 一筆呼叫記錄
type gateCall struct {
	name string
	file string // 相對 module 根
	fn   string // 所在函式
	pos  token.Pos
}

// gateCollectCalls 掃描指定子樹的非測試 Go 檔，收集選擇子呼叫。
// 解析失敗一律 t.Fatal（不得以「掃不到」當成「沒有違規」）
func gateCollectCalls(t *testing.T, root, sub string, want map[string]bool) ([]gateCall, int) {
	t.Helper()
	var calls []gateCall
	scanned := 0
	fset := token.NewFileSet()
	base := filepath.Join(root, sub)
	err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "node_modules" || d.Name() == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		scanned++
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("解析 %s 失敗: %v（掃描失真即等同守衛失效）", path, perr)
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
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
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if want[sel.Sel.Name] {
					calls = append(calls, gateCall{
						name: sel.Sel.Name, file: rel, fn: fn.Name.Name, pos: call.Pos(),
					})
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("走訪 %s 失敗: %v", base, err)
	}
	return calls, scanned
}

// TestUnsealOutletOnlyAtFixedPosition 不變式 1
func TestUnsealOutletOnlyAtFixedPosition(t *testing.T) {
	root := gateModuleRoot(t)
	calls, scanned := gateCollectCalls(t, root, "internal", gateUnsealOutlets)

	// 空集合假綠防呆：掃描檔數與命中數都要有下界
	if scanned < 200 {
		t.Fatalf("掃描檔數 %d 低於下限 200：掃描根疑似失真", scanned)
	}
	if len(calls) < 4 {
		t.Fatalf("解封出口呼叫點只掃到 %d 個（實測應 ≥4）：抽取器疑似失效", len(calls))
	}

	used := map[string]bool{}
	for _, c := range calls {
		key := c.file + "#" + c.fn
		reason, ok := gateUnsealAllowlist[key]
		if !ok {
			t.Errorf("未登記的明文憑證解封點：%s 呼叫 %s。憑證解封只允許出現在兩階段之間的固定位置；"+
				"新增解封點必須先在本檔的 gateUnsealAllowlist 登記理由（缺理由即紅）", key, c.name)
			continue
		}
		used[key] = true
		if strings.TrimSpace(reason) == "" {
			t.Errorf("解封點 %s 的白名單缺理由（缺理由即紅）", key)
		}
	}
	gateAssertAllowlistFullyUsed(t, "解封", gateUnsealAllowlist, used)

	// 兩個連線入口另受「位置必須夾在兩階段之間」約束
	gateAssertBetweenStages(t, root, "internal/sshproxy/handler.go", "HandleSSH", "GetWithCredentialsForAccount")
	gateAssertBetweenStages(t, root, "internal/proxy/handler.go", "HandleConnect", "GetWithCredentialsForAccount")
}

// gateAssertBetweenStages 斷言 target 呼叫嚴格夾在 AuthorizePreResolve 與
// AuthorizeResolvedAccount 之間；三者缺一即紅（缺 stage 呼叫＝骨架被拆掉）
func gateAssertBetweenStages(t *testing.T, root, rel, fnName, target string) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(root, rel), nil, 0)
	if err != nil {
		t.Fatalf("解析 %s 失敗: %v", rel, err)
	}
	var pre, post, unseal []token.Pos
	found := false
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != fnName || fn.Body == nil {
			continue
		}
		found = true
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
			case "AuthorizePreResolve":
				pre = append(pre, call.Pos())
			case "AuthorizeResolvedAccount":
				post = append(post, call.Pos())
			case target:
				unseal = append(unseal, call.Pos())
			}
			return true
		})
	}
	if !found {
		t.Fatalf("%s 內找不到函式 %s：守衛的結構錨點失效（改名須同步本守衛）", rel, fnName)
	}
	if len(pre) != 1 || len(post) != 1 || len(unseal) != 1 {
		t.Fatalf("%s#%s 的兩階段骨架不完整：AuthorizePreResolve=%d、AuthorizeResolvedAccount=%d、%s=%d"+
			"（各須恰 1 次）", rel, fnName, len(pre), len(post), target, len(unseal))
	}
	if !(pre[0] < unseal[0] && unseal[0] < post[0]) {
		t.Fatalf("%s#%s 的憑證解封不在兩階段之間：pre=%d unseal=%d post=%d",
			rel, fnName, pre[0], unseal[0], post[0])
	}
}

// TestJudgmentCallsOnlyInGateDeclarations 不變式 2
func TestJudgmentCallsOnlyInGateDeclarations(t *testing.T) {
	root := gateModuleRoot(t)
	total := 0
	used := map[string]bool{}
	for _, pkg := range gateScanPackages {
		calls, scanned := gateCollectCalls(t, root, pkg, gateJudgmentCalls)
		if scanned < 5 {
			t.Fatalf("%s 掃描檔數 %d 低於下限 5：掃描根疑似失真", pkg, scanned)
		}
		total += len(calls)
		for _, c := range calls {
			if strings.HasSuffix(c.file, "/connect_gates.go") {
				continue // 閘序宣告本身＝唯一合法位置
			}
			key := c.file + "#" + c.fn
			reason, ok := gateJudgmentAllowlist[key]
			if ok {
				used[key] = true
			}
			if !ok {
				t.Errorf("判定類方法 %s 出現在閘序宣告之外：%s。閘序的唯一事實來源是 connect_gates.go 的 []Gate 順序；"+
					"在此直呼會讓等價表與守衛都看不到這道判定", c.name, key)
				continue
			}
			if strings.TrimSpace(reason) == "" {
				t.Errorf("判定例外 %s 缺理由（缺理由即紅）", key)
			}
		}
	}
	gateAssertAllowlistFullyUsed(t, "判定", gateJudgmentAllowlist, used)
	if total < 12 {
		t.Fatalf("兩個交付層 package 的判定呼叫只掃到 %d 個（實測應 ≥12）：抽取器疑似失效", total)
	}
}
