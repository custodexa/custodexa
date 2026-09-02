package keyvault

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// 伺服端不生成 KEK 的 AST 守衛。
//
// 安全紅線要求「generateKEKString 自 rewrap 路徑移除」。單純刪掉函式會讓任何守衛
// 淪為空氣（守衛假綠：目標不存在，掃描恆綠而不證明任何事），故本檔的守衛做兩件事：
//
//  1. **偵測器本身先被證明有效**——以合成 AST 餵入正向案例（呼叫鏈上確實出現
//     生成器／crypto.rand），斷言它會報違規；再餵敏感度案例（同結構但無該呼叫），
//     斷言它不報。偵測器失效時這兩格會先紅。
//  2. 才把偵測器指向真實套件，斷言 RewrapKEK 的呼叫傳遞閉包內零違規，
//     且該閉包**確實走到了**重包會用到的函式（涵蓋面下界，防「掃到空集合」）。

// kekGenerationViolation 一筆違規（位置＋原因）
type kekGenerationViolation struct {
	Pos    string
	Reason string
}

// scanKEKGenerationFromEntry 自 entry 函式起算套件內呼叫傳遞閉包，回報閉包內
// 出現的「KEK 材料生成」跡象：名稱像生成器的函式，或 crypto/rand 的取用。
//
// 保守作法（over-approximation）：函式以名稱索引（不分 receiver），呼叫解析
// 只認套件內的識別字；解析不到的呼叫（跨套件）不展開——本守衛要證的是
// **本套件**內不存在生成路徑，跨套件的包裹（如 AES nonce）不在射程內。
// 回傳的 reachable 供呼叫端做涵蓋面下界斷言。
func scanKEKGenerationFromEntry(files []*ast.File, fset *token.FileSet, entry string) (violations []kekGenerationViolation, reachable map[string]bool) {
	decls := map[string]*ast.FuncDecl{}
	for _, f := range files {
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Name != nil && fd.Body != nil {
				decls[fd.Name.Name] = fd
			}
		}
	}
	reachable = map[string]bool{}
	queue := []string{entry}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if reachable[name] {
			continue
		}
		reachable[name] = true
		fd, ok := decls[name]
		if !ok {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			// crypto/rand（或任何 rand 套件）的取用：rand.Read／rand.Reader／rand.Int
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if x, ok := sel.X.(*ast.Ident); ok && x.Name == "rand" {
					violations = append(violations, kekGenerationViolation{
						Pos:    fset.Position(sel.Pos()).String(),
						Reason: fmt.Sprintf("%s 內取用 rand.%s", name, sel.Sel.Name),
					})
				}
				return true
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			callee, ok := call.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			if looksLikeKEKGenerator(callee.Name) {
				violations = append(violations, kekGenerationViolation{
					Pos:    fset.Position(call.Pos()).String(),
					Reason: fmt.Sprintf("%s 呼叫疑似 KEK 生成器 %s", name, callee.Name),
				})
			}
			if _, isLocal := decls[callee.Name]; isLocal {
				queue = append(queue, callee.Name)
			}
			return true
		})
	}
	return violations, reachable
}

// looksLikeKEKGenerator 名稱層的生成器判別（大小寫不敏感）
func looksLikeKEKGenerator(name string) bool {
	lower := strings.ToLower(name)
	if !strings.Contains(lower, "kek") {
		return false
	}
	// 「kek」與下列任一同時出現才算生成器嫌疑。刻意**不收「new」**：
	// keyvault.NewKEKRetirementMonitor 這類建構子會誤報，而誤報會讓守衛被當噪音關掉
	for _, verb := range []string{"generate", "random", "material"} {
		if strings.Contains(lower, verb) {
			return true
		}
	}
	return false
}

// parseSyntheticFile 供偵測器自證用的合成來源
func parseSyntheticFile(t *testing.T, src string) ([]*ast.File, *token.FileSet) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("解析合成來源失敗: %v", err)
	}
	return []*ast.File{f}, fset
}

// TestKEKGenerationDetectorDetectsPositives 偵測器自證（正向）：呼叫鏈上出現
// 生成器或 rand 取用時必須報違規——否則後面對真實套件的綠燈毫無意義
func TestKEKGenerationDetectorDetectsPositives(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"直接呼叫生成器", `package p
func RewrapKEK() { _ = generateKEKString() }
func generateKEKString() string { return "" }`},
		{"間接（兩層）呼叫生成器", `package p
func RewrapKEK() { helper() }
func helper() { _ = newKEKMaterialString() }
func newKEKMaterialString() string { return "" }`},
		{"閉包內取用 crypto/rand", `package p
func RewrapKEK() { buf := make([]byte, 32); rand.Read(buf) }`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files, fset := parseSyntheticFile(t, tc.src)
			v, _ := scanKEKGenerationFromEntry(files, fset, "RewrapKEK")
			if len(v) == 0 {
				t.Fatal("偵測器未報違規——守衛已失效（真實套件的綠燈將是假綠）")
			}
		})
	}
}

// TestKEKGenerationDetectorSensitivity 偵測器自證（敏感度）：結構相同但呼叫鏈
// 上沒有生成器時不得誤報；且**不可達**的生成器不算違規（射程限於 rewrap 路徑）
func TestKEKGenerationDetectorSensitivity(t *testing.T) {
	files, fset := parseSyntheticFile(t, `package p
func RewrapKEK() { helper() }
func helper() { _ = wrap() }
func wrap() string { return "" }
func unrelatedGenerateKEKString() string { return "" }`)
	v, reachable := scanKEKGenerationFromEntry(files, fset, "RewrapKEK")
	if len(v) != 0 {
		t.Fatalf("乾淨的呼叫鏈不得報違規，得 %+v", v)
	}
	if !reachable["helper"] || !reachable["wrap"] {
		t.Fatalf("偵測器未走完呼叫鏈（reachable=%v）——涵蓋面斷言不可信", reachable)
	}
	if reachable["unrelatedGenerateKEKString"] {
		t.Fatal("不可達函式不應出現在閉包內")
	}
}

// TestRewrapPathHasNoServerSideKEKGeneration 真實套件：RewrapKEK 的呼叫傳遞
// 閉包內不得出現任何 KEK 生成器或 rand 取用（「伺服端不生成」紅線）
func TestRewrapPathHasNoServerSideKEKGeneration(t *testing.T) {
	files, fset := parsePackageNonTestFiles(t, ".")
	violations, reachable := scanKEKGenerationFromEntry(files, fset, "RewrapKEK")
	if len(violations) > 0 {
		var lines []string
		for _, v := range violations {
			lines = append(lines, v.Pos+" "+v.Reason)
		}
		sort.Strings(lines)
		t.Fatalf("重包路徑上出現伺服端 KEK 生成跡象（一律禁止）:\n%s", strings.Join(lines, "\n"))
	}
	// 涵蓋面下界：閉包必須確實走到重包會用到的函式，否則零違規只是掃到空集合
	for _, must := range []string{"RewrapKEK", "wrapMaterial", "countRetireBacklog"} {
		if !reachable[must] {
			t.Fatalf("呼叫傳遞閉包未涵蓋 %s——掃描邏輯已失效（reachable=%d 個函式）", must, len(reachable))
		}
	}
}

// **掃描對象隨檔遷移**：本檔的兩個真實掃描格皆以
// `parsePackageNonTestFiles(t, ".")` 掃「自己所在的那個包」，而 RewrapKEK／
// wrapMaterial／countRetireBacklog 已隨 13 檔遷入 keyvault，故守衛必須同遷——
// 留在 internal/service 會掃到不含 RewrapKEK 的包而在空集合下假綠（涵蓋面下界
// 斷言會先紅，這正是它存在的理由）。**測試名稱刻意不改**（`TestServicePackage…`）：
// 改名會動到測試名集合，屬遷移「零行為變更」之外的變動；名稱中的 Service 讀作
// 「原 service 套件中的這批金鑰程式碼」，實際射程即本包。
//
// **搬檔讓「本包」守衛的射程靜默縮水**：
// `TestServicePackageHasNoKEKGenerator` 在 HEAD 掃的是 internal/service 全包
// （~200 檔），隨檔遷入後只剩 keyvault 的 14 檔——在 internal/service 放一個
// 用 crypto/rand 的 KEK 產生器，本格照樣綠。**以「當前包」定位的守衛，搬檔後
// 射程必然改變，且沒有任何機制會提醒**。修法不是改名或加註解，而是補上真正的
// 射程：下方 `TestBackendHasNoKEKMaterialGenerator` 掃**整個 backend module**
// （以 repoRoot 身分錨點定位，不隨檔案層數漂移），本格則保留為本包的近距守衛。
// 兩格並存＝射程不再與「這批檔案目前住在哪個包」綁定。

// TestServicePackageHasNoKEKGenerator 全套件層：本包內不得再存在任何 KEK
// 材料生成器。與上一格互補——上一格管「rewrap 路徑不可達」，本格管「根本不存在」，
// 免得有人把生成器留在別的路徑上，日後再接回來。
// 射程限本包；跨包的涵蓋面由 TestBackendHasNoKEKMaterialGenerator 負責
func TestServicePackageHasNoKEKGenerator(t *testing.T) {
	files, fset := parsePackageNonTestFiles(t, ".")
	var found []string
	for _, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Name == nil {
				continue
			}
			if looksLikeKEKGenerator(fd.Name.Name) {
				found = append(found, fset.Position(fd.Pos()).String()+" "+fd.Name.Name)
			}
		}
	}
	if len(found) > 0 {
		t.Fatalf("service 套件不得存在 KEK 材料生成器:\n%s", strings.Join(found, "\n"))
	}
	// 敏感度：判別式對真正的生成器名稱必須為真（否則上面的空集合毫無意義）
	if !looksLikeKEKGenerator("generateKEKString") {
		t.Fatal("判別式對 generateKEKString 回 false——本守衛已失效")
	}
}

// ---- 全模組層：伺服端任何一處都不得生成 KEK 材料 ----

// kekGeneratorException 一筆具名例外：名稱命中生成器判別式、但實際不生成材料的函式。
type kekGeneratorException struct {
	File   string // 相對 backend module 根的路徑（正斜線）
	Func   string
	Reason string
}

// kekGeneratorAllowlist 全模組掃描的具名例外。
//
// **例外不是免死金牌**：下方守衛額外要求每一列的函式體內零 `rand.*` 取用——
// 「驗證器日後偷偷開始生成」這條路因此仍會轉紅，而不是靠這份清單放行。
// 清單同時做反向完備性檢查（列了但函式不存在＝陳舊例外，會在下一個同名函式
// 出現時無聲放行），故刪改函式時必須同步維護本清單。
var kekGeneratorAllowlist = []kekGeneratorException{
	{File: "config/kek.go", Func: "ValidateKEKMaterial",
		Reason: "純格式驗證：把材料字串交給 pkg/crypto 的格式檢查並回傳錯誤字串，不產生任何位元組。名稱命中判別式是因為它驗的對象叫 KEK 材料。"},
	{File: "pkg/crypto/kek_material.go", Func: "ValidateKEKMaterialFormat",
		Reason: "同上的底層實作（長度／字元集／編碼檢查）。KEK 材料一律由運維在行程外產生後以 env 或 KMS 提供，本函式只判定其形狀。"},
	{File: "pkg/crypto/kek_material.go", Func: "DecodeKEKMaterial",
		Reason: "純解碼：把運維在行程外產生的材料由三種寫法（原字元／十六進位／base64）解為 32 位元組金鑰。只轉換表述、不產生任何新位元組，亦不取用隨機來源。"},
	{File: "pkg/crypto/kek_material.go", Func: "DecodeKEKMaterialBytes",
		Reason: "同上的 []byte 入口（解封路徑走此支以免多出不可覆寫的 string 副本）。純解碼，不生成。"},
	{File: "config/kek.go", Func: "DecodeKEKMaterialKey",
		Reason: "解碼＋出廠預設值閘的組態層包裝，轉呼 pkg/crypto 的解碼器。不產生任何位元組。"},
	{File: "config/kek.go", Func: "DecodeKEKMaterialKeyBytes",
		Reason: "同上的 []byte 入口。不產生任何位元組。"},
	{File: "config/kek.go", Func: "KEKGenerateCommandLines",
		Reason: "把文件化生成指令的**字串**攤成清單供錯誤訊息與範本比對。行程內不執行那些指令，也不取用任何隨機來源。"},
	// ---- 套件層宣告：合成身分 `const:名稱`／`var:名稱` ----
	{File: "config/kek.go", Func: "var:KEKGenerateCommands",
		Reason: "字串常數集合，內容是**給運維在 shell 執行**的產生指令（openssl／`tr -dc … < /dev/urandom`），由列 3b 錯誤訊息、.env.example 與介面的指令參考引用。行程內不執行它們、也不取用任何隨機來源——它正是「KEK 由運維在行程外產生」的操作說明本體。"},
	{File: "pkg/crypto/kek_material.go", Func: "const:KEKMaterialLength",
		Reason: "整數常數 32（AES-256 的材料長度），供 ValidateKEKMaterialFormat 判形。純尺寸宣告，不產生任何位元組。"},
}

// ---- K2：掃描量下界改按頂層目錄計數----
//
// 原本只有一個總量下限 270 對實測 300——容許 30 個檔悄悄消失而守衛照樣綠，
// 且不隨專案成長自動收緊。改為**逐頂層目錄釘住現況檔數**：任一目錄的非測試
// .go 檔數低於登記值即紅，新增檔案不受影響。**任何減少都須顯式更新本表並在
// commit 中寫明理由**——那正是「一整塊掃描面消失」的唯一入口。
var backendScanFloors = map[string]int{
	"cmd":      8,
	"config":   5,
	"internal": 263,
	"pkg":      22,
	// scripts 7→5（2026-08-11）：`backend/scripts/test_*_connection.go` 兩支本機
	// 連線測試工具隨開源釋出前置清理移除（其編譯產物已列入 .gitignore）。
	// 顯式調降＝守衛要求的正當刪檔申報，非放寬——其餘目錄下界不動。
	"scripts": 5,
}

// minBackendScannedFiles 總量下界（＝各目錄下界之和，保留為單一數字以利訊息可讀）。
const minBackendScannedFiles = 303

// ---- K1：隨機來源的別名解析與跨函式傳遞閉包----

// randSourcePackages 視為「隨機材料來源」的 import 路徑。
var randSourcePackages = map[string]bool{
	"crypto/rand":  true,
	"math/rand":    true,
	"math/rand/v2": true,
}

// backendModulePath go.mod 的 module 路徑（把 import 路徑對應回 module 內目錄）。
const backendModulePath = "github.com/custodexa/backend"

// funcKey 模組內「可含程式碼的宣告」的唯一鍵：所在目錄（≈套件）＋身分名。
//
// **方法與同名函式合併**（同目錄下 `(a) doIt` 與 `(b) doIt` 視為同一鍵）：這是
// 刻意的過近似——合併只會讓閉包更大、更容易轉紅，不會讓違規逃掉。
//
// **套件層宣告的合成身分**（K1-F2）：`var x = …` 與 `const x = …` 的初始化運算式
// 同樣會執行程式碼（含立即呼叫的函式字面量），故一併登記為 `var:x`／`const:x`
// 形態的鍵，讓軸 A 的名稱判別式與軸 B 的來源 ratchet 都看得見它們。
// 多名宣告（`var a, b = f(), g()`）以 `var:a,b` 為單一鍵，值一併掃描。
type funcKey struct {
	Dir  string // 相對 module 根，正斜線
	Name string
}

// pkgLevelVarPrefix／pkgLevelConstPrefix 套件層宣告的合成身分前綴。
const (
	pkgLevelVarPrefix   = "var:"
	pkgLevelConstPrefix = "const:"
)

func (k funcKey) String() string { return k.Dir + ":" + k.Name }

// randUse 一處隨機來源取用
type randUse struct {
	Key    funcKey
	File   string
	Line   int
	Detail string // 例：crand.Read
}

// moduleCallScan 全模組的呼叫圖＋隨機來源取用點
type moduleCallScan struct {
	Scanned    int
	ByTopDir   map[string]int
	Funcs      map[funcKey]bool
	FileOf     map[funcKey]string
	LineOf     map[funcKey]int
	Calls      map[funcKey][]funcKey
	RandUses   map[funcKey][]randUse
	DotImports []string // 以 dot import 引入 rand 套件的檔（一律 fail-close）
	// VarAlias 裸名 → 套件層 var 的合成鍵（`var f = func(){…}` 被 `f()` 呼叫時，
	// 呼叫邊記的是裸名而實體登記在 `var:f` 下，閉包走訪需經此對應）。
	VarAlias map[funcKey]funcKey
}

// scanBackendCallGraph 以 repoRoot 為錨掃描整個 backend module 的非測試碼。
//
// 相對於初版的三處強化（K1）：
//  1. **import 別名解析**——`import crand "crypto/rand"` 的 `crand.Read` 一樣算；
//     dot import 一律 fail-close（無正當用途，且 AST 層無法分辨其識別字來源）。
//  2. **跨檔跨套件呼叫圖**——bare 呼叫解析到同目錄，`pkg.Fn(...)` 經 import 表
//     解析到 module 內目錄，`x.Fn(...)`（receiver 未知）過近似為同目錄同名函式。
//  3. 供 `TestBackendHasNoKEKMaterialGenerator` 對命中與**豁免**函式一併做
//     傳遞閉包判定——豁免函式改以 helper 間接生成的路徑因此被封死。
//
// **第四處強化：套件層宣告的初始化式**。
// 原版只走 `*ast.FuncDecl` 且只 `ast.Inspect(fd.Body)`，`*ast.GenDecl` 整個不進
// 掃描——以
//
//	var generateKEKMaterialProbe = func() string { b := make([]byte, 32); crand.Read(b); … }()
//
// 在任一生產檔繞過**兩軸**（名稱不受檢、rand 取用不計入），三格守衛全綠。
// 現改為：`var`／`const` 宣告中**帶初始化式**的 ValueSpec 一律登記為合成鍵並掃描
// 其 Values（含函式字面量與立即呼叫），rand 取用與呼叫邊比照函式記錄。
//
// **只收帶初始化式者是刻意的**：`var kekBuf []byte` 這種無初始化式的宣告只配置
// 儲存空間、不執行任何程式碼，真正寫入它的賦值必然發生在某個函式（含 `init()`，
// 那是 FuncDecl）內，已在既有射程中——收進來只會製造「變數名像生成器」的誤報，
// 而誤報會讓守衛被當噪音關掉。
func scanBackendCallGraph(t *testing.T, root string) *moduleCallScan {
	t.Helper()
	scan := &moduleCallScan{
		ByTopDir: map[string]int{},
		Funcs:    map[funcKey]bool{},
		FileOf:   map[funcKey]string{},
		LineOf:   map[funcKey]int{},
		Calls:    map[funcKey][]funcKey{},
		RandUses: map[funcKey][]randUse{},
		VarAlias: map[funcKey]funcKey{},
	}
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && strings.HasPrefix(d.Name(), ".") {
				return fs.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			// 解析失敗＝該檔沒被掃過，而本守衛的假綠形態正是「掃不到＝零違規」
			t.Fatalf("解析 %s 失敗（掃描面出現破洞）: %v", path, perr)
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			t.Fatalf("計算 %s 相對路徑失敗: %v", path, rerr)
		}
		rel = filepath.ToSlash(rel)
		scan.Scanned++
		top := rel
		if i := strings.Index(rel, "/"); i >= 0 {
			top = rel[:i]
		}
		scan.ByTopDir[top]++
		dir := filepath.ToSlash(filepath.Dir(rel))

		// import 表：本地名 → module 內目錄；並蒐集 rand 別名
		importDir := map[string]string{}
		randAlias := map[string]bool{}
		for _, imp := range f.Imports {
			ipath := strings.Trim(imp.Path.Value, `"`)
			local := ""
			if imp.Name != nil {
				local = imp.Name.Name
			} else if i := strings.LastIndex(ipath, "/"); i >= 0 {
				local = ipath[i+1:]
			} else {
				local = ipath
			}
			if randSourcePackages[ipath] {
				if local == "." {
					scan.DotImports = append(scan.DotImports,
						fmt.Sprintf("%s:%d dot-import %s", rel, fset.Position(imp.Pos()).Line, ipath))
					continue
				}
				if local != "_" {
					randAlias[local] = true
				}
				continue
			}
			if local == "." || local == "_" {
				continue
			}
			if strings.HasPrefix(ipath, backendModulePath+"/") {
				importDir[local] = strings.TrimPrefix(ipath, backendModulePath+"/")
			}
		}

		// register 登記一個「可含程式碼的宣告」身分（函式或套件層初始化式）
		register := func(key funcKey, line int) {
			scan.Funcs[key] = true
			if _, seen := scan.FileOf[key]; !seen {
				scan.FileOf[key] = rel
				scan.LineOf[key] = line
			}
		}
		// inspectFor 對 node 子樹記錄 rand 取用與呼叫邊，一律歸屬到 key
		inspectFor := func(key funcKey, node ast.Node) {
			ast.Inspect(node, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok {
					if x, ok := sel.X.(*ast.Ident); ok && randAlias[x.Name] {
						scan.RandUses[key] = append(scan.RandUses[key], randUse{
							Key: key, File: rel, Line: fset.Position(sel.Pos()).Line,
							Detail: x.Name + "." + sel.Sel.Name,
						})
					}
				}
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fn := call.Fun.(type) {
				case *ast.Ident:
					scan.Calls[key] = append(scan.Calls[key], funcKey{Dir: dir, Name: fn.Name})
				case *ast.SelectorExpr:
					if x, ok := fn.X.(*ast.Ident); ok {
						if d, ok := importDir[x.Name]; ok {
							scan.Calls[key] = append(scan.Calls[key], funcKey{Dir: d, Name: fn.Sel.Name})
							return true
						}
					}
					// receiver 未知（`s.helper()`／`x.y.helper()`）：過近似為同目錄同名
					scan.Calls[key] = append(scan.Calls[key], funcKey{Dir: dir, Name: fn.Sel.Name})
				}
				return true
			})
		}

		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Name == nil || d.Body == nil {
					continue
				}
				key := funcKey{Dir: dir, Name: d.Name.Name}
				register(key, fset.Position(d.Pos()).Line)
				inspectFor(key, d.Body)
			case *ast.GenDecl:
				// 套件層 var／const 的初始化運算式（含函式字面量與立即呼叫）
				if d.Tok != token.VAR && d.Tok != token.CONST {
					continue
				}
				prefix := pkgLevelVarPrefix
				if d.Tok == token.CONST {
					prefix = pkgLevelConstPrefix
				}
				for _, spec := range d.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok || len(vs.Values) == 0 {
						continue
					}
					var names []string
					for _, id := range vs.Names {
						names = append(names, id.Name)
					}
					key := funcKey{Dir: dir, Name: prefix + strings.Join(names, ",")}
					register(key, fset.Position(vs.Pos()).Line)
					if d.Tok == token.VAR {
						for _, id := range vs.Names {
							scan.VarAlias[funcKey{Dir: dir, Name: id.Name}] = key
						}
					}
					for _, v := range vs.Values {
						inspectFor(key, v)
					}
				}
			}
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("走訪 %s 失敗（掃描根失真）: %v", root, walkErr)
	}
	return scan
}

// reachableRandUses 自 entry 起算呼叫傳遞閉包內的隨機來源取用。
func (s *moduleCallScan) reachableRandUses(entry funcKey) []randUse {
	var out []randUse
	seen := map[funcKey]bool{}
	queue := []funcKey{entry}
	for len(queue) > 0 {
		k := queue[0]
		queue = queue[1:]
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, s.RandUses[k]...)
		for _, c := range s.Calls[k] {
			next := c
			if !s.Funcs[next] {
				// `f()` 呼叫的可能是套件層 `var f = func(){…}`
				alias, ok := s.VarAlias[c]
				if !ok {
					continue
				}
				next = alias
			}
			if !seen[next] {
				queue = append(queue, next)
			}
		}
	}
	return out
}

// randomnessSourceException 一筆具名的隨機來源取用登記。
type randomnessSourceException struct {
	File   string // 相對 module 根，正斜線
	Func   string
	Reason string
}

// randomnessSourceAllowlist 全模組**所有**直接取用 crypto/rand・math/rand 的函式。
//
// **這是 K1「中性名稱」缺口的正解**：`looksLikeKEKGenerator` 是名稱層判別式，
// 一個叫 `makeRootSecret` 的生成器它抓不到。改由本清單從另一個軸把關——
// 任何**新增**的隨機來源取用，不論函式叫什麼、用什麼 import 別名，都必須在此
// 具名登記並寫明「產出的隨機值是什麼、為何不是 KEK 材料」。未登記即紅。
//
// 清單同時做反向完備性檢查（登記了但現實中已不取用＝陳舊登記，會在下一個
// 同名函式出現時無聲放行）。
var randomnessSourceAllowlist = []randomnessSourceException{
	{File: "internal/api/recording_token.go", Func: "Issue",
		Reason: "錄影播放的一次性短期 token（記憶體內、短 TTL、不參與加密），與 KEK 無關。"},
	{File: "internal/modules/keyvault/export_signing_service.go", Func: "NewExportSigningService",
		Reason: "匯出簽章用的 Ed25519 私鑰（簽章金鑰，非 KEK）；其自身以 KEK 包覆後落庫。"},
	{File: "internal/modules/keyvault/checkpoint_signing_service.go", Func: "generateCheckpointSigningKey",
		Reason: "檢查點鏈簽章用的 Ed25519 私鑰（audit-checkpoint-chain，簽章金鑰非 KEK）；其自身經 ColumnCodec 以 KEK 包覆後落庫，與匯出簽章鑰同型。"},
	{File: "internal/modules/keyvault/key_manager_service.go", Func: "insertKey",
		Reason: "資料加密金鑰 DEK。禁止的是伺服端生成 **KEK**（根金鑰一律由運維在行程外產生）；DEK 由伺服端生成並以 KEK 包覆，正是信封加密的定義。"},
	{File: "internal/proxy/connect_token.go", Func: "IssueConnectToken",
		Reason: "連線的一次性 connect token（記憶體內、短 TTL），非加密材料。" +
			"（方法名已對齊 gatewayapi.TokenService，原名 Issue）"},
	{File: "internal/sealjournal/open.go", Func: "newBootID",
		Reason: "封印期日誌的 boot 識別（防檔名／序列碰撞），非加密材料。"},
	{File: "internal/modules/identity/auth_refresh_service.go", Func: "generateRefreshPlain",
		Reason: "web 會話 refresh token 明文（雜湊後落庫），非加密材料。"},
	{File: "internal/modules/identity/auth_service.go", Func: "provisionShadowUser",
		Reason: "外部身分（LDAP／OIDC）影子帳號的不可用隨機佔位密碼——刻意讓本地密碼永不可猜中，非加密材料。"},
	{File: "internal/modules/asset/change_secret_password_policy.go", Func: "GeneratePassword",
		Reason: "改密期為目標帳號產生的新密碼（產品功能本體，含 Fisher-Yates 洗牌），非金鑰材料。" +
			"（自 change_secret_runner.go 遷入本檔並改為策略驅動）"},
	{File: "internal/modules/asset/change_secret_password_policy.go", Func: "pickChar",
		Reason: "上者的字元取樣輔助（自字集均勻取一字元），非金鑰材料。"},
	{File: "internal/modules/asset/ssh_authorized_keys.go", Func: "GenerateSSHKeyPair",
		Reason: "改密期 1 為**目標主機帳號**產生的 Ed25519 登入金鑰對（產品功能本體，等同人工 ssh-keygen 的自動化）；" +
			"私鑰經 ColumnCodec 以 KEK 包覆後落庫，本身不是 KEK 也不參與包覆任何其他金鑰。"},
	{File: "internal/modules/identity/ldap_directory_probe.go", Func: "ldapProbeDiagnosticID",
		Reason: "LDAP 探測的診斷識別（讓探測請求不可預測、便於在目錄側對帳），非加密材料。"},
	{File: "internal/modules/identity/oidc_login_service.go", Func: "randomToken",
		Reason: "OIDC state／nonce／PKCE verifier 的共用隨機來源，非加密材料。"},
	{File: "internal/modules/identity/oidc_login_service.go", Func: "provisionFromClaims",
		Reason: "OIDC 自動佈建帳號的不可用隨機佔位密碼，同 provisionShadowUser。"},
	{File: "internal/sshproxy/share.go", Func: "Create",
		Reason: "終端分享連結的一次性 token，非加密材料。"},
	{File: "pkg/crypto/aes.go", Func: "EncryptBytesAAD",
		Reason: "AES-GCM 的 12-byte nonce（每次加密必須唯一），非金鑰材料。"},
	{File: "internal/dbconsole/ulid.go", Func: "next",
		Reason: "事件 ID（ULID）的 80 位隨機尾碼，長度 10 位元組，純識別字；" +
			"只用於審計列、轉錄與匯出 URL 的定址排序，不進 KEK/DEK/HMAC 任何金鑰路徑，非金鑰材料。"},
}

// TestBackendHasNoKEKMaterialGenerator 安全紅線的**模組級**機械把關：
// 整個 backend module 的非測試碼中不得存在 KEK 材料生成器。
//
// **為何要有這一格**：本檔另兩格以「當前包」定位，射程隨檔案搬家而變（實證：
// 13 檔遷入 keyvault 後，internal/service 全包的涵蓋面歸零而無人察覺）。
// 本格改以 go.mod module 身分為錨（repoRoot），檔案搬到 module 內任何深度都
// 掃同一棵樹，射程不再是搬檔的副作用。
//
// **兩條互補的判準軸**（修補後）：
//
//	軸 A（名稱＋傳遞閉包）：名稱命中 looksLikeKEKGenerator 的函式必須登記於
//	  kekGeneratorAllowlist，且其**跨函式呼叫閉包內**不得出現任何隨機來源取用
//	  （import 別名已解析）。這封死「例外函式改用 helper 間接生成」與
//	  「import crand \"crypto/rand\"」兩種繞法。
//	軸 B（來源 ratchet，與名稱無關）：模組內**每一處**直接取用 crypto/rand・
//	  math/rand 的函式都必須登記於 randomnessSourceAllowlist 並寫明理由。
//	  這封死「取個中性名字（makeRootSecret）」——名稱層判別式抓不到它，
//	  但它一定要碰隨機來源。
//
// **兩軸的掃描面**：`*ast.FuncDecl` 的函式體，
// **加上**套件層 `var`／`const` 帶初始化式的宣告（合成身分 `var:名稱`／
// `const:名稱`，見 scanBackendCallGraph）。原本只走函式體，
// `var x = func(){ crand.Read(b) }()` 因語法位置而兩軸皆盲——那是最直白的一種
// 繞法（名稱含 KEK、別名未改），卻只因寫在 GenDecl 裡就逃逸。
//
// **誠實界定（仍成立的殘餘缺口）**：軸 B 只認 import 得到的 rand 套件；若有人
// 自行實作 CSPRNG、讀 /dev/urandom、或經第三方套件間接取得隨機性，兩軸都看不見。
// 要擋那一類需要型別／資料流分析，不在本守衛射程。另，無初始化式的宣告
// （`var kekBuf []byte`）不登記為身分——它不執行程式碼，寫入它的賦值必在某個
// 函式內（含 `init()`）而已在射程中。本格擋的是「該紅線被無意識地退回」與
// 「以改名／別名／間接呼叫／套件層初始化式規避既有守衛」這些現實形態。
func TestBackendHasNoKEKMaterialGenerator(t *testing.T) {
	root := repoRoot(t)
	scan := scanBackendCallGraph(t, root)

	// ---- 掃描量下界（K2：逐頂層目錄）----
	if len(scan.DotImports) > 0 {
		t.Fatalf("偵測到 rand 套件的 dot import（AST 層無從追蹤其識別字來源，一律禁止）:\n%s",
			strings.Join(scan.DotImports, "\n"))
	}
	for dir, floor := range backendScanFloors {
		got := scan.ByTopDir[dir]
		if got < floor {
			t.Fatalf("頂層目錄 %s 只掃到 %d 個非測試 .go（下限 %d，掃描根 %s）："+
				"該目錄的掃描面已縮水；若確為正當刪檔，SHALL 顯式調降 backendScanFloors[%q] 並在 commit 說明理由",
				dir, got, floor, root, dir)
		}
	}
	for dir := range scan.ByTopDir {
		if _, ok := backendScanFloors[dir]; !ok {
			t.Errorf("頂層目錄 %s 未登記於 backendScanFloors：新目錄不在下界保護內，"+
				"整塊消失時守衛不會轉紅", dir)
		}
	}
	if scan.Scanned < minBackendScannedFiles {
		t.Fatalf("只掃到 %d 個非測試 .go（總量下限 %d）：掃描範圍已失真",
			scan.Scanned, minBackendScannedFiles)
	}

	// ---- 軸 A：名稱命中者＋豁免者的傳遞閉包 ----
	allowed := map[string]string{}
	for _, e := range kekGeneratorAllowlist {
		if strings.TrimSpace(e.Reason) == "" {
			t.Errorf("例外 %s:%s 沒有理由：無理由的例外等於沒有審過", e.File, e.Func)
		}
		allowed[e.File+":"+e.Func] = e.Reason
	}
	seen := map[string]bool{}
	var offenders []string
	hits := 0
	for key := range scan.Funcs {
		if !looksLikeKEKGenerator(key.Name) {
			continue
		}
		hits++
		file := scan.FileOf[key]
		id := file + ":" + key.Name
		if _, ok := allowed[id]; !ok {
			offenders = append(offenders, fmt.Sprintf("%s:%d %s", file, scan.LineOf[key], key.Name))
			continue
		}
		seen[id] = true
		if uses := scan.reachableRandUses(key); len(uses) > 0 {
			var detail []string
			for _, u := range uses {
				detail = append(detail, fmt.Sprintf("%s:%d %s（於 %s）", u.File, u.Line, u.Detail, u.Key))
			}
			sort.Strings(detail)
			t.Errorf("%s 列於 kekGeneratorAllowlist，但其呼叫閉包內取用了隨機來源：\n  %s\n"+
				"該例外的前提（只驗證、不生成）已不成立——直接呼叫與間接 helper 都算，"+
				"請移除例外並把生成移出伺服端", id, strings.Join(detail, "\n  "))
		}
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Fatalf("backend module 內出現伺服端 KEK 材料生成器（禁止：KEK 一律由運維在行程外產生）:\n%s\n"+
			"若確為誤報（名稱像生成器但不生成），於 kekGeneratorAllowlist 具名登記並寫明理由",
			strings.Join(offenders, "\n"))
	}
	for id := range allowed {
		if !seen[id] {
			t.Errorf("kekGeneratorAllowlist 的 %s 已不存在（函式被刪或改名）："+
				"陳舊例外會在下一個同名函式出現時無聲放行，請移除該列", id)
		}
	}

	// ---- 軸 B：隨機來源 ratchet ----
	registered := map[string]string{}
	for _, e := range randomnessSourceAllowlist {
		if strings.TrimSpace(e.Reason) == "" {
			t.Errorf("隨機來源登記 %s:%s 沒有理由：無理由的登記等於沒有審過", e.File, e.Func)
		}
		registered[e.File+":"+e.Func] = e.Reason
	}
	usedRegistered := map[string]bool{}
	var unregistered []string
	for key, uses := range scan.RandUses {
		if len(uses) == 0 {
			continue
		}
		id := scan.FileOf[key] + ":" + key.Name
		if _, ok := registered[id]; ok {
			usedRegistered[id] = true
			continue
		}
		unregistered = append(unregistered,
			fmt.Sprintf("%s:%d %s（%s）", uses[0].File, uses[0].Line, key.Name, uses[0].Detail))
	}
	if len(unregistered) > 0 {
		sort.Strings(unregistered)
		t.Errorf("下列函式直接取用隨機來源但未登記於 randomnessSourceAllowlist：\n%s\n"+
			"新增隨機來源取用 SHALL 具名登記並寫明「產出的是什麼、為何不是 KEK 材料」"+
			"——本軸不看函式名稱，故取中性名字（makeRootSecret）不能規避它",
			strings.Join(unregistered, "\n"))
	}
	for id := range registered {
		if !usedRegistered[id] {
			t.Errorf("randomnessSourceAllowlist 的 %s 已不取用隨機來源（函式被刪、改名或改寫）："+
				"陳舊登記會讓下一個同名函式無聲取得放行，請移除該列", id)
		}
	}

	// 判別式敏感度：空集合只有在判別式仍會抓真生成器時才有意義
	if !looksLikeKEKGenerator("generateKEKString") || !looksLikeKEKGenerator("newKEKMaterial") {
		t.Fatal("判別式對真正的生成器名稱回 false——本守衛已失效")
	}
	if looksLikeKEKGenerator("NewKEKRetirementMonitor") {
		t.Fatal("判別式對建構子誤報——誤報會讓守衛被當噪音關掉")
	}
	t.Logf("KEK 生成全模組掃描：非測試 .go %d 檔 %v；名稱命中 %d 筆／具名例外 %d 筆；"+
		"隨機來源取用 %d 個函式／登記 %d 筆；掃描根 %s",
		scan.Scanned, scan.ByTopDir, hits, len(kekGeneratorAllowlist),
		len(scan.RandUses), len(randomnessSourceAllowlist), root)
}

// parsePackageNonTestFiles 解析目錄下的非測試 Go 檔
func parsePackageNonTestFiles(t *testing.T, dir string) ([]*ast.File, *token.FileSet) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("讀取套件目錄失敗: %v", err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("解析 %s 失敗: %v", name, err)
		}
		files = append(files, f)
	}
	if len(files) < 10 {
		t.Fatalf("只解析到 %d 個檔案——掃描範圍顯然不對", len(files))
	}
	return files, fset
}
