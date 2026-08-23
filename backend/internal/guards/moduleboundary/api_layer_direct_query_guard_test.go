package moduleboundary

import (
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// 「api／middleware 繞 service 直查 model」的復辟守衛。
//
// 收斂的四處：
//   - `api/role_handler.go:28` 直查 `model.Role` → `identity.UserService.ListRoles`（identity）
//   - `api/clipboard_event_handler.go:32` 直查 `model.ClipboardEvent` →
//     `service.SessionService.ListClipboardEvents`（session）
//   - `api/asset_handler.go:679` 直寫 `model.AuditLog` → 已改經 AsyncSink
//   - `middleware/approver_guard.go:53` 直查 `model.ApproverScope` →
//     `authz.EvaluateApproverRouteEligibility`（判準逐字未改）
//
// **守衛的形狀**：接入層（`internal/api`＋`internal/middleware`）的非測試檔中，
// 任何以 `*gorm.DB` 為接收者、以 `model.*` 型別或 SQL 字面量指名資料表的存取，
// 都必須落在具名例外清單內。清單**不含**上述四處——那正是「擋復辟」的意思。
//
// **本守衛不做的事**：不追求把接入層的 `*gorm.DB` 清零。清單裡的三處是**刻意
// 不動**的既有債（各有理由），列出來是為了讓它們可見且有數量上界，不是為了赦免。
// 新增一處未登記的直查即紅——那才是這個守衛的用途。

// apiLayerScanDirs 接入層掃描範圍（相對 module 根）。
var apiLayerScanDirs = []string{"./internal/api/...", "./internal/middleware/..."}

// apiLayerDirectAccessExempt 具名例外：接入層現存的直接資料存取，逐條附理由。
//
// **那四處收斂點不得出現在此表**——加進來就等於把守衛關掉，
// 而 `TestAPILayerConvergedSitesAreNotExempt` 會擋下那個動作。
var apiLayerDirectAccessExempt = map[string]string{
	"internal/api/key_management_handler.go": "KEK 清冊查詢直接 Model(&model.DataKey{})：" +
		"keyvault 的金鑰清冊尚未提供查詢面（搬檔時未反轉查詢），列為既有債（backlog）。",
	"internal/api/syslog_setting_handler.go": "syslog 單列設定的讀寫（First/Save）：" +
		"policy 側無對應服務，且該表為單列組態，列為既有債（backlog）。",
}

// directQueryConvergedFiles 上述四處收斂點所在檔——**永遠不得列入例外清單**。
var directQueryConvergedFiles = []string{
	"internal/api/role_handler.go",
	"internal/api/clipboard_event_handler.go",
	"internal/api/asset_handler.go",
	"internal/middleware/approver_guard.go",
}

// minAPILayerScannedFiles 接入層非測試檔掃描下限（現況 60+，取 40 為保守下界）。
const minAPILayerScannedFiles = 40

// TestAPILayerHasNoDirectModelQuery 接入層直查的復辟守衛。
func TestAPILayerHasNoDirectModelQuery(t *testing.T) {
	root := lifecycleModuleRoot(t)
	modelTables := modelTableNames(t, root)

	fset := token.NewFileSet()
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo |
			packages.NeedImports | packages.NeedDeps,
		Dir:   root,
		Fset:  fset,
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, apiLayerScanDirs...)
	if err != nil {
		t.Fatalf("packages.Load 失敗（守衛無法在無視野下宣稱通過）: %v", err)
	}
	if len(pkgs) < 2 {
		t.Fatalf("只載入 %d 個包（期望至少 api 與 middleware 兩個）：掃描範圍已失真", len(pkgs))
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
	scan := dataBoundaryScan{}
	scanned := 0
	for _, p := range pkgs {
		if p.TypesInfo == nil {
			continue
		}
		for _, f := range p.Syntax {
			path := fset.Position(f.Pos()).Filename
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			rf := rel(path)
			scanned++
			collectFileDataAccess(p.TypesInfo, fset, f, rf, "api-layer", modelTables, false, &scan)
		}
	}
	if scanned < minAPILayerScannedFiles {
		t.Fatalf("只掃到 %d 個接入層非測試檔（下限 %d）：掃描面已失真，"+
			"「零直查」不構成證據", scanned, minAPILayerScannedFiles)
	}

	var violations []string
	hitExempt := map[string]bool{}
	for _, f := range scan.Findings {
		file := f.Site
		if i := strings.LastIndex(file, ":"); i > 0 {
			file = file[:i]
		}
		if _, ok := apiLayerDirectAccessExempt[file]; ok {
			hitExempt[file] = true
			continue
		}
		violations = append(violations, f.Site+"："+f.Kind+" 表 "+f.Table)
	}
	// 例外清單的「仍然有效」二次條件（testing.md §5 形態 14 的歸零反轉）：
	// 登記了卻掃不到任何存取，代表那一處已經收乾淨（該刪列）或偵測器對它失明。
	var idle []string
	for f := range apiLayerDirectAccessExempt {
		if !hitExempt[f] {
			idle = append(idle, f)
		}
	}
	sort.Strings(idle)
	if len(idle) > 0 {
		t.Errorf("例外清單登記的檔已掃不到任何直接資料存取：%s\n"+
			"若是收乾淨了 SHALL 刪除該列（白名單只會越留越寬）；"+
			"若不是，就是偵測器對它失明，本守衛的通過不成立", strings.Join(idle, ", "))
	}
	sort.Strings(violations)
	if len(violations) > 0 {
		t.Errorf("接入層（internal/api／internal/middleware）出現未登記的直接資料存取：\n  %s\n"+
			"正確的處置是「改呼叫擁有該資料的模組」，不是把它加進例外清單——"+
			"handler／middleware 一旦自己查表，判定就會出現第二份真相",
			strings.Join(violations, "\n  "))
	}
	t.Logf("接入層掃描：%d 包／%d 非測試檔／存取點 %d 個／例外檔 %d 個",
		len(pkgs), scanned, len(scan.Findings), len(apiLayerDirectAccessExempt))
}

// TestAPILayerConvergedSitesAreNotExempt 例外清單的二次條件（「列進清單不是免死金牌」）：
// 那四處收斂點不得被加進例外清單。缺這條的話，把守衛關掉的成本只是加一行。
func TestAPILayerConvergedSitesAreNotExempt(t *testing.T) {
	var leaked []string
	for _, f := range directQueryConvergedFiles {
		if _, ok := apiLayerDirectAccessExempt[f]; ok {
			leaked = append(leaked, f)
		}
	}
	if len(leaked) > 0 {
		t.Errorf("已收斂的檔被加進例外清單：%s\n"+
			"這四處直查的消滅是模組化的驗收條件，加進例外＝把驗收條件本身刪掉",
			strings.Join(leaked, ", "))
	}
	// 例外清單的檔必須真實存在（防「登記已過期」的白名單越留越寬）
	root := lifecycleModuleRoot(t)
	var missing []string
	for f := range apiLayerDirectAccessExempt {
		if _, err := os.Stat(filepath.Join(root, f)); err != nil {
			missing = append(missing, f)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("例外清單登記的檔不存在：%s（移除須顯式更新清單）", strings.Join(missing, ", "))
	}
}
