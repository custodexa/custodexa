package api

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

// 權限註冊不得條件化。
//
// # 這個守衛擋的是什麼
//
// 本 change 之前，`internal/api` 下有 10 個 handler、11 處
// `if permissionEnabled { 帶 RequirePermission } else { 裸註冊 }`。
// `FEATURE_PERMISSION_CHECK_ENABLED=false` 時，錄影下載、審計日誌、會話指令、
// 資產帳號等敏感讀取端點全部無守門。release 模式強制該旗標為 true 故正式部署
// 安全，但那是**部署期的補救**，不是結構保證：只要模式還在，任何人照舊樣板
// 新增端點就會複製出一個新的旁路。
//
// 旗標已隨本 change 退場。本守衛把「不得回來」變成機器可驗的事實：
// RegisterRoutes 不得有布林參數，路由註冊不得依布林分支。
//
// # 為何是結構檢查而不是行為檢查
//
// 曾嘗試過的替代方案是「掃所有路由的中間件鏈，斷言都帶 RequirePermission」，
// 實測報出 145 條——因為大量管理端點用的是 `RequireRole("admin")`、逐資產守門
// 用的是 `RequireAssetVisible`，判準本身就不對。要讓它綠只能列一張 145 條的
// 豁免表，而那種表沒有人會讀，「把新端點加進豁免表」會變成例行動作，守衛就死了。
//
// 端點層級的授權覆蓋另有守衛負責（cmd/server 的 audit_route_classification 與
// rejection_coverage 兩支，default-deny 白名單機制）。本守衛只管一件事：
// **註冊本身不得依組態分歧**。
//
// # 已知邊界
//
// 只看 `internal/api` 的 RegisterRoutes 方法簽名與其函式體內的條件分支。
// 以其他形式引入的條件註冊（例如在 cmd/server 依旗標決定要不要呼叫某個
// RegisterRoutes）不在射程內——那一層由 routeDeps 的 bool 欄位矩陣守衛
// （cmd/server 的 TestRouteDepsFlagsCoveredByMatrix）涵蓋。

// permissionFlagNames 被視為「權限旗標」的參數名。
//
// 取名字而非取型別：條件註冊的危害來自語義，而 Go 這一層看不出 `bool` 是什麼意思。
// 這張表要擋的是「照舊樣板複製」——舊樣板用的正是這兩個名字。
var permissionFlagNames = map[string]bool{
	"permissionEnabled":      true,
	"permissionCheckEnabled": true,
	"permEnabled":            true,
}

func TestNoConditionalPermissionRegistration(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		// 測試檔本身不算：gate 測試會刻意提到這些名字
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("解析 internal/api 失敗: %v", err)
	}

	var scanned int
	var offences []string

	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				fn, ok := n.(*ast.FuncDecl)
				if !ok || fn.Name.Name != "RegisterRoutes" || fn.Recv == nil {
					return true
				}
				scanned++
				where := filepath.Base(path)

				// ① 簽名不得帶權限旗標參數
				for _, p := range fn.Type.Params.List {
					ident, ok := p.Type.(*ast.Ident)
					if !ok || ident.Name != "bool" {
						continue
					}
					for _, name := range p.Names {
						if permissionFlagNames[name.Name] {
							offences = append(offences, where+
								": RegisterRoutes 簽名帶權限旗標參數 "+name.Name)
						}
					}
				}

				// ② 函式體內不得以權限旗標分歧
				ast.Inspect(fn.Body, func(inner ast.Node) bool {
					ifStmt, ok := inner.(*ast.IfStmt)
					if !ok {
						return true
					}
					if ident, ok := ifStmt.Cond.(*ast.Ident); ok && permissionFlagNames[ident.Name] {
						offences = append(offences, where+
							": RegisterRoutes 內以 "+ident.Name+" 條件註冊路由")
					}
					return true
				})
				return true
			})
		}
	}

	// 防假綠下界：AST 掃描若因套件路徑或過濾條件失效而零迭代，
	// 上面的 offences 會是空的而測試全綠——「掃不到東西」不是「沒問題」
	const minRegisterRoutesScanned = 25
	if scanned < minRegisterRoutesScanned {
		t.Fatalf("只掃到 %d 個 RegisterRoutes（下界 %d）：掃描本身已失效，"+
			"此時零違規是假綠", scanned, minRegisterRoutesScanned)
	}

	if len(offences) > 0 {
		sort.Strings(offences)
		t.Errorf("發現 %d 處條件式權限註冊：\n  %s\n\n"+
			"權限檢查於所有模式無條件生效——"+
			"路由一律帶授權中間件，不得依旗標分歧。若確有需要條件註冊的正當理由，"+
			"請先在 spec 立案，不要靜默恢復舊樣板",
			len(offences), strings.Join(offences, "\n  "))
	}

	t.Logf("已掃描 %d 個 RegisterRoutes，零條件式權限註冊", scanned)
}
