package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/config"
)

// release 審計底線的端到端守衛（audit-release-floor）。
//
// config 層的 `EnforceReleaseSecurityFloor` 單測證明「旗標值被強制回 true」；
// 本測試接著證明**那個值真的把稽核面帶回來了**——路由與中間件鏈是部署者與稽核
// 實際碰得到的面。兩者缺一：只測旗標會漏掉「強制了但消費點另有旁路」，
// 只測路由會漏掉「路由回來了但寫入路徑仍短路」（後者由 config 層旗標值涵蓋）。
//
// 為何不直接跑 `runStage1`：該函式含 `log.Fatalf` 與資料庫 I/O，不可測。
// 本測試改為複製其真實序（Load 後立即 Enforce，先於任何旗標消費），並以
// `buildRouter` 走與 golden 測試同一條 `registerRoutes` 路徑。

// auditLogPaths `/audit-logs` 三條唯讀查詢端點（關閉旗標時整組消失）。
var auditLogPaths = []string{
	"/api/v1/audit-logs",
	"/api/v1/audit-logs/:id",
	"/api/v1/audit-logs/resource/:resource/:id",
}

// auditMiddlewareStableName 全域審計中間件於鏈指紋中的穩定名（與 golden 同源）。
//
// **audit-coverage-closure 批 1 起改為套件限定名**：該波在 `AuditLogMiddleware`
// 的閉包外加入匿名拒絕留痕器的建構，函式因此不再被編譯器內聯進 `main`，
// 註冊進鏈的閉包符號自 `main.main.AuditLogMiddleware.funcN`（stableName 收斂為
// `main.AuditLogMiddleware`）變為套件自身的 `…/internal/middleware.AuditLogMiddleware.func1`。
// **鏈的內容與順序未變**，變的只是同一個函式物件的符號名；路由 golden 的
// `chain_stable` 已一併重生（193 條 × 3 組態的同一段字串替換，無路由增減）。
const auditMiddlewareStableName = "github.com/custodexa/backend/internal/middleware.AuditLogMiddleware.func1"

// releaseFloorFeatures 模擬「部署者於 .env 關閉審計與權限」後走完啟動期強制的組態。
func releaseFloorFeatures(t *testing.T) config.FeatureFlags {
	t.Helper()
	cfg := &config.Config{
		Server: config.ServerConfig{Mode: "release"},
		Features: config.FeatureFlags{
			AuditLogEnabled:        false,
		},
	}
	cfg.EnforceReleaseSecurityFloor()
	return cfg.Features
}

// TestReleaseModeKeepsAuditSurfaceDespiteEnvDisable release ＋
// `FEATURE_AUDIT_LOG_ENABLED=false` 時，稽核面仍完整存在。
//
// 缺陷原狀：該組態下 `/audit-logs` 三條不註冊、全域鏈少掉 audit 段，且畫面不會
// 顯示「審計已關閉」，只會顯示「沒有事件」——與正常但無操作同形。
func TestReleaseModeKeepsAuditSurfaceDespiteEnvDisable(t *testing.T) {
	features := releaseFloorFeatures(t)

	if !features.AuditLogEnabled {
		t.Fatal("release 模式的審計旗標未被強制為 true：後續路由斷言失去意義")
	}

	routes, chains := buildRouter(t, gin.ReleaseMode, features.AuditLogEnabled)

	// 層 1：三條查詢端點須全數註冊
	var missing []string
	for _, p := range auditLogPaths {
		if _, ok := routes[[2]string{"GET", p}]; !ok {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("release 模式下 /audit-logs 端點缺失 %v：環境變數不得移除稽核查詢面", missing)
	}

	// 層 2：全域審計中間件須出現在每一條路由的鏈上（全操作審計，非部分路由）
	var unaudited []string
	for k, chain := range chains {
		found := false
		for _, n := range chain {
			if n == auditMiddlewareStableName {
				found = true
				break
			}
		}
		if !found {
			unaudited = append(unaudited, k[0]+" "+k[1])
		}
	}
	if len(unaudited) > 0 {
		sort.Strings(unaudited)
		t.Errorf("release 模式下有 %d 條路由的中間件鏈不含 %s（例如 %s）："+
			"全操作審計是安全紅線，不得由環境變數關閉",
			len(unaudited), auditMiddlewareStableName, unaudited[0])
	}
}

// TestDebugModeStillHonorsAuditDisable dev 模式維持可關閉——本守衛的另一半。
//
// 防的是「為了讓某個測試變綠而把強制擴大到全模式」：那會使路由 golden 的
// dev-auditoff 兩格、api-docs 的條件註冊 scenario 與 audit 服務層的關閉語義單測
// 全部指向不可達組態。
func TestDebugModeStillHonorsAuditDisable(t *testing.T) {
	cfg := &config.Config{
		Server:   config.ServerConfig{Mode: "debug"},
		Features: config.FeatureFlags{AuditLogEnabled: false},
	}
	cfg.EnforceReleaseSecurityFloor()

	if cfg.Features.AuditLogEnabled {
		t.Fatal("debug 模式不應被強制啟用審計（條件註冊在非生產組態中須仍可觸發）")
	}

	routes, chains := buildRouter(t, gin.DebugMode, cfg.Features.AuditLogEnabled)

	for _, p := range auditLogPaths {
		if _, ok := routes[[2]string{"GET", p}]; ok {
			t.Errorf("debug ＋ 審計關閉時 %s 不應註冊（條件註冊語義）", p)
		}
	}
	for k, chain := range chains {
		for _, n := range chain {
			if n == auditMiddlewareStableName {
				t.Errorf("debug ＋ 審計關閉時 %s %s 的鏈不應含審計中間件", k[0], k[1])
			}
		}
	}
}

// TestStage1CallsReleaseFloorBeforeFlagOutput 啟動路徑確實呼叫底線強制，且呼叫
// 位置先於功能開關狀態輸出。
//
// **為何需要這條 AST 守衛**：上面兩條測試直接呼叫 `EnforceReleaseSecurityFloor`，
// 若有人刪掉 `runStage1` 裡的呼叫，生產完全失去底線而那兩條仍全綠——強制邏輯
// 存在但沒被接線，是本類守衛最典型的假綠形態。`runStage1` 含 `log.Fatalf` 與
// 資料庫 I/O 不可執行，故以靜態結構驗證接線。
//
// 順序要求不是排版潔癖：強制若晚於「=== 功能開關狀態 ===」輸出，啟動日誌印的是
// 環境變數字面值而非生效值——顯示面與生效面不一致，正是本 change 要消滅的形態。
func TestStage1CallsReleaseFloorBeforeFlagOutput(t *testing.T) {
	const (
		floorFunc  = "EnforceReleaseSecurityFloor"
		flagBanner = "=== 功能開關狀態 ==="
	)

	path := filepath.Join(cmdServerDir(t), "stage1.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("解析 %s 失敗（被驗證對象讀不到即等於沒有守衛）: %v", path, err)
	}

	var body *ast.BlockStmt
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Recv == nil && fn.Name.Name == "runStage1" {
			body = fn.Body
			break
		}
	}
	if body == nil {
		t.Fatalf("%s 內找不到 runStage1：啟動序若搬遷，SHALL 同步更新本守衛", path)
	}

	floorPos, bannerPos := token.NoPos, token.NoPos
	ast.Inspect(body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.SelectorExpr:
			if v.Sel != nil && v.Sel.Name == floorFunc && !floorPos.IsValid() {
				floorPos = v.Pos()
			}
		case *ast.BasicLit:
			if v.Kind == token.STRING && strings.Contains(v.Value, flagBanner) && !bannerPos.IsValid() {
				bannerPos = v.Pos()
			}
		}
		return true
	})

	if !floorPos.IsValid() {
		t.Fatalf("runStage1 未呼叫 %s：release 安全底線未接線，"+
			"環境變數可再次靜默關閉全操作審計（安全紅線）", floorFunc)
	}
	if !bannerPos.IsValid() {
		t.Fatalf("runStage1 內找不到功能開關狀態輸出（%q）：本守衛的順序判準失效，"+
			"若輸出被移除或改寫，SHALL 同步更新本守衛", flagBanner)
	}
	if floorPos > bannerPos {
		t.Errorf("%s 的呼叫（%s）晚於功能開關狀態輸出（%s）："+
			"啟動日誌會印出被強制前的環境變數字面值，顯示面與生效面不一致",
			floorFunc, fset.Position(floorPos), fset.Position(bannerPos))
	}
}
