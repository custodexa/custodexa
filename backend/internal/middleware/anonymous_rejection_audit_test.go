package middleware

// 匿名拒絕留痕與有界機制的行為守衛。
//
// 這裡釘的是**單點契約**，不是路由清單：`cmd/server/audit_rejection_coverage_guard_test.go`
// 負責掃遍實際註冊路由並量缺口數，本檔負責證明「經認證中介層 abort 的請求必產一列，
// 且那一列的欄位與有界行為符合 spec」。兩者刻意分工——路由再多，本檔的斷言不漂移。
//
// # 突變自檢（三種互不掩蓋）
//
//	移除匿名列寫入（audit_log.go 的 anon.record 呼叫刪掉）
//	  → TestAnonRejectionWritesCompleteRow／TestAuthMiddlewareAbortAlwaysProducesOneRow 轉紅
//	移除有界機制（record 內恆 allowed）
//	  → TestAnonRejectionFloodIsBounded 轉紅（寫入量正比於請求量）
//	聚合門檻改為無限大（PerKeyBurst／GlobalBurst 設成天文數字）
//	  → TestAnonRejectionFloodIsBounded 轉紅（同上，且無聚合列）
//	聚合表滿載時直接丟棄事件（aggregateLocked 的 overflow 重映射改為 return）
//	  → TestAnonRejectionAggregateOverflowKeepsEvents 轉紅（總計數短少）
//	超長路徑的收口失效（model.BoundAuditLogFields 改為 no-op）
//	  → TestAnonRejectionOversizedPathStaysWithinSchema 轉紅（path 超出欄位上界）

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/crypto"
)

const anonTestJWTSecret = "anon-rejection-guard-only-not-a-real-secret"

// installAnonAuditDB 裝一個最小的 database.DB 供讀回實列。
// sqlite `:memory:` 每條新連線是獨立的空 DB，連線池必須收到 1，否則 middleware 的
// 寫入與本測試的讀回會落在不同 DB 上而恆為零列（假紅）
func installAnonAuditDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("取底層 sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.AuditLog{}); err != nil {
		t.Fatalf("migrate audit_logs: %v", err)
	}
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })
	return db
}

// newAnonAuditService 同步寫入的審計服務——非同步 worker 會讓「打一發、數一次」
// 的差分帶進批次時序的不確定性
func newAnonAuditService() *audit.AuditLogService {
	return audit.NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false,
	})
}

// anonTestClock 可注入時鐘：限流測試不得依賴真實時間 sleep（既慢又 flaky）
type anonTestClock struct{ now time.Time }

func newAnonTestClock() *anonTestClock {
	return &anonTestClock{now: time.Date(2026, 8, 13, 9, 0, 0, 0, time.UTC)}
}

func (c *anonTestClock) Now() time.Time          { return c.now }
func (c *anonTestClock) advance(d time.Duration) { c.now = c.now.Add(d) }

// anonRouter 建一個掛「審計中介層 → 認證中介層 → handler」的 router，
// 順序與 registerRoutes 的實際鏈一致（審計在外、認證在內）
func anonRouter(t *testing.T, paths []string, opts ...auditLogOption) (*gin.Engine, *gorm.DB) {
	t.Helper()
	prev := gin.Mode()
	gin.SetMode(gin.TestMode)
	t.Cleanup(func() { gin.SetMode(prev) })

	db := installAnonAuditDB(t)
	authService := identity.NewAuthService(anonTestJWTSecret, time.Hour)

	r := gin.New()
	r.Use(AuditLogMiddleware(newAnonAuditService(), opts...))
	for _, p := range paths {
		r.GET(p, AuthMiddleware(authService), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"ok": true})
		})
	}
	return r, db
}

// anonRows 讀回全部審計列（Unscoped：軟刪欄不得影響）
func anonRows(t *testing.T, db *gorm.DB) []model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	if err := db.Unscoped().Order("id asc").Find(&rows).Error; err != nil {
		t.Fatalf("讀回 audit_logs: %v", err)
	}
	return rows
}

// anonDetailsOf 解析一列的 details JSON
func anonDetailsOf(t *testing.T, row model.AuditLog) map[string]any {
	t.Helper()
	out := map[string]any{}
	if row.Details == "" {
		return out
	}
	if err := json.Unmarshal([]byte(row.Details), &out); err != nil {
		t.Fatalf("details 不是合法 JSON（%q）: %v", row.Details, err)
	}
	return out
}

// expiredBearer 以正確密鑰簽出但 TTL 為負的 token：簽章驗得過、時效驗不過
func expiredBearer(t *testing.T) string {
	t.Helper()
	stale := crypto.NewJWTManager(anonTestJWTSecret, -time.Hour)
	tok, err := stale.GenerateToken(1, "anon-guard", "guard@example.invalid", "admin", crypto.AuthContext{})
	if err != nil {
		t.Fatalf("簽出已過期 token: %v", err)
	}
	return "Bearer " + tok
}

func anonShoot(r *gin.Engine, method, path, authHeader, remoteAddr string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// ── 欄位契約 ──────────────────────────────────────────────────────────────

// TestAnonRejectionWritesCompleteRow spec「拒絕路徑必留痕」的欄位契約。
//
// 缺口的形態是「整筆消失」，故本測試同時釘住**列存在**與**四欄非空**：只驗有列
// 不驗欄位時，一個 `AuditLogEntry{Status: failure}` 的空殼列也會通過，而稽核在那
// 種列上答不出「誰從哪裡敲了哪一扇門」。
func TestAnonRejectionWritesCompleteRow(t *testing.T) {
	r, db := anonRouter(t, []string{"/api/v1/assets"})

	w := anonShoot(r, http.MethodGet, "/api/v1/assets", "", "203.0.113.9:51000", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("狀態碼 = %d，應為 401", w.Code)
	}

	rows := anonRows(t, db)
	if len(rows) != 1 {
		t.Fatalf("入庫 %d 列，應為 1 列——認證中介層 abort 的請求必須留痕", len(rows))
	}
	row := rows[0]
	if row.UserID != 0 {
		t.Errorf("user_id = %d，應為 0（匿名就該看得出是匿名，不得拿佔位帳號冒充）", row.UserID)
	}
	if row.Username != "" {
		t.Errorf("username = %q，應為空", row.Username)
	}
	if row.Resource != model.ResourceAuth {
		t.Errorf("resource = %q，應為 %q", row.Resource, model.ResourceAuth)
	}
	if row.Status != model.StatusFailure {
		t.Errorf("status = %q，應為 %q（認證失敗＝憑證不成立，與授權拒絕的 denied 分流）",
			row.Status, model.StatusFailure)
	}
	if row.ClientIP != "203.0.113.9" {
		t.Errorf("client_ip = %q，應為連線對端 203.0.113.9", row.ClientIP)
	}
	if row.Path != "/api/v1/assets" {
		t.Errorf("path = %q", row.Path)
	}
	if row.Method != http.MethodGet {
		t.Errorf("method = %q", row.Method)
	}
	if row.StatusCode != http.StatusUnauthorized {
		t.Errorf("status_code = %d，應為 401", row.StatusCode)
	}
	d := anonDetailsOf(t, row)
	if d["event"] != anonEventRejected {
		t.Errorf("details.event = %v，應為 %q", d["event"], anonEventRejected)
	}
}

// TestAnonRejectionReasonDistinguishesCredentialCases spec「失敗原因可區分憑證缺失
// 與憑證無效」。原因沿用既有 apierror 機器碼，不新造散文字串——稽核端篩選的語彙
// 與前端拿到的錯誤碼是同一套。
func TestAnonRejectionReasonDistinguishesCredentialCases(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   string
	}{
		{"無憑證", "", "AUTH_TOKEN_MISSING"},
		{"簽章無效", "Bearer not-a-real-token", "AUTH_TOKEN_INVALID"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, db := anonRouter(t, []string{"/api/v1/assets"})
			anonShoot(r, http.MethodGet, "/api/v1/assets", c.header, "203.0.113.9:51000", nil)
			rows := anonRows(t, db)
			if len(rows) != 1 {
				t.Fatalf("入庫 %d 列，應為 1 列", len(rows))
			}
			if got := anonDetailsOf(t, rows[0])["reason"]; got != c.want {
				t.Errorf("details.reason = %v，應為 %q——兩種憑證形態必須分得開，"+
					"否則「沒帶憑證的探測」與「帶著失效憑證的正常使用者」在稽核上同形", got, c.want)
			}
		})
	}

	// 已過期：**審計側分流、對外不分流**。
	//
	// 分流的理由在計數面：access token 每 15 分鐘到期一次、前端自動 refresh，
	// 每次都留一列；與「無憑證」「簽章無效」混計會讓每日覆核的登入失敗數被正常
	// 流量淹沒（PCI 10.4.1 的覆核價值歸零）。不分流的理由在攻擊面：讓外部能區分
	// 「這張 token 曾經有效」與「這張是偽造的」等於開出憑證存在性的探測面。
	//
	// 故本子測試**兩半都要驗**——只驗其一時，「順手把過期也回成獨立機器碼」
	// 這種退化不會有任何測試轉紅。
	t.Run("已過期於審計分流但對外不可區分", func(t *testing.T) {
		r, db := anonRouter(t, []string{"/api/v1/assets"})
		wExpired := anonShoot(r, http.MethodGet, "/api/v1/assets", expiredBearer(t), "203.0.113.9:51000", nil)
		rows := anonRows(t, db)
		if len(rows) != 1 {
			t.Fatalf("入庫 %d 列，應為 1 列", len(rows))
		}
		if got := anonDetailsOf(t, rows[0])["reason"]; got != model.AuditReasonTokenExpired {
			t.Errorf("details.reason = %v，應為 %q——例行到期須與真正的無效存取嘗試分得開，"+
				"否則每日覆核的登入失敗數會被正常流量淹沒", got, model.AuditReasonTokenExpired)
		}

		// 對外那一半：與簽章無效的回應逐字相同（狀態碼與機器碼皆然）
		r2, _ := anonRouter(t, []string{"/api/v1/assets"})
		wForged := anonShoot(r2, http.MethodGet, "/api/v1/assets", "Bearer not-a-real-token", "203.0.113.9:51000", nil)
		if wExpired.Code != wForged.Code || wExpired.Body.String() != wForged.Body.String() {
			t.Errorf("過期與偽造的對外回應必須逐字相同，實得 %d/%s vs %d/%s",
				wExpired.Code, wExpired.Body.String(), wForged.Code, wForged.Body.String())
		}
		if !strings.Contains(wExpired.Body.String(), "AUTH_TOKEN_INVALID") {
			t.Errorf("對外機器碼應維持 AUTH_TOKEN_INVALID（審計側才分流），實得 %s", wExpired.Body.String())
		}
	})
}

// ── 單點契約（與路由數量無關）────────────────────────────────────────────
//
// TestAuthMiddlewareAbortAlwaysProducesOneRow 釘住核心主張：留痕發生在
// **中介層單點**，故「有幾條路由」不影響契約。路徑刻意取一組現實中不存在的
// 名字——若哪天有人把留痕改成逐 handler／逐路由的登記表，這些路徑不會在表上，
// 本測試立刻轉紅。
func TestAuthMiddlewareAbortAlwaysProducesOneRow(t *testing.T) {
	paths := []string{
		"/api/v1/not-a-real-endpoint",
		"/api/v1/another/:id/made-up",
		"/api/v1/third/one",
		"/api/v1/fourth",
		"/api/v1/fifth",
	}
	r, db := anonRouter(t, paths)

	requests := []string{
		"/api/v1/not-a-real-endpoint",
		"/api/v1/another/7/made-up",
		"/api/v1/third/one",
		"/api/v1/fourth",
		"/api/v1/fifth",
	}
	for _, p := range requests {
		if w := anonShoot(r, http.MethodGet, p, "", "198.51.100.4:40000", nil); w.Code != http.StatusUnauthorized {
			t.Fatalf("%s 回 %d，應為 401", p, w.Code)
		}
	}

	rows := anonRows(t, db)
	if len(rows) != len(requests) {
		t.Fatalf("打了 %d 發拒絕卻入庫 %d 列——單點契約是「每一次 abort 一列」，"+
			"筆數與路由數量無關", len(requests), len(rows))
	}
	seen := map[string]bool{}
	for _, row := range rows {
		seen[row.Path] = true
	}
	for _, p := range requests {
		if !seen[p] {
			t.Errorf("%s 的拒絕沒有對應的匿名列", p)
		}
	}
}

// TestAuthMiddlewareHasSingle401Exit AST 守衛：`internal/middleware` 內任何 401
// 出口都必須走 `abortUnauthenticated`。
//
// **為什麼需要 AST 而不是行為測試**：新增一個 abort 分支卻忘記留下拒絕標記時，
// 症狀是「那條路徑的拒絕又回到零留痕」——沒有任何既有行為測試會轉紅，而覆蓋守衛
// 要等到有人跑 cmd/server 全包才看得到。判準放在語法層，新增分支當場被擋。
//
// # 射程限制（明載而不擴大）
//
// 本守衛**只認 `apierror.Respond(…, http.StatusUnauthorized, …)` 這一種形態**。
// 以其他表達式回 401——`c.AbortWithStatusJSON(401, …)`、`c.JSON` 後 `c.Abort()`、
// 把狀態碼藏進變數或常數、經由 helper 間接回應——本守衛掃不到，會照樣全綠。
// 驗收者實測即以 `c.AbortWithStatusJSON` 繞過本守衛。
//
// **刻意不追這些形態**：401 的表達方式是開放集合，逐一補形態會變成無止境的
// 形態追逐，而每補一種都讓守衛更難讀、更容易在下一次重構時整個失效（掃不到
// 東西的守衛全綠，是最糟的失敗模式）。
//
// **後盾是行為測試而不是本守衛**：同一次繞過會讓
// `TestAnonRejectionWritesCompleteRow`、`TestAnonRejectionReasonDistinguishesCredentialCases`、
// `TestAuthMiddlewareAbortAlwaysProducesOneRow` 三個行為測試轉紅（實測），
// 外加 `cmd/server` 的拒絕覆蓋守衛以缺口數上升的形態轉紅。本守衛的價值在
// **早**（不必等跑全包）與**明確**（直接指出是哪個函式），不在完備。
func TestAuthMiddlewareHasSingle401Exit(t *testing.T) {
	dir := middlewarePackageDir(t)
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("解析 %s 失敗（守衛不在殘缺 AST 上作判定）: %v", dir, err)
	}

	helperSetsMark := false
	respondExits := 0
	helperCalls := 0
	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			rel := filepath.Base(path)
			ast.Inspect(file, func(n ast.Node) bool {
				fn, ok := n.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					return true
				}
				inHelper := fn.Name.Name == "abortUnauthenticated"
				ast.Inspect(fn.Body, func(m ast.Node) bool {
					call, ok := m.(*ast.CallExpr)
					if !ok {
						return true
					}
					if inHelper && calleeName(call) == "c.Set" && len(call.Args) == 2 {
						if id, ok := call.Args[0].(*ast.Ident); ok && id.Name == "authRejectionContextKey" {
							helperSetsMark = true
						}
					}
					if calleeName(call) == "abortUnauthenticated" {
						helperCalls++
					}
					if calleeName(call) != "apierror.Respond" || len(call.Args) < 2 {
						return true
					}
					if !isUnauthorizedStatus(call.Args[1]) {
						return true
					}
					respondExits++
					if !inHelper {
						t.Errorf("%s 的 %s 直接以 apierror.Respond 回 401——"+
							"中介層的 401 出口必須走 abortUnauthenticated，"+
							"否則該次拒絕不會留下標記，審計中介層就會照舊整筆跳過",
							rel, fn.Name.Name)
					}
					return true
				})
				return true
			})
		}
	}

	if !helperSetsMark {
		t.Error("abortUnauthenticated 內找不到 c.Set(authRejectionContextKey, …)——" +
			"標記是匿名留痕的唯一觸發條件，拿掉它等於整批 401 回到零留痕")
	}
	if respondExits != 1 {
		t.Errorf("掃到 %d 個 401 的 apierror.Respond 出口，應恰為 1（helper 內那一個）", respondExits)
	}
	// 防空掃：AST 走訪失效時最可能的症狀是「一個呼叫點都沒掃到」而全綠。
	// 現況 10 處（auth.go 6／approver_guard.go 2／asset_visibility.go 1／permission.go 1）
	if helperCalls < 8 {
		t.Errorf("只掃到 %d 處 abortUnauthenticated 呼叫（下界 8）——掃描失效的守衛"+
			"不是「沒發現問題」，是「沒在看」", helperCalls)
	}
}

func middlewarePackageDir(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller 取本檔路徑失敗")
	}
	return filepath.Dir(self)
}

func calleeName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		if x, ok := fn.X.(*ast.Ident); ok {
			return x.Name + "." + fn.Sel.Name
		}
		return fn.Sel.Name
	}
	return ""
}

func isUnauthorizedStatus(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	x, ok := sel.X.(*ast.Ident)
	return ok && x.Name == "http" && sel.Sel.Name == "StatusUnauthorized"
}

// ── 有界機制 ──────────────────────────────────────────────────────────────

// TestAnonRejectionNormalExpiryStaysPerRequest spec「正常過期逐筆留痕」。
//
// 這條是有界機制的**邊界**：門檻若被調到比正常使用還低，稽核在日常就只剩聚合列，
// 「這位使用者何時在哪一台機器上被擋」就此不可查。故用預設參數（不覆寫）打少量請求。
func TestAnonRejectionNormalExpiryStaysPerRequest(t *testing.T) {
	r, db := anonRouter(t, []string{"/api/v1/assets"})

	const shots = 6
	for i := 0; i < shots; i++ {
		anonShoot(r, http.MethodGet, "/api/v1/assets", expiredBearer(t), "203.0.113.20:44000", nil)
	}

	rows := anonRows(t, db)
	if len(rows) != shots {
		t.Fatalf("%d 發正常過期入庫 %d 列，應逐筆留痕（%d 列）", shots, len(rows), shots)
	}
	for _, row := range rows {
		if ev := anonDetailsOf(t, row)["event"]; ev != anonEventRejected {
			t.Errorf("正常過期的列 details.event = %v，不應是聚合列", ev)
		}
	}
}

// TestAnonRejectionFloodIsBounded spec「洪水下寫入有界」。
//
// 兩種洪水各打一遍——只測其中一種會留下一條敞開的路：
//   - 同一扇門猛敲：由 per-key 桶擋下。
//   - 輪換路徑（攻擊者換鍵想繞過 per-key）：由全域桶擋下。
//
// 斷言是**寫入量與請求量脫鉤**（不是某個魔術數字）：10000 發請求對上以額度算出的
// 上界。門檻若被改成無限大，寫入量會正比於請求量而立刻超界。
func TestAnonRejectionFloodIsBounded(t *testing.T) {
	const shots = 10000
	params := anonRejectionParams{
		PerKeyBurst: 5, PerKeyRefill: 6 * time.Second,
		GlobalBurst: 50, GlobalRefill: time.Second,
		AggregateWindow: time.Minute,
	}

	t.Run("同一端點猛敲", func(t *testing.T) {
		clock := newAnonTestClock()
		r, db := anonRouter(t, []string{"/api/v1/assets"},
			withAnonRejectionParams(params), withAnonRejectionClock(clock.Now))

		for i := 0; i < shots; i++ {
			anonShoot(r, http.MethodGet, "/api/v1/assets", "Bearer bad", "198.51.100.77:33000", nil)
		}
		perRequest := anonRows(t, db)
		if len(perRequest) > int(params.PerKeyBurst) {
			t.Fatalf("%d 發洪水寫出 %d 列逐筆留痕，上界應為 per-key 額度 %.0f——"+
				"未認證請求可無限寫庫時，偵測機制本身就是攻擊載體",
				shots, len(perRequest), params.PerKeyBurst)
		}

		// 窗結束後聚合列落地，且保留來源／次數／起訖時間
		clock.advance(2 * time.Minute)
		anonShoot(r, http.MethodGet, "/api/v1/assets", "Bearer bad", "198.51.100.77:33000", nil)

		var agg *model.AuditLog
		rows := anonRows(t, db)
		for i := range rows {
			if anonDetailsOf(t, rows[i])["event"] == anonEventRejectedAggregate {
				agg = &rows[i]
				break
			}
		}
		if agg == nil {
			t.Fatalf("窗結束後找不到聚合列——逾界的失敗不逐筆持久化，" +
				"若也不聚合就是把偵測訊號整段丟掉")
		}
		d := anonDetailsOf(t, *agg)
		count, _ := d["count"].(float64)
		if int(count) < shots-int(params.PerKeyBurst)-1 {
			t.Errorf("聚合列 count = %v，應涵蓋逾界的 %d 發", d["count"], shots-int(params.PerKeyBurst))
		}
		if d["client_ip"] != "198.51.100.77" {
			t.Errorf("聚合列 client_ip = %v，應為連線對端", d["client_ip"])
		}
		if d["first_at"] == nil || d["last_at"] == nil || d["first_at"] == "" {
			t.Errorf("聚合列缺起訖時間：%v", d)
		}
		if agg.ClientIP != "198.51.100.77" {
			t.Errorf("聚合列 client_ip 欄 = %q，應為連線對端", agg.ClientIP)
		}
	})

	t.Run("輪換路徑繞過 per-key", func(t *testing.T) {
		clock := newAnonTestClock()
		paths := make([]string, 0, 40)
		for i := 0; i < 40; i++ {
			paths = append(paths, fmt.Sprintf("/api/v1/rotating-%d", i))
		}
		r, db := anonRouter(t, paths,
			withAnonRejectionParams(params), withAnonRejectionClock(clock.Now))

		for i := 0; i < shots; i++ {
			anonShoot(r, http.MethodGet, paths[i%len(paths)], "Bearer bad", "198.51.100.88:33000", nil)
		}
		rows := anonRows(t, db)
		if len(rows) > int(params.GlobalBurst) {
			t.Fatalf("輪換 %d 條路徑打 %d 發，寫出 %d 列，上界應為全域額度 %.0f——"+
				"per-key 的鍵由請求可控，全域桶才是真正的上界",
				len(paths), shots, len(rows), params.GlobalBurst)
		}
	})
}

// TestDefaultParamsKeepProductionBounded 產品**預設值**本身必須有界。
//
// 洪水測試為了跑得快注入自己的參數，故它證明的是「機制會擋」，不是「產品用的門檻
// 夠低」。兩者都要：門檻被調成天文數字時機制照樣運作、洪水測試照樣全綠，而產品
// 在真實部署下已經無界——那正是「有界」這條 spec 最容易被靜默廢掉的方式。
//
// 斷言的是**由參數算出的上界**而非參數本身的數值，故調參數不會製造假紅；
// 只有把上界推高到天花板以上才轉紅，而那必須在同一份 diff 裡把天花板一起改。
func TestDefaultParamsKeepProductionBounded(t *testing.T) {
	p := defaultAnonRejectionParams()

	// 穩態上界＝全域桶每分鐘補回的額度 ＋ 聚合表每分鐘最多落地的列數
	perMinute := float64(time.Minute)/float64(p.GlobalRefill) +
		float64(p.MaxAggregates)*(float64(time.Minute)/float64(p.AggregateWindow))
	const steadyCeiling = 500
	if perMinute > steadyCeiling {
		t.Errorf("預設參數的穩態上界為 %.0f 列／分鐘，超過天花板 %d——"+
			"未認證請求可寫庫即洪水面，門檻一旦形同虛設，偵測機制本身就是攻擊載體",
			perMinute, steadyCeiling)
	}

	// 突發額度是一次性的，但它決定「攻擊者按下 enter 的那一秒能灌進多少列」
	const burstCeiling = 5000
	if p.GlobalBurst > burstCeiling {
		t.Errorf("全域突發額度 %.0f 超過天花板 %d", p.GlobalBurst, burstCeiling)
	}
	// 下界的另一半由 TestAnonRejectionNormalExpiryStaysPerRequest 承擔
	//（門檻若低於正常使用，日常就只剩聚合列）。
	//
	// **全域突發額度另受一個外部約束**：`cmd/server` 的拒絕覆蓋守衛會自單一來源
	// 連打 513 發（171 條受判定路由 × 3 種憑證形態）並要求每一發都留下一列。
	// 突發額度低於該數時那個守衛會以「拒絕零留痕」的形態轉紅——那不是誤報，
	// 是真的有一部分拒絕沒有逐筆留痕。
	if p.GlobalBurst < 600 {
		t.Errorf("全域突發額度 %.0f 過低：憑證過期風暴（NAT 後單一出口）會在一分鐘內"+
			"把逐筆留痕壓成聚合列，日常稽核就此失去單筆解析度", p.GlobalBurst)
	}
}

// TestAnonRejectionAggregateOverflowKeepsEvents 聚合表滿載時**不得丟棄事件**。
//
// 這條補的是獨立驗收打出的零覆蓋：`aggregateLocked` 在表滿時把事件重映射到
// 共用的 `(overflow)` 鍵，語義是「偵測訊號可以失去來源解析度，但不該整段消失」。
// 突變成「表滿即 return」時，`internal/middleware` 全包與覆蓋守衛**皆綠**——
// 也就是說在本測試之前，那句宣稱沒有任何測試保護。
//
// 表滿是**分散式洪水**才會出現的情境（128 個來源同時越界），而那正是最需要
// 留下證據的時刻：丟棄發生在攻擊規模最大的那一刻，且完全靜默。
func TestAnonRejectionAggregateOverflowKeepsEvents(t *testing.T) {
	clock := newAnonTestClock()
	params := anonRejectionParams{
		// per-key 只給 1 發：每個來源的第 2 發起即逾界、必進聚合
		PerKeyBurst: 1, PerKeyRefill: time.Hour,
		GlobalBurst: 1000, GlobalRefill: time.Second,
		AggregateWindow: time.Minute,
		// 聚合表只有 2 格：第 3 個來源起必須落到 (overflow) 共用鍵
		MaxAggregates: 2,
	}
	r, db := anonRouter(t, []string{"/api/v1/assets"},
		withAnonRejectionParams(params), withAnonRejectionClock(clock.Now))

	const sources, shotsPer = 5, 4
	for s := 0; s < sources; s++ {
		for i := 0; i < shotsPer; i++ {
			anonShoot(r, http.MethodGet, "/api/v1/assets", "Bearer bad",
				fmt.Sprintf("203.0.113.%d:35000", 100+s), nil)
		}
	}

	// 窗結束後由後續任一拒絕觸發結清（本機制不留背景 goroutine）
	clock.advance(2 * time.Minute)
	anonShoot(r, http.MethodGet, "/api/v1/assets", "Bearer bad", "203.0.113.200:35000", nil)

	totalAggregated := 0
	sawOverflowKey := false
	for _, row := range anonRows(t, db) {
		d := anonDetailsOf(t, row)
		if d["event"] != anonEventRejectedAggregate {
			continue
		}
		count, _ := d["count"].(float64)
		totalAggregated += int(count)
		if d["client_ip"] == anonAggOverflowIP {
			sawOverflowKey = true
		}
	}

	// 每個來源 4 發：1 發逐筆留痕、3 發逾界。5 個來源共 15 發逾界，一發都不能少
	const wantAggregated = sources * (shotsPer - 1)
	if totalAggregated != wantAggregated {
		t.Errorf("聚合列合計 count = %d，應為 %d——聚合表滿載時丟棄事件，"+
			"等於在分散式洪水（最需要證據的那一刻）靜默抹掉偵測訊號",
			totalAggregated, wantAggregated)
	}
	if !sawOverflowKey {
		t.Errorf("找不到 client_ip=%q 的聚合列——表滿後的來源必須併入共用鍵，"+
			"而不是被丟掉", anonAggOverflowIP)
	}
}

// TestAnonRejectionOversizedPathStaysWithinSchema 超長路徑仍須寫得進 schema。
//
// `:id` 型路由吸得下任意長度，而 `audit_logs.path` 是 varchar(500)：補匿名留痕前
// 未認證請求根本不寫庫，補上之後這條路徑**零憑證即可產出一列寫不進去的審計列**
// ——該次拒絕零留痕，且同批的合法審計列被一併回滾（第二層隔離在
// `modules/audit` 的 flushBatch 守衛）。
//
// 本測試釘的是第一層：匿名列自己就不該產生超界欄位，且截斷後仍答得出
// 「攻擊者打了什麼」。
func TestAnonRejectionOversizedPathStaysWithinSchema(t *testing.T) {
	r, db := anonRouter(t, []string{"/api/v1/assets/:id"})

	payload := strings.Repeat("A", 600)
	w := anonShoot(r, http.MethodGet, "/api/v1/assets/"+payload, "", "203.0.113.60:53000", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("狀態碼 = %d，應為 401", w.Code)
	}

	rows := anonRows(t, db)
	if len(rows) != 1 {
		t.Fatalf("入庫 %d 列，應為 1——超長路徑的拒絕同樣必須留痕", len(rows))
	}
	row := rows[0]

	limit := model.AuditLogRuneLimit("Path")
	if n := utf8.RuneCountInString(row.Path); n > limit {
		t.Fatalf("path 有 %d 字元，超過欄位上界 %d——這一列在 Postgres 上寫不進去，"+
			"而它所在的整批合法審計列會一起被回滾", n, limit)
	}
	// 可歸屬性三問：打的是哪一支、打了多長、是不是同一發
	if !strings.HasPrefix(row.Path, "/api/v1/assets/AAAA") {
		t.Errorf("path 未保留前綴（%q…）——稽核答不出他打的是哪一支端點", row.Path[:32])
	}
	if !strings.Contains(row.Path, fmt.Sprintf("len=%d", len("/api/v1/assets/")+len(payload))) {
		t.Errorf("path 未記原始長度：%q", row.Path)
	}
	if !strings.Contains(row.Path, "sha256=") {
		t.Errorf("path 未帶指紋：%q——沒有指紋就無法把同一條超長路徑的多次嘗試關聯", row.Path)
	}
	// 其餘欄位不受影響：來源與失敗原因仍完整
	if row.ClientIP != "203.0.113.60" {
		t.Errorf("client_ip = %q", row.ClientIP)
	}
	if d := anonDetailsOf(t, row)["reason"]; d != "AUTH_TOKEN_MISSING" {
		t.Errorf("details.reason = %v", d)
	}
}

// TestAnonRejectionForgedForwardedHeaderDoesNotSplitAttribution
// spec「偽造轉送標頭不影響歸戶」。
//
// 未設可信代理時 gin 的 ClientIP() 信任任意 X-Forwarded-For，若拿它歸戶，攻擊者
// 每發換一個標頭就換到全新額度——有界機制形同虛設，且審計列上的「來源」變成
// 攻擊者自己寫的字串。
func TestAnonRejectionForgedForwardedHeaderDoesNotSplitAttribution(t *testing.T) {
	const shots = 500
	clock := newAnonTestClock()
	params := anonRejectionParams{
		PerKeyBurst: 5, PerKeyRefill: 6 * time.Second,
		GlobalBurst: 50, GlobalRefill: time.Second,
	}
	r, db := anonRouter(t, []string{"/api/v1/assets"},
		withAnonRejectionParams(params), withAnonRejectionClock(clock.Now),
		withTrustedProxyDecision(false))

	for i := 0; i < shots; i++ {
		anonShoot(r, http.MethodGet, "/api/v1/assets", "Bearer bad", "198.51.100.99:33000",
			map[string]string{"X-Forwarded-For": fmt.Sprintf("10.0.%d.%d", i/256, i%256)})
	}

	rows := anonRows(t, db)
	if len(rows) > int(params.PerKeyBurst) {
		t.Fatalf("輪換 %d 個偽造轉送標頭寫出 %d 列，上界應為 per-key 額度 %.0f——"+
			"歸戶一旦採信可偽造的標頭，攻擊者即可自選限流桶", shots, len(rows), params.PerKeyBurst)
	}
	for _, row := range rows {
		if row.ClientIP != "198.51.100.99" {
			t.Errorf("client_ip = %q，應為連線對端 198.51.100.99（不得採信轉送標頭）", row.ClientIP)
		}
	}
}

// ── 403 反向斷言 ─────────────────────────────────────────────────────────

// TestForbiddenKeepsNamedDeniedRow spec「授權拒絕維持既有語義」。
//
// 這裡只補**認證失敗**（401）那一半。授權拒絕（403）的身分是成立的，既有的具名列
// 與 `status=denied` 是稽核上「誰被擋在哪一道權限外」的答案，不得因為補 401 而被
// 順手改寫成匿名或 failure。
func TestForbiddenKeepsNamedDeniedRow(t *testing.T) {
	prev := gin.Mode()
	gin.SetMode(gin.TestMode)
	t.Cleanup(func() { gin.SetMode(prev) })

	db := installAnonAuditDB(t)
	r := gin.New()
	r.Use(AuditLogMiddleware(newAnonAuditService()))
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(9))
		c.Set("username", "operator")
		c.Set("role", "user")
		c.Next()
	})
	r.GET("/api/v1/access-requests/pending", RequireRole("admin"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{})
	})

	w := anonShoot(r, http.MethodGet, "/api/v1/access-requests/pending", "", "203.0.113.30:41000", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("狀態碼 = %d，應為 403", w.Code)
	}

	rows := anonRows(t, db)
	if len(rows) != 1 {
		t.Fatalf("入庫 %d 列，應為 1 列", len(rows))
	}
	row := rows[0]
	if row.Status != model.StatusDenied {
		t.Errorf("403 的 status = %q，應維持 %q——授權拒絕與認證失敗是兩種語義，"+
			"混成一團會破壞既有 denied 列的可解釋性", row.Status, model.StatusDenied)
	}
	if row.Username != "operator" || row.UserID != 9 {
		t.Errorf("403 的列被改寫成匿名（user_id=%d username=%q）——身分成立時必須具名",
			row.UserID, row.Username)
	}
	if ev := anonDetailsOf(t, row)["event"]; ev == anonEventRejected || ev == anonEventRejectedAggregate {
		t.Errorf("403 走了匿名列的產生點（details.event=%v）", ev)
	}
}

// TestHandlerSelfAuditedRejectionIsNotDoubleWritten 無標記的 401 維持跳過。
//
// `/auth/login` 密碼錯誤、`/auth/refresh` 壞票證這些路徑同樣是「401 且無身分」，
// 但它們已由 handler 自寫審計列。無差別補寫會讓同一次事件出現兩列，直接汙染
// 每日覆核的登入失敗計數——修一個缺口的同時製造一個計數缺陷。
func TestHandlerSelfAuditedRejectionIsNotDoubleWritten(t *testing.T) {
	prev := gin.Mode()
	gin.SetMode(gin.TestMode)
	t.Cleanup(func() { gin.SetMode(prev) })

	db := installAnonAuditDB(t)
	r := gin.New()
	r.Use(AuditLogMiddleware(newAnonAuditService()))
	// 模擬 handler 自行判定憑證並自寫審計的路徑（不經認證中介層）
	r.POST("/api/v1/auth/login", func(c *gin.Context) {
		c.JSON(http.StatusUnauthorized, gin.H{"code": "AUTH_INVALID_CREDENTIALS"})
	})

	anonShoot(r, http.MethodPost, "/api/v1/auth/login", "", "203.0.113.40:42000", nil)

	if rows := anonRows(t, db); len(rows) != 0 {
		t.Fatalf("handler 自行回 401 的路徑寫出 %d 列匿名列——那些路徑已由 handler 自寫留痕，"+
			"中介層再補一列即為重複計數", len(rows))
	}
}
