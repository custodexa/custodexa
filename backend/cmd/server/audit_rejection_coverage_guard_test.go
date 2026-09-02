package main

// 拒絕路徑審計覆蓋守衛。
//
// # 這個守衛量的是什麼
//
// 「全操作審計」是本產品的安全紅線。實測發現紅線上有一個系統性破口：
// `middleware/auth.go` 的 8 個 401 abort 分支**從不設 `userID`**，而
// `middleware/audit_log.go:52-56` 是審計中介層唯一的整筆跳過條件——取不到
// `userID`/`username` 就 return。兩者相乘的結果是：**任何被認證中介層擋下的請求，
// 一列審計都不會留下**，而且沒有任何測試會因此變紅。
//
// 本守衛把這件事變成可量測的數字：自**實際註冊的路由集**枚舉每條路由，各機打
// 三發憑證（無憑證／簽章無效／已過期），凡回 401 或 403 者，斷言**可錄審計 sink
// 必產 ≥1 列**。sink 是真的 `AuditLogService` 接真的 `database.DB`（sqlite
// `:memory:`），不是 mock——量的是實際入庫，不是「有沒有呼叫某個函式」。
//
// # 這個守衛剛立起來時預期是紅的
//
// 儀表先立、洞後補。跑起來 `TestRejectionAuditCoverage/
// 每條受保護路由的拒絕必留痕` 必然失敗，失敗數即補洞進度的收斂儀表。
// `rejectionAuditGapBaseline` 釘住當下數字，使**缺口變多**在補洞完成前就會轉紅。
//
// # 為什麼不能用「人工填一張留痕清單」的守衛
//
// 同 `audit_route_classification_guard_test.go` 檔頭的論證：一份人工維護的
// `expectedAudited = map[path]bool{...}` 在新增端點時**不會有任何一條斷言失敗**，
// 因為新端點不在 map 裡、迴圈根本不迭代到它。故本守衛的列舉來源是
// `buildRouter` 的 `r.Routes()`，而豁免白名單採 **default-deny**：
// 每條路由要嘛「掛認證中介層 ⇒ 受『拒絕即留痕』判定」，要嘛「登記在
// `coverageExemptRoutes`」，二者必居其一，否則守衛紅。
//
// # 豁免白名單為什麼無法被拿來消音
//
// 豁免不是自由裁量：`豁免登記與中介層鏈一致` 子測試雙向核對——
// 登記豁免者，其中間件鏈**必須不含**認證中介層；鏈中含認證中介層者，
// **必須不在**豁免表且必須三發皆回 401。於是把一條真的會拒絕的路由塞進豁免表
// 只會多一條紅，不會少一條。放寬豁免因此是**紅色**，不是假綠。
//
// # 明載的邊界（不假裝涵蓋）
//
//   - **裝配保真度**：本守衛沿用 `testDeps` 的 zero-value handler，只把
//     `authService`／`auditService` 換成真貨。理由是拒絕發生在 handler **之前**
//     （AuthMiddleware abort），故受判定的 171 條路由完全不觸及 handler 依賴。
//     但反過來說，**拒絕判定寫在 handler 內**的路由（WS 閘、rtoken 取流、
//     scoped token 自解析那幾條）在本裝配下打不出真實行為——它們正是
//     `coverageExemptRoutes` 的內容，其留痕義務由實走驗證承擔，
//     豁免**不等於**免除留痕義務。
//   - **403 在本裝配打不出來**：RBAC 中介層排在認證之後，壞憑證永遠停在 401。
//     判準本身涵蓋 403（`judgeShot`），但實測樣本全是 401。
//   - 本守衛驗「拒絕有沒有留下一列」，**不驗那一列的欄位對不對**。欄位契約由
//     單點契約守衛與 spec 的 scenario 承擔。

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/crypto"
)

// ── 判準 ──────────────────────────────────────────────────────────────────

// shotVerdict 單發請求的判定。三值閉集合，`judgeShot` 是唯一的產生點——
// 判準只有一份，突變它必然被 `TestJudgeShotIsDiscriminating` 抓到。
type shotVerdict string

const (
	// verdictNotRejected 回應不是 401／403：本發不在射程內。
	verdictNotRejected shotVerdict = "未進入拒絕路徑"
	// verdictAudited 拒絕且 sink 收到列。
	verdictAudited shotVerdict = "拒絕且已留痕"
	// verdictGap 拒絕但 sink 零列——這就是本 change 要消滅的缺陷本體。
	verdictGap shotVerdict = "拒絕但無留痕"
)

// judgeShot 是本守衛的**唯一判準**。
//
// `rowsWritten` 為本發請求前後 audit_logs 的列數差。門檻是 `>= 1` 而非 `>= 0`：
// 後者恆真，會讓整個守衛退化成永遠通過的裝飾品。`TestJudgeShotIsDiscriminating`
// 以已知真值表釘住這條線——把門檻放寬即轉紅。
func judgeShot(statusCode int, rowsWritten int64) shotVerdict {
	if statusCode != http.StatusUnauthorized && statusCode != http.StatusForbidden {
		return verdictNotRejected
	}
	if rowsWritten >= 1 {
		return verdictAudited
	}
	return verdictGap
}

// ── 豁免白名單（default-deny）──────────────────────────────────────────────

// coverageExemptReason 豁免理由的**閉集合**。自由文字理由是同型缺口能潛伏三年的
// 成因，故理由必須是可枚舉的常數，不是散文。
type coverageExemptReason string

const (
	// exemptProbe 無審計語義：存活／連通性探針與內部指標。
	exemptProbe coverageExemptReason = "無審計語義的探針或指標端點"
	// exemptPreAuth 登入前可達：身分尚未成立，拒絕留痕由登入流程自身的產生點承擔。
	exemptPreAuth coverageExemptReason = "登入前可達，身分尚未成立"
	// exemptHandlerSelfAuth 憑證在 handler 內自解析（WS 閘、rtoken、scoped token），
	// 中介層刻意不掛認證。留痕義務**不因豁免而消失**——由實走驗證承擔。
	exemptHandlerSelfAuth coverageExemptReason = "憑證於 handler 內自解析，中介層不掛認證"
	// exemptSealEpoch 封印期端點：須早於認證系統可用，留痕在 seal journal。
	exemptSealEpoch coverageExemptReason = "封印期端點，留痕由 seal journal 承擔"
)

var coverageExemptReasons = map[coverageExemptReason]bool{
	exemptProbe: true, exemptPreAuth: true,
	exemptHandlerSelfAuth: true, exemptSealEpoch: true,
}

// coverageExemptRoutes 不受「拒絕即留痕」判定的路由。
//
// **登記的唯一合法條件是「中間件鏈不含認證中介層」**，且該條件由
// `豁免登記與中介層鏈一致` 子測試機械核對。想靠加一筆豁免讓紅轉綠是做不到的：
// 會拒絕的路由必然掛著認證中介層，一登記就撞上反向核對。
//
// 鍵＝`{method, path}`，與路由 golden 同鍵。
var coverageExemptRoutes = map[[2]string]coverageExemptReason{
	{"GET", "/health"}:                  exemptProbe,
	{"POST", "/health"}:                 exemptProbe,
	{"GET", "/healthz"}:                 exemptProbe,
	{"GET", "/api/v1/ping"}:             exemptProbe,
	// 營運指標曝光：監控採集端無使用者身分，
	// 且封印期即須可採（否則「封印中」與「當機」在監控上不可區分）。
	// 保護不靠認證中介層而靠拓撲——它不在 `/api` 之下，正式版 edge 只代理
	// `/api` 與 `/ws`；需對外時另以 `METRICS_TOKEN` 於 handler 內強制 bearer。
	{"GET", "/metrics"}: exemptProbe,

	{"POST", "/api/v1/auth/login"}:         exemptPreAuth,
	{"GET", "/api/v1/auth/banner"}:         exemptPreAuth,
	{"GET", "/api/v1/auth/methods"}:        exemptPreAuth,
	{"GET", "/api/v1/auth/oidc/:id/begin"}: exemptPreAuth,
	{"GET", "/api/v1/auth/oidc/callback"}:  exemptPreAuth,
	{"POST", "/api/v1/auth/oidc/exchange"}: exemptPreAuth,

	{"POST", "/api/v1/auth/change-password"}:    exemptHandlerSelfAuth,
	{"POST", "/api/v1/auth/mfa/enroll/confirm"}: exemptHandlerSelfAuth,
	{"POST", "/api/v1/auth/mfa/enroll/setup"}:   exemptHandlerSelfAuth,
	{"POST", "/api/v1/auth/mfa/verify"}:         exemptHandlerSelfAuth,
	{"POST", "/api/v1/auth/refresh"}:            exemptHandlerSelfAuth,
	{"GET", "/api/v1/connect"}:                  exemptHandlerSelfAuth,
	{"GET", "/api/v1/recordings/stream"}:        exemptHandlerSelfAuth,
	{"GET", "/api/v1/sessions/:id/monitor"}:     exemptHandlerSelfAuth,
	{"GET", "/api/v1/sessions/share/:code/ws"}:  exemptHandlerSelfAuth,
	// `/api/v1/ssh` **不能移出豁免**：連線票證於 handler 內自解析，
	// 路由刻意不掛 AuthMiddleware，故 ④ 的反向核對（豁免者鏈中不得含認證中介層）
	// 正是它成立的條件；移出反而會撞上 ③ 的 default-deny。
	// 留痕已由 handler 自寫（AP-69 `proxy.AuditConnectDenied`，
	// 與 `/connect` 共用同一寫入點）：缺票／偽票／過期票／閘序拒絕四路皆寫列，
	// 行為由 `internal/sshproxy/ssh_redeem_deny_audit_test.go` 承擔。
	// 同 `/recordings/stream` 的形態——豁免的是**本守衛的機打判定**，不是留痕義務。
	{"GET", "/api/v1/ssh"}: exemptHandlerSelfAuth,
	// `/api/v1/db-console` 同 `/ssh` 的形態：同一種一次性票、同一個
	// `auditRedeemDenied` 寫入點（缺票／偽票／過期票／閘序拒絕四路皆寫列），
	// 路由刻意不掛認證中介層。豁免的是本守衛的機打判定，不是留痕義務
	{"GET", "/api/v1/db-console"}: exemptHandlerSelfAuth,

	{"GET", "/api/v1/seal/status"}:  exemptSealEpoch,
	{"POST", "/api/v1/seal/unseal"}: exemptSealEpoch,
}

// rejectionAuditGapBaseline 拒絕路徑無留痕的**路由**條數上限（單調下降的儀表）。
//
// **現值 0**（2026-08-14 實測下修）。起始值 171 是 2026-08-13 的實測數，
// 即「掛認證中介層卻對拒絕零留痕」的路由總數；後於 `audit_log.go` 單點插入匿名
// 失敗列後歸零。**棘輪停在 171 等同全鬆**：現況缺口是 0，上限卻容得下 171 條，
// 於是任何新缺口都不會讓這條轉紅——刻度失去意義。下修是收緊，不是放寬。
//
// 契約與 `maxUnclassifiedRoutes` 同形：**要多一條缺口就必須在同一份 diff 把這個
// 數字調高**，沒有豁免、沒有 skip 可以繞過；而下修只能靠真的補洞——豁免表改不動
// 這個數字（豁免只對鏈中無認證中介層者成立，那些路由本就不計入）。
const rejectionAuditGapBaseline = 0

// minRejectionShotsFired 防假綠下界：若 `r.Routes()` 失效或迴圈提前 break，
// 掃描會零迭代而全綠。三發 × 193 條 = 579；取保守下界。
const minRejectionShotsFired = 400

// coverageJWTSecret 本守衛專用的 JWT 簽章材料。測試用途、不進任何設定檔，
// 與產品密鑰無關。
const coverageJWTSecret = "audit-coverage-guard-only-not-a-real-secret"

// ── 三發憑證 ──────────────────────────────────────────────────────────────

// credentialShot 一種憑證形態。
//
// 兩種「壞憑證」（簽章無效／簽章有效但已過期）在現況實碼走的是**同一個 abort
// 分支**——`auth.go:41-45` 只判 `ValidateToken` 有沒有回錯，不分辨錯在哪。
// 仍然兩發都打：分支合一是實作細節，日後若拆成兩個分支（例如過期另給機器碼），
// 本守衛的覆蓋不需要跟著改；而 `壞憑證兩形態的 abort 分支` 子測試把「現在是同一
// 分支」這件事機械釘住，拆分時會轉紅並提醒同步更新本註解。
type credentialShot struct {
	name   string
	header string // Authorization 標頭值；空字串＝不帶
}

func coverageShots(t *testing.T) []credentialShot {
	t.Helper()

	// 簽章無效：以**另一組**密鑰簽出的合法 JWT。結構完整、僅簽章對不上。
	foreign := crypto.NewJWTManager("a-different-secret-entirely", time.Hour)
	badSig, err := foreign.GenerateToken(1, "coverage-guard", "guard@example.invalid", "admin", crypto.AuthContext{})
	if err != nil {
		t.Fatalf("簽出「簽章無效」token 失敗: %v", err)
	}

	// 已過期：以**正確**密鑰簽出但 TTL 為負，exp 落在過去。簽章驗得過、時效驗不過。
	stale := crypto.NewJWTManager(coverageJWTSecret, -time.Hour)
	expired, err := stale.GenerateToken(1, "coverage-guard", "guard@example.invalid", "admin", crypto.AuthContext{})
	if err != nil {
		t.Fatalf("簽出「已過期」token 失敗: %v", err)
	}

	return []credentialShot{
		{"無憑證", ""},
		{"壞憑證：簽章無效", "Bearer " + badSig},
		{"壞憑證：已過期", "Bearer " + expired},
	}
}

// ── sink 與 router 的裝配 ─────────────────────────────────────────────────

// installCoverageAuditDB 裝一個最小的 `database.DB` 供斷言讀回實列。
// sqlite `:memory:` 每條新連線是獨立的空 DB，連線池必須收到 1，否則
// middleware 的寫入與本測試的讀回會落在不同 DB 上而恆為零列（假紅）。
func installCoverageAuditDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("開 sqlite: %v", err)
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

// newCoverageAuditService 同步寫入的審計服務（`AsyncAuditEnabled=false`）。
// 非同步會讓「打一發、數一次」的差分帶進 worker 批次的時序不確定性。
func newCoverageAuditService() *audit.AuditLogService {
	return audit.NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false,
	})
}

// countAuditRows 讀回 audit_logs 實列數（Unscoped：軟刪欄不得影響計數）。
func countAuditRows(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	if err := db.Unscoped().Model(&model.AuditLog{}).Count(&n).Error; err != nil {
		t.Fatalf("計數 audit_logs: %v", err)
	}
	return n
}

// buildCoverageRouter 以**真的** authService／auditService 建 router。
//
// 其餘 handler 沿用 `testDeps` 的 zero-value——受判定的路由在 AuthMiddleware
// 就 abort，根本走不到 handler。鏈中無認證中介層者會真的進 handler 並多半 panic，
// 故掛 Recovery（輸出丟棄）：那些路由一律在豁免表內，其回應碼不參與判定。
func buildCoverageRouter(t *testing.T, svc *audit.AuditLogService) *gin.Engine {
	t.Helper()
	prev := gin.Mode()
	gin.SetMode(gin.ReleaseMode)
	t.Cleanup(func() { gin.SetMode(prev) })

	d := testDeps(true, true)
	d.authService = identity.NewAuthService(coverageJWTSecret, time.Hour)
	d.auditService = svc

	r := gin.New()
	r.Use(gin.RecoveryWithWriter(io.Discard))
	registerRoutes(r, d)
	return r
}

// ── 掃描結果 ──────────────────────────────────────────────────────────────

type shotResult struct {
	shot    string
	status  int
	rows    int64
	verdict shotVerdict
}

type routeCoverage struct {
	method, path string
	hasAuthMW    bool
	exempt       bool
	shots        []shotResult
}

func (rc routeCoverage) key() [2]string { return [2]string{rc.method, rc.path} }

// gapShots 回傳判定為缺口的發次。
func (rc routeCoverage) gapShots() []shotResult {
	var out []shotResult
	for _, s := range rc.shots {
		if s.verdict == verdictGap {
			out = append(out, s)
		}
	}
	return out
}

// runCoverageSweep 對每條註冊路由機打三發並記錄結果。
func runCoverageSweep(t *testing.T) []routeCoverage {
	t.Helper()

	db := installCoverageAuditDB(t)
	svc := newCoverageAuditService()
	r := buildCoverageRouter(t, svc)
	shots := coverageShots(t)

	// 中間件鏈另取自 `buildRouter`（與本 router 同一個 `registerRoutes`，
	// 鏈的形狀不因 deps 的服務指標而異）。
	_, chains := buildRouter(t, gin.ReleaseMode, true)

	// 審計中介層對每個請求各印一行 log，193 × 3 發會把失敗清單淹掉。
	// 掃描期間丟棄標準 log 輸出，掃完還原。
	prevWriter := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(prevWriter)

	routes := r.Routes()
	if len(routes) < minAuditRoutesScanned {
		t.Fatalf("router 只回了 %d 條路由（下界 %d）——列舉來源失效時迴圈會零迭代而全綠，"+
			"故 Fatal 而非 skip", len(routes), minAuditRoutesScanned)
	}

	out := make([]routeCoverage, 0, len(routes))
	for _, rt := range routes {
		key := [2]string{rt.Method, rt.Path}
		rc := routeCoverage{method: rt.Method, path: rt.Path}
		_, rc.exempt = coverageExemptRoutes[key]
		for _, name := range chains[key] {
			if containsAuthMiddleware(name) {
				rc.hasAuthMW = true
				break
			}
		}

		for _, s := range shots {
			before := countAuditRows(t, db)
			req := httptest.NewRequest(rt.Method, concreteTestPath(rt.Path), nil)
			if s.header != "" {
				req.Header.Set("Authorization", s.header)
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			after := countAuditRows(t, db)
			delta := after - before
			rc.shots = append(rc.shots, shotResult{
				shot: s.name, status: w.Code, rows: delta,
				verdict: judgeShot(w.Code, delta),
			})
		}
		out = append(out, rc)
	}

	fired := 0
	for _, rc := range out {
		fired += len(rc.shots)
	}
	if fired < minRejectionShotsFired {
		t.Fatalf("只打出 %d 發（下界 %d）——掃描提前中斷的守衛不是「沒發現問題」，是「沒在看」",
			fired, minRejectionShotsFired)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].path != out[j].path {
			return out[i].path < out[j].path
		}
		return out[i].method < out[j].method
	})
	return out
}

// containsAuthMiddleware 鏈段是否為認證中介層。判準與
// `audit_route_classification_guard_test.go` 的方向 5 共用 `authMiddlewareMarker`，
// 兩個守衛不得各持一份「什麼叫認證中介層」。
func containsAuthMiddleware(chainEntry string) bool {
	return strings.Contains(chainEntry, authMiddlewareMarker)
}

// ── 前置：sink 必須是活的 ─────────────────────────────────────────────────

// TestRejectionAuditSinkIsLive 前置條件：計數機制本身要能數到列。
//
// 若 AutoMigrate 失敗、連線池設定失誤或 `AuditLogEnabled` 沒開，列數會**恆為 0**，
// 於是覆蓋守衛會因為完全錯誤的理由而紅（假紅），且補洞後也不會轉綠。
// 本測試以「帶身分的請求」走真的審計中介層，斷言確實入庫 ≥1 列。
//
// 刻意**不**斷言「無身分 ⇒ 零列」：那正是補洞要改掉的行為，釘住它等於替缺陷
// 立一道護欄。
func TestRejectionAuditSinkIsLive(t *testing.T) {
	prev := gin.Mode()
	gin.SetMode(gin.TestMode)
	t.Cleanup(func() { gin.SetMode(prev) })

	db := installCoverageAuditDB(t)
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(newCoverageAuditService()))
	r.GET("/coverage-sink-liveness", func(c *gin.Context) {
		c.Set("userID", uint(1))
		c.Set("username", "coverage-guard")
		c.Status(http.StatusOK)
	})

	before := countAuditRows(t, db)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/coverage-sink-liveness", nil))
	after := countAuditRows(t, db)

	if after-before < 1 {
		t.Fatalf("帶身分的請求走完審計中介層卻沒有任何列入庫（前 %d 後 %d）。"+
			"計數機制若是死的，覆蓋守衛的紅與綠都沒有意義", before, after)
	}
}

// TestJudgeShotIsDiscriminating 判準的已知真值表。
//
// 這是擋「把斷言改成 ≥0」那一類放寬的釘子：門檻一旦放寬，前兩列立刻對不上。
// 判準只有 `judgeShot` 一份實作，掃描迴圈也走它，故本表與實掃同源。
func TestJudgeShotIsDiscriminating(t *testing.T) {
	cases := []struct {
		name   string
		status int
		rows   int64
		want   shotVerdict
	}{
		{"401 零列即缺口", http.StatusUnauthorized, 0, verdictGap},
		{"403 零列即缺口", http.StatusForbidden, 0, verdictGap},
		{"401 有列即合格", http.StatusUnauthorized, 1, verdictAudited},
		{"403 有列即合格", http.StatusForbidden, 2, verdictAudited},
		{"200 不在射程", http.StatusOK, 0, verdictNotRejected},
		{"500 不在射程", http.StatusInternalServerError, 0, verdictNotRejected},
		{"400 不在射程", http.StatusBadRequest, 0, verdictNotRejected},
	}
	for _, c := range cases {
		if got := judgeShot(c.status, c.rows); got != c.want {
			t.Errorf("%s：judgeShot(%d, %d) = %q，應為 %q。"+
				"判準被放寬時整個覆蓋守衛會退化成永遠通過的裝飾品",
				c.name, c.status, c.rows, got, c.want)
		}
	}
}

// TestCoverageExemptEntriesAreWellFormed 豁免表自身的形狀：鍵與理由都不得是垃圾。
func TestCoverageExemptEntriesAreWellFormed(t *testing.T) {
	for key, reason := range coverageExemptRoutes {
		if key[0] == "" || key[1] == "" {
			t.Errorf("豁免表有空鍵：%v", key)
		}
		if !coverageExemptReasons[reason] {
			t.Errorf("%s %s 的豁免理由 %q 不在閉集合內——理由必須是可枚舉的常數，"+
				"自由文字無機械核對", key[0], key[1], reason)
		}
	}
}

// ── 主守衛 ────────────────────────────────────────────────────────────────

func TestRejectionAuditCoverage(t *testing.T) {
	sweep := runCoverageSweep(t)

	// ① 覆蓋本體：受判定路由的每一發拒絕都必須留下列。
	//    **儀表剛立時預期為紅**——這就是要記錄下來的基準。
	t.Run("每條受保護路由的拒絕必留痕", func(t *testing.T) {
		var gapRoutes []routeCoverage
		for _, rc := range sweep {
			if rc.exempt {
				continue
			}
			if len(rc.gapShots()) > 0 {
				gapRoutes = append(gapRoutes, rc)
			}
		}
		if len(gapRoutes) == 0 {
			return
		}

		shown := len(gapRoutes)
		if shown > 10 {
			shown = 10
		}
		msg := ""
		for _, rc := range gapRoutes[:shown] {
			for _, s := range rc.gapShots() {
				msg += fmt.Sprintf("\n  %s %s ｜ %s ｜ HTTP %d ｜ 入庫 %d 列",
					rc.method, rc.path, s.shot, s.status, s.rows)
			}
		}
		t.Errorf("%d 條路由的拒絕路徑零留痕（基準 %d）。"+
			"認證中介層 abort 時從未設過 userID，審計中介層在 audit_log.go:52-56 整筆跳過——"+
			"「誰在敲門、敲了幾次」在稽核上完全答不出來。\n"+
			"現階段只立儀表不補洞，本失敗為預期結果；單點插入匿名失敗列後應歸零。\n"+
			"前 %d 條（共 %d 條）：%s",
			len(gapRoutes), rejectionAuditGapBaseline, shown, len(gapRoutes), msg)
	})

	// ② 儀表：缺口數不得增加。這條若轉紅，代表補洞倒退或新端點帶進新缺口。
	t.Run("缺口數不得超過基準", func(t *testing.T) {
		n := 0
		for _, rc := range sweep {
			if !rc.exempt && len(rc.gapShots()) > 0 {
				n++
			}
		}
		if n > rejectionAuditGapBaseline {
			t.Errorf("拒絕路徑無留痕的路由有 %d 條，超過基準 %d。"+
				"要多一條就必須在同一份 diff 把 rejectionAuditGapBaseline 調高——"+
				"沒有豁免或 skip 可以繞過它", n, rejectionAuditGapBaseline)
		}
	})

	// ③ default-deny：不掛認證中介層又沒登記豁免的路由，一律紅。
	//    新增端點必然命中此條（要嘛掛認證 ⇒ 受 ① 判定，要嘛沒掛 ⇒ 必須具名登記）。
	t.Run("不受判定的路由必須顯式登記豁免", func(t *testing.T) {
		for _, rc := range sweep {
			if rc.hasAuthMW || rc.exempt {
				continue
			}
			t.Errorf("%s %s 的中間件鏈不含認證中介層，卻未登記於 coverageExemptRoutes。"+
				"豁免是 default-deny：新端點若刻意不掛認證，必須寫下具名理由"+
				"（探針／登入前可達／handler 自解析／封印期），不得預設放行",
				rc.method, rc.path)
		}
	})

	// ④ 豁免的反向核對：豁免表無法被拿來替「真的會拒絕的路由」消音。
	t.Run("豁免登記與中介層鏈一致", func(t *testing.T) {
		seen := map[[2]string]bool{}
		for _, rc := range sweep {
			seen[rc.key()] = true
			if rc.exempt && rc.hasAuthMW {
				t.Errorf("%s %s 登記了豁免，但它的中間件鏈**含**認證中介層。"+
					"掛了認證就會拒絕、就必須留痕——豁免只對鏈中無認證中介層者成立，"+
					"不是用來讓紅色消失的開關", rc.method, rc.path)
			}
			if !rc.exempt && rc.hasAuthMW {
				for _, s := range rc.shots {
					if s.status != http.StatusUnauthorized {
						t.Errorf("%s %s 掛了認證中介層，%s 卻回 HTTP %d（應為 401）。"+
							"認證中介層若對壞憑證放行，本守衛量到的「無缺口」全是假的",
							rc.method, rc.path, s.shot, s.status)
					}
				}
			}
		}
		for key := range coverageExemptRoutes {
			if !seen[key] {
				t.Errorf("豁免表登記了 %s %s，但該路由未註冊——過期的豁免會在同名端點"+
					"日後重新出現時預設放行", key[0], key[1])
			}
		}
	})

	// ⑤ 兩種壞憑證的 abort 分支現況（0.3 的機械註記）。
	t.Run("壞憑證兩形態的 abort 分支", func(t *testing.T) {
		var probe *routeCoverage
		for i := range sweep {
			if sweep[i].hasAuthMW {
				probe = &sweep[i]
				break
			}
		}
		if probe == nil {
			t.Fatalf("找不到任何掛認證中介層的路由——鏈判定失效")
		}
		byShot := map[string]int{}
		for _, s := range probe.shots {
			byShot[s.shot] = s.status
		}
		for _, name := range []string{"無憑證", "壞憑證：簽章無效", "壞憑證：已過期"} {
			if byShot[name] != http.StatusUnauthorized {
				t.Errorf("%s %s 的「%s」回 HTTP %d，應為 401",
					probe.method, probe.path, name, byShot[name])
			}
		}
		// 現況：`auth.go:41-45` 只判 ValidateToken 有沒有回錯，兩種壞憑證同分支同碼。
		// 日後若把「已過期」拆成獨立分支／獨立機器碼，這裡不會紅（狀態碼仍是 401），
		// 故把事實記在覆蓋層而非碼層——兩發都打，分支怎麼拆都不漏。
	})
}
