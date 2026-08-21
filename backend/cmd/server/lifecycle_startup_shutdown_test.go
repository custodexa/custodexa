package main

// 啟停整合測試（modular-architecture Phase B / W1 任務 1.15）。
//
// **本檔要證明的事，既有的 build／test／golden 一個也證明不了**：模組化會改變
// init／註冊／shutdown／zeroize 的**順序**，而順序錯誤的失敗形態全部是安靜的——
// 少蓋一個章、晚一步歸零、早一步關佇列，編譯照過、既有測試照綠。故本檔驗的
// 不是「跑得起來」，而是「以什麼順序跑起來、以什麼順序收回去」。
//
// 三個順序敏感點（W1.3-1.4 lifecycle manifest 盤點得出的結論；原始推演紀錄歸檔於
// 維護者的私有開發歷程，未隨公開倉庫發佈）：
//
//  1. `model.SetAuditCreateHooks` 註冊時點：此點之前寫出的審計列 HMAC 為空，
//     而驗章端把空章列當成上線前的歷史列**不計入竄改判定**——失敗形態是
//     更安靜而非更吵。既有守衛只釘「同檔且先於遷移呼叫」
//     （internal/service/post_unseal_guard_test.go:308），不釘「先於全部審計寫入」。
//     → TestLifecycleAuditStampHookPrecedesAuditProducingSteps（結構）
//     ＋ TestLifecycleFullStartupThenReverseShutdown 的全列蓋章斷言（行為）。
//  2. `StopAlertNotifierForRelease` 依賴 LIFO 的隱含前提：「呼叫端 SHALL 先停
//     排程器」無任何程式碼強制，成立僅因兩個排程器碰巧登記在推送器之後。
//     → 釋放登記序斷言（推送器必須早於兩排程器登記 ⇒ 晚於它們釋放）。
//  3. `keyManager.ZeroizeForRelease` 的釋放位置：它是「封印」在記憶體層面唯一的
//     實體動作。被移到更晚登記（＝更早執行）時，被丟棄的服務圖在其餘收束期間
//     仍持有可用 codec，「封印」退化為路由層假象，**且這條路徑上沒有任何既有
//     測試會變紅**。→ 登記序斷言（必須第一個登記 ⇒ 最後執行）＋收束後 codec
//     實際不可用的行為斷言。
//
// **誠實界定（未涵蓋項）見本檔末的 TestLifecycleKnownUncoveredOrderingTension**。
//
// 沿用 seal_integration_test.go 的環境（檔案型 sqlite、真的跑段 2）：後續各波
// 擴充本檔即可，不需另建一套 harness。

import (
	"context"
	"github.com/custodexa/backend/internal/modules/audit"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
)

// expectedReleaseRegistration 是段 2 資源收束袋的**登記序**（＝釋放序的反序）。
//
// 對應 openspec/changes/archive/2026-08-11-modular-architecture/research/manifest-lifecycle.md
//（隨公開快照出門）§7 的 R-1…R-13，另含該節以「摺疊」處理的
// 5 個迴圈登記排程器（manifest 的有序序列只掃字面量名稱，迴圈項由本清單承擔）。
// manifest §7 的列序依檔名排序故把 R-1 列於首位，但其註記已寫明「本項於
// publishStage2 內登記，故登記時點晚於 R-2…R-13 全部」——**執行期的真實登記序
// 即下表**，`keyManager` 第一個登記、`sealJournalReplay` 最後一個登記。
//
// 這份清單是可執行契約：任何搬檔造成的登記重排會在此逐位失敗，而不是在某個
// 收束窗口靜靜地少歸零一段金鑰。
var expectedReleaseRegistration = []string{
	"keyManager",                 // R-2　第一個登記 ⇒ 最後執行（危險點 3）
	"auditFailureService",        // R-3
	"syslogForwarder",            // R-4　晚於 R-5 執行（先解 hook 再停轉發器）
	"auditIntegrity",             // R-5　SetAuditCreateHooks(nil,nil) ＋ 解單例
	"connectionRegistry",         // R-6
	"auditService",               // R-7　已知排序張力，見本檔末
	"alertMatcher",               // R-8
	"alertNotifier",              // R-9　必須早於兩排程器登記 ⇒ 晚於其停止（危險點 2）
	"exportSigning",              // R-10 衍生材料，早於根材料執行
	"checkpointSigning",          // R-10b 同上（檢查點簽章鑰，多版本逐一歸零）
	"changeSecretScheduler",      // R-11
	"changeSecretRetryScheduler", // R-11b（change-secret-ssh-deepening D4）
	"accessRequestScheduler",     // R-12
	"retentionScheduler",         // 迴圈登記（manifest §7 摺疊）
	"reviewReminderScheduler",    // 迴圈登記
	"inactivityScheduler",        // 迴圈登記
	"kekRetirementScheduler",     // 迴圈登記
	"reconcileScheduler",         // 迴圈登記
	"checkpointScheduler",        // 迴圈登記（audit-checkpoint-chain 第 4 組）
	"chainVerifyScheduler",       // 迴圈登記（audit-chain-scheduled-verification 第 1 組）
	"metricsRefresher",           // R-13 段 2 最後登記（observability-lite，接替 perfMonitor）
	"sealJournalReplay",          // R-1　publishStage2 內登記 ⇒ 最先被等待
}

// lifecycleProbeRef 是 zeroize 行為探針用的列身分（任意合法表／欄即可）。
var lifecycleProbeRef = crypto.CipherRef{Table: "assets", Column: "password"}

// indexOfRelease 回傳名稱在登記序中的位置；不存在回 -1。
func indexOfRelease(names []string, want string) int {
	for i, n := range names {
		if n == want {
			return i
		}
	}
	return -1
}

// insertProbeAuditRow 直寫一列審計並回傳它——用來觀察「此刻蓋章 hook 是否掛著」。
//
// 走 GORM 直寫（非 auditService）是刻意的：危險點 1 的失敗路徑正是 model 層
// hook 未掛時的直寫路徑（asset GORM hook、file_tap、k8s cp 皆走此路）。
func insertProbeAuditRow(t *testing.T, detail string) model.AuditLog {
	t.Helper()
	row := model.AuditLog{
		Username: "lifecycle-probe",
		Action:   model.ActionExecute,
		Resource: model.ResourceKeyManagement,
		Status:   model.StatusSuccess,
		Details:  detail,
	}
	if err := database.DB.Create(&row).Error; err != nil {
		t.Fatalf("寫入探針審計列失敗: %v", err)
	}
	return row
}

// assertAllAuditRowsStamped 全部審計列 SHALL 帶非空 HMAC 與 key_version >= 1。
//
// 這是危險點 1 的**行為面**斷言：蓋章 hook 若晚於任何審計寫入註冊，那些列會以
// 空 HMAC 落地，而驗章端把空章列當歷史列而不計入竄改判定——不會有任何既有測試
// 因此變紅。`want` 為列數下界，防「零列即零違規」的空集合假綠。
func assertAllAuditRowsStamped(t *testing.T, minRows int) {
	t.Helper()
	var rows []model.AuditLog
	if err := database.DB.Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("讀取審計列失敗: %v", err)
	}
	if len(rows) < minRows {
		t.Fatalf("審計列只有 %d 列（下限 %d）：本斷言將在空集合下假綠", len(rows), minRows)
	}
	for _, r := range rows {
		if r.IntegrityHMAC == "" || r.KeyVersion < 1 {
			t.Errorf("審計列 id=%d（action=%s resource=%s）未蓋章：hmac=%q key_version=%d\n"+
				"　　蓋章 hook 晚於此列寫入即為此形態；驗章端會把空章列當成上線前的歷史列而不計入竄改判定",
				r.ID, r.Action, r.Resource, r.IntegrityHMAC, r.KeyVersion)
		}
	}
}

// assertGraphFullyRolledBack 收束後 SHALL 不留任何半初始化狀態。
//
// 五項全部是「被丟棄的服務圖仍在生效」的實際形態，逐項對應 stage2_release.go
// 的收束契約。任一項為假即代表 Release 沒有真的把資源交還。
func assertGraphFullyRolledBack(t *testing.T, g *appGraph, probeCiphertext string) {
	t.Helper()

	// (1) 蓋章／tee hook 已解除：直寫路徑不再打到已釋放的完整性服務。
	row := insertProbeAuditRow(t, "rollback-probe")
	if row.IntegrityHMAC != "" || row.KeyVersion != 0 {
		t.Errorf("收束後直寫審計列仍被蓋章（hmac=%q key_version=%d）："+
			"model.SetAuditCreateHooks(nil,nil) 未執行，舊持有者的完整性服務仍在生效",
			row.IntegrityHMAC, row.KeyVersion)
	}

	// (2) 套件級單例已解除：新的取用不再落到被丟棄的圖上。
	if s := audit.GetAuditIntegrity(); s != nil {
		t.Errorf("收束後 auditIntegrity 單例仍在（%p）", s)
	}
	if s := audit.GetAuditFailure(); s != nil {
		t.Errorf("收束後 auditFailure 單例仍在（%p）", s)
	}
	if s := audit.GetAlertMatcher(); s != nil {
		t.Errorf("收束後 alertMatcher 單例仍在（%p）", s)
	}
	if s := audit.GetAlertNotifier(); s != nil {
		t.Errorf("收束後 alertNotifier 單例仍在（%p）", s)
	}

	// (3) 根材料已歸零——「封印」在記憶體層面唯一的實體動作（危險點 3）。
	//     被丟棄的圖若仍能解密，封印就只是路由層的假象。
	if g.keyManager != nil {
		if _, err := g.keyManager.EncryptFor(context.Background(), lifecycleProbeRef, "after-release"); err == nil {
			t.Error("收束後被丟棄的 keyManager 仍能加密：ZeroizeForRelease 未生效，" +
				"「封印」退化為路由層假象（這條路徑上沒有任何既有測試會變紅）")
		}
		if probeCiphertext != "" {
			if _, err := g.keyManager.DecryptFor(context.Background(), lifecycleProbeRef, probeCiphertext); err == nil {
				t.Error("收束後被丟棄的 keyManager 仍能解密收束前的密文：ciphers 快取未清空")
			}
		}
		if ver, key := g.keyManager.ActiveHMACKey(); ver != 0 || key != nil {
			t.Errorf("收束後蓋章鑰仍在記憶體：version=%d len=%d", ver, len(key))
		}
	}

	// (4) 收束是冪等的：行程收尾與段 2 重試可能同時抵達同一個 bag。
	if !g.bag.Released() {
		t.Error("Release 後 bag.Released() 仍為 false")
	}
	if err := g.Release(context.Background()); err != nil {
		t.Errorf("重複收束回錯（Release SHALL 冪等）: %v", err)
	}
}

// TestLifecycleFullStartupThenReverseShutdown 完整啟動 → 反向關閉的順序契約。
//
// 走真的 B 模式解封路徑（真的段 2、真的 router 換手），再對**同一張服務圖**
// 逐項檢查釋放登記序與收束後的實際狀態。
func TestLifecycleFullStartupThenReverseShutdown(t *testing.T) {
	env := newSealIntegrationEnv(t)

	if w := env.do(http.MethodPost, "/api/v1/seal/unseal", initPayload(testInitialKEK)); w.Code != http.StatusOK {
		t.Fatalf("完整啟動（初始化解封）回 %d：%s", w.Code, w.Body.String())
	}
	if w := env.do(http.MethodGet, "/api/v1/ping", ""); w.Code != http.StatusOK {
		t.Fatalf("啟動後 /ping 回 %d，期望 200——完整路由未換上", w.Code)
	}

	snap := env.machine.Snapshot()
	g, ok := snap.Services.(*appGraph)
	if !ok || g == nil {
		t.Fatalf("服務圖型別為 %T，期望 *appGraph", snap.Services)
	}

	// —— 啟動側：建構順序與宣告清單逐位相符 ——
	if got, want := len(g.ServiceNames()), len(stage2ServiceInventory); got != want {
		t.Fatalf("段 2 建構 %d 個服務，宣告清單 %d 個", got, want)
	}
	for i, name := range g.ServiceNames() {
		if name != stage2ServiceInventory[i] {
			t.Errorf("啟動步驟第 %d 位不符：實際=%q、清單=%q", i+1, name, stage2ServiceInventory[i])
		}
	}

	// —— 關閉側：釋放登記序即釋放序的反序（ResourceBag LIFO）——
	names := g.bag.Names()
	if len(names) != len(expectedReleaseRegistration) {
		t.Fatalf("釋放登記 %d 項、期望 %d 項\n  實際=%v\n  期望=%v\n"+
			"　　登記項增減即釋放行為改變：新增資源未登記＝洩漏，登記消失＝資源不再被收回",
			len(names), len(expectedReleaseRegistration), names, expectedReleaseRegistration)
	}
	for i := range names {
		if names[i] != expectedReleaseRegistration[i] {
			t.Errorf("釋放登記第 %d 位不符：實際=%q、期望=%q\n"+
				"　　順序即契約：釋放以 LIFO 進行，登記序被重排等同於釋放序被重排",
				i+1, names[i], expectedReleaseRegistration[i])
		}
	}

	// 危險點 3：keyManager 必須第一個登記 ⇒ 最後執行；全部 KEK 衍生材料持有者
	// 都必須排在它之後登記（故先釋放）。
	if idx := indexOfRelease(names, "keyManager"); idx != 0 {
		t.Errorf("keyManager 登記於第 %d 位（期望第 1 位 ⇒ 最後釋放）："+
			"移到更後面登記＝更早歸零，被丟棄的服務圖在其餘收束期間仍持有可用 codec", idx+1)
	}
	for _, derived := range []string{"exportSigning", "alertNotifier", "auditIntegrity", "auditService"} {
		if indexOfRelease(names, derived) <= indexOfRelease(names, "keyManager") {
			t.Errorf("%s 登記早於 keyManager ⇒ 釋放晚於根材料歸零：仍需 codec 的收束步驟會打到已歸零的金鑰", derived)
		}
	}

	// 危險點 2：StopAlertNotifierForRelease 的 LIFO 前提——推送器必須早於兩個
	// 排程器登記，才會晚於它們停止。無任何程式碼強制此事，只有本斷言。
	for _, sched := range []string{"changeSecretScheduler", "changeSecretRetryScheduler", "accessRequestScheduler"} {
		if indexOfRelease(names, "alertNotifier") >= indexOfRelease(names, sched) {
			t.Errorf("alertNotifier 未早於 %s 登記 ⇒ 推送器會先於排程器停止："+
				"in-flight 的 Enqueue 將對已關閉的佇列 send 而 panic"+
				"（stage2_release.go:48 的「呼叫端 SHALL 先停排程器」只靠這個 LIFO 巧合成立）", sched)
		}
	}

	// R-4/R-5：先解 hook 再停轉發器（轉發器登記較早 ⇒ 執行較晚）。
	if indexOfRelease(names, "syslogForwarder") >= indexOfRelease(names, "auditIntegrity") {
		t.Error("syslogForwarder 未早於 auditIntegrity 登記 ⇒ 會先停轉發器再解 hook：" +
			"其間佇列中的列無人消費")
	}
	// R-1：回灌等待點最後登記 ⇒ 最先被等待，此時審計服務（R-7）仍在。
	if idx := indexOfRelease(names, "sealJournalReplay"); idx != len(names)-1 {
		t.Errorf("sealJournalReplay 登記於第 %d 位（期望最後一位 ⇒ 最先被等待）："+
			"回灌中的列會落在已收束的審計服務上", idx+1)
	}

	// —— 收束前的正向前提：材料確實可用（否則收束後的「不可用」斷言是空的）——
	ciphertext, err := g.keyManager.EncryptFor(context.Background(), lifecycleProbeRef, "sealed-material")
	if err != nil {
		t.Fatalf("收束前 keyManager 無法加密（本測試的 zeroize 斷言將無意義）: %v", err)
	}
	if plain, err := g.keyManager.DecryptFor(context.Background(), lifecycleProbeRef, ciphertext); err != nil || plain != "sealed-material" {
		t.Fatalf("收束前 round-trip 失敗（plain=%q err=%v）", plain, err)
	}
	if audit.GetAuditIntegrity() == nil || audit.GetAlertNotifier() == nil {
		t.Fatal("收束前單例未就緒：後續的「已解除」斷言將由空集合假綠")
	}

	// —— 反向關閉 ——
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := g.Release(ctx); err != nil {
		t.Fatalf("反向關閉失敗（單項 panic 會被 ResourceBag 轉為 error，"+
			"故此處回錯即代表某個收束步驟真的炸了）: %v", err)
	}

	// 危險點 1（行為面）：整條啟動路徑寫出的審計列全部帶章。
	// 下界 2：初始化解封事件 + 至少一列封印期 journal 回灌（回灌已於 R-1 被等待）。
	assertAllAuditRowsStamped(t, 2)

	assertGraphFullyRolledBack(t, g, ciphertext)
}

// stepCancelContext 在第 N 次取消檢查時轉為已取消的 context。
//
// **為何要自造而不是 time.AfterFunc**：段 2 的取消檢查點是合作式的
// （seal.CheckCancelStep 逐步呼叫 ctx.Err()），以時間觸發等於讓失敗落點隨機——
// 而本測試要驗的正是「在**特定**步驟失敗時回滾得乾不乾淨」。計數觸發使落點
// 確定；落錯步驟時，呼叫端會因錯誤訊息不含期望的步驟名而當場失敗，
// 不會靜靜地驗了另一個點。
type stepCancelContext struct {
	context.Context
	mu       sync.Mutex
	seen     int
	cancelAt int
	done     chan struct{}
	once     sync.Once
}

func newStepCancelContext(parent context.Context, cancelAt int) *stepCancelContext {
	return &stepCancelContext{Context: parent, cancelAt: cancelAt, done: make(chan struct{})}
}

func (c *stepCancelContext) Err() error {
	c.mu.Lock()
	c.seen++
	hit := c.seen >= c.cancelAt
	c.mu.Unlock()
	if hit {
		c.once.Do(func() { close(c.done) })
		return context.Canceled
	}
	return c.Context.Err()
}

func (c *stepCancelContext) Done() <-chan struct{} { return c.done }

// lifecycleInjectedFailureStep 注入點：段 2 的第 7 個取消檢查點。
//
// 選這個點的理由是它落在「蓋章 hook 已掛、推送器已起、排程器已起一個、
// 金鑰材料已載入」之後——半初始化狀態要夠豐富，回滾斷言才有內容。
const (
	lifecycleInjectedFailureStep = 7
	lifecycleInjectedFailureName = "accessRequestScheduler.Start"
)

// TestLifecycleStage2InjectedFailureRollsBack 注入失敗 → 整體回滾、不留半初始化狀態。
//
// 直接呼叫 runStage2（而非經解封端點）是為了拿到**半建構圖本身**：狀態機在失敗
// 路徑上會收束並丟棄它，經端點只能觀察到「狀態轉 sealed-faulted」，觀察不到
// 「被丟棄的那張圖上還留著什麼」——而後者正是 D6.2.4 要擋的形態。
// 狀態機層的失敗處置另由 TestStage2FailureKeepsProcessAliveAndRetryable 涵蓋。
func TestLifecycleStage2InjectedFailureRollsBack(t *testing.T) {
	env := newSealIntegrationEnv(t)

	kek, err := buildUIKEKProvider([]byte(testInitialKEK))
	if err != nil {
		t.Fatalf("建構 KEK provider 失敗: %v", err)
	}

	ctx := newStepCancelContext(context.Background(), lifecycleInjectedFailureStep)
	g, err := runStage2(ctx, env.s1, kek)
	if err == nil {
		t.Fatal("注入取消後段 2 竟成功：合作式取消未生效，本測試的回滾斷言無從談起")
	}
	if g == nil {
		t.Fatal("段 2 失敗回傳 nil 圖：已取得的資源將無人收束（SHALL NOT 在失敗時丟棄已登記的 bag）")
	}
	if !strings.Contains(err.Error(), lifecycleInjectedFailureName) {
		t.Fatalf("失敗落在非預期的步驟：%v\n　　期望步驟 %q（第 %d 個取消檢查點）。"+
			"段 2 的檢查點增減時 SHALL 同步調整 lifecycleInjectedFailureStep，"+
			"否則本測試會靜靜地驗了另一個注入點",
			err, lifecycleInjectedFailureName, lifecycleInjectedFailureStep)
	}

	// 半建構圖 SHALL 是宣告清單的嚴格前綴：多出或缺漏都代表建構順序已偏離。
	built := g.ServiceNames()
	if len(built) == 0 || len(built) >= len(stage2ServiceInventory) {
		t.Fatalf("半建構圖有 %d 個服務（宣告清單 %d 個）：期望為嚴格前綴", len(built), len(stage2ServiceInventory))
	}
	for i, name := range built {
		if name != stage2ServiceInventory[i] {
			t.Fatalf("半建構圖第 %d 位為 %q，宣告清單為 %q", i+1, name, stage2ServiceInventory[i])
		}
	}
	if built[len(built)-1] != "changeSecretRetryScheduler" {
		t.Fatalf("半建構圖最後一項為 %q，期望 changeSecretRetryScheduler（注入點的前一步）", built[len(built)-1])
	}

	// —— 回滾前：半初始化狀態確實存在（否則回滾斷言是空的）——
	if stamped := insertProbeAuditRow(t, "half-initialized-probe"); stamped.IntegrityHMAC == "" {
		t.Fatal("半建構圖上蓋章 hook 未掛：本測試的「hook 已解除」斷言將由假前提成立")
	}
	if audit.GetAlertNotifier() == nil || audit.GetAuditIntegrity() == nil ||
		audit.GetAuditFailure() == nil || audit.GetAlertMatcher() == nil {
		t.Fatal("半建構圖上單例未就緒：回滾斷言將由空集合假綠")
	}
	ciphertext, err := g.keyManager.EncryptFor(context.Background(), lifecycleProbeRef, "half-initialized")
	if err != nil {
		t.Fatalf("半建構圖上 keyManager 無法加密（zeroize 斷言將無意義）: %v", err)
	}

	// —— 回滾 ——
	rctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := g.Release(rctx); err != nil {
		t.Fatalf("半建構圖收束失敗: %v", err)
	}
	assertGraphFullyRolledBack(t, g, ciphertext)
}

// lifecycleAuditProducingStartupCalls 段 2 中會（或可能）寫出審計列的啟動步驟。
//
// 逐項具名而非只數數量：改名或搬家時要當場失敗，不是靜靜地少驗一個。
// 每一項都必須真的在 stage2.go 內出現（下方守衛強制），否則清單即形同虛設。
var lifecycleAuditProducingStartupCalls = []string{
	"RunPostUnsealMigrations",   // 解封後遷移佇列：遷移可寫審計
	"logKEKSwitchAudit",         // KEK 切換審計補記（明確寫 audit_logs）
	"ReconcileStartup",          // session 啟動清掃：收斂殘留 active
	"ReportOnStartup",           // KEK 退役 degraded 首次評估
	"ReportAADResidueOnStartup", // 非終態格式殘值啟動哨兵
}

// TestLifecycleAuditStampHookPrecedesAuditProducingSteps 危險點 1 的結構面守衛。
//
// 既有的 TestMigrationCallersRegisterAuditHooks 只釘「同檔且先於遷移呼叫」。
// 本守衛把界線推到「先於全部會寫審計的啟動步驟」，並以 mark() 的字面量步驟序
// 機械地釘住註冊所在的步驟位置——把註冊往後挪一步即當場轉紅。
func TestLifecycleAuditStampHookPrecedesAuditProducingSteps(t *testing.T) {
	root := lifecycleModuleRoot(t)
	path := filepath.Join(root, "cmd", "server", "stage2.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("解析 %s 失敗（守衛拒絕在殘缺 AST 上作判定）: %v", path, err)
	}

	lineOf := func(p token.Pos) int { return fset.Position(p).Line }

	var (
		registerLine = -1 // model.SetAuditCreateHooks(stamp, publish) 的註冊呼叫
		unregisterN  = 0  // 收束閉包內的 SetAuditCreateHooks(nil, nil)
		initLine     = -1 // InitAuditIntegrityVersioned
		markLines    = map[string]int{}
		markOrder    []string
		callLines    = map[string][]int{}
	)

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := ""
		switch fn := call.Fun.(type) {
		case *ast.SelectorExpr:
			name = fn.Sel.Name
		case *ast.Ident:
			name = fn.Name
		}
		if name == "" {
			return true
		}
		callLines[name] = append(callLines[name], lineOf(call.Pos()))

		switch name {
		case "SetAuditCreateHooks":
			nilArgs := 0
			for _, a := range call.Args {
				if id, ok := a.(*ast.Ident); ok && id.Name == "nil" {
					nilArgs++
				}
			}
			if nilArgs == len(call.Args) {
				unregisterN++
			} else if registerLine == -1 || lineOf(call.Pos()) < registerLine {
				registerLine = lineOf(call.Pos())
			}
		case "InitAuditIntegrityVersioned":
			initLine = lineOf(call.Pos())
		case "mark":
			if len(call.Args) == 1 {
				if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
					step := lit.Value[1 : len(lit.Value)-1]
					markLines[step] = lineOf(call.Pos())
					markOrder = append(markOrder, step)
				}
			}
		}
		return true
	})

	// 防空集合假綠：三個錨點缺任一，本守衛即什麼也沒驗。
	if registerLine == -1 {
		t.Fatal("stage2.go 內找不到 model.SetAuditCreateHooks 的註冊呼叫：組裝根已失真或改名，本守衛失去對象")
	}
	if unregisterN != 1 {
		t.Errorf("stage2.go 內 SetAuditCreateHooks(nil, nil) 出現 %d 次，期望恰 1 次（釋放路徑）", unregisterN)
	}
	if initLine == -1 || initLine > registerLine {
		t.Errorf("InitAuditIntegrityVersioned（L%d）未先於蓋章 hook 註冊（L%d）", initLine, registerLine)
	}
	if len(markOrder) < 25 {
		t.Fatalf("只掃到 %d 個字面量 mark() 步驟（下限 25）：AST 掃描已失真", len(markOrder))
	}

	// 註冊 SHALL 落在 syslogForwarder 步驟之後、auditIntegrity 步驟收尾之前。
	// 這是機械化的步驟位置釘子：往前往後挪一步都會失敗。
	prev, cur := markLines["syslogForwarder"], markLines["auditIntegrity"]
	if prev == 0 || cur == 0 {
		t.Fatal("找不到 mark(\"syslogForwarder\") 或 mark(\"auditIntegrity\")：步驟已改名，守衛須同步更新")
	}
	if registerLine <= prev || registerLine >= cur {
		t.Errorf("蓋章 hook 註冊於 L%d，不在 auditIntegrity 步驟內（L%d < x < L%d）：\n"+
			"　　此點之前寫出的審計列 HMAC 為空且不進 syslog tee，而驗章端會把空章列"+
			"當成上線前的歷史列而**不計入竄改判定**——失敗形態是更安靜而非更吵",
			registerLine, prev, cur)
	}

	// 全部會寫審計的啟動步驟 SHALL 晚於註冊。
	for _, name := range lifecycleAuditProducingStartupCalls {
		lines := callLines[name]
		if len(lines) == 0 {
			t.Errorf("[清單→現實] stage2.go 內找不到 %s 的呼叫：清單已過時，該項形同未驗", name)
			continue
		}
		for _, l := range lines {
			if l < registerLine {
				t.Errorf("%s（L%d）早於蓋章 hook 註冊（L%d）：該步驟寫出的審計列將以空 HMAC 落地",
					name, l, registerLine)
			}
		}
	}
}

// TestLifecycleKnownUncoveredOrderingTension 誠實界定：本檔涵蓋不到的一項。
//
// **未涵蓋項**：`auditService.Shutdown`（R-7）執行序早於 `connectionRegistry.CloseAll`
// （R-6）。HTTP 路徑由 main.go:212「先關 HTTP server、再收束段 2 資源」的外層順序
// 保證請求已停；但**協議連線（WS）不經 HTTP Shutdown**，理論上存在「審計已 flush、
// 連線仍在寫審計」的窗口。
//
// **為何本檔驗不了**：這個 harness 以 httptest.Recorder 送請求，從不建立真正的
// WebSocket／SSH 連線，因此那個窗口在此根本不會被執行到——跑綠不構成該張力
// 不存在的證據（phase-b-baseline.md §5.1.2 對 e2e 亦作同一判定：e2e 全程不停
// backend，該路徑同樣未被執行）。
//
// **建議的替代驗證**：一個在 WS 連線存活期間觸發 backend 優雅關閉、並比對關閉
// 前後審計列數的專用測試（e2e 現有 14 段皆不含此形態）。已列 Phase C 誠實清單。
//
// 本測試因此只做一件事：**把現況釘住**。若哪一波把 R-6／R-7 的相對序改掉了
// （不論改對改錯），這裡會轉紅，強迫改動者說明理由，而不是讓它靜靜地變。
func TestLifecycleKnownUncoveredOrderingTension(t *testing.T) {
	env := newSealIntegrationEnv(t)
	if w := env.do(http.MethodPost, "/api/v1/seal/unseal", initPayload(testInitialKEK)); w.Code != http.StatusOK {
		t.Fatalf("初始化解封回 %d", w.Code)
	}
	g, ok := env.machine.Snapshot().Services.(*appGraph)
	if !ok || g == nil {
		t.Fatalf("服務圖型別為 %T", env.machine.Snapshot().Services)
	}
	names := g.bag.Names()

	registry, audit := indexOfRelease(names, "connectionRegistry"), indexOfRelease(names, "auditService")
	if registry < 0 || audit < 0 {
		t.Fatalf("釋放登記中找不到 connectionRegistry／auditService：%v", names)
	}
	if registry >= audit {
		t.Errorf("connectionRegistry 登記於第 %d 位、auditService 於第 %d 位——相對序已與基線"+
			"（§5.1.2／manifest R-6·R-7）不同。\n"+
			"　　現況是 auditService.Shutdown 先執行、connectionRegistry.CloseAll 後執行；"+
			"若本波刻意改了方向，SHALL 於 manifest 更新並說明理由，"+
			"不得反向遷就程式碼", registry+1, audit+1)
	}
	t.Logf("已知排序張力（未涵蓋、僅釘住現況）：auditService.Shutdown 於第 %d 位釋放、"+
		"connectionRegistry.CloseAll 於第 %d 位釋放；WS 連線不經 HTTP Shutdown 的窗口"+
		"需另建專用測試才可證實或推翻",
		len(names)-audit, len(names)-registry)
}
