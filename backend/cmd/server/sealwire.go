package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/seal"
	"github.com/custodexa/backend/internal/sealjournal"
	"github.com/custodexa/backend/pkg/crypto"
)

// B 模式的封印狀態機接線（kek-provider-modularization D6.1／D6.3／D6.4／D6.6）。

// verifiedUnseal 是 VerifyFunc 交給段 2 的載荷。
type verifiedUnseal struct {
	kek crypto.KEKProvider
	// bootstrap 為 true 代表走初始化解封路徑（data_keys 為空，D6.3）。
	// 顯式欄位而非由其他欄位推導：分流結果決定 bootstrap 是否執行，
	// 用「使用者名稱是否為空」代表它，等於把兩件事綁在一個巧合上。
	bootstrap bool
	// adminUsername 僅初始化路徑有值，供審計事件記錄「由誰宣告主金鑰」。
	adminUsername string
}

// sealAuditEvent 是兩條解封路徑各自的審計事件名（D6.3 審計區分）。
//
// 稽核上「這個部署的 KEK 是何時、由哪個來源初始化的」必須可回答，
// 故初始化與一般解封 SHALL 產生**可區分**的事件，而不是同一個 unseal 事件
// 帶一個布林欄位——後者在既有審計查詢面（依 action/resource 篩選）看不出差別。
const (
	sealAuditEventInitialize = "seal_initialize"
	sealAuditEventUnseal     = "seal_unseal"
)

// sealWiring 是 B 模式接線的產物。
//
// **兩個 handler 共用同一台狀態機**：main 掛在主監聽、admin 掛在解封端點的
// 獨立監聽（D6.4）。未設定獨立監聽時 admin 為 nil，main 保留解封能力。
// 兩者不是同一個實例的理由是「主監聽上的解封須硬拒」——同一實例無法同時
// 對兩個監聽面表達不同的受理政策。
type sealWiring struct {
	machine *seal.Machine
	main    *api.SealHandler
	admin   *api.SealHandler
}

// bootstrapPendingState 記錄「初始化解封已被受理、但初始化審計尚未寫成」的狀態。
//
// **為何必須跨重試保留**：初始化解封的段 2 在 InitKeyManager 就會把 bootstrap
// 金鑰持久化。若段 2 於其後失敗，重試時金鑰表已非空，分流會轉走一般解封路徑，
// 於是這次部署的**初始化事件被記成一筆普通 unseal**——稽核從此無法回答
// 「這個部署的 KEK 是何時、由誰初始化的」，而那正是 D6.3 要求兩條路徑可區分
// 的全部理由。狀態只存在於行程內、不受請求控制，故不構成新的授權面。
type bootstrapPendingState struct {
	mu       sync.Mutex
	pending  bool
	username string
}

// arm 標記初始化解封已被受理。
func (b *bootstrapPendingState) arm(username string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pending = true
	b.username = username
}

// snapshot 讀取目前的待決狀態。
func (b *bootstrapPendingState) snapshot() (bool, string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pending, b.username
}

// clear 於初始化審計寫成後解除待決。
func (b *bootstrapPendingState) clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pending = false
	b.username = ""
}

// newSealMachine 建立 B 模式的封印狀態機並完成接線。
//
// swap 為 http.Server 的可換手 handler：解封成功後才把段 2 的完整 router 換上
// （publish 之後，見 sealgate.go 的換手時機說明）。
func newSealMachine(s1 *stage1, swap *swappableHandler) (*sealWiring, error) {
	sealCfg := s1.cfg.Seal
	allowed, err := sealCfg.ParseAllowedCIDRs()
	if err != nil {
		return nil, err
	}

	limiter := seal.NewLimiter(seal.LimiterConfig{
		BaseBackoff:       sealCfg.BackoffBase,
		MaxBackoff:        sealCfg.BackoffMax,
		GlobalThreshold:   sealCfg.CooldownThreshold,
		GlobalCooldown:    sealCfg.Cooldown,
		MaxGlobalCooldown: sealCfg.CooldownMax,
	})

	// machine／mainHandler 於下方建構，但段 2 需要它們來組 router。以變數捕獲
	// 而非參數傳遞：兩者互相引用，且閉包實際執行的時點必然晚於賦值。
	var (
		machine     *seal.Machine
		mainHandler *api.SealHandler
	)
	pending := &bootstrapPendingState{}

	machine, err = seal.New(seal.Config{
		Journal: s1.journal,
		Limiter: limiter,
		Verify: func(ctx context.Context, material []byte) (seal.VerifiedMaterial, error) {
			v, err := verifyUnsealMaterial(material, pending)
			if err != nil {
				return seal.VerifiedMaterial{}, err
			}
			return seal.VerifiedMaterial{Bootstrap: v.bootstrap, Payload: v}, nil
		},
		Stage2: func(ctx context.Context, vm seal.VerifiedMaterial) (seal.ServiceGraph, error) {
			return runStage2Graph(ctx, s1, vm, machine, &mainHandler)
		},
	})
	if err != nil {
		return nil, err
	}

	w := &sealWiring{machine: machine}
	w.main = newWiredSealHandler(s1, machine, allowed, sealCfg, swap, pending)
	mainHandler = w.main
	// 解封端點另行繫結時：主監聽的 handler 硬拒解封，獨立監聽另建一個可受理的。
	if sealCfg.UnsealBindAddr != "" {
		w.main.SetUnsealRelocated(true)
		w.admin = newWiredSealHandler(s1, machine, allowed, sealCfg, swap, pending)
	}
	return w, nil
}

// newWiredSealHandler 建一個完成全部接線的解封 handler。
//
// 兩個監聽面各持一個實例，但**狀態機、journal、限速與 admission 全部共用**——
// 獨立監聽是網路可達面的隔離，不是第二套授權模型，更不是第二份狀態。
func newWiredSealHandler(s1 *stage1, machine *seal.Machine, allowed []*net.IPNet,
	sealCfg config.SealConfig, swap *swappableHandler, pending *bootstrapPendingState) *api.SealHandler {
	h := api.NewSealHandler(machine, s1.journal)
	h.SetSourceControls(sealCfg.TrustedProxyConfigured(), allowed, sealCfg.UnsealBindAddr)
	h.SetInitRequiredProbe(func() (bool, error) {
		n, err := keyvault.CountDataKeys(database.DB)
		return n == 0, err
	})
	h.SetAdmitter(func(ctx context.Context) (func(bool), error) {
		ticket, err := s1.journal.Admit(ctx)
		if err != nil {
			return nil, err
		}
		return ticket.Release, nil
	})
	h.SetOnUnsealed(func(published seal.ServiceGraph) {
		publishStage2(published, machine, swap, s1.journal, pending)
	})
	return h
}

// runStage2Graph 建構段 2 服務圖，**並在同一個失敗處置範圍內建好完整 router**。
//
// **engine 的建構必須落在 publish 之前**（本函式內），不得留到解封成功後的
// 換手回呼：回呼執行時狀態已是 unsealed，而 unsealed 沒有任何出邊——此時任何
// 建構失敗或 panic 都會停在「狀態已解封、router 仍是段 1 的」，對外恆 503 且
// 無法重試，只能重啟行程。放在此處則失敗即是段 2 失敗，走 sealed-faulted、可重試。
func runStage2Graph(ctx context.Context, s1 *stage1, vm seal.VerifiedMaterial,
	machine *seal.Machine, mainHandler **api.SealHandler) (seal.ServiceGraph, error) {
	v, ok := vm.Payload.(*verifiedUnseal)
	if !ok || v == nil {
		return nil, fmt.Errorf("段 2 收到非預期的驗證載荷型別 %T", vm.Payload)
	}
	g, err := runStage2(ctx, s1, v.kek)
	// 解封路徑的中繼資料掛在**本次**的服務圖上，不放共享變數：
	// 逾時後才返回的殭屍段 2 會寫入同一份共享狀態，用共享變數承接
	// 等於自造一個資料競賽。
	if g != nil {
		g.bootstrap = vm.Bootstrap
		g.adminUsername = v.adminUsername
	}
	// **不得 log.Fatalf**（D6.1）：回錯即由狀態機轉 sealed-faulted、
	// 行程續存，管理員可讀狀態並重試。半建構圖照樣回傳，供狀態機收束。
	if err != nil {
		log.Printf("[Seal] 段 2 初始化失敗（行程續存，狀態轉 sealed-faulted，可重試解封）: %v", err)
		if g == nil {
			return nil, err
		}
		return g, err
	}
	// 解封時點於 router 建構前定值：換手回呼只做原子交換，不再產生任何新事實。
	g.unsealedAt = time.Now()
	engine, err := buildStage2Engine(s1, machine, *mainHandler, g)
	if err != nil {
		log.Printf("[Seal] 段 2 路由建構失敗（行程續存，狀態轉 sealed-faulted，可重試解封）: %v", err)
		return g, fmt.Errorf("段 2 步驟 %q 失敗: %w", "buildStage2Engine", err)
	}
	g.engine = engine
	return g, nil
}

// publishStage2 於解封成功**之後**換上完整路由並收尾。
//
// 此刻 SUCCESS 已 durable 且 publish CAS 已成功（Unseal 回 nil 的充要條件），
// 故服務放行的時點嚴格晚於「驗證通過且段 2 完成」的落地。
// 本函式**只做一次原子換手**：router 早已在段 2 內建好，這裡沒有任何可能失敗的
// 建構工作。
func publishStage2(published seal.ServiceGraph, machine *seal.Machine,
	swap *swappableHandler, j *sealjournal.Journal, pending *bootstrapPendingState) {
	g, ok := published.(*appGraph)
	if !ok || g == nil || g.engine == nil {
		// **結構上不可達**：Stage2 的唯一回傳型別是 *appGraph，且其 engine 於
		// publish 之前即建構完成（runStage2Graph）。真的走到這裡代表段 2 的
		// 型別契約已被破壞，而此刻狀態已是 unsealed、沒有任何出邊：
		// 不換手＝服務恆 503 且無法重試，log 一行然後返回是 fail-open 的
		// 最壞形態（看起來成功、實際鎖死）。故以 fail-close 結束行程——
		// 重啟後回到 sealed，管理員可重新解封。這與 D6.1「段 2 失敗不殺行程」
		// 不衝突：該條規範的是段 2 的**執行結果**，不是發佈後的結構性違反。
		log.Fatalf("[Seal] 已發佈的服務圖不具備段 2 router（型別 %T）：段 2 契約已被破壞，拒絕以不可路由的解封狀態續存", published)
		return
	}
	swap.Set(g.engine)
	log.Printf("[Seal] 已解封並換上完整路由（generation=%d）", machine.Snapshot().Generation)

	if writeSealAudit(g) {
		pending.clear()
	}
	startSealJournalReplay(j, g)
}

// verifyUnsealMaterial 執行材料格式檢查與材料驗證（臨界區之內）。
//
// 兩條路徑以 data_keys 筆數分流，**沿用 InitKeyManager 既有的 count == 0 判定**：
//
//   - count == 0 → 初始化解封：提交的材料即成為本部署的初始 KEK。
//     認證擋的是「誰有權宣告」，paste-back 擋的是「宣告錯內容」，兩者正交、都要；
//     D8 完整格式驗證另擋弱材料。
//   - count > 0 → 一般解封：**不驗格式、不要求憑證**，只驗能否解包現行代表列
//     （既有部署的 KEK 可能早於格式規則；而「能解開代表列」本身即最強授權證明）。
//
// **例外：初始化待決**（bootstrapPendingState）。金鑰已被 bootstrap 寫入、但初始化
// 審計尚未寫成時，重試雖然看到非空金鑰表，仍屬同一次初始化的續作，
// 故沿用一般解封的材料判準（能解包＝同一把材料），但事件仍記為初始化。
//
// 全部失敗路徑回傳的 error 都只作為 Cause——狀態機對外一律是同一個材料失敗碼，
// 回應內容因此不可區分（D6.6）。
func verifyUnsealMaterial(material []byte, pending *bootstrapPendingState) (*verifiedUnseal, error) {
	payload, err := api.DecodeSealMaterial(material)
	if err != nil {
		return nil, err
	}
	defer payload.Zeroize()

	count, err := keyvault.CountDataKeys(database.DB)
	if err != nil {
		return nil, err
	}

	if count == 0 {
		v, err := verifyInitializeUnseal(payload)
		if err != nil {
			return nil, err
		}
		pending.arm(v.adminUsername)
		return v, nil
	}
	kek, err := buildUIKEKProvider(payload.KEK)
	if err != nil {
		return nil, err
	}
	if err := keyvault.ProbeKEKUnwrap(database.DB, kek); err != nil {
		return nil, err
	}
	if armed, username := pending.snapshot(); armed {
		return &verifiedUnseal{kek: kek, bootstrap: true, adminUsername: username}, nil
	}
	return &verifiedUnseal{kek: kek}, nil
}

// verifyInitializeUnseal 是初始化解封（空金鑰表）的驗證。
//
// 順序刻意是「格式 → paste-back → 憑證」：三者皆為必要條件、失敗結果相同，
// 順序不影響對外可觀察性；由便宜到昂貴排列則使被拒的請求盡早返回。
func verifyInitializeUnseal(p *api.SealUnsealPayload) (*verifiedUnseal, error) {
	// D8 完整伺服端格式驗證：長度、字元集、非出廠預設值。
	// **string 轉換是誠實邊界的一部分**：驗證器以 string 為介面，此處必然產生
	// 一份不可覆寫的副本（見 api.SealUnsealPayload.Zeroize）。不為此重寫一份
	// 平行的驗證邏輯——重複的安全驗證比一份不可歸零的副本更危險。
	if v := config.ValidateKEKMaterial(string(p.KEK)); v != "" {
		return nil, fmt.Errorf("初始 KEK 材料不合格式: %s", v)
	}
	// D7 paste-back 二次輸入＋保存確認：初始化解封輸錯會把打錯的字串固化為
	// 整個部署的 KEK，後果與重包輸錯同級，故防護等級必須同級。
	// 定時比較：兩者皆為使用者輸入，不比較耗時本身有意義，但一致性成本為零。
	if subtle.ConstantTimeCompare(p.KEK, p.KEKConfirm) != 1 {
		return nil, errors.New("初始 KEK 的二次輸入不符")
	}
	if !p.ConfirmSaved {
		return nil, errors.New("未確認已保存初始 KEK")
	}
	// 初始管理員憑證：缺此項＝未認證的主金鑰領主權競賽（D6.3）。
	if err := identity.VerifyInitialAdminCredential(database.DB, p.Username, p.Password); err != nil {
		return nil, err
	}
	kek, err := buildUIKEKProvider(p.KEK)
	if err != nil {
		return nil, err
	}
	return &verifiedUnseal{kek: kek, bootstrap: true, adminUsername: p.Username}, nil
}

// buildStage2Engine 以段 2 的完整依賴建 router。
//
// 閘仍在最外層，但其 live 判定改讀狀態機——本 engine 只在解封成功後才被安裝，
// 而 unsealed 沒有任何出邊，故實際恆放行。保留閘的理由是使「registerRoutes
// 最外層有封印閘」在三模式下都成立，而不是靠部署形態碰巧成立。
//
// **撕裂窗不可達**：業務 handler 直接持有段 2 建構的服務參考，不從狀態機讀取，
// 故「閘看到 unsealed、handler 拿到 nil」在本結構下不存在——那個窗口需要
// 「閘與 handler 各讀一次狀態」才會出現。
func buildStage2Engine(s1 *stage1, machine *seal.Machine, sealHandler *api.SealHandler, g *appGraph) (*gin.Engine, error) {
	r, err := newEngine(s1, false)
	if err != nil {
		return nil, err
	}
	deps := g.deps
	deps.sealGate = sealGateMiddleware(func() bool {
		return machine.Snapshot().State == seal.StateUnsealed
	})
	deps.seal = sealHandler
	// 金鑰清冊的封印狀態欄（D10）：由本行程實際運轉的狀態機導出，
	// 不由組態或環境變數推導——清冊要回答的正是「實際跑的是什麼」。
	deps.keyManagement.SetSealStateProbe(func() (string, time.Time) {
		return string(machine.Snapshot().State), g.unsealedAt
	})
	registerRoutes(r, deps)
	return r, nil
}

// writeSealAudit 記錄可區分的解封審計事件（D6.3）。
//
// 初始化事件另記新 KEK 指紋與 bootstrap 產生的金鑰版本清單——稽核上
// 「這個部署的 KEK 是何時、由哪個來源初始化的」必須可回答。
//
// 回傳「初始化事件是否已提交」：待決狀態只在此為真時解除。序列化失敗或圖不完整
// 時維持待決，下一次解封仍會記為初始化——寧可重複一筆初始化事件，
// 也不可讓部署的初始化在審計上完全消失。
func writeSealAudit(g *appGraph) bool {
	if g == nil || g.auditService == nil || g.keyManager == nil {
		return false
	}
	event := sealAuditEventUnseal
	details := map[string]any{"event": event}
	username := "system"
	if g.bootstrap {
		event = sealAuditEventInitialize
		username = g.adminUsername
		details["event"] = event
		details["kek_fingerprint"] = g.keyManager.KEKRef().KeyID
		details["kek_mode"] = g.keyManager.KEKMode()
		details["bootstrap_key_versions"] = bootstrapKeyVersions(g)
	} else {
		details["kek_fingerprint"] = g.keyManager.KEKRef().KeyID
		details["kek_mode"] = g.keyManager.KEKMode()
	}
	body, err := json.Marshal(details)
	if err != nil {
		log.Printf("[Seal] 解封審計序列化失敗（不阻塞服務）: %v", err)
		return false
	}
	g.auditService.Log(&audit.AuditLogEntry{
		UserID: 0, Username: username,
		Action:   model.ActionExecute,
		Resource: model.ResourceKeyManagement,
		Status:   model.StatusSuccess,
		Path:     "/api/v1/seal/unseal",
		Method:   http.MethodPost,
		Details:  string(body),
	})
	return g.bootstrap
}

// bootstrapKeyVersions 列出金鑰表現行版本清單（purpose:version）。
func bootstrapKeyVersions(g *appGraph) []string {
	var rows []model.DataKey
	if err := database.DB.Where("kek_retired_at IS NULL").Order("purpose, version").Find(&rows).Error; err != nil {
		log.Printf("[Seal] 讀取 bootstrap 金鑰版本清單失敗（審計欄留空）: %v", err)
		return nil
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, fmt.Sprintf("%s:v%d", r.Purpose, r.Version))
	}
	return out
}

// startSealJournalReplay 把封印期 journal 的事件回灌進審計，且**回灌可被等待**。
//
// **走既有審計寫入路徑（同一序列化入口），不另開直寫**（D6.5 第 6 點）：
// 回灌只是「另一個審計事件來源」，其 DB 交易與 HMAC 蓋章與一般審計相同；
// 兩路各自進入會並行競爭鏈尾。
//
// **納入服務圖的收束袋**：一條沒有主的 goroutine 不在 machine.WaitCleanup()
// 的涵蓋範圍內，行程收尾與測試清理都等不到它——實測形態是測試偶發
// 「TempDir RemoveAll: directory not empty」（journal 目錄仍被寫）。
// 登記於 bag 且**最後登記**：LIFO 使它最先被等待，於是稍後才收的審計服務
// 仍在，回灌中的列不會落空。
//
// 失敗不阻服務、不清 checkpoint（Replay 自身保證），走既有審計失效告警族。
func startSealJournalReplay(j *sealjournal.Journal, g *appGraph) {
	if j == nil || g == nil || g.bag == nil {
		return
	}
	done := make(chan struct{})
	// 先登記等待點、再起 goroutine：反序會留下「已在跑但還沒有人等得到」的窗口。
	g.bag.AddFunc("sealJournalReplay", func(ctx context.Context) error {
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return fmt.Errorf("封印期 journal 回灌未於收束逾時內結束: %w", ctx.Err())
		}
	})
	go func() {
		defer close(done)
		res, err := j.Replay(context.Background(), audit.NewSealJournalSink(g.auditService))
		if err != nil {
			log.Printf("[SealJournal] 回灌失敗（不阻服務，下次解封重跑去重）: %v", err)
			return
		}
		if res.Skipped {
			return
		}
		log.Printf("[SealJournal] 回灌完成：事件 %d 筆、序號 %d-%d、聚合列 %s",
			res.Events, res.StartSeq, res.EndSeq, res.AggregateID)
	}()
}
