package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/k8sproxy"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/internal/observability"
	"github.com/custodexa/backend/internal/offsite"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/custodexa/backend/internal/recorder"
	"github.com/custodexa/backend/internal/scheduler"
	"github.com/custodexa/backend/internal/seal"
	"github.com/custodexa/backend/internal/sshproxy"
	"github.com/custodexa/backend/pkg/crypto"
)

// 段 2（完整圖）。
//
// 內容：InitKeyManager（load／bootstrap／finalizeSwitch）、policy／audit／通知／
// 排程器、全部業務 handler、完整路由樹。
//
// **fail-close 語義變更（本檔的核心差異）**：段 2 的任何失敗一律
// `return nil, err`，**不得 log.Fatalf**。同一份建構邏輯、兩種失敗處置由呼叫端決定：
//
//   - A／C 模式（main.go）：啟動期失敗即 log.Fatalf，行為與現況零差異。
//   - B 模式（sealwire.go）：轉為「回機器碼給解封請求＋狀態轉 sealed-faulted」，
//     行程續存以便管理員讀狀態與重試。
//
// 合作式取消：每個具外部副作用的步驟之前 SHALL 呼叫
// seal.CheckCancelStep——建立外部連線、開始通知投遞、啟動排程器為硬性檢查點。
// 逾時只取消 context、epoch 只擋發佈，兩者都擋不住「已經啟動的副作用」。

// stage2ServiceInventory 是段 2 建構的服務清單：**延後建構的服務逐項列出
// 並有測試**確認其在段 1 期間不存在。
//
// 本清單是可執行契約而非文件：appGraph.ServiceNames() 回傳實際建構的項目，
// 守衛測試逐項比對兩者，任一遺漏或多出即紅。
var stage2ServiceInventory = []string{
	"keyManager",
	"policyService",
	// auditTxSink：交易內審計落地面＋未注入即 fail-close 的啟動自檢。
	// 落點在 ldapDirectoryService 之前是契約——它是第一個消費者，且 postUnsealMigrations
	// 的 LDAP seed 在段 2 期間就會寫審計
	"auditTxSink",
	"ldapDirectoryService",
	"transmissionPolicy",
	"auditFailureService",
	"syslogForwarder",
	"auditIntegrity",
	"postUnsealMigrations",
	"authService",
	"assetService",
	"connectionRegistry",
	"sessionService",
	"reconciliationService",
	"recordingService",
	"auditService",
	// 離機儲存（evidence-offsite-storage）三項。落點在 auditService 之後是契約——
	// 保管鏈事件的非同步落地面就是它，早於它建構只能拿到 nil。
	// **三項恆建構、與是否啟用無關**：它們是被動物件（零 goroutine、零指標註冊），
	// 而「設定表零列＝行為完全不變」的機械保證由 uploader 不啟動、指標不註冊、
	// 排隊點自我早退三者承擔，不靠「不建物件」
	"offsiteProfiles",
	"offsiteLedger",
	"dailyReviewService",
	"connHandler",
	"userService",
	// alertSink：指令告警落地面＋未注入即 fail-close 的啟動自檢。
	// 落點在 alertMatcher／sshHandler 之前是契約——兩者是它僅有的消費者
	"alertSink",
	"alertMatcher",
	"alertNotifier",
	"kekRetirementMonitor",
	"notificationChannelService",
	"oidcServices",
	"exportSigning",
	"checkpointSigning",
	"sshHandler",
	"hostKeyService",
	"changeSecretScheduler",
	"changeSecretRetryScheduler",
	"accessRequestScheduler",
	"apiHandlers",
	"retentionScheduler",
	"reviewReminderScheduler",
	"inactivityScheduler",
	"kekRetirementScheduler",
	"reconcileScheduler",
	"checkpointScheduler",
	// chainVerifyScheduler：
	// 必須晚於 checkpointScheduler——驗證的對象是封章產出的鏈
	"chainVerifyScheduler",
	// offsiteUploader：離機上傳 worker。
	// **停在 auditExportJobWorker 之後**（它讀 export 產物；反序釋放故登記在前）
	"offsiteUploader",
	// auditExportJobWorker：證據包打包 worker。
	// 晚於 apiHandlers——與 handler 共用的匯出服務在 buildRouteDeps 之前建構完成
	"auditExportJobWorker",
	// metricsRefresher：接替原 perfMonitor 的段 2 末步位置。
	// 刷新的是查詢成本不對稱的指標（DB 查詢、檔案系統遍歷），故定期刷新而非
	// 於每次採集時同步查詢——後者會讓外部採集頻率直接放大成本系統的負載
	"metricsRefresher",
}

// appGraph 是段 2 的產物：完整服務圖＋其資源收束袋。
//
// 實作 seal.ServiceGraph（Releaser）：逾時或初始化失敗時，狀態機以 Release 收束
// 已取得的資源。Release 為冪等（ResourceBag 自身保證）。
type appGraph struct {
	deps  routeDeps
	bag   *seal.ResourceBag
	built []string

	cfg          *config.Config
	auditService *audit.AuditLogService
	keyManager   *keyvault.KeyManagerService

	// unsealedAt 本世代的解封時點（清冊 seal_state 的伴隨欄位）。
	unsealedAt time.Time

	// engine 為本世代的完整 router，**於 publish 之前建構完成**（runStage2Graph）。
	// 放在圖上而非共享變數：換手回呼只做一次原子指標交換，不做任何可能失敗的
	// 建構工作，故「解封成功但服務不可路由」在結構上不存在。
	engine *gin.Engine

	// bootstrap／adminUsername 為本次解封路徑的中繼資料（B 模式才有值），
	// 由 sealwire 於段 2 返回後填入，供解封審計事件區分兩條路徑。
	// 掛在**本次**的圖上而非共享變數：殭屍段 2 不會覆寫別代的值。
	bootstrap     bool
	adminUsername string
}

// Release 收束段 2 建構的全部資源（LIFO；單項失敗不中斷後續）。
func (g *appGraph) Release(ctx context.Context) error {
	if g == nil || g.bag == nil {
		return nil
	}
	return g.bag.Release(ctx)
}

// ServiceNames 回傳實際建構的服務名，供清單完備性守衛比對。
func (g *appGraph) ServiceNames() []string {
	if g == nil {
		return nil
	}
	out := make([]string, len(g.built))
	copy(out, g.built)
	return out
}

// runStage2 建構完整服務圖。
//
// kek 為本次生效的 KEK provider：A／C 模式來自段 1 的組態建構，
// B 模式來自解封時提交並已驗證的材料。**兩條路徑之後的程式碼完全相同**
// ——KEK 來源模式的差異封裝在 KEKProvider 介面之下，此處零語義差異。
//
// 回傳的 graph 即使在 err != nil 時也可為非 nil（半建構圖）：狀態機會對它呼叫
// Release 以收束已取得的資源，故 SHALL NOT 在失敗時丟棄已登記的 bag。
func runStage2(ctx context.Context, s1 *stage1, kek crypto.KEKProvider) (*appGraph, error) {
	cfg := s1.cfg
	g := &appGraph{bag: &seal.ResourceBag{}, cfg: cfg}

	mark := func(name string) { g.built = append(g.built, name) }
	fail := func(step string, err error) (*appGraph, error) {
		return g, fmt.Errorf("段 2 步驟 %q 失敗: %w", step, err)
	}

	// 信封加密金鑰管理：DEK 由 KEK 包裹落庫；首啟 bootstrap
	// 生成 data DEK 並凍結 legacy 審計蓋章鑰為 v0 快照。KEK provider 與 legacy 審計鑰已於連 DB 前
	// 建構（B 模式則來自解封材料）；此處為 DB-dependent 的金鑰表比對，
	// KEK 與金鑰表不符即拒絕（不靜默退回 legacy 帶病運行）。
	if err := seal.CheckCancelStep(ctx, "InitKeyManager"); err != nil {
		return fail("InitKeyManager", err)
	}
	keyManager, err := keyvault.InitKeyManager(database.DB, kek)
	if err != nil {
		return fail("InitKeyManager", err)
	}
	g.keyManager = keyManager
	// 釋放 SHALL 歸零記憶體中的明文金鑰材料（格 5b「清除已解封 KEK」的落點）
	g.bag.AddFunc("keyManager", func(context.Context) error {
		keyManager.ZeroizeForRelease()
		return nil
	})
	mark("keyManager")

	// 安全政策服務：政策數值後台可調，鎖定/密碼 validator 的讀取來源
	policyService := policy.NewSecurityPolicyService(database.DB)
	// 協議會話逾時政策以既有 env 初始化（升級相容：既有部署值沿用，政策頁設定後 env 不再介入）
	policyService.SeedFromEnv(policy.PolicySessionIdleMinutes, "SSH_IDLE_TIMEOUT_MINUTES")
	policyService.SeedFromEnv(policy.PolicySessionMaxMinutes, "SSH_MAX_SESSION_MINUTES")
	// 錄影保留政策以既有 env 播種（升級後行為不變，此後政策為準）
	policyService.SeedFromEnv(policy.PolicyRetentionRecordingDays, "RECORDING_RETENTION_DAYS")
	// 封章門檻自 env 播種（audit-checkpoint-chain）：既有部署的 env 值成為初值，
	// 此後政策頁為準。單位與 env 1:1（秒／筆），不做換算故播種不會失真
	policyService.SeedFromEnv(policy.PolicyAuditCheckpointIntervalSeconds, "AUDIT_CHECKPOINT_INTERVAL_SECONDS")
	policyService.SeedFromEnv(policy.PolicyAuditCheckpointRowThreshold, "AUDIT_CHECKPOINT_ROW_THRESHOLD")
	// 三個營運調校鍵自 env 播種：既有部署的 env 值
	// 成為初值，此後政策頁為準。單位與 env 1:1（筆／筆／秒），不做換算故播種不會失真。
	// 三者皆為「調小才危險」的預算／逾時型鍵，下界由 PolicyDef.Min 承擔
	policyService.SeedFromEnv(policy.PolicyRetentionMaxPerRun, "RETENTION_MAX_PER_RUN")
	policyService.SeedFromEnv(policy.PolicyKeyRotationMaxPerRun, "KEY_ROTATION_MAX_PER_RUN")
	policyService.SeedFromEnv(policy.PolicyK8sListTimeoutSeconds, "K8S_LIST_TIMEOUT_SECONDS")
	// refresh cookie 的 Secure 屬性自部署組態播種。
	//
	// **走 SeedValue 而非 SeedFromEnv**：本鍵的種子是兩層優先序的**推導結果**
	//（AUTH_REFRESH_COOKIE_SECURE 顯式值 → PUBLIC_BASE_URL 的 scheme），
	// 不是某個 env 的原值。Source 為 default（兩者皆缺）時**不寫列**——出廠預設
	// 已是同值 true，寫列只會製造「看似被人設定過」的假訊號，並讓日誌的來源
	// 歸因把「沒人設定」說成「組態播種」
	if d := cfg.Security.RefreshCookie; d.Source != config.RefreshCookieSecureFromDefault {
		policyService.SeedValue(policy.PolicyRefreshCookieSecure,
			strconv.FormatBool(d.Secure), d.Source)
	}
	// refresh cookie 的 Secure 現值與其來源歸因（決策 2）。
	//
	// **落在這裡而非 main 的啟動橫幅**：生效值住在政策服務裡，而封印啟動
	//（KEK_PROVIDER=ui）的段 2 要到解封後才跑——印在 main 只會在封印模式下
	// 永遠印不出來。接在播種之後，兩種模式都在「政策已就緒」的同一時點留話
	logRefreshCookieSecurity(policyService)
	// 換鑰上限與叢集列表逾時改由政策頁供給（env 僅為初值）：兩者皆執行期現讀，
	// 調整即刻生效不需重啟
	keyManager.SetPolicySource(policyService)
	k8sproxy.SetPolicySource(policyService)
	mark("policyService")

	// LDAP 目錄設定服務：設定自 env 遷入 DB，
	// 執行期唯一事實源。**落點必須在 keyManager 之後**——bind 密碼走信封加密，
	// codec 未就緒即無法解密。
	//
	// **恆注入、無 cfg.LDAP.Enabled 分支**：「是否啟用」由 DB 查詢結果表達，
	// 啟動時的 env 快照不再參與任何執行期判定；否則 admin 於 UI 建立設定後仍
	// 須改 env 重啟才生效，遷移即形同未做
	//
	// **auditTxSink 的落點必須在此之前**：交易內審計落地面是無狀態的，
	// 但它的第一個消費者就是本服務，且 LDAP seed 遷移（:261 的 post-unseal 佇列）
	// 在段 2 期間就會寫審計——自檢晚於那一步等於沒檢查。
	auditTxSink := audit.NewTxSink()
	if err := requireAuditTxSink(auditTxSink); err != nil {
		return fail("auditTxSink", err)
	}
	mark("auditTxSink")

	ldapDirectoryService := identity.NewLDAPDirectoryService(database.DB, keyManager, auditTxSink)
	mark("ldapDirectoryService")

	// 傳輸安全政策判定核心：六通道判定規則
	// 唯一所在，簽發閘/設定閘/LDAP 登入閘/徽章/清冊共用。
	//
	// 打環順序：先建目錄服務 → 以其 risk view provider 建本服務 →
	// 回頭把本服務注入目錄服務當存檔閘。兩者互為對方依賴，setter 是唯一解
	transmissionPolicy := policy.NewTransmissionPolicyService(
		policyService, ldapDirectoryService.RiskViewProvider())
	ldapDirectoryService.SetTransmissionPolicy(transmissionPolicy)
	mark("transmissionPolicy")

	// 審計機制失效事件（10.7.2/10.7.3）：記錄恆開、
	// 通知受政策 failure_alert_enabled 控制；啟動先回填重啟遺留的進行中事件
	//（失效狀態不跨進程保存，不回填即成永久懸掛）
	auditFailureService := audit.InitAuditFailure(database.DB, policyService)
	auditFailureService.ReconcileOnStartup()
	g.bag.AddFunc("auditFailureService", func(context.Context) error {
		audit.ResetAuditFailureSingleton()
		return nil
	})
	mark("auditFailureService")

	// syslog 離機轉發器（10.3.3）：audit/alert 寫入鏈以
	// model hook 與套件級單例 tee 取用；預設停用，設定頁啟用後即時生效。
	// reporter 必須先於 Start 注入——run loop 啟動後再無鎖寫 onFailure 是 data race
	if err := seal.CheckCancelStep(ctx, "syslogForwarder.Start"); err != nil {
		return fail("syslogForwarder.Start", err)
	}
	syslogForwarder := audit.InitSyslogForwarder(database.DB)
	syslogForwarder.SetFailureReporter(func(mechanism, causeCode string, params map[string]string, recovered bool) {
		if recovered {
			auditFailureService.Resolve(mechanism)
		} else {
			auditFailureService.Report(mechanism, causeCode, params)
		}
	})
	syslogForwarder.Start()
	g.bag.AddFunc("syslogForwarder", func(context.Context) error {
		syslogForwarder.Stop()
		return nil
	})
	mark("syslogForwarder")

	// audit_logs 逐列完整性 HMAC（10.3.4）：
	// 版本化蓋章——新列以系統生成鑰蓋章並記
	// key_version，v0=legacy 派生鑰快照，JWT_SECRET 輪替不再影響驗章
	auditIntegrity, err := audit.InitAuditIntegrityVersioned(database.DB, keyManager)
	if err != nil {
		return fail("InitAuditIntegrityVersioned", err)
	}
	// 完整性蓋章（BeforeCreate）與 syslog tee（AfterCreate）掛 model 建立
	// hook——audit_logs 有 middleware 批次以外的直寫路徑（asset GORM hook、
	// file_tap、k8s cp），集中 model 層才覆蓋全部
	model.SetAuditCreateHooks(auditIntegrity.StampOne, syslogForwarder.EnqueueAuditLog)
	// 釋放 SHALL 解 hook：否則舊持有者的物件會在封印期間仍被 GORM 直寫路徑呼叫
	g.bag.AddFunc("auditIntegrity", func(context.Context) error {
		model.SetAuditCreateHooks(nil, nil)
		audit.ResetAuditIntegritySingleton()
		return nil
	})
	mark("auditIntegrity")

	// 解封後遷移佇列（交叉相容契約 3(b)）：任何需要 codec 的資料 migration
	// 於此執行——A／C 模式下與段 1 連續執行故行為與現況無異，B 模式下自然延後至解封後。
	// 內建項目前只有 LDAP 設定 env seed（ldap_seed）；AAD 與 legacy 遷移**不在**佇列。
	if err := seal.CheckCancelStep(ctx, "RunPostUnsealMigrations"); err != nil {
		return fail("RunPostUnsealMigrations", err)
	}
	// **內建遷移的登記在組裝根**：佇列機制屬 keyvault、
	// 遷移內容屬各業務模組，由此處縫合。新增內建遷移 SHALL 在此加一行登記，
	// 且 SHALL 落在 RunPostUnsealMigrations 之前——否則佇列在執行時只有一半
	// （守衛：post_unseal_guard_test.go 的 TestAssemblyRegistersPostUnsealBuiltins）。
	// 登記器收 auditTxSink（AP-51）：seed 的插列＋審計＋marker 同事務，
	// 審計落地面以閉包捕獲——佇列項的執行體簽名（db, codec）表達不了第三個依賴，
	// 而套件級全域 sink 正是被拒絕的形態（可漏接成 nil no-op）
	keyvault.RegisterPostUnsealBuiltin(identity.PostUnsealMigrationLDAPSeed, func() {
		identity.RegisterLDAPSeedMigration(auditTxSink)
	})
	// 離機儲存設定的 env→DB **初次** seed：
	// 需 codec 加密物件儲存憑證，故必登記於本佇列而非段 1 migration。
	// marker 寫入後 env 不再參與任何執行期判定，設定變更改由管理介面進行。
	// 保管鏈落地面在此縫合（不開 offsite→audit 的出向邊）
	keyvault.RegisterPostUnsealBuiltin(offsite.PostUnsealMigrationOffsiteSeed, func() {
		offsite.RegisterOffsiteSeedMigration(offsiteCustodyJournal{tx: auditTxSink, db: database.DB})
	})
	// 剪貼簿明文欄→信封加密欄的一次性轉換：
	// 回填需要 codec 故走本佇列；全新庫由 baseline 直建終態形狀，此項為 no-op
	keyvault.RegisterPostUnsealBuiltin(session.PostUnsealMigrationClipboardContent,
		session.RegisterClipboardContentMigration)
	keyvault.RunPostUnsealMigrations(database.DB, keyManager)
	mark("postUnsealMigrations")

	// 協議會話閒置/最大時長讀取：SSH/k8s/DB 與 guacd（RDP/VNC）路徑共用
	sessionTimeoutPolicy := func() (time.Duration, time.Duration) {
		return time.Duration(policyService.GetInt(policy.PolicySessionIdleMinutes)) * time.Minute,
			time.Duration(policyService.GetInt(policy.PolicySessionMaxMinutes)) * time.Minute
	}

	// 初始化服務（MFA TOTP secret 加解密走信封 key manager）。
	// access token 固定短效 15 分：撤銷殘窗上限，
	// 會話續命走 /auth/refresh（rotation＋DB 撤銷），不再發 24h 長效 token
	authService, err := identity.NewAuthServiceWithMFA(cfg.Security.JWTSecret, identity.AccessTokenTTL, keyManager)
	if err != nil {
		return fail("NewAuthServiceWithMFA", err)
	}
	authService.SetSecurityPolicies(policyService)
	// 憑證世代閘的資料來源：**組裝根顯式注入**。
	//
	// 注入的就是回退分支會取到的同一個 `database.DB`（stage1 的 InitDatabase 已完成，
	// 見 stage1.go 的資料庫初始化步），故生產行為逐位未變；差別在於「有沒有注入」
	// 從此是組裝根的顯式決定，而不是靠 identity 內部的全域回退默默補上。
	//
	// 為何值得顯式注入：世代閘是撤銷機制的執行點，登記在案的風險正是
	// 「一條漏接注入的組裝路徑會讓 fail-close 在生產靜默觸發而無人察覺」。
	// 注入點釘在 `TestAssemblyInjectsEpochGateDB`（行為面，非讀碼）。
	authService.SetEpochGateDB(database.DB)

	// 來源政策的恢復謂詞：啟動時掃一次 users.allowed_cidrs。
	// **雙向**——有損壞列即開失效（否則那個狀態要等到有人登入才被看見），
	// 全部可解析則結案重啟前遺留的 open 事件
	identity.EvaluateSourcePolicyHealth(database.DB)

	// LDAP 認證：**恆注入 resolver**，不再有
	// cfg.LDAP.Enabled 分支——「是否啟用」由每次登入的 DB 解析結果表達，設定
	// 於 UI 變更即時生效。無設定列或設定停用時 resolver 回 unavailable，
	// 登入行為與舊版「未啟用」完全一致（查無帳號回憑證錯誤，本地帳號不受影響）。
	//
	// 撥號副作用發生在登入當下而非此處，故不需 CheckCancelStep。
	authService.SetLDAPResolver(identity.NewLDAPLoginResolver(ldapDirectoryService))
	// LDAP 登入傳輸閘：warn 留痕/strict 拒絕。
	// 舊版只在 LDAP 啟用時注入，現在恆注入——閘本身對本地路徑無作用
	authService.SetTransmissionPolicy(transmissionPolicy)
	mark("authService")

	// 初始化資產服務（憑證加解密走信封 key manager）
	assetService, err := asset.NewAssetService(keyManager, cfg.Guacamole.Host, cfg.Guacamole.Port, auditTxSink)
	if err != nil {
		return fail("NewAssetService", err)
	}
	assetService.SetTransmissionPolicy(transmissionPolicy) // 資產列表傳輸風險徽章（5.1）
	mark("assetService")

	// 初始化授權服務
	authorizationService := authz.NewAssetAuthorizationService(database.DB)
	// 資產刪除即撤銷其授權與審核範圍（走 tx-taking 窄 port）
	assetService.SetAuthorizationRevoker(authorizationService)

	// 初始化連線註冊表（先創建，供 SessionService 使用）
	registry := proxy.NewConnectionRegistry()
	// 釋放 SHALL 全量收線，否則連線 goroutine 續存
	g.bag.AddFunc("connectionRegistry", func(context.Context) error {
		registry.CloseAll()
		return nil
	})
	mark("connectionRegistry")

	// 初始化 Session 服務（注入 Registry）
	sessionService := session.NewSessionService(registry)
	assetService.SetSessionTerminator(sessionService) // 資產停用即收線
	mark("sessionService")

	// session-reconciliation 啟動清掃：重啟後不可能有存活連線，殘留 active
	// 於受理新連線前一次收斂（backend_restart）。失敗不擋開服——殘留由
	// 週期孤兒偵測補收
	reconciliationService := session.NewSessionReconciliationService(registry)
	if n, err := reconciliationService.ReconcileStartup(); err != nil {
		log.Printf("[Reconcile] 啟動清掃失敗: %v", err)
	} else if n > 0 {
		log.Printf("[Reconcile] 啟動清掃：收斂 %d 筆殘留 active session（backend_restart）", n)
	}
	mark("reconciliationService")

	// 初始化錄製服務
	// 錄影根只在此解析一次並正規化（recorder.ResolveBasePath），下傳給 RecordingService
	// 與 sshproxy——組裝根持有唯一的一份，避免各消費端各自讀 env 又各自拼路徑
	recordingBasePath := recorder.ResolveBasePath("")
	recordingService := session.NewRecordingService(recordingBasePath)
	mark("recordingService")

	// 初始化審計日誌服務
	auditService := audit.NewAuditLogService(&cfg.Features)
	// C-plain 兩點（AP-04 k8s 檔案操作、AP-28 檔案上傳）的直寫投遞面：
	// 它們現況不受 AuditLogEnabled 管制，接到受管制的 auditService 上即行為變更
	auditDirectSink := audit.NewDirectSink(database.DB)
	if err := requireAuditAsyncSinks(auditService, auditDirectSink); err != nil {
		return fail("auditAsyncSinks", err)
	}
	g.auditService = auditService
	g.bag.AddFunc("auditService", func(rctx context.Context) error { return auditService.Shutdown(rctx) })
	mark("auditService")

	// ── 離機儲存（evidence-offsite-storage） ────────────────────────────
	//
	// **保管鏈的非同步面在此才注入**：seed 的登記必須早於
	// RunPostUnsealMigrations，而 auditService 到這一步才存在，故 seed 用的那一份
	// 是「以根 DB 同步寫」的退路版；worker 與取回路徑用的是本份，帶真正的
	// 非同步投遞面——否則每次上傳都會同步寫一列審計，把旁路功能的成本壓在熱路徑上。
	offsiteJournal := offsiteCustodyJournal{tx: auditTxSink, db: database.DB, async: auditService}
	offsiteProfiles := offsite.NewOffsiteProfileService(database.DB, keyManager, offsiteJournal)
	offsiteLedger := offsite.NewLedger(database.DB, offsiteProfiles, offsiteJournal)
	offsiteProfiles.SetLedger(offsiteLedger)
	mark("offsiteProfiles")

	// **健檢，不是世代拒啟**（降級語義）：帳冊出現的 storage_generation_id
	// 必須都能在世代表找到（含已退役者——退役是合法歸屬）。違反＝資料損壞
	// （部分還原、DB 手術），此時繼續啟動只會讓取回以「用現行設定猜」收場
	if err := offsiteLedger.CheckProfileContinuity(); err != nil {
		return fail("offsiteLedger", err)
	}
	mark("offsiteLedger")

	// adapters 與取回器：**與是否啟用無關**（停用態的取回子系統照常組裝，
	// 停用態表第二列）。保留天數以函式取得而非值——政策營運中會改
	recordingOffsiteAdapter := session.NewRecordingOffsiteAdapter(database.DB, func() int {
		return policyService.GetInt(policy.PolicyRetentionRecordingDays)
	})
	exportOffsiteAdapter := audit.NewExportOffsiteAdapter(database.DB)
	offsiteFetcher := offsite.NewFetcher(cfg.Offsite.SpoolPath, offsiteLedger, offsiteProfiles,
		offsiteJournal, auditFailureService, recordingOffsiteAdapter, exportOffsiteAdapter)

	// 擁有表快取的批次寫回面：世代切換與停止離機時，帳冊轉 foreign 的**同一交易內**
	// 把 sessions／audit_export_jobs 的 offsite_status 一併寫成 foreign。
	// 不接線的後果不是壞掉而是**說謊**——世代已換，會話詳情仍顯示「已上傳到現行儲存」
	offsiteProfiles.SetOwnerCacheMarkers(recordingOffsiteAdapter, exportOffsiteAdapter)

	// 排隊點與取回點的接線。**未設定時這些注入不改變任何行為**：
	// 排隊點自行以 HasCurrentGeneration 早退（零交易），取回點只在擁有表有
	// offsite_object_id 時才會被走到，而那需要曾經排隊過
	sessionService.SetOffsiteEnqueuer(offsiteLedger)
	recordingService.SetOffsiteRetriever(offsiteFetcher)
	recordingService.SetOffsiteRetentionLedger(offsiteLedger)

	// 單實例守衛事件 sink：審計服務只在段 2 之後存在，
	// 守衛在段 1 緩衝的事件（含 ack 啟動的 overridden）於此注入時依序補寫
	database.SetInstanceGuardEventSink(instanceGuardAuditSink(auditService))

	// KEK 切換審計補記（best-effort）
	logKEKSwitchAudit(keyManager, auditService)

	// 每日審閱簽核服務（10.4.1）：政策 daily_review_enabled
	// 控制，關閉時 API 拒簽、提醒排程空轉
	dailyReviewService := audit.NewDailyReviewService(database.DB, policyService, auditService)
	mark("dailyReviewService")

	// 剪貼簿內容加密器：欄位身分於此封進閉包，
	// proxy 層只拿得到「加密到 clipboard_events.content_enc」這一件事
	clipboardEncrypt := func(ctx context.Context, plaintext string) (string, error) {
		return keyManager.EncryptFor(ctx, keyvault.RefClipboardContent, plaintext)
	}

	// 初始化連線處理器（添加授權服務）
	connHandler := proxy.NewConnectionHandler(cfg.Guacamole.Host, cfg.Guacamole.Port, sessionService, assetService, authService, authorizationService, auditService, clipboardEncrypt)
	connHandler.Registry = registry // 設定 Registry
	// RDP/VNC 會話閒置/最大時長改讀安全政策（與 SSH/k8s/DB 同一政策鍵）
	connHandler.TimeoutPolicy = sessionTimeoutPolicy
	// 檔案上傳審計的投遞面（AP-28）：每條圖形連線的 FileTap 由此取得。
	// 用 DirectSink 而非 auditService——該點現況不受 AuditLogEnabled 管制
	connHandler.AuditSink = auditDirectSink
	mark("connHandler")

	// 使用者服務（頂層建立，供 v1 路由與閒置停用排程器共用）：自助改密端點依賴。
	// 停用帳號即時撤權收線：撤 refresh 之外同步終斷進行中協議會話
	userService := identity.NewUserService(database.DB, authorizationService)
	userService.SetSecurityPolicies(policyService)
	userService.SetSessionTerminator(sessionService)
	// 外部身分管理四操作的審計出口
	userService.SetAuditSink(auditService)
	mark("userService")

	// 指令告警落地面：入庫＋通知＋syslog 離機轉發
	// 收在同一個出口，比對路徑與阻斷路徑共用。**唯一建構點**——任何服務自行建構
	// 等於繞過下方的注入自檢，由 TestAlertSinkIsConstructedOnlyAtAssemblyRoot 釘住
	alertSink := audit.NewAlertRecorder(database.DB)
	if err := requireAlertSink(alertSink); err != nil {
		return fail("alertSink", err)
	}
	mark("alertSink")

	// 註冊危險指令告警路由（command-alerts）：
	// 啟動即載入規則快取供 recorder 路徑比對；載入失敗不致命（無快取=不告警）
	alertMatcher := audit.InitAlertMatcher(database.DB, alertSink)
	if err := alertMatcher.LoadRules(); err != nil {
		log.Printf("告警規則快取載入失敗（告警暫不生效，規則變更時重試）: %v", err)
	}
	g.bag.AddFunc("alertMatcher", func(context.Context) error {
		audit.ResetAlertMatcherSingleton()
		return nil
	})
	mark("alertMatcher")

	// 註冊告警通知通道路由（alert-notifications）：
	// 啟動即載入通道快取並起推送 worker；載入失敗不致命（無快取=不推送）
	if err := seal.CheckCancelStep(ctx, "alertNotifier"); err != nil {
		return fail("alertNotifier", err)
	}
	alertNotifier := audit.InitAlertNotifier(database.DB, keyManager)
	if err := alertNotifier.LoadChannels(); err != nil {
		log.Printf("通知通道快取載入失敗（推送暫不生效，通道變更時重試）: %v", err)
	}
	// 釋放 SHALL 停 worker、歸零通道明文並解除單例（見 session.StopAlertNotifierForRelease）：
	// 已啟動的 worker 持有解密後的通道 URL／secret（KEK 衍生材料），
	// 段 2 重試時每一代都會多留一份，且舊單例仍會被 GORM／告警路徑取用。
	g.bag.AddFunc("alertNotifier", func(context.Context) error {
		audit.StopAlertNotifierForRelease(alertNotifier)
		return nil
	})
	mark("alertNotifier")

	// KEK 退役收斂 degraded 首次評估
	kekRetirementMonitor := keyvault.NewKEKRetirementMonitor(keyManager, auditFailureService)
	kekRetirementMonitor.ReportOnStartup(time.Now())
	mark("kekRetirementMonitor")

	// 非終態格式殘值的啟動哨兵：廉價 SQL 下界
	// 計數、fail-visible、不阻塞啟動、不提供遷移入口。置於告警服務就緒後
	// （否則通知必被丟棄）
	keyvault.ReportAADResidueOnStartup(database.DB, auditFailureService)

	// codec 為建構參數（cutover）：secret/url 一律以 ColumnCodec 寫 enc:a1
	notificationChannelService := audit.NewNotificationChannelService(database.DB, keyManager)
	notificationChannelService.SetTransmissionPolicy(transmissionPolicy) // 傳輸政策閘
	mark("notificationChannelService")

	// OIDC 身分提供者整合。
	//
	// egress 政策：dev 靶機的 http hostname 僅在非 release 模式放行——
	// release 一律無例外（issuer 必須 https）
	oidcEgress := &identity.OIDCEgressPolicy{
		AllowedInternalHosts: cfg.OIDC.AllowedInternalHosts,
	}
	if cfg.Server.Mode != "release" {
		oidcEgress.AllowInsecureHosts = cfg.OIDC.AllowedInternalHosts
	}
	oidcProviderService := identity.NewOIDCProviderService(
		database.DB, keyManager, oidcEgress, cfg.OIDC.DedicatedIssuers, cfg.OIDC.PublicBaseURL)
	oidcDiscovery := identity.NewOIDCDiscoveryService(oidcEgress)
	oidcLoginService := identity.NewOIDCLoginService(
		database.DB, oidcProviderService, oidcDiscovery, authService, auditService)
	mark("oidcServices")

	// 匯出簽章服務（10.3.4）：首啟自動生成 Ed25519 金鑰，
	// 私鑰經信封 key manager 加密落 DB
	exportSigning, err := keyvault.NewExportSigningService(database.DB, keyManager)
	if err != nil {
		return fail("NewExportSigningService", err)
	}
	// 解密後的 Ed25519 私鑰常駐記憶體，屬 KEK 衍生材料，釋放 SHALL 歸零
	g.bag.AddFunc("exportSigning", func(context.Context) error {
		exportSigning.ZeroizeForRelease()
		return nil
	})
	mark("exportSigning")

	// 檢查點簽章服務（audit-checkpoint-chain）：首啟自動生成 Ed25519 v1，
	// 私鑰經 ColumnCodec 以 RefCheckpointSigningPrivateKey 綁定 AAD 落 DB。
	// 載入失敗一律 fail-close——帶病啟動會產出一批永遠驗不了的檢查點，
	// 而檢查點的全部價值就在「可驗」
	checkpointSigning, err := keyvault.NewCheckpointSigningService(database.DB, keyManager)
	if err != nil {
		return fail("NewCheckpointSigningService", err)
	}
	// 解密後的 Ed25519 私鑰（**全部版本**）常駐記憶體，屬 KEK 衍生材料，釋放 SHALL 歸零
	g.bag.AddFunc("checkpointSigning", func(context.Context) error {
		checkpointSigning.ZeroizeForRelease()
		return nil
	})
	mark("checkpointSigning")

	// 原生 SSH 終端路由：只收 token + asset_id，憑證後端注入
	sshHandler := sshproxy.NewHandler(assetService, authService, authorizationService, sessionService, registry, recordingBasePath, auditService)
	sshHandler.TimeoutPolicy = sessionTimeoutPolicy
	// 錄影 fail-close 政策（改動對新簽發即時生效）
	sshHandler.RecordingFailClose = func() bool {
		return policyService.GetBool(policy.PolicyRecordingFailCloseEnabled)
	}
	// 阻斷告警的落地面：每條會話的 commandBlocker 由此取得。
	// 未注入即在上方 requireAlertSink 拒絕啟動，不會走到這裡才發現
	sshHandler.AlertSink = alertSink
	// 帳號新來源位址基準：兩條建線路徑共用**同一份**服務。
	// 分開建兩份不會壞掉，但兩條協議的「已見」判定會落在同一張表的同一組鍵上、
	// 卻各自持有不同的鉤子與接線狀態——接線只斷一側時症狀是「SSH 會響、RDP 不響」，
	// 而兩者對同一帳號同一位址本該只響一次
	sourceIPBaseline := audit.NewSourceIPBaseline(database.DB, alertSink, auditTxSink)
	sshHandler.SourceIPBaseline = sourceIPBaseline
	connHandler.SourceIPBaseline = sourceIPBaseline
	// 兩路徑共用同一 token manager（簽發端點掛在 sshHandler）
	connHandler.ConnectTokens = sshHandler.ConnectTokens
	// host-key-verification: TOFU host key 服務（SSH 與 SFTP 共用）
	hostKeyService := asset.NewHostKeyService(database.DB)
	sshHandler.HostKeys = hostKeyService
	assetService.SetHostKeyService(hostKeyService) // SSH 直連測試共用 TOFU
	// **釋放路徑待補**：MonitorHub／ShareManager／ConnectTokenManager
	// 與 statsClients 持有的活躍 *ssh.Client 皆無全量關閉入口。同上，不登記空
	// releaser。實際收線的主力是 connectionRegistry.CloseAll（已登記）。
	// 使用者級收線管道：解綁外部身分／解綁＋停用／
	// 改為僅外部登入推進 credential_epoch 後，須主動收線**已建立**的唯讀訂閱——
	// 監看與分享觀看不建 sessions 列，SessionTerminator 完全掃不到它們
	userService.SetSubscriptionTerminator(sshHandler.Monitor)
	// provider 級收線管道：provider 停用／刪除／密鑰
	// 輪替推進 auth_epoch 後，須主動收線**已建立**的協議連線與唯讀訂閱——
	// 世代閘只能拒絕「下一次出示憑證」的請求，長連線建立後不再出示憑證。
	// 錄影 token 的 provider 級撤銷於 recordingHandler 建立後接（見下方 stage）
	oidcProviderService.SetSessionTerminator(sessionService)
	oidcProviderService.SetSubscriptionTerminator(sshHandler.Monitor)
	mark("sshHandler")
	mark("hostKeyService")

	// change-secret: 改密計劃（排程器於下方統一啟動）
	changeSecretPlanService := asset.NewChangeSecretPlanService(database.DB)
	changeSecretCandidates, err := asset.NewChangeSecretCandidateService(
		database.DB, keyManager, assetService, auditTxSink)
	if err != nil {
		return fail("changeSecretCandidateService", err)
	}
	changeSecretRunner := asset.NewChangeSecretRunner(
		database.DB, assetService, changeSecretCandidates, hostKeyService, alertNotifier)
	changeSecretScheduler := scheduler.NewChangeSecretScheduler(changeSecretPlanService, changeSecretRunner)
	if err := seal.CheckCancelStep(ctx, "changeSecretScheduler.Start"); err != nil {
		return fail("changeSecretScheduler.Start", err)
	}
	changeSecretScheduler.Start()
	// 阻擋項 2（RESOURCES.md）：現況 main 無對應 defer，屬既有洩漏；此處補上
	g.bag.AddFunc("changeSecretScheduler", func(context.Context) error {
		changeSecretScheduler.Stop()
		return nil
	})
	mark("changeSecretScheduler")

	// 未驗證候選憑證的重試排程。與改密排程分立——
	// 改密是使用者定義的 cron，重試是系統自身的可靠性機制，兩者的節奏與失效語義不同
	changeSecretRetryRunner := asset.NewChangeSecretRetryRunner(
		database.DB, changeSecretCandidates, assetService, hostKeyService, alertNotifier)
	changeSecretRetryScheduler := scheduler.NewChangeSecretRetryScheduler(changeSecretRetryRunner)
	if err := seal.CheckCancelStep(ctx, "changeSecretRetryScheduler.Start"); err != nil {
		return fail("changeSecretRetryScheduler.Start", err)
	}
	changeSecretRetryScheduler.Start()
	g.bag.AddFunc("changeSecretRetryScheduler", func(context.Context) error {
		changeSecretRetryScheduler.Stop()
		return nil
	})
	mark("changeSecretRetryScheduler")

	// 連線同意閘
	transmissionConsent := policy.NewTransmissionConsentService(database.DB, transmissionPolicy)
	sshHandler.TransmissionConsent = transmissionConsent

	// 存取政策閘——無條件注入，不掛功能開關
	// sources 為 policy 自宣告的窄介面（拆環）：authz 的
	// AssetAuthorizationService 實作，policy 不再持有 authz 的 repository
	// 資料傳輸有效能力解析（data-transfer-control 第 2 組）：SFTP／K8s 端點閘、
	// guacd 連線參數與 FileTap 逐次判定共用同一實例——兩套解析遲早分岔，
	// 而分岔的那一側就是越權面
	dataTransferService := policy.NewDataTransferService(policyService)
	accessPolicyService := policy.NewAccessPolicyService(database.DB, policyService, authorizationService)
	sshHandler.AccessPolicy = accessPolicyService
	connHandler.AccessPolicy = accessPolicyService // 兌換點政策重查（與 SSH 對稱）
	// 資料傳輸管控（data-transfer-control）：guacd 連線參數＋FileTap 逐次判定
	connHandler.SetDataTransfer(dataTransferService)
	// 查詢主控台的結果匯出走同一份判定實例（第四個強制點）：
	// 兩套解析遲早分岔，而分岔的那一側就是越權面
	sshHandler.DataTransfer = dataTransferService
	sshHandler.DB = database.DB

	// 申請核准流
	accessRequestService := authz.NewAccessRequestService(
		database.DB, policyService, accessPolicyService, auditService, alertNotifier)
	// 撤銷即斷線政策開啟時收線（沿 Terminate CAS）
	accessRequestService.SetSessionService(sessionService)
	accessRequestScheduler := scheduler.NewAccessRequestTimeoutScheduler(accessRequestService)
	if err := seal.CheckCancelStep(ctx, "accessRequestScheduler.Start"); err != nil {
		return fail("accessRequestScheduler.Start", err)
	}
	if err := accessRequestScheduler.Start(); err != nil {
		return fail("accessRequestScheduler.Start", err)
	}
	g.bag.AddFunc("accessRequestScheduler", func(context.Context) error {
		accessRequestScheduler.Stop()
		return nil
	})
	mark("accessRequestScheduler")

	// 全部 API handler：僅引用上列服務，非資源持有者
	// 檢查點鏈的三個共用元件（audit-checkpoint-chain 第 4／6／8 組）。
	//
	// **建在 buildRouteDeps 之前**：驗證端點需要與封章、清除**同一份**實作
	// ——聚合若在 API 側另寫一套，驗證就會永遠自洽（拿自己的算法驗自己的資料）。
	// 封章排程與 retention 於下方沿用同一組實例
	checkpointPurger := audit.NewCheckpointPurger(database.DB, checkpointSigning)
	checkpointService := audit.NewCheckpointService(database.DB, checkpointSigning, syslogForwarder,
		func(mechanism, causeCode string, params map[string]string, recovered bool) {
			if recovered {
				auditFailureService.Resolve(mechanism)
			} else {
				auditFailureService.Report(mechanism, causeCode, params)
			}
		})
	// 封章門檻改由政策頁供給（env 僅為初值）：每次 Due() 重讀，調短即刻生效
	checkpointService.SetPolicySource(policyService)
	checkpointVerifier := audit.NewCheckpointVerifier(database.DB, checkpointService,
		checkpointPurger, auditIntegrity, policyService)

	// 檢查點鏈兩層自動驗證的編排者。
	//
	// **在路由建構之前建立，且全程只有這一個實例**：它同時是排程器的執行體與
	// 驗證頁的營運狀態來源（狀態經既有結構層報告揭露，不新增路由）。
	// 狀態全數持久化於狀態列、`Status()` 唯讀且不建列，故另建一份**不會**憑空生出
	// 一份假的新鮮狀態；要避免的是排程器與呈現面各自綁一組依賴裝配（verifier、
	// 封章服務、政策來源、調參來源、告警面）而彼此漂移——任一項給的不是同一個，
	// 頁面描述的就不是實際在跑的那一個。共用單一實例把兩者釘在同一份真相上
	chainVerifyService := audit.NewChainVerifyService(database.DB, checkpointVerifier,
		checkpointService, checkpointSigning, policyService,
		scheduler.NewChainVerifyPolicyTuning(policyService), auditFailureService)

	// 稽核證據匯出服務（audit-workflows；組裝根在此處而非
	// buildRouteDeps 內）：打包 worker 與 API handler 必須共用**同一實例**——簽章與
	// 剪貼簿解密器若只注入其中一份，另一份會產出未簽章、或遇可用內容即失敗的包。
	// 指令流讀取服務無狀態，另建實例不與 sessionCommandHandler 那份分歧
	auditExportService := audit.NewAuditExportService(database.DB, auditService,
		audit.NewSessionCommandService(database.DB), recordingService)
	auditExportService.SetSigning(exportSigning)
	auditExportService.SetClipboardCodec(keyManager)
	auditExportJobService := audit.NewAuditExportJobService(database.DB)

	deps, err := buildRouteDeps(cfg, routeServices{
		metrics:              s1.metrics,
		checkpointVerifier:   checkpointVerifier,
		chainVerifyStatus:    chainVerifyService,
		checkpointSigning:    checkpointSigning,
		authService:          authService,
		auditService:         auditService,
		auditTxSink:          auditTxSink,
		auditDirectSink:      auditDirectSink,
		authorizationService: authorizationService,
		policyService:        policyService,
		transmissionPolicy:   transmissionPolicy,
		ldapDirectoryService: ldapDirectoryService,
		offsiteProfiles:      offsiteProfiles,
		offsiteLedger:        offsiteLedger,
		offsiteDescribers: []api.OffsiteOwnerDescriber{
			recordingOffsiteAdapter, exportOffsiteAdapter,
		},
		offsiteFetcher:             offsiteFetcher,
		userService:                userService,
		assetService:               assetService,
		sessionService:             sessionService,
		reconciliationService:      reconciliationService,
		recordingService:           recordingService,
		dailyReviewService:         dailyReviewService,
		auditFailureService:        auditFailureService,
		notificationChannelService: notificationChannelService,
		oidcProviderService:        oidcProviderService,
		oidcLoginService:           oidcLoginService,
		exportSigning:              exportSigning,
		keyManager:                 keyManager,
		hostKeyService:             hostKeyService,
		syslogForwarder:            syslogForwarder,
		auditIntegrity:             auditIntegrity,
		alertNotifier:              alertNotifier,
		accessPolicyService:        accessPolicyService,
		dataTransferService:        dataTransferService,
		accessRequestService:       accessRequestService,
		changeSecretPlanService:    changeSecretPlanService,
		changeSecretRunner:         changeSecretRunner,
		changeSecretCandidates:     changeSecretCandidates,
		changeSecretRetryRunner:    changeSecretRetryRunner,
		changeSecretScheduler:      changeSecretScheduler,
		sourceIPBaseline:           sourceIPBaseline,
		auditExportService:         auditExportService,
		auditExportJobs:            auditExportJobService,
		connHandler:                connHandler,
		sshHandler:                 sshHandler,
		corsMiddleware:             s1.corsMiddleware,
	})
	if err != nil {
		return fail("buildRouteDeps", err)
	}
	g.deps = deps
	mark("apiHandlers")

	// 排程器群：
	// 每一個都是「具外部副作用的步驟」，故各自於啟動前檢查取消。
	starts := []struct {
		name  string
		start func() error
		stop  func()
	}{
		{"retentionScheduler", nil, nil},
		{"reviewReminderScheduler", nil, nil},
		{"inactivityScheduler", nil, nil},
		{"kekRetirementScheduler", nil, nil},
		{"reconcileScheduler", nil, nil},
		{"checkpointScheduler", nil, nil},
		{"chainVerifyScheduler", nil, nil},
		// offsiteUploader 登記在 auditExportJobWorker **之前**＝停在它之後
		// （ResourceBag 反序釋放）：上傳 worker 讀 export 產物，先停打包器再停它，
		// 才不會出現「產物還在寫、上傳已停」以外的順序
		{"offsiteUploader", nil, nil},
		{"auditExportJobWorker", nil, nil},
	}
	retentionService := audit.NewRetentionService(database.DB, policyService, recordingService, auditService)
	// audit_logs 改走檢查點區間清除（本行是唯一切換點）：
	// 已封區間整段清除＋簽章 tombstone，genesis 之前的殘量續走逐列路徑。
	// 部署後首輪 retention 會出現「已過期但所屬區間未全數過期的列暫留」，
	// 為 spec 明載的預期行為（有界過度保留）。回滾即拿掉這一行
	retentionService.UseCheckpointIntervals(checkpointPurger)
	// 保留水位（auditor-workbench）：每輪清除後前進 audit_retention_watermarks。
	// **缺這一行，招牌能力會反向失效**——真的被清除過的區間在工作台回 present＋空白，
	// 亦即把「已依政策清除」呈現成「本來就沒發生」，正是本能力要防止的誤報
	retentionService.SetWatermarks(audit.NewRetentionWatermarkService(database.DB))
	// 離機啟用後的錄影保留補充面：快取清除段與政策到期段的 DB 分支。
	// **恆注入**——兩者各自以「政策值 0」與「帳冊無列」自我早退，
	// 未啟用時一次查詢也不會發出
	retentionService.SetOffsiteRecordingRetention(recordingService)
	retentionScheduler := scheduler.NewRetentionScheduler(retentionService)
	starts[0].start, starts[0].stop = retentionScheduler.Start, retentionScheduler.Stop
	reviewReminderScheduler := scheduler.NewDailyReviewReminderScheduler(dailyReviewService)
	starts[1].start, starts[1].stop = reviewReminderScheduler.Start, reviewReminderScheduler.Stop
	inactivityService := identity.NewInactivityService(database.DB, policyService, userService, auditService)
	inactivityScheduler := scheduler.NewInactivityCleanupScheduler(inactivityService)
	starts[2].start, starts[2].stop = inactivityScheduler.Start, inactivityScheduler.Stop
	kekRetirementScheduler := scheduler.NewKEKRetirementScheduler(kekRetirementMonitor)
	starts[3].start, starts[3].stop = kekRetirementScheduler.Start, kekRetirementScheduler.Stop
	reconcileScheduler := scheduler.NewSessionReconciliationScheduler(reconciliationService)
	starts[4].start, starts[4].stop = reconcileScheduler.Start, reconcileScheduler.Stop
	// 檢查點封章（audit-checkpoint-chain 第 4／5 組）：旁路批次工作，
	// 每分鐘檢查門檻，觸發後延遲 grace 再掃描聚合簽章。錨定出口為既有
	// syslogForwarder，失效上報走 auditFailureService（獨立機制碼）。
	// Start 內含 genesis 建立，失敗即啟動失敗——沒有 genesis 的排程器
	// 每輪都會失敗，是「活著但什麼都沒保護」的靜默狀態
	checkpointScheduler := scheduler.NewCheckpointScheduler(checkpointService)
	starts[5].start, starts[5].stop = checkpointScheduler.Start, checkpointScheduler.Stop
	// 檢查點鏈兩層自動驗證：
	// 每分鐘判到期，近期層買低延遲（隨封章觸發、驗最近 N 天已封區間）、
	// 全鏈層買無盲區（依政策週期跑結構層全鏈＋內容層滾動窗）。
	//
	// **與上一行共用同一組 checkpointVerifier／checkpointService 實例**：驗證邏輯
	// 若在此另建一份，自動驗證就會拿另一套聚合算法去驗封章的產物，兩套一旦分歧
	// 不是「驗出竄改」就是「永遠自洽」，兩種結果都無法判讀。
	//
	// **旋鈕經 ChainVerifyPolicyTuning 現讀安全政策三鍵、不快取**：政策一改下一
	// 分鐘生效。若在此取值一次帶進服務，政策頁顯示的數字與排程實際節奏會在改值
	// 後長期不一致——「顯示值 ≠ 生效值」是本專案在別處已拒絕的形態。
	//
	// **告警出口為 auditFailureService（三個獨立機制碼）**：出站 payload 只帶碼與
	// 受控計數，序號清單與紀錄區間只落 cause_params（DB），以守住去識別紅線。
	// 漏接此排程器不會有任何錯誤：鏈仍在、驗證頁的按鈕仍在，只是再也沒有人被
	// 通知——證據存在卻無人知曉，正是本 change 要消滅的靜默狀態。
	//
	// **服務本體建於路由建構之前**（見該處註解）：驗證頁揭露的營運狀態與此處
	// 執行的是同一個實例
	chainVerifyScheduler := scheduler.NewChainVerifyScheduler(chainVerifyService)
	starts[6].start, starts[6].stop = chainVerifyScheduler.Start, chainVerifyScheduler.Stop
	// 證據包打包 worker：Ticker 領件、
	// panic recover、領件與每次重試重驗申請者。
	//
	// 申請者重驗閉包由組裝根組出（audit 模組不直讀 users 表）：允許＝帳號存在
	// 且啟用且任一角色具 audit:view。與 RequirePermission 的判定等價——
	// middleware 取 primaryRole（優先序 admin>auditor>user），而 audit:view 僅
	// admin/auditor 具備，故「任一角色具權」與「最高優先角色具權」同值。
	// (allowed=false, err=nil)＝失權取消；err 非 nil＝查詢面故障，交給重試
	// （查不到不等於失權，誤取消會把暫時性故障放大成申請者的損失）
	exportJobVerify := func(userID uint) (bool, error) {
		user, err := userService.GetByID(userID)
		if err != nil {
			if errors.Is(err, identity.ErrUserNotFound) {
				return false, nil // 已刪除（含軟刪）＝失權
			}
			return false, err
		}
		if !user.Active {
			return false, nil
		}
		for i := range user.Roles {
			if authz.RoutePermissions(user.Roles[i].Name, authz.PermAuditView) {
				return true, nil
			}
		}
		return false, nil
	}
	// 離機上傳 worker。**未啟用時不建 goroutine**：
	// 啟動時無現行世代（設定表零列＝從未設定，或零現行世代＝已停用）即只記一行
	// 日誌，等管理員完成設定後由設定服務即時拉起（startOffsiteUploader）。
	//
	// env→DB 的初次 seed **不需要**另一條熱啟動路徑：它跑在解封後遷移佇列
	// （本步之前的 postUnsealMigrations），故 seed 建出的世代在此就讀得到。
	// 兩者的先後由服務清單的順序釘住。
	offsiteUploader := offsite.NewUploader(offsiteLedger, offsiteProfiles, auditFailureService,
		recordingOffsiteAdapter, exportOffsiteAdapter)
	offsiteWorkerCtx, stopOffsiteWorker := context.WithCancel(context.Background())
	offsiteEnabled, offsiteErr := offsiteLedger.HasCurrentGeneration()
	if offsiteErr != nil {
		// 讀不到現行世代**不得靜默當成未設定**（三態 fail-close）：
		// 那會讓一次 DB 故障看起來像「功能沒開」
		stopOffsiteWorker()
		return fail("offsiteUploader", offsiteErr)
	}
	// 設定世代總列數：零＝從未設定（全部離機序列缺席、不排背景刷新源），
	// 非零而 offsiteEnabled 為 false＝停用態（存量與失敗面照常曝光）。
	// **同樣不得把讀取失敗當成零**——那會讓一次 DB 故障靜默抹掉整組指標
	offsiteGenerations, offsiteGenErr := offsiteProfiles.GenerationCount()
	if offsiteGenErr != nil {
		stopOffsiteWorker()
		return fail("offsiteUploader", offsiteGenErr)
	}
	// 上傳車道的四項由 worker 直寫。`*observability.Metrics` 直接滿足
	// `offsite.UploadMetrics`（方法名對齊），故此處零 adapter
	offsiteUploader.SetMetrics(s1.metrics)
	// worker 的**唯一啟動點**，冪等：啟動時已有現行世代即由下方的啟動步呼叫，
	// 否則等管理員於管理介面完成首次設定時由設定服務呼叫。
	//
	// **once 而非「有沒有在跑」的旗標**：後者要嘛在兩個 goroutine 之間比對狀態
	// （競態下起兩條迴圈，同一件被兩邊各領一次），要嘛得再加一把鎖；
	// 而這裡真正要的語義就是「至多一次」。
	//
	// 停用（退役現行世代）不需要反向殺 worker：該世代的帳冊列在同一筆交易內
	// 轉為 foreign，取件查的是待上傳列，故 worker 只是空轉不領件。
	var offsiteUploaderOnce sync.Once
	startOffsiteUploader := func() {
		offsiteUploaderOnce.Do(func() {
			// 收束已開始：不再放出新的 goroutine，否則它會逃過本次資源收束
			if offsiteWorkerCtx.Err() != nil {
				return
			}
			go offsiteUploader.Run(offsiteWorkerCtx)
		})
	}
	// 熱啟動的接線：零現行世代啟動的服務，於管理介面完成設定後不必重啟即開始上傳。
	// **接線落在此處**（worker 建構之後、路由發佈之前）：更早接不到 worker，
	// 更晚則存在「設定已可寫入而 worker 拉不起來」的窗口
	offsiteProfiles.SetUploaderStarter(startOffsiteUploader)
	starts[7].start = func() error {
		if !offsiteEnabled {
			log.Printf("[OffsiteUploader] 目前無現行離機儲存設定世代，暫不啟動上傳 worker（完成設定後即時啟動）")
			return nil
		}
		startOffsiteUploader()
		return nil
	}
	starts[7].stop = stopOffsiteWorker

	auditExportJobWorker := audit.NewAuditExportJobWorker(database.DB, auditExportService,
		exportJobVerify, auditService, audit.ResolveExportArtifactDir(""))
	// 產物落定與排入離機佇列同一筆交易
	auditExportJobWorker.SetOffsiteEnqueuer(offsiteLedger)
	starts[8].start, starts[8].stop = auditExportJobWorker.Start, auditExportJobWorker.Stop

	for _, s := range starts {
		if err := seal.CheckCancelStep(ctx, s.name); err != nil {
			return fail(s.name, err)
		}
		if err := s.start(); err != nil {
			return fail(s.name, err)
		}
		stop := s.stop
		g.bag.AddFunc(s.name, func(context.Context) error {
			stop()
			return nil
		})
		mark(s.name)
	}

	// 營運指標的段 2 註冊與背景刷新。
	//
	// **接替原 perfMonitor 的位置**（段 2 最後一步）：同為可停止的背景任務，
	// 形態一致使啟停順序的變動面最小。原任務連同其行程內延遲統計整組退場——
	// 它與新的 HTTP middleware 落在同一個全域位置，留著即每個請求統計兩次，
	// 而其「效能退化偵測」只 log.Printf（無人消費、容器重啟即失），
	// 正解是採集端對 histogram 設 alerting rule。
	if err := seal.CheckCancelStep(ctx, "metricsRefresher"); err != nil {
		return fail("metricsRefresher", err)
	}

	// 註冊段 2 才成立的指標。封印期未註冊者在曝光內容中缺席而非為 0——
	// 0 值會讓採集端把「服務不存在」讀成「服務正常且計數為零」
	s1.metrics.RegisterStage2()

	// 現讀資料源（取值成本 O(1)，不需背景刷新）
	s1.metrics.SetConnectionSource(func() float64 { return float64(registry.Count()) })
	s1.metrics.SetAuditQueueSource(func() float64 { return float64(auditService.QueueDepth()) })

	// 審計丟棄的觀測掛勾：語義映射留在此處，audit 模組不因監控而新增依賴
	auditService.SetDropObserver(func(fellBackToFile bool) {
		reason := observability.AuditDropReasonDiscarded
		if fellBackToFile {
			reason = observability.AuditDropReasonFallbackFile
		}
		s1.metrics.ObserveAuditDropped(reason)
	})

	// 離機指標的兩面各自依狀態註冊（停用態表）：
	//   設定表零列 → 兩面皆不註冊，全部離機序列缺席
	//   有歷史世代、零現行世代（停用態）→ 只註冊存量與失敗面
	//   有現行世代 → 兩面皆註冊
	// **未註冊即缺席而非為 0**：0 會讓採集端把「worker 不存在」讀成「一切正常且無事可做」
	if offsiteGenerations > 0 {
		s1.metrics.RegisterOffsiteInventory()
	}
	if offsiteEnabled {
		s1.metrics.RegisterOffsiteUploadLane()
	}

	stopRefresher := observability.StartRefresher(
		s1.metrics,
		newMetricsRefreshSources(database.DB, sessionService, recordingService,
			offsiteQueueSource(offsiteGenerations > 0, offsiteLedger, offsiteProfiles, offsiteFetcher)),
		observability.DefaultRefreshInterval)

	// 停止＝送信號＋等待進行中的刷新結束（見 observability.StopWaitBudget）。
	// 直接把收束 ctx 交給它：關機總預算是共用的，refresher 只該花掉自己那份。
	// 等不到就回錯讓 bag 聚合——「刷新仍在跑」是關機序後段（關 DB）需要知道的事實，
	// 不是可以靜默的細節
	g.bag.AddFunc("metricsRefresher", func(ctx context.Context) error {
		return stopRefresher(ctx)
	})
	mark("metricsRefresher")

	return g, nil
}

// newMetricsRefreshSources 組裝背景刷新的三個資料源。
//
// **DB 句柄在建構時捕獲，資料源執行當下不再裸讀全域 `database.DB`**：刷新跑在背景
// goroutine，其執行時刻與組裝根的生命週期無關（首次刷新甚至可能晚於呼叫端返回）。
// 全域句柄在關機（`database.Close`）與測試（替換／還原全域）時都會變動，執行當下
// 才讀等於把「那一刻全域剛好是什麼」寫進資料流——讀到 nil 就是 gorm 的解參考 panic，
// 而背景 goroutine 的 panic 會終止整個行程。此即 2026-08-16 那次 `cmd/server`
// 競態 FAIL 的根因。
//
// **為何不改成「全部走建構時的句柄」就了事**：`SessionService` 的查詢方法內部
// 仍現讀 `database.DB`（其呼叫端遍佈全庫，收口不在本次範圍）。故此處退一步做
// **前置可用性檢查**：驗自己捕獲的句柄非 nil、且全域仍指向同一個句柄，不成立即回
// error，走 `RefreshSources` 既有的「只記 log、不中止任務」契約。檢查與使用之間
// 仍有理論上的窗口（全域可在兩者之間被換掉），那一段殘餘由 `StartRefresher` 的
// panic 攔截兜底——分層而非單點，因為這裡沒有能一次收乾淨的辦法。
//
// **「全域仍指向同一句柄」這條對 PendingAlerts 而言偏嚴**（它已持有捕獲的句柄，
// 全域換掉也查得動），仍套用是因為三個資料源必須對「哪個 DB 是事實源」給出一致
// 答案；否則全域一換，指標盤就會由兩個不同的 DB 各拼一半，而那種數字比沒有數字
// 更難察覺。偏嚴的代價只是指標停在前一輪並留下 log，方向與既有失敗處置一致。
func newMetricsRefreshSources(
	metricsDB *gorm.DB,
	sessionService *session.SessionService,
	recordingService *session.RecordingService,
	offsiteQueue func() (observability.OffsiteQueueSnapshot, error),
) observability.RefreshSources {
	// 就地建構告警查詢服務：它只持有句柄、無狀態、無背景資源，與 handler 側那份
	// 互不影響；建構時做掉是為了讓句柄的來源固定在此刻，而非每輪刷新重新決定
	alertService := audit.NewCommandAlertService(metricsDB)

	dbUsable := func() error {
		if metricsDB == nil {
			return errors.New("指標刷新的 DB 句柄在組裝時即為空")
		}
		if database.DB != metricsDB {
			return errors.New("全域 DB 句柄已在指標刷新啟動後被替換或移除")
		}
		return nil
	}

	return observability.RefreshSources{
		ActiveSessions: func() (map[string]float64, error) {
			if err := dbUsable(); err != nil {
				return nil, err
			}
			sessions, err := sessionService.GetActiveSessions()
			if err != nil {
				return nil, err
			}
			byProtocol := make(map[string]float64, len(sessions))
			for _, sess := range sessions {
				byProtocol[string(sess.Protocol)]++
			}
			return byProtocol, nil
		},
		// 錄影儲存量走檔案系統遍歷、不碰 DB，故不做 dbUsable 檢查
		RecordingStorage: func() (float64, error) {
			stats, err := recordingService.GetRecordingStats()
			if err != nil {
				return 0, err
			}
			return float64(stats.TotalSize), nil
		},
		// 查詢走 audit 模組自己的方法，不在此直接碰 `command_alerts`——
		// 該表由 audit 擁有，組裝根直接查會撞跨模組資料存取 ratchet。
		PendingAlerts: func() (map[string]float64, error) {
			if err := dbUsable(); err != nil {
				return nil, err
			}
			counts, err := alertService.CountUnreviewedBySeverity()
			if err != nil {
				return nil, err
			}
			bySeverity := make(map[string]float64, len(counts))
			for severity, n := range counts {
				bySeverity[severity] = float64(n)
			}
			return bySeverity, nil
		},
		// nil＝設定表零列，`StartRefresher` 會整項跳過（連 DB 往返都不發生）
		OffsiteQueue: offsiteQueue,
	}
}

// offsiteQueueSource 離機帳冊切面的背景刷新源（「帳冊查詢」那一組）。
//
// `configured` 為 false（設定表零列）時回 nil——`RefreshSources` 對 nil 項整項跳過，
// 「未設定＝行為完全不變」因此連一次 `GROUP BY` 都不發生，而不只是「查了但不曝光」。
//
// **停用態仍回非 nil**：存量、失敗、完整性不符、歷史世代數與暫存佔用在停用後
// 照常曝光；缺席的是上傳車道，而那由「不註冊」承擔，不由「不查」承擔——
// 兩者混為一談的話，日後把註冊打開就會得到一組永遠不更新的序列。
func offsiteQueueSource(configured bool, ledger *offsite.Ledger,
	profiles *offsite.OffsiteProfileService, fetcher *offsite.Fetcher,
) func() (observability.OffsiteQueueSnapshot, error) {
	if !configured {
		return nil
	}
	return func() (observability.OffsiteQueueSnapshot, error) {
		rows, err := ledger.CountsDetailed()
		if err != nil {
			return observability.OffsiteQueueSnapshot{}, err
		}
		snap := observability.OffsiteQueueSnapshot{
			Pending:           map[observability.OffsiteKindOrigin]float64{},
			Uploading:         map[string]float64{},
			Failed:            map[string]float64{},
			IntegrityMismatch: map[string]float64{},
			Foreign:           map[string]float64{},
		}
		for _, r := range rows {
			switch r.State {
			case offsite.StatePending:
				snap.Pending[observability.OffsiteKindOrigin{Kind: r.Kind, Origin: r.Origin}] += float64(r.N)
			case offsite.StateUploading:
				snap.Uploading[r.Kind] += float64(r.N)
			case offsite.StateFailed:
				snap.Failed[r.Kind] += float64(r.N)
			case offsite.StateIntegrityMismatch:
				snap.IntegrityMismatch[r.Kind] += float64(r.N)
			case offsite.StateForeign:
				snap.Foreign[r.Kind] += float64(r.N)
			}
			// uploaded／local_purged 不成序列：前者是「已完成」（累計量由
			// uploads_total 承擔），後者是本機到期清除的終局，兩者都不是待處理積壓
		}
		ages, err := ledger.OldestPendingAges(time.Now())
		if err != nil {
			return observability.OffsiteQueueSnapshot{}, err
		}
		snap.OldestPendingAgeSeconds = ages
		n, err := profiles.GenerationCount()
		if err != nil {
			return observability.OffsiteQueueSnapshot{}, err
		}
		snap.Generations = float64(n)
		if fetcher != nil {
			snap.SpoolBytes = float64(fetcher.SpoolBytes())
		}
		// **憑證三態每輪重讀**：金鑰事故（解密失敗）是執行期才會發生的事，
		// 啟動當下讀一次寫死等於讓指標永遠停在「事故發生前」。
		// 讀取失敗**不吞成 unconfigured**——那正是三態 fail-close 明令禁止的併吞
		state, err := profiles.CredentialState(context.Background())
		if err != nil {
			return observability.OffsiteQueueSnapshot{}, err
		}
		snap.CredentialState = string(state)
		return snap, nil
	}
}

// logKEKSwitchAudit 補記 load 期間偵測並收尾的 KEK 切換。
// best-effort：序列化失敗僅 log、不阻塞啟動；僅實際退役 >0 時產生。
func logKEKSwitchAudit(keyManager *keyvault.KeyManagerService, auditService *audit.AuditLogService) {
	sw := keyManager.LastKEKSwitch()
	if sw == nil {
		return
	}
	// 逐把舊 KEK 各記一筆審計（多把同次退役不合併）
	for fromKEK, count := range sw.Retired {
		changes := []struct {
			Field string      `json:"field"`
			Old   interface{} `json:"old"`
			New   interface{} `json:"new"`
		}{
			{Field: "kek_fingerprint", Old: fromKEK, New: sw.ToKEKID},
			{Field: "retired_rows", Old: nil, New: count},
		}
		details, err := json.Marshal(map[string]interface{}{"changes": changes})
		if err != nil {
			log.Printf("[KeyManager] KEK 切換審計序列化失敗（不阻塞啟動）: %v", err)
			continue
		}
		auditService.Log(&audit.AuditLogEntry{
			UserID: 0, Username: "system",
			Action:   model.ActionUpdate,
			Resource: model.ResourceKeyManagement,
			Status:   model.StatusSuccess,
			Details:  string(details),
		})
	}
	log.Printf("[KeyManager] KEK 切換審計已補記：%d 把舊 KEK → %s（退役 %d 筆）",
		len(sw.Retired), sw.ToKEKID, sw.RetiredCount)
}

// instanceGuardAuditSink 把單實例守衛事件轉成 audit_logs 系統列。
//
// 三個事件各一列：overridden（ack 啟動）、lost（失鎖）、regained（取得或重取成功）。
// 系統主體（user_id 0／username system）、action=execute、resource=instance_guard；
// status：regained→success、lost／overridden→failure——反映的是「互斥是否成立」而非
// 「行程有沒有跑起來」，稽核者篩 failure 即撈到所有守衛失守的時刻（不用 denied：系統並未拒絕）。
//
// **走 AsyncSink 的 Submit 而非 Log**：段 1 緩衝的 overridden 事件要以**發生當下**入列
// （Log 的簽名表達不了事件時刻，見 audit_log_service.go 的 logAt）。AsyncSink 為
// at-most-once、失敗落 JSONL，不宣稱必達。
func instanceGuardAuditSink(auditService *audit.AuditLogService) func(database.GuardEvent) {
	return func(ev database.GuardEvent) {
		body, err := json.Marshal(instanceGuardEventDetails(ev))
		if err != nil {
			log.Printf("[InstanceGuard] 守衛事件 %s 序列化失敗（審計列未寫）: %v", ev.Event, err)
			return
		}
		status := model.StatusFailure
		if ev.Event == database.GuardEventRegained {
			status = model.StatusSuccess
		}
		if err := auditService.Submit(context.Background(), gatewayapi.AuditEvent{
			OccurredAt: ev.At,
			Actor:      gatewayapi.Actor{UserID: 0, Username: "system"},
			Action:     string(model.ActionExecute),
			Resource:   string(model.ResourceInstanceGuard),
			Status:     string(status),
			Details:    string(body),
		}); err != nil {
			log.Printf("[InstanceGuard] 守衛事件 %s 投遞審計失敗: %v", ev.Event, err)
		}
	}
}

// routeServices 是 buildRouteDeps 的輸入：段 2 建構完成的服務集合。
type routeServices struct {
	// metrics 段 1 建立、段 1／段 2 共用的指標實例
	metrics      *observability.Metrics
	authService  *identity.AuthService
	auditService *audit.AuditLogService
	// auditTxSink 交易內審計落地面：節點樹與使用者群組的刪除留痕與
	// 業務變更同交易，寫不進去即整筆回滾
	auditTxSink port.TxSink
	// auditDirectSink C-plain 兩點的直寫投遞面：不受 AuditLogEnabled 管制
	auditDirectSink      gatewayapi.AsyncSink
	authorizationService *authz.AssetAuthorizationService
	policyService        *policy.SecurityPolicyService
	transmissionPolicy   *policy.TransmissionPolicyService
	ldapDirectoryService *identity.LDAPDirectoryService
	// offsiteProfiles／offsiteLedger／offsiteDescribers 離機儲存管理端點的依賴
	// （設定服務、帳冊讀取面、失敗清單的擁有者描述面）
	offsiteProfiles   *offsite.OffsiteProfileService
	offsiteLedger     *offsite.Ledger
	offsiteDescribers []api.OffsiteOwnerDescriber
	// offsiteFetcher 證據包下載的離機退路（本機產物隨容器重建消失時）
	offsiteFetcher             *offsite.Fetcher
	userService                *identity.UserService
	assetService               *asset.AssetService
	sessionService             *session.SessionService
	reconciliationService      *session.SessionReconciliationService
	recordingService           *session.RecordingService
	dailyReviewService         *audit.DailyReviewService
	auditFailureService        *audit.AuditFailureService
	notificationChannelService *audit.NotificationChannelService
	oidcProviderService        *identity.OIDCProviderService
	oidcLoginService           *identity.OIDCLoginService
	exportSigning              *keyvault.ExportSigningService
	keyManager                 *keyvault.KeyManagerService
	hostKeyService             *asset.HostKeyService
	syslogForwarder            *audit.SyslogForwarder
	auditIntegrity             *audit.AuditIntegrityService
	checkpointVerifier         *audit.CheckpointVerifier // 檢查點驗證服務（第 8 組）
	// chainVerifyStatus 兩層自動驗證的營運狀態來源（與排程器同一實例）
	chainVerifyStatus       *audit.ChainVerifyService
	checkpointSigning       *keyvault.CheckpointSigningService
	alertNotifier           *audit.AlertNotifier
	accessPolicyService     *policy.AccessPolicyService
	dataTransferService     *policy.DataTransferService
	accessRequestService    *authz.AccessRequestService
	changeSecretPlanService *asset.ChangeSecretPlanService
	changeSecretRunner      *asset.ChangeSecretRunner
	changeSecretCandidates  *asset.ChangeSecretCandidateService
	changeSecretRetryRunner *asset.ChangeSecretRetryRunner
	changeSecretScheduler   *scheduler.ChangeSecretScheduler
	// auditExportService／auditExportJobs 段 2 建構（與打包 worker 共用實例），
	// buildRouteDeps 只組 handler
	auditExportService *audit.AuditExportService
	auditExportJobs    *audit.AuditExportJobService
	connHandler        *proxy.ConnectionHandler
	sshHandler         *sshproxy.Handler
	// sourceIPBaseline 與兩條建線路徑共用同一份（見 sshHandler.SourceIPBaseline
	// 的注入處）：登入點與建線點寫的是同一張基準表，服務分裂即判定分裂
	sourceIPBaseline *audit.SourceIPBaseline
	corsMiddleware   gin.HandlerFunc
}

// buildRouteDeps 建構全部 API handler 並組出 routeDeps。
//
// 純建構＋依賴注入，無 I/O 副作用：故不需取消檢查點。
func buildRouteDeps(cfg *config.Config, s routeServices) (routeDeps, error) {
	authHandler := api.NewAuthHandler(s.authService, s.auditService)
	authHandler.SetUserService(s.userService)

	// refresh 憑證的 httpOnly cookie：
	// 三個 handler 共用同一 writer，Secure 旗標於**發放時**自安全政策現讀——
	// 管理員在政策頁改了即生效，不需重啟
	refreshCookies := api.NewRefreshCookieWriter(s.policyService)
	authHandler.SetRefreshCookieWriter(refreshCookies)

	oidcHandler := api.NewOIDCHandler(s.oidcProviderService, s.oidcLoginService,
		cfg.OIDC.PublicBaseURL, s.auditService)
	oidcHandler.SetRefreshCookieWriter(refreshCookies)

	// 帳號新來源位址基準：本地認證流與 OIDC 流共用**同一份**（也與兩條建線路徑同一份）。
	// 各建各的不會壞掉，但「已見」判定會分裂成幾套接線狀態，症狀是某一條登入路徑
	// 的新位址從此永遠不算新——而那正是這個功能唯一要答的問題
	authHandler.SetSourceIPBaseline(s.sourceIPBaseline)
	oidcHandler.SetSourceIPBaseline(s.sourceIPBaseline)

	// 允許來源網段的現讀面（G1 強制點）：三個 handler 共用同一份服務。
	// **未注入即 fail-close**（判定點讀不到清單一律拒絕），故遺漏會在第一次登入
	// 就被看見，不會變成靜默放行——這與世代閘同一條紀律
	authHandler.SetSourcePolicyReader(s.authService)
	oidcHandler.SetSourcePolicyReader(s.authService)

	// 安全政策管理路由（admin；變更入審計，PCI 10.2.2）
	securityPolicyHandler := api.NewSecurityPolicyHandler(s.policyService, s.auditService)

	// syslog 轉發設定（10.3.3，admin 限定）
	syslogSettingHandler := api.NewSyslogSettingHandler(database.DB, s.syslogForwarder, s.auditService)
	syslogSettingHandler.SetTransmissionPolicy(s.transmissionPolicy) // 傳輸政策閘

	// audit_logs 完整性驗證（10.3.4；admin＋auditor）
	auditIntegrityHandler := api.NewAuditIntegrityHandler(database.DB, s.auditIntegrity)

	// 檢查點鏈查詢／驗證／公鑰（audit-checkpoint-chain，admin＋auditor 唯讀）
	auditCheckpointHandler := api.NewAuditCheckpointHandler(s.checkpointVerifier, s.checkpointSigning)
	// 自動驗證的營運狀態掛在既有結構層報告上揭露（不新增路由）：
	// 偵測控制若在畫面上看不見，稽核只能假設它沒在跑
	if s.chainVerifyStatus != nil {
		auditCheckpointHandler.SetAutoVerifyStatus(s.chainVerifyStatus)
	}

	// 註冊資產管理路由（注入授權服務）
	assetHandler := api.NewAssetHandler(s.assetService, s.authorizationService, s.auditDirectSink)
	assetHandler.SetDataTransfer(s.dataTransferService) // K8s 檔案進出的資料傳輸閘（4.3）

	// 資產帳號 CRUD
	assetAccountHandler := api.NewAssetAccountHandler(
		asset.NewAssetAccountService(s.assetService, s.keyManager, s.auditTxSink).WithAuthorization(s.authorizationService),
		s.authorizationService)

	sessionHandler := api.NewSessionHandler(s.sessionService)
	myConnectionHandler := api.NewMyConnectionHandler(session.NewMyConnectionService(s.sessionService))

	// 註冊指令審計路由（command-audit）：單會話指令流 + 跨會話搜尋
	sessionCommandService := audit.NewSessionCommandService(database.DB)
	sessionCommandHandler := api.NewSessionCommandHandler(sessionCommandService)

	alertRuleHandler := api.NewAlertRuleHandler(audit.NewAlertRuleService(database.DB))
	commandAlertHandler := api.NewCommandAlertHandler(audit.NewCommandAlertService(database.DB))
	commandAlertHandler.SetAuditService(s.auditService) // 審閱處置留痕（audit-workflows）

	dailyReviewHandler := api.NewDailyReviewHandler(s.dailyReviewService)
	auditFailureHandler := api.NewAuditFailureHandler(s.auditFailureService)

	// 通道加密清冊＋稽核匯出（admin-only）
	transmissionInventoryHandler := api.NewTransmissionInventoryHandler(
		policy.NewTransmissionInventoryService(database.DB, s.transmissionPolicy, s.notificationChannelService),
		s.auditService,
	)
	notificationChannelHandler := api.NewNotificationChannelHandler(s.notificationChannelService)

	// LDAP 目錄設定（admin-only singleton 資源）。
	// 服務層已於段 2 建構並注入 codec 與傳輸政策閘，handler 只是轉接層
	ldapDirectoryHandler := api.NewLDAPDirectoryHandler(s.ldapDirectoryService)
	offsiteStorageHandler := api.NewOffsiteStorageHandler(s.offsiteProfiles, s.offsiteLedger,
		s.offsiteDescribers...)
	// 單實例守衛全貌（admin 限定、唯讀）：探針讀包級單例快照
	instanceGuardHandler := api.NewInstanceGuardHandler(instanceGuardProbe)

	// 金鑰清冊與換鑰精靈（admin only）。
	// JWT 指紋於此算好注入（handler 不接觸 secret 材料）
	jwtFingerprint := crypto.Fingerprint([]byte(cfg.Security.JWTSecret))
	keyManagementHandler := api.NewKeyManagementHandler(database.DB, s.keyManager, s.policyService, jwtFingerprint, s.exportSigning)
	keyManagementHandler.SetAuditService(s.auditService) // 清理退役資料顯式留痕
	// 委託重包目標的 provider 建構器：組裝根是唯一知道本部署
	// KMS 組態的地方，故由此注入；未注入時委託分支回「尚未提供」而非靜默退化
	keyManagementHandler.SetDelegatedProviderFactory(buildDelegatedRewrapProvider)
	// 檢查點簽章鑰的清冊項（audit-checkpoint-chain 3.4）：公鑰指紋＋版本＋系統管理標示
	keyManagementHandler.SetCheckpointSigning(s.checkpointSigning)

	snippetHandler := api.NewSnippetHandler(session.NewSnippetService(database.DB))
	assetGroupHandler := api.NewAssetGroupHandler(asset.NewAssetGroupService(database.DB, s.auditTxSink, s.authorizationService), s.authorizationService, s.authorizationService)
	userGroupHandler := api.NewUserGroupHandler(identity.NewUserGroupService(database.DB, s.auditTxSink, s.authorizationService))

	userHandler := api.NewUserHandler(s.userService)
	userHandler.SetAuditService(s.auditService)
	userHandler.SetSourcePolicyReader(s.authService)

	roleHandler := api.NewRoleHandler(s.userService)
	authorizationHandler := api.NewAuthorizationHandler(s.authorizationService, authz.NewEffectiveAccessResolver(database.DB))
	// 審計服務為建構子必填：`/recordings/stream` 未套 AuthMiddleware，審計中介層
	// 因無身分而整筆跳過，取走錄影本體的留痕完全靠 handler 自寫（audit-resource-
	// classification-closure）。漏接＝取證無痕，故不留 setter 形態
	recordingHandler := api.NewRecordingHandler(s.recordingService, s.sessionService, s.auditService)
	// 錄影 token 的使用者級撤銷管道：token 不做
	// 世代比對，缺此接線時「已撤銷憑證者在 120 秒內仍能下載錄影」
	s.userService.SetRecordingTokenRevoker(recordingHandler.TokenManager())
	// 錄影 token 的 provider 級撤銷管道：
	// provider 停用／刪除時，經該 provider 認證者手上的錄影 token 同樣須即刻作廢
	s.oidcProviderService.SetRecordingTokenRevoker(recordingHandler.TokenManager())
	// 審計日誌查詢 handler：建構恆執行，實際是否註冊由 registerRoutes
	// 依 auditLogEnabled 旗標決定（關閉時整組 3 條 /audit-logs 不存在）
	auditLogHandler := api.NewAuditLogHandler(s.auditService)
	if cfg.Features.AuditLogEnabled {
		log.Println("審計日誌查詢 API 已註冊")
	}

	// 稽核證據匯出（audit-workflows，PCI 10.5.1）：服務已於段 2 建構
	// （與打包 worker 共用同一實例），此處只組 handler
	exportSigningHandler := api.NewExportSigningHandler(s.exportSigning)
	auditExportHandler := api.NewAuditExportHandler(s.auditExportService, s.auditExportJobs, s.auditService)
	// 證據包下載的離機退路：本機產物缺檔或大小與帳冊不符時，
	// 於下載窗口內自離機副本取回並驗過才交付
	auditExportHandler.SetOffsiteRetriever(s.offsiteFetcher)

	accessReviewHandler := api.NewAccessReviewHandler(authz.NewAccessReviewService(database.DB), s.auditService)
	hostKeyHandler := api.NewHostKeyHandler(s.hostKeyService, s.authorizationService)
	// 單筆剪貼簿內容調閱：解密＋逐筆留痕
	// （fail-close，留痕不成即不交付），審計失敗經告警鏈揭露
	clipboardContentService := session.NewClipboardContentService(
		database.DB, s.keyManager, s.auditTxSink, s.auditFailureService)
	clipboardHandler := api.NewClipboardEventHandler(s.sessionService, clipboardContentService)

	// 稽核調查工作台（auditor-workbench）：六來源聚合＋主體目錄，唯讀
	auditTimelineHandler := api.NewAuditTimelineHandler(audit.NewTimelineService(database.DB))
	changeSecretHandler := api.NewChangeSecretHandler(s.changeSecretPlanService, s.changeSecretRunner,
		s.changeSecretCandidates, s.changeSecretRetryRunner, s.changeSecretScheduler)

	accessRequestHandler := api.NewAccessRequestHandler(
		s.accessRequestService, authz.NewApproverScopeService(database.DB), database.DB)

	// 資產列表連線入口三態標註（伺服端單一事實源）
	// 三態標註歸 authz：改由 AccessRequestService 承載
	assetHandler.SetAccessStateAnnotator(s.accessRequestService)

	// SSH 資產檔案管理：資產收口 + 全操作審計
	sftpHandler := api.NewSFTPHandler(session.NewSFTPService(s.assetService, s.hostKeyService), s.authorizationService, s.auditService, s.authService)
	sftpHandler.SetAccessPolicy(s.accessPolicyService) // 檔案資料面同套存取政策閘
	sftpHandler.SetDataTransfer(s.dataTransferService) // 資料傳輸閘（data-transfer-control 4.1）

	return routeDeps{
		corsMiddleware:  s.corsMiddleware,
		auditLogEnabled: cfg.Features.AuditLogEnabled,

		authService:          s.authService,
		auditService:         s.auditService,
		authorizationService: s.authorizationService,

		auth:                  authHandler,
		securityPolicy:        securityPolicyHandler,
		syslogSetting:         syslogSettingHandler,
		auditIntegrity:        auditIntegrityHandler,
		auditCheckpoint:       auditCheckpointHandler,
		asset:                 assetHandler,
		assetAccount:          assetAccountHandler,
		session:               sessionHandler,
		myConnection:          myConnectionHandler,
		sessionCommand:        sessionCommandHandler,
		alertRule:             alertRuleHandler,
		commandAlert:          commandAlertHandler,
		dailyReview:           dailyReviewHandler,
		auditFailure:          auditFailureHandler,
		transmissionInventory: transmissionInventoryHandler,
		notificationChannel:   notificationChannelHandler,
		oidc:                  oidcHandler,
		ldapDirectory:         ldapDirectoryHandler,
		offsiteStorage:        offsiteStorageHandler,
		instanceGuard:         instanceGuardHandler,
		keyManagement:         keyManagementHandler,
		snippet:               snippetHandler,
		assetGroup:            assetGroupHandler,
		userGroup:             userGroupHandler,
		user:                  userHandler,
		role:                  roleHandler,
		authorization:         authorizationHandler,
		recording:             recordingHandler,
		metrics:               s.metrics,
		metricsToken:          cfg.Server.MetricsToken,
		auditLog:              auditLogHandler,
		exportSigning:         exportSigningHandler,
		auditExport:           auditExportHandler,
		accessReview:          accessReviewHandler,
		hostKey:               hostKeyHandler,
		clipboard:             clipboardHandler,
		auditTimeline:         auditTimelineHandler,
		changeSecret:          changeSecretHandler,
		accessRequest:         accessRequestHandler,
		sftp:                  sftpHandler,

		conn: s.connHandler,
		ssh:  s.sshHandler,
	}, nil
}
