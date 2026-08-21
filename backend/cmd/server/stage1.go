package main

import (
	"context"
	"github.com/custodexa/backend/internal/modules/identity"
	"log"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/k8sproxy"
	"github.com/custodexa/backend/internal/observability"
	"github.com/custodexa/backend/internal/sealjournal"
	"github.com/custodexa/backend/pkg/crypto"
)

// 段 1（最小圖）——kek-provider-modularization D6.1。
//
// 內容：config 判定、DB 連線／migration／seed、封印期 journal 寫入器、
// 封印閘 middleware、健康檢查與 /seal/* 路由、開監聽。
//
// **段 1 的失敗處置在三模式下相同**：一律 fail-close 且不開放監聽
// （沿用既有 log.Fatalf）。啟動期無人可回覆，續存無意義；
// 兩種失敗處置的分歧只出現在段 2（見 stage2.go 與 sealwire.go）。
//
// 段 1 **不讀 data_keys、不建構 KEK provider 之外的任何金鑰狀態**：
// B 模式的 KEK 材料要等解封 API 才進入記憶體，這正是兩段啟動存在的理由。

// stage1 為段 1 的產物，交棒給段 2 與封印狀態機。
type stage1 struct {
	cfg         *config.Config
	kekDecision *config.KEKDecision
	// kekProvider 僅 A（env）／C（kms／hsm）模式有值；B（ui）模式為 nil,
	// 由解封時提交的材料建構（sealwire.go）。
	kekProvider crypto.KEKProvider
	// corsMiddleware 已建構完成的全域 CORS middleware。
	// cors.New 會 Validate 並在設定非法時 panic，屬可終止行程的呼叫，
	// 故建構落在段 1 而非 registerRoutes 內。
	corsMiddleware gin.HandlerFunc
	// journal 封印期定長環狀留痕；僅 B 模式建立。
	// **建立失敗即不開放監聽**——未認證端點的嘗試不得零留痕（D6.5）。
	journal *sealjournal.Journal
	// metrics 營運指標（observability-lite）。**建於段 1** 有兩個理由：
	// 封印期就要能被採集（否則「封印中」與「當機」在監控上不可區分），
	// 且段 1 與段 2 必須共用同一實例——換 router 時另建一份會使 counter 歸零，
	// 而 counter 回退在採集端被讀成行程重啟。
	metrics *observability.Metrics
}

// sealedMode 是否為 B（ui）模式：段 2 延後至解封成功後執行。
func (s *stage1) sealedMode() bool { return s.kekDecision.Mode == config.KEKModeUI }

// validateTrustedProxies 以 gin 自身的解析器驗證可信代理清單。
//
// **刻意重用 gin 的驗證而非另寫一份 CIDR 檢查**：真正生效的是 gin 的解析結果，
// 自己寫的第二份規則一旦與它分歧，驗證就會通過而實際設定失敗——那正是本項
// 要消滅的「回報已設定、實際是預設」狀態。空清單為合法（代表不啟用）。
func validateTrustedProxies(proxies []string) error {
	if len(proxies) == 0 {
		return nil
	}
	return gin.New().SetTrustedProxies(proxies)
}

// runStage1 執行段 1 全部步驟。任一步失敗即 log.Fatalf（三模式一致）。
func runStage1() *stage1 {
	cfg := config.Load()

	// 部署層 OIDC 專用 issuer 宣告的指紋（3.10a）：於段 1 設定而非段 2——
	// 封印期 /health 即開放探測，若延到段 2 才填，B 模式下解封前的探測會回
	// 「空宣告」指紋，使監控在最需要比對副本設定的時間窗內讀到假一致
	oidcIssuerDeclarationDigest = identity.DedicatedIssuerDeclarationDigest(cfg.OIDC.DedicatedIssuers)

	// release 安全底線（audit-release-floor）：把安全紅線類 feature flag 強制回啟用。
	//
	// **落在功能開關狀態輸出之前**，且落在任何旗標消費之前：強制若晚於輸出，
	// 日誌會印出 env 的停用字面值而實際已強制啟用——顯示面與生效面不一致，
	// 正是本項要消滅的形態（無訊號的安全機制取消）。成員與判準見
	// config.releaseSecurityFloor。
	if forced := cfg.EnforceReleaseSecurityFloor(); len(forced) > 0 {
		log.Printf("release 模式安全底線：忽略 %v 的停用設定，強制啟用（安全紅線，不可由環境變數關閉）", forced)
	}

	// 輸出功能開關狀態（強制後的生效值）
	log.Println("=== 功能開關狀態 ===")
	log.Println("權限控制: 無條件啟用（無開關）")
	log.Printf("審計日誌: %v", cfg.Features.AuditLogEnabled)
	log.Printf("  ├─ 異步寫入: %v", cfg.Features.AsyncAuditEnabled)
	log.Printf("  └─ 文件備份: %v", cfg.Features.AuditFallbackToFile)
	log.Printf("異常偵測: %v", cfg.Features.AnomalyDetectionEnabled)
	log.Printf("告警系統: %v", cfg.Features.AlertingEnabled)
	log.Println("====================")

	// 設定 Gin 模式
	gin.SetMode(cfg.Server.Mode)

	// 解封端點的速率參數（D6.4）：**純組態段，先於任何 I/O 驗證**。
	// 這些旋鈕唯一的作用是限制未認證端點的嘗試速率，零／負值／max < base／溢位
	// 的寫法效果都是把保護關掉，故一律 fail-close 而非以預設值靜默頂替。
	if err := cfg.Seal.Validate(); err != nil {
		log.Fatalf("解封端點速率組態不合法（拒絕啟動）: %v", err)
	}
	// 可信代理清單同樣先驗：非法設定過去只記一行警告並保留 gin 預設的
	// 「信任全部代理」，同時仍向來源控管回報「已設定」——偽造的轉送標頭
	// 因此可同時繞過網段白名單與 per-source 退避。
	if err := validateTrustedProxies(cfg.Seal.TrustedProxies); err != nil {
		log.Fatalf("TRUSTED_PROXIES 設定無效（拒絕啟動）: %v", err)
	}
	// 資料庫驅動同屬純組態、無出廠預設值：缺值即拒絕啟動（理由與訊息見
	// config.ValidateDatabaseDriver）。**刻意驗在此段而非 InitDatabase 前一行**：
	// 本段 DB-independent，組態錯誤要在任何 I/O 與任何持久化之前擋下；留到連 DB
	// 才發現，錯誤還會被 gorm 的連線失敗訊息蓋掉一層
	if err := config.ValidateDatabaseDriver(cfg.Database.Driver); err != nil {
		log.Fatalf("資料庫驅動組態不合法（拒絕啟動）: %v", err)
	}

	// KEK 來源模式判定（kek-provider-modularization D2）：**純組態段，DB-independent**，
	// 一律在連 DB 之前完成——此段任一 fail-close 路徑不產生任何 DB 寫入。
	// 判定不經 config 的預設值注入（D2.0）：金鑰類鍵一律 os.LookupEnv 三值語義。
	kekDecision, err := config.DecideKEK(config.OSEnvLookup, config.HSMBuildEnabled)
	if err != nil {
		log.Fatalf("KEK 來源模式判定失敗（拒絕啟動）: %v", err)
	}
	log.Println(kekDecision.LogLine())

	// 生產部署基線自檢（PCI 2.2.2/7.2.x，auth-hardening D9）：release 模式 fail-close
	if cfg.IsReleaseMode() {
		// 出廠預設密鑰不得上線（2.2.2）：偵測到即 fatal，逼部署者換金鑰。
		// 模式感知（D3）：非 env 模式下「本地 KEK 鑰未設」是合法組態而非違規
		if violations := cfg.DefaultSecretViolations(kekDecision); len(violations) > 0 {
			log.Fatalf("拒絕以出廠預設密鑰啟動生產模式（PCI 2.2.2）：%v 仍為預設值，請設定環境變數後重啟",
				violations)
		}
		// 註：安全紅線類 feature flag 的 release 強制**已上移**至本函式開頭的
		// EnforceReleaseSecurityFloor（audit-release-floor）。原本內聯於此的
		// 權限旗標強制不再保留——同一件事兩份實作會分歧，且內聯版本晚於功能
		// 開關輸出、印的是被強制前的字面值。
	}

	// 無條件金鑰驗證與 DB-independent 金鑰材料建構（deployment-hardening D5 階段 1）：
	// 一律在連 DB 前完成，使任何金鑰設定錯誤在任何持久化（含 seed 初始 admin）之前即 fail-close，
	// 不留半初始化的 DB。DB-dependent 的金鑰表比對（InitKeyManager）仍留在 migration 之後。
	// JWT_SECRET 長度下限（key-inventory-transparency）：HS256 認證信任根，>=32 bytes（256-bit 下限，
	// 不足 fail-close；長度為降低常見弱值風險的務實下限、不保證熵，SHOULD 由 CSPRNG 生成）。
	if len(cfg.Security.JWTSecret) < 32 {
		log.Fatalf("JWT_SECRET 長度 %d bytes 低於下限 32 bytes：請設定 >=32 bytes 的隨機字串（建議 CSPRNG，如 openssl rand -base64 32）", len(cfg.Security.JWTSecret))
	}
	// 信封加密 KEK provider（kek-provider-modularization D4）：由判定結果建構，
	// DB-independent，前置於連 DB 前驗證。DEK/金鑰表比對於 migration 後由 InitKeyManager 執行。
	// **三職拆解（D3）**：後兩職（legacy 單鑰、服務建構期預設 Codec）已隨過渡機制
	// 拆除，`ENCRYPTION_KEY` 自此僅承擔 KEK 材料一職。
	//
	// **B（ui）模式在此回 nil 而非 error**（D6.1）：材料要等解封 API 才存在，
	// 段 1 建構不出 provider 是正常狀態，不是啟動失敗。
	//
	// **委託模式（C）於此即向 KMS／HSM 探測**（D11.1 裁決 1）：探測失敗
	// （不可達／無權限／金鑰不合用）即 fail-close，SHALL NOT 降級啟動。
	// 探測落在此處而非 DB 連線之後，是為維持「組態段 DB-independent」的立約。
	var kekProvider crypto.KEKProvider
	if kekDecision.Mode != config.KEKModeUI {
		kekProvider, err = buildKEKProvider(context.Background(), kekDecision)
		if err != nil {
			log.Fatalf("初始化 KEK provider 失敗: %v", err)
		}
	}
	// 初始化資料庫
	if err := database.InitDatabase(cfg); err != nil {
		log.Fatalf("資料庫初始化失敗: %v", err)
	}

	// 執行 migrations：schema baseline 建立全部表結構、索引、約束與內建告警規則種子。
	// **開機 AutoMigrate 已移除**（migration-baseline-compression D3）：schema 的唯一
	// 事實源是 baseline 的 DDL，model 與 baseline 的一致性改由 parity 守衛把關。
	if err := database.RunMigrations(); err != nil {
		log.Fatalf("資料庫 migrations 執行失敗: %v", err)
	}

	// DB-aware bootstrap 序（deployment-hardening D5）：schema 已就緒，先判定安裝狀態，
	// 再據以驗證初始密碼 / 跑 legacy 掃描。ADMIN_INITIAL_PASSWORD 為 DB 條件式（僅空 DB 需要），
	// 故不併入無條件的 DefaultSecretViolations（否則既有安裝未設即被誤擋）。
	userCount, err := database.CountUsers()
	if err != nil {
		log.Fatalf("查詢使用者數失敗（bootstrap 判定）: %v", err)
	}
	adminInitialPassword := ""
	if userCount == 0 {
		// 全新安裝（D5 階段 4）：seed 前驗證 ADMIN_INITIAL_PASSWORD 的 byte 契約（D8）——
		// 任何會 seed 的模式皆要求合格值，不因 dev/release 而放寬（D9）
		if v := config.ValidateAdminInitialPassword(cfg.Security.AdminInitialPassword); v != "" {
			log.Fatalf("拒絕以不合格 ADMIN_INITIAL_PASSWORD 建立初始管理員（%s）：請於 .env 設定合格高熵密碼（>=%d bytes、非預設/placeholder、無空白換行）後重啟",
				v, config.AdminInitialPasswordMinLength)
		}
		adminInitialPassword = cfg.Security.AdminInitialPassword
	} else if config.ValidateAdminInitialPassword(cfg.Security.AdminInitialPassword) == "" {
		// 既有安裝（D5 階段 5）：初始密碼已退役（D7）。仍留有效格式值 → 告警提醒移除/輪替，不 fail-close
		log.Println("偵測到 ADMIN_INITIAL_PASSWORD 仍設於環境但資料庫已初始化：初始密碼已退役，請自 .env 移除或輪替以避免 stale credential（重建空 DB 時務必換新值）")
	}

	// 初始化資料（角色恆冪等；初始管理員僅空 DB 時以驗證過的密碼建立）。
	//
	// **這一步是初始化解封「要求憑證不會重蹈 MFA 死鎖」論證的第一個前提**（D6.3）：
	// seed 落在段 1，故解封端點做憑證驗證時初始管理員必然已存在。
	if err := database.SeedDatabase(adminInitialPassword); err != nil {
		log.Fatalf("資料庫初始化資料失敗: %v", err)
	}

	// legacy 預設憑證掃描（deployment-hardening D6）：release serving 前掃所有具 admin 角色帳號，
	// 任一密碼仍為出廠預設 admin123 即 fail-close，要求離線 remediation（見 QUICKSTART）。
	// 不靠 username/排序/單一 admin 假設，涵蓋改名與多 admin；空 DB 剛以合格密碼建號故不會命中。
	if cfg.IsReleaseMode() {
		hits, err := database.ScanLegacyDefaultAdmins()
		if err != nil {
			log.Fatalf("legacy 預設憑證掃描失敗: %v", err)
		}
		if len(hits) > 0 {
			log.Fatalf("拒絕啟動（deployment-hardening）：偵測到 %d 個管理帳號仍使用出廠預設密碼，屬公開已知憑證，請依 QUICKSTART 離線 remediation 重設後重啟", len(hits))
		}
	}

	// 啟動期清掃殘留臨時 kubeconfig（k8s-exec D8：補後端崩潰/OOM/SIGKILL 未跑 Close 的路徑）
	if n := k8sproxy.SweepResidualKubeconfigs(); n > 0 {
		log.Printf("啟動清掃：移除 %d 個殘留 k8sproxy 臨時目錄", n)
	}

	// CORS（7.3/D9）：於此計算設定並**建構 middleware**——cors.New 會 Validate 並在
	// 設定非法時 panic，屬可終止行程的呼叫，不得留在 registerRoutes 內。
	corsMiddleware := cors.New(buildCORSConfig(cfg.Server.CORSAllowedOrigins, cfg.IsReleaseMode()))
	switch {
	case len(cfg.Server.CORSAllowedOrigins) > 0:
		log.Printf("CORS allowlist：%v", cfg.Server.CORSAllowedOrigins)
	case cfg.IsReleaseMode():
		log.Println("CORS：release 模式未設 CORS_ALLOWED_ORIGINS，僅允許同源")
	}
	if cfg.Features.AuditLogEnabled {
		log.Println("審計日誌中間件已啟用")
	}

	s := &stage1{
		cfg:            cfg,
		kekDecision:    kekDecision,
		kekProvider:    kekProvider,
		corsMiddleware: corsMiddleware,
		metrics:        observability.New(),
	}

	// 封印期留痕（D6.5）：僅 B 模式需要——A／C 模式恆 unsealed，不存在封印期。
	// **建立失敗即不開放監聽**：不受任何 feature flag 控制、不可關閉。
	if s.sealedMode() {
		j, err := sealjournal.Open(sealjournal.ResolveDir())
		if err != nil {
			log.Fatalf("封印期 journal 建立/開啟失敗（拒絕開放監聽，未認證端點的嘗試不得零留痕）: %v", err)
		}
		s.journal = j
		unknown, missing, corrupt := j.OpenRecovery()
		if len(unknown) > 0 || len(missing) > 0 || corrupt > 0 {
			log.Printf("[SealJournal] 啟動恢復：結果未知 %d 筆、序號缺口 %d 段、CRC 損毀槽 %d 個（將於解封後據實入審計）",
				len(unknown), len(missing), corrupt)
		}
	}

	return s
}
