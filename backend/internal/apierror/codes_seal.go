package apierror

// B 模式封印狀態機的出口碼。
//
// 與 codes.go 同一 registry，分檔僅為 domain 隔離。**碼值逐字等於
// internal/seal 的 Code* 常數**——狀態機只生成機器碼、不生成文字，接線層
// 若另造一套碼，同一失敗就會有兩個名字，稽核與監控無從對照。故此處以
// `SEAL_*` 命名空間登記，字串與 seal 套件常數一一對應（由
// internal/api/seal_codes_test.go 的 TestSealCodesMapToRegisteredAPIErrors
// 對照守衛把關）。三語 apiError.* 由 TestCodeTranslationsComplete 的雙射守衛
// 把關，zh-TW 逐字＝此處 ZhFallback。
//
// **失敗回應內容不可區分**：格式錯、材料錯、paste-back 不符、初始管理員
// 憑證錯，全部收斂為單一 CodeSealMaterialInvalid，回應體不得攜帶可區分成因的
// 欄位。timing 差異不在承諾範圍內。
var (
	// CodeSealServiceSealed 封印閘：白名單外的路由於封印期一律 503＋本碼。
	// 不是 500、不是 401——狀態必須可被外部監控正確辨識。
	//
	// **文案明寫路徑 `/unseal`**：原文案只說
	// 「請先於解封頁提交金鑰材料」而沒說那一頁在哪，全新安裝的管理員登入後就卡在
	// 這裡。介面已有導覽守衛會把人接過去，本文案是守衛失效時（停用 JS、以 API
	// 直接互動、非瀏覽器用戶端）的最後一道線索。
	CodeSealServiceSealed = register("SEAL_SERVICE_SEALED",
		Descriptor{ZhFallback: "系統尚未解封，服務未上線。請至解封頁 /unseal 輸入主金鑰。"})

	// CodeSealUnsealInProgress 已有持有者在飛（遷移表格 3）。對外 409。
	CodeSealUnsealInProgress = register("SEAL_UNSEAL_IN_PROGRESS",
		Descriptor{ZhFallback: "已有解封作業進行中，請稍候再試"})

	// CodeSealCleanupPending 前代持有者尚待收束（格 3）。對外 409，專屬機器碼，
	// 使呼叫端明確知道在等什麼，而非籠統的「進行中」。
	CodeSealCleanupPending = register("SEAL_CLEANUP_PENDING",
		Descriptor{ZhFallback: "前一次解封的資源還沒釋放，請稍候再試。一直沒恢復就重啟服務。"})

	// CodeSealAlreadyUnsealed 已解封（格 3），且不重跑任何初始化。對外 409。
	CodeSealAlreadyUnsealed = register("SEAL_ALREADY_UNSEALED",
		Descriptor{ZhFallback: "系統已解封，無需再次解封"})

	// CodeSealCooldownActive 全域冷卻期內抵達。不驗證、不進 CAS、
	// 不計入失敗計數、不刷新到期時間；冷卻到期時間由 /seal/status 暴露。
	CodeSealCooldownActive = register("SEAL_COOLDOWN_ACTIVE",
		Descriptor{ZhFallback: "解封嘗試太頻繁，已進入冷卻。時間到會自動恢復，不用重啟服務。"})

	// CodeSealBackoffActive per-source 退避期內抵達。
	CodeSealBackoffActive = register("SEAL_BACKOFF_ACTIVE",
		Descriptor{ZhFallback: "這個來源的解封嘗試太密集，請稍候再試。"})

	// CodeSealMaterialInvalid 材料驗證失敗（格 4）。對外 400，計入退避。
	// **唯一的材料類失敗碼**：格式／解包／paste-back／初始管理員憑證皆共用本碼。
	CodeSealMaterialInvalid = register("SEAL_MATERIAL_INVALID",
		Descriptor{ZhFallback: "解封失敗，送出的內容沒有通過驗證。"})

	// CodeSealAborted 解封嘗試被主動中止（格 3b／4b）：請求取消、panic 或
	// PREPARE 寫入逾時。不計入材料失敗計數。
	CodeSealAborted = register("SEAL_ABORTED",
		Descriptor{ZhFallback: "解封中斷了，沒有做任何驗證。可以直接再試一次。"})

	// CodeSealJournalIOFailure 封印期 journal I/O 故障：fail-close 拒收新嘗試，
	// 運維修復後自動恢復（狀態經 /seal/status 標示）。
	CodeSealJournalIOFailure = register("SEAL_JOURNAL_IO_FAILURE",
		Descriptor{ZhFallback: "無法寫入稽核紀錄，已暫停受理解封。請檢查稽核目錄的磁碟空間與寫入權限。"})

	// CodeSealInitFailed 段 2 初始化失敗（格 6，逾時以外的一切失敗）。
	// 行程續存、狀態轉 sealed-faulted、可重試——SHALL NOT log.Fatalf。
	CodeSealInitFailed = register("SEAL_INIT_FAILED",
		Descriptor{ZhFallback: "金鑰是對的，但服務初始化失敗，系統維持封印。請看伺服器日誌，再重試解封。"})

	// CodeSealStage2Timeout 段 2 逾時（格 7）。不計入材料失敗計數。
	// 初始化路徑逾時的重試指引由 /seal/status 另行暴露。
	CodeSealStage2Timeout = register("SEAL_STAGE2_TIMEOUT",
		Descriptor{ZhFallback: "服務初始化逾時。若這是初次初始化，請用第一次輸入的那把金鑰重試。千萬不要改用新的金鑰。"})

	// CodeSealPublishUnconfirmed 段 2 完成但服務從未發佈（格 5b）。不鎖死，
	// 重試產生新世代。
	CodeSealPublishUnconfirmed = register("SEAL_PUBLISH_UNCONFIRMED",
		Descriptor{ZhFallback: "服務初始化完成，但發佈未確認，系統維持封印。請重試解封。"})

	// CodeSealSourceNotAllowed 來源不在解封端點允許的網段內（網段繫結組態）。
	CodeSealSourceNotAllowed = register("SEAL_SOURCE_NOT_ALLOWED",
		Descriptor{ZhFallback: "此來源不在解封端點允許的網段內"})

	// CodeSealStatusUnavailable 狀態彙整失敗（fail-close，不以預設值頂替未知狀態）。
	CodeSealStatusUnavailable = register("SEAL_STATUS_UNAVAILABLE",
		Descriptor{ZhFallback: "讀取封印狀態失敗"})
)
