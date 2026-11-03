package apierror

// 主機帳號盤點的出口碼。與 codes.go 同一 registry，分檔僅為 domain 隔離；
// 三語 apiError.* 由 TestCodeTranslationsComplete 的雙射守衛把關，zh-TW 逐字等於此處 ZhFallback。
// 每個業務碼與 asset 服務的一個 sentinel 一對一，handler 不合併、不改寫；
// 未預期錯誤依讀取或寫入分成兩個內部碼。
var (
	// CodeInventoryPlatformUnsupported 目標不是可盤點的平台（目前只支援以 SSH 連線的 POSIX 主機）。
	CodeInventoryPlatformUnsupported = register("RULE_INVENTORY_PLATFORM_UNSUPPORTED",
		Descriptor{ZhFallback: "這台資產的平台不支援帳號盤點，目前只支援以 SSH 連線的 Linux／Unix 主機"})

	// CodeInventoryNoAccount 資產沒有可用的預設帳號。
	CodeInventoryNoAccount = register("RULE_INVENTORY_NO_ACCOUNT",
		Descriptor{ZhFallback: "這台資產沒有預設帳號，無法登入進行帳號盤點"})

	// CodeInventoryNoSecret 預設帳號沒有生效的密碼或私鑰。
	CodeInventoryNoSecret = register("RULE_INVENTORY_NO_SECRET",
		Descriptor{ZhFallback: "預設帳號沒有可用的密碼或私鑰，無法登入進行帳號盤點"})

	// CodeInventoryScanRunning 同一資產已有盤點在進行。
	CodeInventoryScanRunning = register("CONFLICT_INVENTORY_SCAN_RUNNING",
		Descriptor{ZhFallback: "這台資產已有一次帳號盤點正在進行"})

	// CodeInventoryIgnoreReason 忽略理由缺漏或超出長度。
	CodeInventoryIgnoreReason = register("VALIDATION_INVENTORY_IGNORE_REASON",
		Descriptor{ZhFallback: "忽略理由必填，且不得過長"})

	// CodeInvalidFindingID 路徑上的盤點結果識別碼不是正整數。
	CodeInvalidFindingID = register("VALIDATION_INVALID_FINDING_ID",
		Descriptor{ZhFallback: "無效的盤點結果 ID"})

	// CodeInventoryFindingNotFound 盤點結果不存在，或不屬於路徑上的資產（兩者同形）。
	CodeInventoryFindingNotFound = register("NOTFOUND_INVENTORY_FINDING",
		Descriptor{ZhFallback: "盤點結果不存在"})

	// CodeInternalInventoryQuery 讀取盤點（單資產或全域清單）時發生未預期錯誤。
	CodeInternalInventoryQuery = register("INTERNAL_INVENTORY_QUERY",
		Descriptor{ZhFallback: "查詢帳號盤點失敗"})

	// CodeInternalInventoryUpdate 發起盤點、忽略或重新開啟結果時發生未預期錯誤。
	CodeInternalInventoryUpdate = register("INTERNAL_INVENTORY_UPDATE",
		Descriptor{ZhFallback: "帳號盤點操作失敗"})

	// CodeInventoryExecutorUnavailable 專用帳號沒有可用的秘密，盤點沒有開始。
	CodeInventoryExecutorUnavailable = register("RULE_INVENTORY_EXECUTOR_UNAVAILABLE",
		Descriptor{ZhFallback: "這台的堡壘機專用帳號目前沒有可用的秘密，沒有開始盤點。請重新設定專用帳號。"})

	// CodeInventoryExecutorBusy 專用帳號正在改密，盤點沒有開始。
	CodeInventoryExecutorBusy = register("CONFLICT_INVENTORY_EXECUTOR_BUSY",
		Descriptor{ZhFallback: "這台的堡壘機專用帳號正在改密，沒有開始盤點。改密完成後再試。"})

	// CodeInventoryExecutorRateLimited 以專用帳號登入太頻繁，盤點沒有開始。回應不帶等待秒數或上限數值。
	CodeInventoryExecutorRateLimited = register("RULE_INVENTORY_EXECUTOR_RATE_LIMITED",
		Descriptor{ZhFallback: "最近以這台的堡壘機專用帳號登入太頻繁（含測試登入），沒有開始盤點。請稍後再試。"})
)
