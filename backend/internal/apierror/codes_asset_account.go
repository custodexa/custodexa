package apierror

// 資產帳號的出口碼。
//
// 本檔與 codes.go 同一 registry，分檔僅為並行開發隔離：收 internal/api 的
// asset_account_handler.go 一檔。命名沿用既有慣例：VALIDATION_*（請求欄位／
// 參數）、CONFLICT_*（唯一性）、NOTFOUND_*、RULE_ACCOUNT_*（可預期的帳號業務
// 規則攔截）、INTERNAL_*（5xx，成因僅落伺服端日誌）。
//
// 帳號錯誤一律不回填 username／資產名等自由字串：帳號名是請求方可控輸入，
// apierror 的 params 僅收受控 enum/int（見 ParamSpec），且回填會讓「帳號不存在」
// 的回應變成可枚舉帳號名的探測器。

// --- VALIDATION_*（請求欄位／參數）---
var (
	// 路徑參數 account id 解析失敗。不复用 VALIDATION_INVALID_ID：那支碼的
	// {resource} 是受控 enum（asset/user），新增 account 值會連帶要求前端 enum
	// 命名空間補鍵，成本高於獨立一碼（同 CodeInvalidNodeID 的既有裁決）
	CodeInvalidAccountID = register("VALIDATION_INVALID_ACCOUNT_ID", Descriptor{ZhFallback: "無效的帳號 ID"})

	// 帳號名稱含換行／冒號／控制字元。非美觀問題：username 會進 chpasswd 的
	// `user:password` stdin 條目，含這些字元者可拆出額外條目改到別的帳號
	CodeAccountUsernameInvalid = register("VALIDATION_ACCOUNT_USERNAME_INVALID", Descriptor{ZhFallback: "帳號名稱不得含換行、冒號或控制字元"})
	CodeAccountUsernameTooLong = register("VALIDATION_ACCOUNT_USERNAME_TOO_LONG", Descriptor{ZhFallback: "帳號名稱超過長度上限（100 字元）"})
	// 帳號名稱不得佔用授權範圍的別名命名空間（`@` 前綴）：真實帳號若能叫 @ALL，
	// 「只授權該帳號」會被解讀成「全部帳號」——命名巧合直接變成溢授
	CodeAccountUsernameReserved = register("VALIDATION_ACCOUNT_USERNAME_RESERVED", Descriptor{ZhFallback: "帳號名稱不得以 @ 開頭（保留給授權範圍別名，如 @ALL）"})
	CodeAccountNoteTooLong      = register("VALIDATION_ACCOUNT_NOTE_TOO_LONG", Descriptor{ZhFallback: "帳號備註超過長度上限（255 字元）"})
)

// --- CONFLICT_* / NOTFOUND_* ---
var (
	CodeAccountUsernameExists = register("CONFLICT_ACCOUNT_USERNAME", Descriptor{ZhFallback: "同一資產下已有同名帳號"})

	// 帳號不存在、已刪除，或不屬於路徑上的資產——三者共用一碼是刻意的：
	// 分開回應等於告訴請求方「這個 id 存在，只是不屬於你查的資產」
	CodeAssetAccountNotFound = register("NOTFOUND_ASSET_ACCOUNT", Descriptor{ZhFallback: "資產帳號不存在或不屬於該資產"})
	// 「從其他資產帳號複製」的來源帳號不存在
	CodeAssetAccountSourceNotFound = register("NOTFOUND_ASSET_ACCOUNT_SOURCE", Descriptor{ZhFallback: "複製來源帳號不存在"})
)

// --- RULE_ACCOUNT_*（帳號業務規則；service sentinel 一對一）---
var (
	// 「有帳號必有 default」：資產仍有其他帳號時不得刪掉預設帳號
	CodeAccountDefaultRequired = register("RULE_ACCOUNT_DEFAULT_REQUIRED", Descriptor{ZhFallback: "資產仍有其他帳號時不可刪除預設帳號，請先指定新的預設帳號"})
	// 資產有帳號卻無預設（不變式破損）：不靜默挑一筆頂替，擋下要求人工修正
	CodeAccountDefaultMissing = register("RULE_ACCOUNT_DEFAULT_MISSING", Descriptor{ZhFallback: "資產帳號資料異常：有帳號但無預設帳號，請指定預設帳號後再試"})
	// 零帳號資產的連線／取憑證請求（連線入口 fail-close）：空憑證會退化成匿名或
	// 免密嘗試，受管連線的前提是有受管憑證
	CodeAccountNoneUsable = register("RULE_ACCOUNT_NONE_USABLE", Descriptor{ZhFallback: "資產未設定可用帳號憑證，請先新增帳號"})
	// 併發下 default partial unique index 衝突（與「同名帳號」分流，語義不同）
	CodeAccountDefaultConflict = register("CONFLICT_ACCOUNT_DEFAULT", Descriptor{ZhFallback: "預設帳號同時被其他操作變更，請重試"})
	// K8s 資產固定單一預設帳號：連線 token 帶非預設 account_id 時擋下，
	// 不靜默忽略——忽略會讓使用者以為連的是所選帳號，實際用的是別組憑證
	CodeAccountK8sDefaultOnly = register("RULE_ACCOUNT_K8S_DEFAULT_ONLY", Descriptor{ZhFallback: "K8s 資產固定使用預設帳號，不支援指定連線帳號"})
)

// --- RULE_ASSET_TEST_*（撥測結果碼，非 HTTP 錯誤；語義見 codes_asset.go 同段）---
var (
	// 零帳號資產的撥測：空密碼 ssh.Password("") 對允許空密碼的伺服器可能「測試成功」，
	// 給出資產可連的假象；直接判失敗並說明成因
	CodeAssetTestNoAccount = register("RULE_ASSET_TEST_NO_ACCOUNT", Descriptor{ZhFallback: "資產未設定可用帳號憑證，無法測試"})
)

// --- INTERNAL_*（5xx；成因僅落伺服端日誌）---
var (
	CodeInternalAssetAccountList       = register("INTERNAL_ASSET_ACCOUNT_LIST", Descriptor{ZhFallback: "查詢資產帳號失敗"})
	CodeInternalAssetAccountCreate     = register("INTERNAL_ASSET_ACCOUNT_CREATE", Descriptor{ZhFallback: "建立資產帳號失敗"})
	CodeInternalAssetAccountUpdate     = register("INTERNAL_ASSET_ACCOUNT_UPDATE", Descriptor{ZhFallback: "更新資產帳號失敗"})
	CodeInternalAssetAccountDelete     = register("INTERNAL_ASSET_ACCOUNT_DELETE", Descriptor{ZhFallback: "刪除資產帳號失敗"})
	CodeInternalAssetAccountSetDefault = register("INTERNAL_ASSET_ACCOUNT_SET_DEFAULT", Descriptor{ZhFallback: "設定預設帳號失敗"})
	// 連線 token 簽發點驗帳號客體綁定時的 DB 錯誤（非「不存在」——後者走
	// NOTFOUND_ASSET_ACCOUNT）：查不動就不簽發，不當作綁定成立
	CodeInternalAssetAccountResolve = register("INTERNAL_ASSET_ACCOUNT_RESOLVE", Descriptor{ZhFallback: "驗證資產帳號失敗"})
)
