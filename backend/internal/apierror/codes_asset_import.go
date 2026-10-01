package apierror

// 資產批次新增（線上多筆＋CSV 匯入）與單筆建立補映射的出口碼。
//
// 分三層：
//   - 檔案層（400，整份拒收）：編碼、大小、列數、空檔、CSV 格式、表頭、秘密欄；
//   - 請求層：有列未過檢查（400，Meta.rows 附逐列報告）、交易內重驗失敗（409，已整筆回滾）；
//   - 列層：出現在預檢回應的 rows[].errors[].code，前端以同一組 apiError 鍵翻譯。
//
// 列層碼不經 Write 輸出，但仍以 ParamSpec 宣告參數，使三語模板的佔位與後端一致
// （完整性守衛逐碼比對）。自由字串（欄名、節點路徑）一律 ParamOpaque：淨化後原樣帶出。

// --- 檔案層與請求層 ---
var (
	CodeAssetImportEncoding    = register("VALIDATION_ASSET_IMPORT_ENCODING", Descriptor{ZhFallback: "檔案不是 UTF-8 編碼，請以「CSV UTF-8（逗號分隔）」格式另存後重新上傳"})
	CodeAssetImportTooLarge    = register("VALIDATION_ASSET_IMPORT_TOO_LARGE", Descriptor{ZhFallback: "匯入內容超過 1 MB 上限"})
	CodeAssetImportTooManyRows = register("VALIDATION_ASSET_IMPORT_TOO_MANY_ROWS", Descriptor{
		ZhFallback: "匯入資料超過 {max} 列上限",
		Params:     []ParamSpec{{Key: "max", Kind: ParamInt}},
	})
	CodeAssetImportEmpty        = register("VALIDATION_ASSET_IMPORT_EMPTY", Descriptor{ZhFallback: "沒有可匯入的資料列"})
	CodeAssetImportCSVMalformed = register("VALIDATION_ASSET_IMPORT_CSV_MALFORMED", Descriptor{
		ZhFallback: "CSV 格式錯誤（第 {line} 列附近），請檢查引號是否成對",
		Params:     []ParamSpec{{Key: "line", Kind: ParamInt}},
	})
	// 表頭的三種問題（未知欄、重複欄、缺必填欄）共用一碼；哪一種由 Meta.reason
	// （unknown／duplicate／missing）帶出，供前端選擇說明
	CodeAssetImportHeader = register("VALIDATION_ASSET_IMPORT_HEADER", Descriptor{
		ZhFallback: "表頭欄位「{column}」無法使用（無法辨識、重複或缺少必填欄），請依範本修正表頭",
		Params:     []ParamSpec{{Key: "column", Kind: ParamOpaque}},
	})
	CodeAssetImportSecretField = register("VALIDATION_ASSET_IMPORT_SECRET_FIELD", Descriptor{
		ZhFallback: "匯入資料不可包含密碼、私鑰或帳號名欄位（「{column}」），請刪除該欄後重新送出",
		Params:     []ParamSpec{{Key: "column", Kind: ParamOpaque}},
	})
	CodeAssetImportRowsInvalid  = register("VALIDATION_ASSET_IMPORT_ROWS_INVALID", Descriptor{ZhFallback: "有資料列未通過檢查，未建立任何資產"})
	CodeAssetImportStateChanged = register("CONFLICT_ASSET_IMPORT_STATE_CHANGED", Descriptor{ZhFallback: "檢查後資料已被變更，本次未建立任何資產，請重新檢查"})
)

// --- 列層 ---
var (
	CodeAssetImportFieldRequired = register("VALIDATION_ASSET_IMPORT_FIELD_REQUIRED", Descriptor{ZhFallback: "此欄為必填"})
	CodeAssetImportFieldTooLong  = register("VALIDATION_ASSET_IMPORT_FIELD_TOO_LONG", Descriptor{
		ZhFallback: "長度超過上限（至多 {max} 字元）",
		Params:     []ParamSpec{{Key: "max", Kind: ParamInt}},
	})
	CodeAssetImportPort          = register("VALIDATION_ASSET_IMPORT_PORT", Descriptor{ZhFallback: "埠須為 1 至 65535 的整數"})
	CodeAssetImportFieldFormat   = register("VALIDATION_ASSET_IMPORT_FIELD_FORMAT", Descriptor{ZhFallback: "格式不正確（不可含控制字元；憑證編號須為正整數）"})
	CodeAssetImportNotApplicable = register("VALIDATION_ASSET_IMPORT_FIELD_NOT_APPLICABLE", Descriptor{ZhFallback: "此欄不適用於該協定，請留空"})
	CodeAssetImportNameInBatch   = register("CONFLICT_ASSET_IMPORT_NAME_IN_BATCH", Descriptor{
		ZhFallback: "與第 {other_line} 列名稱重複",
		Params:     []ParamSpec{{Key: "other_line", Kind: ParamInt}},
	})
	CodeAssetImportNodePath = register("NOTFOUND_ASSET_IMPORT_NODE_PATH", Descriptor{
		ZhFallback: "找不到唯一對應的節點路徑「{path}」",
		Params:     []ParamSpec{{Key: "path", Kind: ParamOpaque}},
	})
)

// --- 單筆建立補映射（列層同用）：原本這些 sentinel 落到 INTERNAL_ASSET_CREATE（500）---
var (
	CodeAssetUsernameRequired     = register("VALIDATION_ASSET_USERNAME_REQUIRED", Descriptor{ZhFallback: "此協定需要使用者名稱"})
	CodeAssetK8sNamespaceRequired = register("VALIDATION_ASSET_K8S_NAMESPACE_REQUIRED", Descriptor{ZhFallback: "K8s 資產需要 namespace"})
	CodeAssetSftpUsernameRequired = register("VALIDATION_ASSET_SFTP_USERNAME_REQUIRED", Descriptor{ZhFallback: "啟用 SFTP 檔案傳輸需要目標主機的 SSH 使用者名稱"})
)
