package apierror

// 資產／資產節點樹／標籤治理的出口碼。
//
// 本檔與 codes.go 同一 registry，分檔僅為並行開發隔離：收 internal/api 的
// asset_handler.go、asset_group_handler.go 兩檔，以及 asset.ConnectionTestResult
// 的碼化——後者不是 HTTP 錯誤封套，而是 200 回應內的結果欄，
// `code` 供前端查譯、`message` 暫留同一 ZhFallback 當過渡 fallback。
//
// 命名沿用既有慣例：VALIDATION_*（請求欄位／參數）、AUTH_*（角色閘）、
// CONFLICT_*（唯一性）、NOTFOUND_*、RULE_*（可預期的業務規則攔截）、
// INTERNAL_<RESOURCE>_<VERB>（5xx，成因僅落伺服端日誌）。
// ZhFallback 對既有中文一律逐字保留（遷移只換形狀不改語意）。

// --- VALIDATION_*（請求欄位／參數）---
var (
	// 節點樹端點的路徑／查詢參數 ID 解析失敗。不复用 VALIDATION_INVALID_ID：
	// 那支碼的 {resource} 是受控 enum（asset/user），新增 node 值會連帶要求
	// 前端 resource enum 命名空間補鍵，成本高於獨立一碼。
	CodeInvalidNodeID = register("VALIDATION_INVALID_NODE_ID", Descriptor{ZhFallback: "無效的節點 ID"})

	// 標籤格式／數量驗證（service.ErrTag* sentinel 一對一）
	CodeTagEmpty         = register("VALIDATION_TAG_EMPTY", Descriptor{ZhFallback: "標籤不得為空"})
	CodeTagContainsComma = register("VALIDATION_TAG_CONTAINS_COMMA", Descriptor{ZhFallback: "標籤不得含逗號"})
	CodeTagTooLong       = register("VALIDATION_TAG_TOO_LONG", Descriptor{ZhFallback: "標籤長度超過上限（單項至多 64 字元）"})
	CodeTooManyTags      = register("VALIDATION_TAG_TOO_MANY", Descriptor{ZhFallback: "標籤數量超過上限（至多 20 項）"})
	CodeTagsTotalTooLong = register("VALIDATION_TAGS_TOTAL_TOO_LONG", Descriptor{ZhFallback: "標籤總長度超過上限（合計至多 500 字元）"})

	// 資產欄位列舉驗證（service.ErrInvalid* sentinel 一對一）
	CodeInvalidProtocol     = register("VALIDATION_ASSET_PROTOCOL", Descriptor{ZhFallback: "無效的協議，僅支援 ssh, rdp, vnc, mysql, postgres, redis, mssql, k8s"})
	CodeInvalidRDPSecurity  = register("VALIDATION_ASSET_RDP_SECURITY", Descriptor{ZhFallback: "rdp_security 僅允許空值（沿現狀）、nla 或 tls"})
	CodeInvalidDBTLSMode    = register("VALIDATION_ASSET_DB_TLS_MODE", Descriptor{ZhFallback: "db_tls_mode 僅允許空值（沿現狀）、disable、require、verify-ca 或 verify-full"})
	CodeInvalidAccessPolicy = register("VALIDATION_ASSET_ACCESS_POLICY", Descriptor{ZhFallback: "access_policy 僅允許空值（跟隨全域預設）、open、reason 或 approval"})
	// 允許資料庫清單的格式與適用協議。五種違規（協議不符、逾長、空項、
	// 含控制字元、重複、超過項數上限）共用一碼：它們都是「這份清單不合格式」，
	// 逐項分碼會讓前端多五個鍵而使用者拿到的指引沒有更精確
	CodeInvalidAllowedDatabases = register("VALIDATION_ASSET_ALLOWED_DATABASES", Descriptor{ZhFallback: "allowed_databases 僅資料庫協議（mysql、postgres、mssql）可為非空；每項須為 1 至 128 字元、不含控制字元且不重複，至多 64 項"})

	// 改密通道側車（windows-account-rotation）。兩碼分開：通道值本身不合
	// （值域外、與協定不相容）是選錯了通道，附屬欄位不合是同一個通道沒設完整——
	// 前者要改選單，後者要補欄位，指引不同
	CodeInvalidRotationChannel = register("VALIDATION_ASSET_ROTATION_CHANNEL", Descriptor{ZhFallback: "rotation_channel 僅允許空值（依協定推導）、posix_ssh、windows_winrm、windows_ssh 或 none；posix_ssh 限 ssh 協議，windows_winrm 與 windows_ssh 限 rdp 或 ssh 協議"})
	// 附屬欄位的五種違規共用一碼（連線方式缺、TLS 模式缺、CA 憑證無法解析、
	// http 之下設了 TLS 模式、埠逾值域）：它們都是「這組通道設定不完整或不合格式」
	CodeInvalidRotationChannelParams = register("VALIDATION_ASSET_ROTATION_CHANNEL_PARAMS", Descriptor{ZhFallback: "改密通道設定不完整或不合格式：windows_winrm 須指定連線方式（http／https），https 須指定憑證驗證模式（system／ca／insecure），ca 模式須提供可解析的 CA 憑證（PEM），埠須為 0（取預設）或 1 至 65535"})

	// MSSQL 資產主機欄：sqlcmd 的 -S host,port 以逗號分隔埠，
	// host 內含逗號會被解讀成埠。只擋 mssql，不動 SafeArg 的通用語義
	CodeMSSQLHostComma = register("VALIDATION_ASSET_MSSQL_HOST_COMMA", Descriptor{ZhFallback: "mssql 主機不得含逗號（與連線字串的埠分隔語義衝突）"})

	// 帳號認證類型。兩碼分開：值域錯是打錯字，
	// 而 domain 是「值合法但本版做不到」——後者靜默降級會讓管理員誤以為域認證已生效
	CodeAccountAuthMethod            = register("VALIDATION_ACCOUNT_AUTH_METHOD", Descriptor{ZhFallback: "auth_method 僅允許 sql 或 domain"})
	CodeAccountAuthMethodUnsupported = register("VALIDATION_ACCOUNT_AUTH_METHOD_UNSUPPORTED", Descriptor{ZhFallback: "本版尚未支援網域認證（Windows／Kerberos），請改用 SQL 認證"})

	// K8s 容器檔案進出的請求欄位
	CodeUploadFileMissing = register("VALIDATION_UPLOAD_FILE_MISSING", Descriptor{ZhFallback: "缺少上傳檔案"})
	CodeFilePathMissing   = register("VALIDATION_FILE_PATH_MISSING", Descriptor{ZhFallback: "缺少檔案路徑"})
	CodeK8sPathIsDir      = register("VALIDATION_K8S_PATH_IS_DIR", Descriptor{ZhFallback: "目標是目錄，請指定單一檔案"})
)

// --- AUTH_*（角色閘；狀態碼沿用遷移前，不因碼化改變）---
var (
	CodeTagFilterPrivilegedOnly = register("AUTH_TAG_FILTER_PRIVILEGED_ONLY", Descriptor{ZhFallback: "標籤篩選僅限管理角色"})
	CodeTagListPrivilegedOnly   = register("AUTH_TAG_LIST_PRIVILEGED_ONLY", Descriptor{ZhFallback: "僅管理角色可取得標籤清單"})
	CodeTagGovernanceAdminOnly  = register("AUTH_TAG_GOVERNANCE_ADMIN_ONLY", Descriptor{ZhFallback: "僅 admin 可執行標籤治理"})
)

// --- CONFLICT_* / NOTFOUND_* ---
var (
	CodeAssetNameExists     = register("CONFLICT_ASSET_NAME", Descriptor{ZhFallback: "資產名稱已存在"})
	CodeAssetNodeNameExists = register("CONFLICT_ASSET_NODE_NAME", Descriptor{ZhFallback: "同層已有同名節點"})

	CodeAssetNodeNotFound = register("NOTFOUND_ASSET_NODE", Descriptor{ZhFallback: "節點不存在"})
	// 下載端點的來源檔不存在。原文尾接使用者提供的 path，碼化後不再回填：
	// path 是請求方自帶的輸入，前端可自行組字（apierror 的 params 僅收受控
	// enum/int，自由字串無承載型別）。
	CodeK8sFileNotFound = register("NOTFOUND_K8S_FILE", Descriptor{ZhFallback: "容器內找不到該檔案"})
)

// --- RULE_*（節點樹結構規則；service.ErrNode* sentinel 一對一）---
var (
	CodeNodeDepthExceeded = register("RULE_NODE_DEPTH_EXCEEDED", Descriptor{ZhFallback: "節點深度超過上限（10 層）"})
	CodeNodeCycle         = register("RULE_NODE_CYCLE", Descriptor{ZhFallback: "不可搬移到自身或其子孫節點"})
	CodeNodeNotEmpty      = register("RULE_NODE_NOT_EMPTY", Descriptor{ZhFallback: "僅可刪除無子節點且無直掛資產的空節點"})
)

// --- RULE_ASSET_TEST_*（ConnectionTestResult.Message 碼化）---
//
// 撥測結果不是 HTTP 錯誤（端點回 200），但 message 同屬使用者可見文字，故一併
// 進 registry：service 只設 Code，message 取同一支碼的 ZhFallback。
// host key 變更與 SSH 認證失敗直接复用 RULE_SSH_*（codes.go）——同一事實、同一文案。
var (
	CodeAssetTestHostKeyUnavailable = register("RULE_ASSET_TEST_HOST_KEY_UNAVAILABLE", Descriptor{ZhFallback: "host key 驗證未配置"})
	// 協議中性：本碼自 DB／k8s 撥測上線後跨協議共用，
	// 原文案「SSH 連線失敗」會對 postgres／k8s 資產指錯協議。
	CodeAssetTestConnectionFailed  = register("RULE_ASSET_TEST_CONNECTION_FAILED", Descriptor{ZhFallback: "連線失敗，請確認目標主機與網路可達性"})
	CodeAssetTestConnectionRefused = register("RULE_ASSET_TEST_CONNECTION_REFUSED", Descriptor{ZhFallback: "連線被拒絕，請確認目標主機與連接埠"})
	CodeAssetTestAuthFailed        = register("RULE_ASSET_TEST_AUTH_FAILED", Descriptor{ZhFallback: "認證失敗，請確認資產憑證"})
	CodeAssetTestTimeout           = register("RULE_ASSET_TEST_TIMEOUT", Descriptor{ZhFallback: "連線逾時"})
	CodeAssetTestProtocolError     = register("RULE_ASSET_TEST_PROTOCOL_ERROR", Descriptor{ZhFallback: "協議交握失敗"})
	// 未分類失敗：guacd 原始訊息只落伺服端日誌，不外洩（可含目標主機細節）。
	CodeAssetTestUnknownError = register("RULE_ASSET_TEST_UNKNOWN_ERROR", Descriptor{ZhFallback: "連線測試失敗，請確認目標主機與服務狀態"})

	// 撥測對照表 default 分支與 k8s 五類錯誤分類
	CodeAssetTestProtocolUnsupported = register("RULE_ASSET_TEST_PROTOCOL_UNSUPPORTED", Descriptor{ZhFallback: "此協議尚未支援連線測試"})
	CodeAssetTestExecForbidden       = register("RULE_ASSET_TEST_EXEC_FORBIDDEN", Descriptor{ZhFallback: "憑證無此 namespace 的 pods/exec 權限"})
	CodeAssetTestNamespaceNotFound   = register("RULE_ASSET_TEST_NAMESPACE_NOT_FOUND", Descriptor{ZhFallback: "目標 namespace 不存在"})
	CodeAssetTestTLSFailed           = register("RULE_ASSET_TEST_TLS_FAILED", Descriptor{ZhFallback: "TLS 憑證驗證失敗，請確認 CA 憑證設定"})
)

// --- INTERNAL_*（5xx／502；成因僅落伺服端日誌）---
var (
	CodeInternalAuthorizedAssetQuery = register("INTERNAL_AUTHORIZED_ASSET_QUERY", Descriptor{ZhFallback: "查詢已授權資產失敗"})
	CodeInternalAssetCreate          = register("INTERNAL_ASSET_CREATE", Descriptor{ZhFallback: "建立資產失敗"})
	CodeInternalAssetUpdate          = register("INTERNAL_ASSET_UPDATE", Descriptor{ZhFallback: "更新資產失敗"})
	CodeInternalAssetDelete          = register("INTERNAL_ASSET_DELETE", Descriptor{ZhFallback: "刪除資產失敗"})
	CodeInternalAssetTestConnection  = register("INTERNAL_ASSET_TEST_CONNECTION", Descriptor{ZhFallback: "連線測試失敗"})

	CodeInternalTagListQuery = register("INTERNAL_TAG_LIST_QUERY", Descriptor{ZhFallback: "查詢標籤清單失敗"})
	CodeInternalTagRename    = register("INTERNAL_TAG_RENAME", Descriptor{ZhFallback: "標籤改名失敗"})
	CodeInternalTagDelete    = register("INTERNAL_TAG_DELETE", Descriptor{ZhFallback: "標籤刪除失敗"})

	CodeInternalK8sPodList     = register("INTERNAL_K8S_POD_LIST", Descriptor{ZhFallback: "列出 Pod 失敗"})
	CodeInternalTempFileCreate = register("INTERNAL_TEMP_FILE_CREATE", Descriptor{ZhFallback: "建立暫存檔失敗"})
	CodeInternalUploadFileSave = register("INTERNAL_UPLOAD_FILE_SAVE", Descriptor{ZhFallback: "儲存上傳檔失敗"})

	CodeInternalAssetNodeQuery      = register("INTERNAL_ASSET_NODE_QUERY", Descriptor{ZhFallback: "查詢資產節點失敗"})
	CodeInternalAssetNodeTreeQuery  = register("INTERNAL_ASSET_NODE_TREE_QUERY", Descriptor{ZhFallback: "查詢節點樹失敗"})
	CodeInternalAssetNodeVisibility = register("INTERNAL_ASSET_NODE_VISIBILITY", Descriptor{ZhFallback: "解析可視節點失敗"})
	CodeInternalAssetNodeFilter     = register("INTERNAL_ASSET_NODE_FILTER", Descriptor{ZhFallback: "節點過濾失敗"})
	CodeInternalAssetNodeCreate     = register("INTERNAL_ASSET_NODE_CREATE", Descriptor{ZhFallback: "建立資產節點失敗"})
	CodeInternalAssetNodeUpdate     = register("INTERNAL_ASSET_NODE_UPDATE", Descriptor{ZhFallback: "更新資產節點失敗"})
	CodeInternalAssetNodeMove       = register("INTERNAL_ASSET_NODE_MOVE", Descriptor{ZhFallback: "搬移資產節點失敗"})
	CodeInternalAssetNodeDelete     = register("INTERNAL_ASSET_NODE_DELETE", Descriptor{ZhFallback: "刪除資產節點失敗"})
)
