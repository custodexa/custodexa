package apierror

// Session / my-connection / SFTP handler codes (backend-i18n-unification A3 批).
//
// 涵蓋 internal/api 的 sftp_handler.go、my_connection_handler.go、
// session_handler.go、session_command_handler.go 四檔——原先直寫
// gin.H{"error": "中文"} 的站點遷移至本檔碼。ZhFallback 對「已知錯誤」
// 逐條 byte-exact 沿用遷移前 c.JSON 文字；「err.Error() 未知」類（sftp
// 遠端操作的泛化錯誤）另立一個消化式碼，見下方註記。
var (
	// --- SFTP: 500 class（原本 err 遭靜默吞掉未落 log，RespondInternal 一併補上）---

	CodeInternalSFTPPermissionCheck = register("INTERNAL_SFTP_PERMISSION_CHECK", Descriptor{ZhFallback: "權限檢查失敗"})
	CodeInternalSFTPAssetStatus     = register("INTERNAL_SFTP_ASSET_STATUS_CHECK", Descriptor{ZhFallback: "資產狀態檢查失敗"})
	CodeInternalSFTPAccessPolicy    = register("INTERNAL_SFTP_ACCESS_POLICY_CHECK", Descriptor{ZhFallback: "存取政策檢查失敗"})

	// respondSFTPError 的遠端操作失敗碼，依**呼叫點動作**拆分（V2 對抗驗收 H3）。
	//
	// 原為單一 INTERNAL_SFTP_OPERATION_FAILED「檔案操作失敗」：使用者按下「下載」
	// 收到「檔案操作失敗」，資訊量低於遷移前那句「下載失敗」，是 i18n 統一的淨損失。
	// service 層有 12 條 fmt.Errorf 前綴（連線 4 條＋各動作 8 條），但它們不是穩定
	// 契約（含被包裹的 ssh/sftp 庫原文，且連線類前綴五個動作共用）——故粒度取
	// **呼叫點**：五個 handler 各一碼，錯在哪個動作一定準確，底層原因仍只落
	// 伺服端 log（RespondInternal 自帶，不外洩）。狀態碼一律維持 502。
	CodeInternalSFTPListFailed     = register("INTERNAL_SFTP_LIST_FAILED", Descriptor{ZhFallback: "讀取目錄失敗"})
	CodeInternalSFTPDownloadFailed = register("INTERNAL_SFTP_DOWNLOAD_FAILED", Descriptor{ZhFallback: "下載檔案失敗"})
	CodeInternalSFTPUploadFailed   = register("INTERNAL_SFTP_UPLOAD_FAILED", Descriptor{ZhFallback: "上傳檔案失敗"})
	CodeInternalSFTPMkdirFailed    = register("INTERNAL_SFTP_MKDIR_FAILED", Descriptor{ZhFallback: "建立目錄失敗"})
	CodeInternalSFTPDeleteFailed   = register("INTERNAL_SFTP_DELETE_FAILED", Descriptor{ZhFallback: "刪除失敗"})

	// CodeSFTPDirNotEmpty 對映 service.ErrRemoveDirNotEmpty sentinel（errors.Is）。
	// 與上列動作碼分家的理由：這句是**可行動指引**（清空目錄再刪），不是
	// 「底層出錯」的同義反覆，混進泛碼即等於把唯一有用的提示丟掉。
	// 狀態碼沿用 502（遠端操作失敗），不因碼化改變既有語義。
	CodeSFTPDirNotEmpty = register("RULE_SFTP_DIR_NOT_EMPTY", Descriptor{ZhFallback: "刪除目錄失敗（須為空目錄）"})

	// --- SFTP: 400 class（已知字面量 / 已知 sentinel）---

	CodeSFTPFileMissing      = register("VALIDATION_SFTP_FILE_MISSING", Descriptor{ZhFallback: "缺少上傳檔案"})
	CodeSFTPUploadReadFailed = register("VALIDATION_SFTP_UPLOAD_READ_FAILED", Descriptor{ZhFallback: "讀取上傳檔案失敗"})
	CodeSFTPMkdirPathMissing = register("VALIDATION_SFTP_MKDIR_PATH_MISSING", Descriptor{ZhFallback: "缺少 path"})
	// CodeSFTPInvalidPath 對映 service.ErrInvalidRemotePath sentinel（errors.Is）。
	CodeSFTPInvalidPath = register("VALIDATION_SFTP_INVALID_PATH", Descriptor{ZhFallback: "遠端路徑必須為絕對路徑且不得包含 .."})

	// --- 資料傳輸管控：403（data-transfer-control 4.2）---
	//
	// **與授權拒絕（404 CodeAuthorizationDenied 之屬）刻意不同碼**：授權拒絕的語義是
	// 「你不能碰這台資產」，資料傳輸拒絕的語義是「你能連這台，但這類資料動作被政策
	// 關掉了」。共用一碼會讓使用者收到「查無此資產」而去找管理員要授權，實際上要改的
	// 是政策鍵——診斷方向被誤導。
	//
	// **狀態 403 而非 404**：不需要隱藏存在性（能走到這一步代表 connect 授權已通過，
	// 資產存在對此使用者早已不是秘密），且 403 才表達「已認證但被禁止」。
	//
	// `action` 標示被擋的動作、`reason` 標示拒絕來源（期 1 恆為 global_policy；
	// 期 2 會多出「無匹配放寬」一種來源）。兩者皆為機器欄，前端據以查譯。
	CodeTransferDenied = register("RULE_TRANSFER_DENIED", Descriptor{
		ZhFallback: "資料傳輸已被安全政策禁止（{action}，來源：{reason}）",
		Params: []ParamSpec{
			{Key: "action", Kind: ParamEnum, EnumNS: "transferAction", ZhLabels: transferActionZhLabels},
			{Key: "reason", Kind: ParamEnum, EnumNS: "transferDenyReason", ZhLabels: transferDenyReasonZhLabels},
		},
	})

	// --- 共用 ID 驗證 ---
	//
	// session ID 驗證复用 codes_connect.go 既有的 CodeInvalidSessionID
	// （VALIDATION_INVALID_SESSION_ID，ZhFallback「無效的會話 ID」）——該碼由
	// A8 批註冊，涵蓋 monitor/stats/share 三處「無效的 Session ID」/「無效的
	// 會話 ID」措辭差異；本批 session_handler.go／session_command_handler.go
	// 的「無效的 Session ID」語義相同，直接复用不重複註冊（D2 复用優先）。
	//
	// my-connection 的「連線 ID」是另一資源命名（非 session 的同義詞——
	// my-connection 端點對外一律稱「連線」），故另立一碼：
	CodeInvalidConnectionID = register("VALIDATION_INVALID_CONNECTION_ID", Descriptor{ZhFallback: "無效的連線 ID"})

	// --- my-connection（自助連線紀錄）---

	CodeInternalMyConnectionQuery     = register("INTERNAL_MY_CONNECTION_QUERY", Descriptor{ZhFallback: "查詢連線紀錄失敗"})
	CodeMyConnectionNotFound          = register("NOTFOUND_MY_CONNECTION", Descriptor{ZhFallback: "連線不存在"})
	CodeMyConnectionEnded             = register("RULE_MY_CONNECTION_ENDED", Descriptor{ZhFallback: "連線已結束"})
	CodeInternalMyConnectionTerminate = register("INTERNAL_MY_CONNECTION_TERMINATE", Descriptor{ZhFallback: "終止連線失敗"})

	// --- session（管理端 Session 列表／詳情／統計／強制終止）---

	// CodeSessionNotFound 复用 codes_connect.go 既有碼（NOTFOUND_SESSION，
	// ZhFallback「會話不存在」）——同一資源不存在語義，D2 复用優先；本檔不重複註冊。
	//
	// INTERNAL_SESSION_QUERY 已被 codes_audit.go（A7 批，錄影播放前置查詢，
	// ZhFallback「獲取 Session 資訊失敗」）取走——雖語義相近但呼叫網域不同
	// （本檔為 session 管理端列表/詳情查詢），另立 _ADMIN_ 命名避免同批次
	// 平行作業撞碼（A3/A7 為並行 batch，非本檔可調解）。
	CodeInternalSessionAdminQuery  = register("INTERNAL_SESSION_ADMIN_QUERY", Descriptor{ZhFallback: "查詢 Session 失敗"})
	CodeInternalSessionActiveQuery = register("INTERNAL_SESSION_ACTIVE_QUERY", Descriptor{ZhFallback: "查詢活動 Session 失敗"})
	CodeSessionTerminateAdminOnly  = register("AUTH_SESSION_TERMINATE_ADMIN_ONLY", Descriptor{ZhFallback: "僅管理員可強制終止 Session"})
	CodeSessionClosed              = register("RULE_SESSION_CLOSED", Descriptor{ZhFallback: "Session 已關閉"})
	CodeInternalSessionTerminate   = register("INTERNAL_SESSION_TERMINATE", Descriptor{ZhFallback: "終止 Session 失敗"})
	CodeInternalSessionStatistics  = register("INTERNAL_SESSION_STATISTICS", Descriptor{ZhFallback: "查詢統計資訊失敗"})

	// --- session command（指令審計）---

	CodeInternalSessionCommandQuery  = register("INTERNAL_SESSION_COMMAND_QUERY", Descriptor{ZhFallback: "查詢會話指令失敗"})
	CodeInternalSessionCommandSearch = register("INTERNAL_SESSION_COMMAND_SEARCH", Descriptor{ZhFallback: "查詢指令記錄失敗"})
)

// transferActionZhLabels 資料傳輸動作的允許清單（data-transfer-control 4.2）。
// 動作是機器名，三語一致顯示原字串，故 label 即值本身；此處的價值在**允許清單**——
// 綁 ParamEnum 後任意字串進不了 wire。
// 值域須與 `internal/modules/policy` 的 TransferAction* 常數一致
// （`internal/modules/policy/transfer_action_display_completeness_test.go` 的
// `TestTransferActionLabelsTranslated` 守衛之）。
var transferActionZhLabels = identityLabels(
	"clipboard_send",
	"clipboard_recv",
	"file_upload",
	"file_download",
	"file_delete",
)

// transferDenyReasonZhLabels 拒絕來源的允許清單。
// 期 1 只有 global_policy 一種來源；期 2 的 per-authorization 放寬會新增
// no_matching_grant（全域禁止且無匹配放寬）。
var transferDenyReasonZhLabels = identityLabels(
	"global_policy",
)
