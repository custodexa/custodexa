package apierror

// Audit/recording/key-management handler codes .
// Covers: recording_handler / audit_log_handler / audit_integrity_handler /
// audit_failure_handler / audit_export_handler / security_policy_handler /
// key_management_handler (residual RespondError/RespondInternalError) /
// transmission_inventory_handler. ZhFallback is byte-exact to the
// pre-migration c.JSON text (bijection test pins zh-TW == ZhFallback).

// --- NOTFOUND_* ---
var (
	CodeSessionNotFound         = register("NOTFOUND_SESSION", Descriptor{ZhFallback: "Session 不存在"})
	CodeSessionHasNoRecording   = register("NOTFOUND_SESSION_RECORDING", Descriptor{ZhFallback: "此 Session 沒有錄製檔案"})
	CodeRecordingFileNotFound   = register("NOTFOUND_RECORDING_FILE", Descriptor{ZhFallback: "錄製檔案不存在"})
	CodeRecordingTimingNotFound = register("NOTFOUND_RECORDING_TIMING", Descriptor{ZhFallback: "錄製時間檔案不存在"})
	CodeAuditLogNotFound        = register("NOTFOUND_AUDIT_LOG", Descriptor{ZhFallback: "審計日誌不存在"})
	// CodeClipboardEventNotFound 單筆剪貼簿內容調閱的**收斂拒絕**：
	// 事件不存在、事件識別非法、事件不屬路徑中會話（跨會話探測）
	// 三種情形共用本碼——存在性細節
	// 不對外，只進審計（audit-detail-not-outward）
	CodeClipboardEventNotFound = register("NOTFOUND_CLIPBOARD_EVENT", Descriptor{ZhFallback: "剪貼簿記錄不存在"})
)

// --- 證據包非同步匯出 ---
var (
	// CodeExportJobRequesterOnly 下載端點的**收斂 403**（下載綁申請者本人，
	// 非申請者——含其他具稽核檢視權限帳號——一律 403）：job 不存在、識別非法、
	// 非申請者本人三種情形共用本碼且同回 403——分成 404/403 會讓具權限的
	// 探測者以狀態碼枚舉 job 存在性；文案只陳述規則，不指涉任何一筆 job
	CodeExportJobRequesterOnly = register("AUTH_EXPORT_JOB_REQUESTER_ONLY",
		Descriptor{ZhFallback: "匯出產物僅限申請者本人下載"})
	// CodeAuditExportBundleAsyncOnly 既有同步端點對證據包模式的一律拒絕：
	// 不轉 job（GET 不得產生建立副作用）、不回 bundle 位元組——同步路徑
	// 若續供 bundle 即繞過申請者綁定與限時下載鏈
	CodeAuditExportBundleAsyncOnly = register("RULE_AUDIT_EXPORT_BUNDLE_ASYNC_ONLY",
		Descriptor{ZhFallback: "證據包已改為非同步交付，請改以匯出 job 發起"})
	// CodeExportJobBundleOnly job 發起端點只受理證據包；事件報告維持同步匯出
	CodeExportJobBundleOnly = register("RULE_EXPORT_JOB_BUNDLE_ONLY",
		Descriptor{ZhFallback: "匯出 job 僅受理證據包，事件報告請走同步匯出端點"})
	// CodeExportJobLimit 每申請者或全域進行中上限已滿（兩者收斂一碼：
	// 申請者的可行動語義相同——稍後再試，拆開只是多洩系統負載細節）
	CodeExportJobLimit = register("CONFLICT_EXPORT_JOB_LIMIT",
		Descriptor{ZhFallback: "匯出打包佇列已滿，請稍後再試"})
	// CodeExportArtifactUnavailable 申請者本人的 job 產物不可下載（未完成、
	// 已失敗或已逾保留期收斂一碼，HTTP 410——即「過期後 410 或同型
	// 收斂錯誤」；實際狀態申請者可經清單端點查得，細節不經下載端點展開）
	CodeExportArtifactUnavailable = register("RULE_EXPORT_ARTIFACT_UNAVAILABLE",
		Descriptor{ZhFallback: "匯出產物目前不可下載"})
	// CodeInternalExportJob job 受理／查詢的 5xx 收斂碼
	CodeInternalExportJob = register("INTERNAL_EXPORT_JOB",
		Descriptor{ZhFallback: "匯出 job 處理失敗"})
)

// --- VALIDATION_* ---
var (
	// {resource} 為前端傳入、經 switch 白名單驗證過的資源類型字串——見
	// audit_log_handler.go GetByResourceID；valid_types 走 Meta 供前端呈現允許清單
	CodeAuditResourceTypeInvalid = register("VALIDATION_AUDIT_RESOURCE_TYPE", Descriptor{ZhFallback: "無效的資源類型"})

	CodeAuditIntegrityFromFormat   = register("VALIDATION_AUDIT_INTEGRITY_FROM_FORMAT", Descriptor{ZhFallback: "from 格式須為 YYYY-MM-DD"})
	CodeAuditIntegrityToFormat     = register("VALIDATION_AUDIT_INTEGRITY_TO_FORMAT", Descriptor{ZhFallback: "to 格式須為 YYYY-MM-DD"})
	CodeAuditIntegrityRangeInvalid = register("VALIDATION_AUDIT_INTEGRITY_RANGE", Descriptor{ZhFallback: "to 須晚於 from"})

	// 檢查點驗證（audit-checkpoint-chain 8.1／8.2）。RANGE_REQUIRED 是內容層的
	// 硬閘：全鏈重掃是數十億列級掃描，同步請求必逾時，故未帶範圍一律拒絕而
	// **不是**「預設全歷史」——後者會讓一次誤點擊拖垮生產庫
	CodeCheckpointRangeRequired = register("VALIDATION_CHECKPOINT_RANGE_REQUIRED", Descriptor{ZhFallback: "內容層驗證須指定 seq 或日期範圍"})
	CodeCheckpointRangeFormat   = register("VALIDATION_CHECKPOINT_RANGE_FORMAT", Descriptor{ZhFallback: "範圍參數格式不正確（seq 為正整數、日期為 YYYY-MM-DD）"})
	CodeAuditExportFilterRequired  = register("VALIDATION_AUDIT_EXPORT_FILTER_REQUIRED", Descriptor{ZhFallback: "至少需指定一個篩選條件（session_id/user_id/asset_id/時段）"})
	CodePolicyUpdateEmpty          = register("VALIDATION_POLICY_EMPTY", Descriptor{ZhFallback: "未提供任何政策項"})
	CodeKeyRotatePurposeInvalid    = register("VALIDATION_KEY_ROTATE_PURPOSE", Descriptor{ZhFallback: "purpose 必須為 data 或 audit_integrity"})
)

// 政策批次更新是一次送多鍵，錯誤不指名鍵時 admin 無從得知該改哪一項，故兩碼
// 皆以 {key} 還原（service 端 typed error 具名帶出）。兩者的 kind 刻意不同：
//
//   - UNKNOWN_KEY 的鍵**依定義**不在任何允許清單內（它就是因為不認得才報錯），
//     用 ParamEnum 必然驗證失敗、params 被丟棄，訊息反而更空——只能走
//     ParamOpaque（淨化＋限長），且該值來自請求 body，淨化是必要的。
//   - INVALID_VALUE 的鍵已通過 service.findDef，保證出自靜態政策表，故用
//     ParamEnum 綁允許清單（policyKeyZhLabels），杜絕任意字串進 wire。
//     清單與 service.policyDefs 的一致性由 service 側守衛測試把關。
//
// 值不合法的**原因**（須為非負整數／不可為 0／超過上限…）仍不進 wire：
// 那是句子而非受控值，碼化需另拆一組 RULE_* 碼，屬本次範圍外。
var (
	CodePolicyUnknownKey = register("VALIDATION_POLICY_UNKNOWN_KEY", Descriptor{
		ZhFallback: "未定義的安全政策項：{key}",
		Params:     []ParamSpec{{Key: "key", Kind: ParamOpaque}},
	})
	CodePolicyInvalidValue = register("VALIDATION_POLICY_INVALID_VALUE", Descriptor{
		ZhFallback: "安全政策值不合法：{key}",
		Params:     []ParamSpec{{Key: "key", Kind: ParamEnum, EnumNS: "policyKey", ZhLabels: policyKeyZhLabels}},
	})
	// CodePolicyRetentionCrossKey 跨鍵保留約束違反（audit-checkpoint-chain）。
	//
	// 與 INVALID_VALUE 分開一碼而非共用：後者的成因在**該鍵自己的值域**，
	// 修法是改小／改大那一個數字；本碼的成因是**兩個鍵的關係**，修法是
	// 「先調升檢查點保留期，或改小這個資料保留期」——共用一碼會讓 admin
	// 對著一個值域合法的數字反覆試錯。{key} 指出是哪個資料保留鍵絆住整批
	CodePolicyRetentionCrossKey = register("VALIDATION_POLICY_RETENTION_CROSS_KEY", Descriptor{
		ZhFallback: "檢查點保留天數不得短於資料保留天數：{key}",
		Params:     []ParamSpec{{Key: "key", Kind: ParamEnum, EnumNS: "policyKey", ZhLabels: policyKeyZhLabels}},
	})
)

// policyKeyZhLabels 是安全政策鍵的允許清單。政策鍵是機器名，三語一致顯示原字串
// （前端無 enum getter，params 原樣插值），故 label 即鍵本身；此處的價值在
// **允許清單**而非翻譯。新增政策鍵時必須同步本清單，否則
// service.TestPolicyKeyAllowlistCoversDefs 會紅。
var policyKeyZhLabels = identityLabels(
	// 帳號安全
	"lockout_max_attempts",
	"lockout_duration_minutes",
	"password_min_length",
	"password_require_alnum",
	"password_history_count",
	"password_max_age_days",
	"force_change_on_reset",
	"mfa_required",
	"web_idle_minutes",
	"web_max_session_hours",
	// refresh cookie 的 Secure 屬性
	"refresh_cookie_secure",
	"session_idle_minutes",
	"session_max_minutes",
	"inactive_disable_days",
	// 日誌保留與審閱（PCI Req 10）
	"retention_audit_log_days",
	"retention_session_command_days",
	"retention_alert_days",
	"retention_recording_days",
	// 檢查點鏈保留（audit-checkpoint-chain）
	"retention_checkpoint_days",
	// 封章觸發門檻（audit-checkpoint-chain）：週期與筆數先到先觸發
	"audit_checkpoint_interval_seconds",
	"audit_checkpoint_row_threshold",
	// 鏈自動驗證三鍵
	"audit_chain_recent_verify_days",
	"audit_chain_verify_interval_seconds",
	"audit_chain_verify_rows_per_hour",
	// 單輪清理刪除上限：調小才危險，下界由 Min 承擔
	"retention_max_per_run",
	"daily_review_enabled",
	"failure_alert_enabled",
	"recording_failclose_enabled",
	// 金鑰管理
	"key_cryptoperiod_reminder_days",
	// 單輪換鑰重加密上限
	"key_rotation_max_per_run",
	// 叢集存取
	"k8s_list_timeout_seconds",
	// 傳輸安全
	"transport_rdp_level",
	"transport_vnc_level",
	"transport_db_level",
	"transport_ldap_level",
	"transport_syslog_level",
	"transport_notify_level",
	"transport_consent_ttl_days",
	// 存取政策
	"access_policy_default",
	"access_request_max_duration_minutes",
	"access_request_pending_timeout_hours",
	"access_request_min_approvals",
	// 破窗與撤銷
	"break_glass_enabled",
	"break_glass_duration_minutes",
	"break_glass_review_timeout_hours",
	"access_revoke_disconnect",
	// 資料傳輸管控（data-transfer-control）
	"clipboard_send_enabled",
	"clipboard_recv_enabled",
	"file_upload_enabled",
	"file_download_enabled",
	"file_delete_enabled",
)

// identityLabels 建立「值即標籤」的 ZhLabels（機器名枚舉專用：需要允許清單的
// 約束力，但不需要翻譯）。
func identityLabels(values ...string) map[string]string {
	m := make(map[string]string, len(values))
	for _, v := range values {
		m[v] = v
	}
	return m
}

// --- AUTH_* (opaque recording playback token, distinct from the JWT session token) ---
var (
	CodeRecordingTokenMissing = register("AUTH_RECORDING_TOKEN_MISSING", Descriptor{ZhFallback: "缺少錄影 token"})
	CodeRecordingTokenInvalid = register("AUTH_RECORDING_TOKEN_INVALID", Descriptor{ZhFallback: "錄影 token 無效或已逾時"})
	// CodeRecordingTokenRevoked 簽發端的世代閘拒絕（帳號停用／解綁／provider 停用
	// 或刪除）。與 INVALID 分開一碼：後者是「這張 token 不能用」，前者是
	// 「你的登入憑證已失效」——使用者處置是重新登入，不是重按播放
	CodeRecordingTokenRevoked = register("AUTH_RECORDING_TOKEN_REVOKED", Descriptor{
		ZhFallback: "登入憑證已失效，無法取得錄影存取權限，請重新登入"})
)

// --- INTERNAL_* (generalized 5xx; cause logged server-side by RespondInternal) ---
var (
	CodeInternalRecordingMetadataQuery = register("INTERNAL_RECORDING_METADATA_QUERY", Descriptor{ZhFallback: "獲取錄製元數據失敗"})
	CodeInternalRecordingFileQuery     = register("INTERNAL_RECORDING_FILE_QUERY", Descriptor{ZhFallback: "獲取錄製檔案失敗"})
	CodeInternalSessionQuery           = register("INTERNAL_SESSION_QUERY", Descriptor{ZhFallback: "獲取 Session 資訊失敗"})
	CodeInternalRecordingTokenIssue    = register("INTERNAL_RECORDING_TOKEN_ISSUE", Descriptor{ZhFallback: "簽發錄影 token 失敗"})
	CodeInternalRecordingFileOpen      = register("INTERNAL_RECORDING_FILE_OPEN", Descriptor{ZhFallback: "開啟錄製檔案失敗"})
	CodeInternalRecordingFileStat      = register("INTERNAL_RECORDING_FILE_STAT", Descriptor{ZhFallback: "獲取檔案資訊失敗"})
	CodeInternalRecordingStatsQuery    = register("INTERNAL_RECORDING_STATS_QUERY", Descriptor{ZhFallback: "獲取統計資訊失敗"})
	CodeInternalRecordingDelete        = register("INTERNAL_RECORDING_DELETE", Descriptor{ZhFallback: "刪除錄製檔案失敗"})

	CodeInternalAuditLogQuery                = register("INTERNAL_AUDIT_LOG_QUERY", Descriptor{ZhFallback: "查詢審計日誌失敗"})
	CodeInternalAuditLogResourceHistoryQuery = register("INTERNAL_AUDIT_LOG_RESOURCE_HISTORY_QUERY", Descriptor{ZhFallback: "查詢資源審計歷史失敗"})
	CodeInternalAuditIntegrityVerify         = register("INTERNAL_AUDIT_INTEGRITY_VERIFY", Descriptor{ZhFallback: "完整性驗證失敗"})
	CodeInternalAuditFailureQuery            = register("INTERNAL_AUDIT_FAILURE_QUERY", Descriptor{ZhFallback: "查詢失效事件失敗"})
	CodeInternalCheckpointQuery              = register("INTERNAL_CHECKPOINT_QUERY", Descriptor{ZhFallback: "查詢檢查點失敗"})
	CodeInternalCheckpointVerify             = register("INTERNAL_CHECKPOINT_VERIFY", Descriptor{ZhFallback: "檢查點驗證失敗"})
	CodeInternalPolicyWrite                  = register("INTERNAL_POLICY_WRITE", Descriptor{ZhFallback: "政策寫入失敗"})

	CodeInternalKeyInventoryQuery  = register("INTERNAL_KEY_INVENTORY_QUERY", Descriptor{ZhFallback: "讀取金鑰清冊失敗"})
	CodeInternalKeyKEKHistoryQuery = register("INTERNAL_KEY_KEK_HISTORY_QUERY", Descriptor{ZhFallback: "讀取 KEK 退役史失敗"})
	CodeInternalKeyRotate          = register("INTERNAL_KEY_ROTATE", Descriptor{ZhFallback: "金鑰輪替失敗"})
	CodeInternalKeyRewrap          = register("INTERNAL_KEY_REWRAP", Descriptor{ZhFallback: "KEK 重包失敗"})
	CodeInternalKeyAbandonRewrap   = register("INTERNAL_KEY_ABANDON_REWRAP", Descriptor{ZhFallback: "放棄 KEK 重包失敗"})
	CodeInternalKeyCleanupRetired  = register("INTERNAL_KEY_CLEANUP_RETIRED", Descriptor{ZhFallback: "清理退役金鑰資料失敗"})

	CodeInternalTransmissionInventoryBuild = register("INTERNAL_TRANSMISSION_INVENTORY_BUILD", Descriptor{ZhFallback: "彙整通道清冊失敗"})

	CodeInternalClipboardQuery = register("INTERNAL_CLIPBOARD_QUERY", Descriptor{ZhFallback: "查詢剪貼簿記錄失敗"})
)
