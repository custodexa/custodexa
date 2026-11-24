package apierror

// syslog / notification-channel / alert-rule / command-alert 的 HTTP 出口碼。
//
// 命名沿用 codes.go 慣例：VALIDATION_*（輸入問題，使用者可據此改正）／
// NOTFOUND_*／INTERNAL_*（500/502，泛化訊息+cause 入 log）。
//
// 已知例外（刻意不遷移，見 syslog_setting_handler.go／notification_channel_handler.go
// 的 respondChannelError）：TransmissionGateError 的 "code"（ack_required/
// strict_reject）與 "risks" 欄不經本檔碼化——它們是傳輸政策既有的
// 機器欄，SyslogForwardCard.vue/Alerts.vue 直接以字面值
// `resp.data.code === 'ack_required'` 做控制流分支（syslog_setting_gate_test.go
// 亦鎖定此契約），與 apierror 的 "code" 保留鍵語義衝突，無法安全合流。
var (
	// --- syslog 設定驗證（syslog_setting_handler.go）---

	CodeSyslogPortRange = register("VALIDATION_SYSLOG_PORT_RANGE", Descriptor{
		ZhFallback: "port 須在 1-65535"})
	CodeSyslogProtocol = register("VALIDATION_SYSLOG_PROTOCOL", Descriptor{
		ZhFallback: "protocol 須為 udp/tcp/tcp+tls"})
	// CodeSyslogHostRequired Update（啟用轉發時）與 Test（恆須 host）共用同一規則
	CodeSyslogHostRequired = register("VALIDATION_SYSLOG_HOST_REQUIRED", Descriptor{
		ZhFallback: "host 不可為空"})

	CodeInternalSyslogSettingQuery = register("INTERNAL_SYSLOG_SETTING_QUERY", Descriptor{
		ZhFallback: "讀取 syslog 設定失敗"})
	CodeInternalSyslogSettingSave = register("INTERNAL_SYSLOG_SETTING_SAVE", Descriptor{
		ZhFallback: "儲存 syslog 設定失敗"})
	// CodeInternalSyslogGateCheck 防禦性出口：CheckSettingSave 目前只回
	// nil 或 *TransmissionGateError，此碼對應理論上不可達的第三種型別
	CodeInternalSyslogGateCheck = register("INTERNAL_SYSLOG_GATE_CHECK", Descriptor{
		ZhFallback: "傳輸政策檢查失敗"})

	// --- 通知通道（notification_channel_handler.go）---

	CodeInvalidChannelURL = register("VALIDATION_CHANNEL_URL", Descriptor{
		ZhFallback: "URL 必須為 http 或 https"})
	CodeInvalidChannelType = register("VALIDATION_CHANNEL_TYPE", Descriptor{
		ZhFallback: "通道類型必須為 webhook、slack 或 slack_app"})
	// CodeInvalidChannelLanguage 映射 service.ErrInvalidChannelLanguage sentinel
	// （語系空值或白名單外皆拒，服務層不區分兩種成因）
	CodeInvalidChannelLanguage = register("VALIDATION_CHANNEL_LANGUAGE", Descriptor{
		ZhFallback: "語系必須為 zh-TW、en-US 或 ja-JP"})
	// CodeInvalidChannelMinSeverity 映射 service.ErrInvalidChannelMinSeverity sentinel
	// （推送門檻空值或白名單外皆拒）
	CodeInvalidChannelMinSeverity = register("VALIDATION_CHANNEL_MIN_SEVERITY", Descriptor{
		ZhFallback: "推送等級必須為 low、medium 或 high"})
	CodeInvalidChannelID = register("VALIDATION_INVALID_CHANNEL_ID", Descriptor{
		ZhFallback: "無效的通道 ID"})
	// CodeInvalidChannelTarget 映射 audit.ErrInvalidChannelTarget（slack_app 的頻道識別碼格式）
	CodeInvalidChannelTarget = register("VALIDATION_CHANNEL_TARGET", Descriptor{
		ZhFallback: "頻道識別碼須為 1 到 64 個英數字"})
	// CodeInvalidChannelSecret 映射 audit.ErrInvalidChannelSecret（機器人 token 格式）
	CodeInvalidChannelSecret = register("VALIDATION_CHANNEL_SECRET", Descriptor{
		ZhFallback: "機器人 token 須以 xoxb- 開頭且不含空白"})
	// CodeChannelSecretRequired 映射 audit.ErrChannelSecretRequired（型別需要秘密而請求沒有給，或要清除它）
	CodeChannelSecretRequired = register("VALIDATION_CHANNEL_SECRET_REQUIRED", Descriptor{
		ZhFallback: "儲存失敗：Slack 應用程式需要機器人 token，請在同一次儲存時輸入。通道維持原狀。"})
	// CodeChannelTypeChangeNeedsURL 映射 audit.ErrChannelTypeChangeNeedsURL
	CodeChannelTypeChangeNeedsURL = register("VALIDATION_CHANNEL_TYPE_CHANGE_NEEDS_URL", Descriptor{
		ZhFallback: "儲存失敗：改了類型時要同時填入網址。通道維持原狀。"})
	// CodeChannelURLChangeNeedsSecret 映射 audit.ErrChannelURLChangeNeedsSecret
	CodeChannelURLChangeNeedsSecret = register("VALIDATION_CHANNEL_URL_CHANGE_NEEDS_SECRET", Descriptor{
		ZhFallback: "儲存失敗：改了 Slack 位址或改成 Slack 應用程式時，要同時輸入 token。通道維持原狀。"})
	// CodeChannelDMConflict 映射 audit.ErrDirectMessageConflict：已有另一個通道開啟對個人派送（name 為那個通道的名稱）
	CodeChannelDMConflict = register("VALIDATION_CHANNEL_DM_CONFLICT", Descriptor{
		ZhFallback: "已有通道「{name}」開啟對個人派送。同一時間只能有一個通道開啟；要改用這個通道，請先到「{name}」關閉這個設定。",
		Params:     []ParamSpec{{Key: "name", Kind: ParamOpaque}}})
	// CodeChannelDMURLNotAllowed 映射 audit.ErrDirectMessageURLNotAllowed 與 audit.ErrSelfTestURLNotAllowed
	CodeChannelDMURLNotAllowed = register("VALIDATION_CHANNEL_DM_URL_NOT_ALLOWED", Descriptor{
		ZhFallback: "這個網址不能用於對個人派送，需由部署者設定允許。"})
	// CodeChannelDMTypeUnsupported 映射 audit.ErrDirectMessageUnsupportedType 與 audit.ErrSelfTestUnsupportedType
	CodeChannelDMTypeUnsupported = register("VALIDATION_CHANNEL_DM_TYPE_UNSUPPORTED", Descriptor{
		ZhFallback: "這個通道類型不能送私訊給個人。"})
	// CodeInvalidDeliveryAudience 投遞紀錄的收件對象篩選不在值域內
	CodeInvalidDeliveryAudience = register("VALIDATION_DELIVERY_AUDIENCE", Descriptor{
		ZhFallback: "無法篩選：收件對象只能是頻道或個人。"})
	// CodeInvalidDeliveryState 投遞紀錄的狀態篩選不在值域內
	CodeInvalidDeliveryState = register("VALIDATION_DELIVERY_STATE", Descriptor{
		ZhFallback: "無法篩選：狀態只能是等待中、重送中、已送達、已放棄或已取消。"})

	CodeChannelNotFound = register("NOTFOUND_NOTIFICATION_CHANNEL", Descriptor{
		ZhFallback: "通知通道不存在"})

	CodeInternalChannelOp = register("INTERNAL_CHANNEL_OP", Descriptor{
		ZhFallback: "通知通道操作失敗"})
	CodeInternalChannelQuery = register("INTERNAL_CHANNEL_QUERY", Descriptor{
		ZhFallback: "查詢通知通道失敗"})
	// CodeChannelTestConnFailed / CodeChannelTestTimeout 送達失敗回 502：
	// 兩碼保留既有的逾時/連線失敗區分（形狀遷移不動邏輯）
	CodeChannelTestConnFailed = register("INTERNAL_CHANNEL_TEST_CONN_FAILED", Descriptor{
		ZhFallback: "通道測試失敗: 無法連線通知端點"})
	CodeChannelTestTimeout = register("INTERNAL_CHANNEL_TEST_TIMEOUT", Descriptor{
		ZhFallback: "通道測試失敗: 連線逾時"})

	// --- 告警規則（alert_rule_handler.go）---

	CodeInvalidAlertDirection = register("VALIDATION_ALERT_DIRECTION", Descriptor{ZhFallback: "direction 必須為 input/output"})
	CodeAlertOutputBlock      = register("VALIDATION_ALERT_OUTPUT_BLOCK", Descriptor{ZhFallback: "輸出面不支援阻斷：位元組送達之後無從收回。"})
	CodeInvalidAlertPattern   = register("VALIDATION_ALERT_RULE_PATTERN", Descriptor{
		ZhFallback: "regex pattern 無效"})
	// CodeInvalidAlertSeverity 與 command_alert_handler.go 共用（同一規則：
	// severity 必須為 high/medium/low）
	CodeInvalidAlertSeverity = register("VALIDATION_ALERT_SEVERITY", Descriptor{
		ZhFallback: "severity 必須為 high/medium/low"})
	CodeInvalidAlertAction = register("VALIDATION_ALERT_ACTION", Descriptor{
		ZhFallback: "action 必須為 alert/block"})
	CodeInvalidAlertProtocols = register("VALIDATION_ALERT_PROTOCOLS", Descriptor{
		ZhFallback: "protocols 僅接受 ssh/k8s/mysql/postgres/redis/mssql（逗號分隔，空=全協議）"})
	CodeInvalidAlertRuleID = register("VALIDATION_INVALID_ALERT_RULE_ID", Descriptor{
		ZhFallback: "無效的規則 ID"})
	// --- 告警規則唯一性衝突（alert_rule_handler.go）---

	// CodeAlertRuleNameExists 規則名撞 alert_rules.name 唯一索引
	// （種子冪等的前提）。
	//
	// 歸 CONFLICT_* 並回 409，與既有的 CONFLICT_ASSET_NAME／
	// CONFLICT_ACCOUNT_USERNAME／CONFLICT_USERNAME_EXISTS 同一形狀：同一支 API
	// 裡「既有資源同名」若一處回 409、一處回 400，呼叫端就無法再靠狀態碼分流
	// 「我送錯東西」與「資源已存在」，只能回頭比對錯誤碼字串。
	//
	// 撞名的是哪一條既有規則不入 wire——規則清單 admin 本就看得到，
	// 回應無須也不該複述資料庫層的比對結果。
	CodeAlertRuleNameExists = register("CONFLICT_ALERT_RULE_NAME", Descriptor{
		ZhFallback: "告警規則名稱已存在"})

	CodeAlertRuleNotFound = register("NOTFOUND_ALERT_RULE", Descriptor{
		ZhFallback: "告警規則不存在"})

	CodeInternalAlertRuleOp = register("INTERNAL_ALERT_RULE_OP", Descriptor{
		ZhFallback: "告警規則操作失敗"})
	CodeInternalAlertRuleQuery = register("INTERNAL_ALERT_RULE_QUERY", Descriptor{
		ZhFallback: "查詢告警規則失敗"})

	// --- 告警查詢／審閱（command_alert_handler.go）---

	CodeInvalidCommandAlertID = register("VALIDATION_INVALID_ALERT_ID", Descriptor{
		ZhFallback: "無效的告警 ID"})
	CodeInvalidReviewRequest = register("VALIDATION_ALERT_REVIEW_REQUEST", Descriptor{
		ZhFallback: "請求參數錯誤：需提供 disposition（benign/escalated）"})
	CodeInvalidDisposition = register("VALIDATION_ALERT_DISPOSITION", Descriptor{
		ZhFallback: "處置分類須為 benign 或 escalated"})

	CodeCommandAlertNotFound = register("NOTFOUND_COMMAND_ALERT", Descriptor{
		ZhFallback: "告警不存在"})

	// 批次審閱：理由碼供批次審閱端點、逐筆送出的批次與單筆審閱的字數上限共用（同一上限）。
	// 本人觸發碼只用於以單筆端點帶批次關聯碼逐筆送出的請求：這種請求無法表達確認筆數
	CodeAlertBatchNote = register("VALIDATION_ALERT_BATCH_NOTE", Descriptor{
		ZhFallback: "審閱理由不得超過 500 字，批次審閱另須填寫理由"})
	CodeAlertBatchSelfTriggered = register("RULE_ALERT_BATCH_SELF_TRIGGERED", Descriptor{
		ZhFallback: "你自己觸發的告警不能以逐筆送出的批次處置，請改用批次審閱並確認，或逐筆審閱"})
	// 批次審閱端點的整批拒收：筆數超過單次上限（meta 帶 limit），
	// 或請求明示的本人觸發筆數與伺服端計得的不符（meta 帶 self_triggered）
	CodeAlertBatchTooLarge = register("VALIDATION_ALERT_BATCH_TOO_LARGE", Descriptor{
		ZhFallback: "一次批次審閱的告警筆數超過上限，請分次送出"})
	CodeAlertBatchSelfAck = register("CONFLICT_ALERT_BATCH_SELF_ACK", Descriptor{
		ZhFallback: "這一批中你自己觸發的告警筆數與確認的筆數不符，請重新確認後再送出"})
	CodeAlertAlreadyReviewed = register("CONFLICT_ALERT_ALREADY_REVIEWED", Descriptor{
		ZhFallback: "送出時已有審閱結果"})

	CodeInternalCommandAlertQuery = register("INTERNAL_COMMAND_ALERT_QUERY", Descriptor{
		ZhFallback: "查詢告警記錄失敗"})
	CodeInternalAlertReview = register("INTERNAL_ALERT_REVIEW", Descriptor{
		ZhFallback: "審閱告警失敗"})

	// 傳輸政策門：原為 legacy 小寫碼
	// ack_required/strict_reject 的裸 gin.H 回應，前後端同步收斂為 registry 碼；
	// risks 陣列經 Meta 平鋪保留，前端據 code 分支彈確認框的控制流不變（值同步改）
	CodeTransmissionAckRequired = register("VALIDATION_TRANSMISSION_ACK_REQUIRED", Descriptor{
		ZhFallback: "設定含不安全傳輸，需附風險確認聲明（risk_acknowledged）"})
	// 識別字帶 Save 以與 codes_connect.go 的連線閘 RULE_TRANSMISSION_STRICT_REJECT 區分
	CodeTransmissionSaveStrictReject = register("VALIDATION_TRANSMISSION_STRICT_REJECT", Descriptor{
		ZhFallback: "傳輸安全政策（嚴格）拒絕存檔：設定含不安全傳輸"})
)
