package apierror

// 鍵盤紀錄查看端點的出口碼。與 codes.go 同一 registry，分檔僅為並行開發隔離。
//
// 回應文字一律不含任何按鍵內容；原因細節只進伺服器端 log 與告警鏈。
var (
	// CodeKeystrokeReasonRequired 查看理由缺少或去除前後空白後為空。
	CodeKeystrokeReasonRequired = register("VALIDATION_KEYSTROKE_REASON_REQUIRED", Descriptor{
		ZhFallback: "查看鍵盤紀錄須填寫理由"})
	// CodeKeystrokeReasonTooLong 查看理由超過 1000 個字元（以字元計，非位元組）。
	CodeKeystrokeReasonTooLong = register("VALIDATION_KEYSTROKE_REASON_TOO_LONG", Descriptor{
		ZhFallback: "查看理由不得超過 1000 個字元"})
	// CodeKeystrokeNotViewable 此連線沒有可查看的鍵盤紀錄內容（上線前、不產生、未建立、已清除等）。
	CodeKeystrokeNotViewable = register("RESOURCE_KEYSTROKE_NOT_VIEWABLE", Descriptor{
		ZhFallback: "此連線沒有可查看的鍵盤紀錄內容"})
	// CodeKeystrokeVaultSealed 平台金鑰材料尚未解封，無法解密鍵盤紀錄。
	CodeKeystrokeVaultSealed = register("RULE_KEYSTROKE_VAULT_SEALED", Descriptor{
		ZhFallback: "平台金鑰尚未解封，暫時無法查看鍵盤紀錄"})
	// CodeKeystrokeRecordRejected 紀錄標頭與資料庫不符或檔案路徑越界，不交付任何事件。
	CodeKeystrokeRecordRejected = register("RULE_KEYSTROKE_RECORD_REJECTED", Descriptor{
		ZhFallback: "鍵盤紀錄無法驗證，已拒絕交付內容"})
	// CodeInternalKeystrokeView 查看留痕失敗、讀取失敗等內部錯誤的收斂碼（fail-close，不含內容）。
	CodeInternalKeystrokeView = register("INTERNAL_KEYSTROKE_VIEW", Descriptor{
		ZhFallback: "查看鍵盤紀錄失敗"})
)
