package apierror

// 系統告警目錄與明細（system_alert_handler.go）。
var (
	// CodeSystemAlertSeverity 分級不是 high／medium／low。
	CodeSystemAlertSeverity = register("VALIDATION_SYSTEM_ALERT_SEVERITY", Descriptor{
		ZhFallback: "系統告警分級必須為 high、medium 或 low"})
	// CodeSystemAlertLocked 請求帶了分級以外的欄位（含啟停、刪除意圖）：系統告警只能調分級。
	CodeSystemAlertLocked = register("VALIDATION_SYSTEM_ALERT_LOCKED", Descriptor{
		ZhFallback: "系統告警只能調整分級，不能停用或刪除"})
	// CodeSystemAlertTypeNotFound 類型鍵未登錄。
	CodeSystemAlertTypeNotFound = register("NOTFOUND_SYSTEM_ALERT_TYPE", Descriptor{
		ZhFallback: "系統告警類型不存在"})
	// CodeInternalSystemAlertRaise 交易內產生系統告警或寫分級調整的審計失敗，整筆變更已回滾
	// （生產端與分級調整共用同一碼：兩者都是「變更與其留痕同生同滅」）。
	CodeInternalSystemAlertRaise = register("INTERNAL_SYSTEM_ALERT_RAISE", Descriptor{
		ZhFallback: "系統告警處理失敗，變更已取消"})
)
