package apierror

// 來源位址限定（使用者允許網段清單與各判定點）的出口碼。
//
// 分檔理由同 codes_connect.go：同一 registry，只為並行開發隔離。
// 拒絕的**原因細節**（清單內容、命中的位址、政策損壞的成因）只進稽核，
// 對外一律收斂為下列機器碼——回應不回顯位址值與清單內容。

// --- AUTH_* ---
var (
	// CodeAuthSourceNotAllowed 憑證（或票證）已驗證通過，但請求來源不在該帳號的
	// 允許網段清單內。**只在憑證驗證之後回覆**（先於憑證驗證即構成帳號存在性
	// 預言機）；正當使用者需要知道該找管理員，而不是重試密碼。
	// 政策不可用（清單讀不到或損壞）也回本碼——對外不分岔，歸因只在稽核。
	CodeAuthSourceNotAllowed = register("AUTH_SOURCE_NOT_ALLOWED", Descriptor{
		ZhFallback: "目前的來源位址不在允許範圍內，請聯繫管理員"})
)

// --- VALIDATION_*（允許網段清單與位址參數）---
var (
	// CodeValidationSourcePrefixInvalid 清單含無法解析為位址或 CIDR 的項目：
	// 任一項失敗整體拒絕（fail-close），不靜默丟棄
	CodeValidationSourcePrefixInvalid = register("VALIDATION_SOURCE_PREFIX_INVALID", Descriptor{
		ZhFallback: "允許來源網段含無法解析的項目"})
	// CodeValidationSourcePrefixLimit 去重後超過每帳號上限（32 項）
	CodeValidationSourcePrefixLimit = register("VALIDATION_SOURCE_PREFIX_LIMIT", Descriptor{
		ZhFallback: "允許來源網段超過上限（32 項）"})
	// CodeValidationSourceAddress 參數不是合法的 IPv4／IPv6 位址
	//（稽核工作台的 subject_ip／client_ip 篩選；client_ip 的保留字 unknown 除外）
	CodeValidationSourceAddress = register("VALIDATION_SOURCE_ADDRESS", Descriptor{
		ZhFallback: "不是合法的來源位址"})
)
