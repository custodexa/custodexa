package authz

// 權限型別與最初的 11 個權限點常數。
//
// 舊的角色→權限對照函式已移除：授權判定改由權限目錄（permission_catalog.go）、
// 路由登錄與內建範本（builtin_templates.go）承擔，角色名不再直接對應權限。
// 本檔只保留型別與常數，不得引入任何 DB 存取或模組相依。

// Permission 權限常數
type Permission string

const (
	// Asset 權限
	PermAssetView   Permission = "asset:view"
	PermAssetCreate Permission = "asset:create"
	PermAssetUpdate Permission = "asset:update"
	PermAssetDelete Permission = "asset:delete"
	PermAssetTest   Permission = "asset:test"

	// Session 權限
	PermSessionView      Permission = "session:view"
	PermSessionTerminate Permission = "session:terminate"

	// Audit 權限
	PermAuditView Permission = "audit:view"

	// Alert 權限
	PermAlertView   Permission = "alert:view"
	PermAlertManage Permission = "alert:manage"

	// Credential 權限：憑證庫的建立、掛載、卸載、改密、範圍轉換與脫離共用。
	//
	// **不列入 user 與 auditor**：憑證識別、名稱與掛載拓撲合起來就是一張
	// 「哪些主機共用同一組秘密」的地圖，對非管理者而言那是免費的橫向移動路線。
	// 稽核角色要核對共用關係走輪替證據報告（只投影名稱與共用標記，不含識別與密文），
	// 那是刻意的顯式例外，不以本授權點承載。
	PermCredentialManage Permission = "credential:manage"
)
