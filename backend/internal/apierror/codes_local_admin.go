package apierror

// 「最後一個本地 admin」不變式的出口碼（idp-oidc-integration 2.7）。
//
// 與既有的 RULE_USER_LAST_ADMIN_DELETE／_DISABLE 語義**不同**、故不複用：
// 那兩碼問的是「還有沒有 admin」，本碼問的是「還有沒有**本地** admin」
// （啟用中、具 admin 角色、且憑證未由外部身分提供者託管）。系統封印後的解封
// 只認本地 admin 憑證（seal_verify.go），全員切 SSO 後即使 admin 帳號滿地，
// 遇 KEK 重啟仍無人能解封——這是持久性的管理面鎖死，故需獨立一碼讓管理端
// 能給出「請先建立或啟用另一個本地管理員」這句可行動的指引。
//
// 本檔與 codes.go 同一 registry，分檔僅為並行開發隔離。
var (
	// CodeLastLocalAdmin 操作將使「啟用中且未外部化的 admin」數量自一降為零。
	// 數量已為零時本不變式不阻擋任何操作（既有部署不得被鎖死），故此碼只會
	// 出現在「原本還有、這一刀之後就沒了」的情形。
	CodeLastLocalAdmin = register("RULE_USER_LAST_LOCAL_ADMIN", Descriptor{
		ZhFallback: "此操作將使系統失去最後一個本地管理員（啟用中且憑證未由外部身分提供者託管）；系統封印後僅本地管理員可解封，故拒絕。請先建立或啟用另一個本地管理員帳號",
	})
)
