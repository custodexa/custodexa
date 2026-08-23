package model

import (
	"context"
)

// 資產帳號操作審計。
//
// 為何不掛 GORM hook（Asset 的做法）：帳號變更的可稽核事實是「哪個欄位被動過」，
// 而 hook 拿不到 diff（AfterUpdate 只看得到新值）——Asset 的 hook 正因此只能記
// 空 Details，真正的 diff 由 service 顯式呼叫 RecordAssetChange 補。帳號直接走
// 顯式呼叫，省掉「空事件 ＋ 補記事件」兩筆的既有毛病。
//
// 安全紅線：Details **只記欄位名稱**，永不含 PasswordEnc/PrivateKeyEnc 的密文或
// 任何明文憑證——審計庫的讀取面遠比憑證欄寬（auditor 角色、匯出、syslog 轉發），
// 把密文寫進去等於把憑證複製到一個防護較弱的位置。

// 帳號操作類型（審計 Details 的 operation 欄）
const (
	AccountOpCreate     = "create"
	AccountOpUpdate     = "update"
	AccountOpDelete     = "delete"
	AccountOpSetDefault = "set_default"
	// AccountOpDiscardCandidate admin 顯式清除未驗證的候選憑證
	// 候選是那把可能已在遠端生效的秘密的
	// 唯一副本，清除後只能以帶外途徑救回該帳號，故必須留痕
	AccountOpDiscardCandidate = "discard_candidate"
)

// AssetAccountAudit 一次帳號操作的可稽核事實
type AssetAccountAudit struct {
	AssetID   uint
	AccountID uint
	// Username 操作當下的帳號名稱（帳號可能隨後改名或刪除，快照才問責得到人）
	Username string
	// Operation 見 AccountOp* 常數
	Operation string
	// Fields 被變更的欄位名稱清單（password/private_key 只記名稱，不記值）
	Fields []string
	// CopyFromAssetID／CopyFromAccount 建號時「從其他資產帳號複製」的來源出處。
	// 憑證跨資產複製若零軌跡，事後無從回答「這台的 root 密碼哪來的」；
	// 記的是 id 不是值，不觸及密文
	CopyFromAssetID uint
	CopyFromAccount uint
}

// AssetAccountAuditDetails 審計 Details 的 JSON 形狀（與 AssetChangeDetails 平行，
// 但獨立命名——帳號事件的讀者需要一眼看出這不是資產欄位 diff）
type AssetAccountAuditDetails struct {
	Resource  string   `json:"resource"`
	AccountID uint     `json:"account_id"`
	Username  string   `json:"account_username"`
	Operation string   `json:"operation"`
	Fields    []string `json:"fields,omitempty"`
	// 複製建號的來源出處（僅 create 且走複製時出現）
	CopyFromAssetID uint `json:"copy_from_asset_id,omitempty"`
	CopyFromAccount uint `json:"copy_from_account_id,omitempty"`
}

// `RecordAssetAccountChange` 與其私有的 `auditActionForAccountOp`
// 已隨 T-2 收口遷入 asset 模組（`internal/modules/asset/asset_audit_events.go` 的
// `writeAssetAccountAudit`），落地改經 `audit/port.WriteInTx`。本檔只留資料型別。

// UserFromContext 匯出 context 中的操作者身分（service 層審計呼叫用）。
// 無身分時回 (0, "system")——系統路徑（改密 runner、遷移）的操作同樣要留痕。
func UserFromContext(ctx context.Context) (uint, string) {
	return getUserFromContext(ctx)
}
