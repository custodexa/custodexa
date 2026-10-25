package asset

import (
	"context"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
)

// 帳號列的動作判定（範圍化檢視者讀到引用範圍外憑證的帳號列時使用）。
//
// 每個動作以該動作寫入端點的同一個判定函式、同一個請求形狀求值，只是不開交易、不取鎖、不寫入：
// 更換憑證照所屬資產判定（掛載能力，不帶目標憑證：選單只列範圍內來源，選定的來源由寫入端點再判）；
// 移除帳號照帳號寫入範圍判定；更正登記秘密與脫離共用照憑證管理判定（歸屬在範圍外即不成立）。
// 旗標只決定畫面，寫入端點照常自行裁決。

// 帳號列動作鍵。
const (
	AccountRowActionRebind    = "rebind"
	AccountRowActionRemove    = "remove"
	AccountRowActionSecretFix = "secret_fix"
	AccountRowActionDetach    = "detach"
)

// AccountRowChecks 帳號列各動作的判定結果：nil＝可操作；非 nil 為該寫入端點會回的拒絕
// （能力拒絕、範圍拒絕），或判定本身無法完成的錯誤（由呼叫端分辨）。
type AccountRowChecks struct {
	Rebind    error
	Remove    error
	SecretFix error
	Detach    error
}

// AccountRowActionJudge 帳號列動作判定；組裝根以正式的憑證服務與帳號服務建立。
type AccountRowActionJudge struct {
	credentials *CredentialService
	accounts    *AssetAccountService
}

// NewAccountRowActionJudge 建立帳號列動作判定。
func NewAccountRowActionJudge(credentials *CredentialService, accounts *AssetAccountService) *AccountRowActionJudge {
	return &AccountRowActionJudge{credentials: credentials, accounts: accounts}
}

// AccountRowChecks 判定資產 assetID 上引用憑證 credentialID 的帳號 accountID 的四個動作。
func (j *AccountRowActionJudge) AccountRowChecks(ctx context.Context, assetID, accountID, credentialID uint) AccountRowChecks {
	if j == nil || j.credentials == nil || j.accounts == nil {
		return AccountRowChecks{
			Rebind: ErrCredentialAuthzUnavailable, Remove: ErrAccountWriteScopePortMissing,
			SecretFix: ErrCredentialAuthzUnavailable, Detach: ErrCredentialAuthzUnavailable,
		}
	}
	db := database.DB
	c := j.credentials
	return AccountRowChecks{
		// 與 Rebind 同一關卡；目標憑證未選定，只帶所屬資產
		Rebind: c.requireManagement(ctx, db, CredOpBind, []string{CredCapBind}, nil, []uint{assetID}),
		// 與帳號刪除同一個範圍判定
		Remove: j.accounts.checkAccountWrite(ctx, db, assetID, accountID),
		// 與宣告新秘密同一關卡（能力加全部掛載）
		SecretFix: c.requireBoundManagement(ctx, db, CredOpSetSecret, credentialID, CredCapSetSecret),
		// 與單台脫離的起始交易同一個請求形狀
		Detach: func() error {
			_, err := c.mgmt.require(ctx, db, splitManagementRequest(splitGateDetach(), credentialID,
				[]model.AssetAccount{{ID: accountID, AssetID: assetID}}))
			return err
		}(),
	}
}
