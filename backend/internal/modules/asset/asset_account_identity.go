package asset

import (
	"github.com/custodexa/backend/internal/database"
)

// asset 模組：連線帳號身分解析（modular-architecture W6 6.5／R3.1 §5.4 拆檔）。
//
// 自 `account_scope_service.go`（authz）遷出：該檔的主體是授權帳號範圍判定，
// 但 `AccountIdentity` 與 `ResolveAccountIdentity` 是 asset 的型別與其方法。
// 兩者的呼叫關係（authz 的強制點呼叫 asset 的解析）不變，改變的只是宣告位置。

// AccountIdentity 帳號的身分（不含憑證）：強制點把 account_id 轉為判定所需的
// 名字，不必解密憑證。Found=false＝零帳號資產（合法狀態，見 resolveAssetAccount）
type AccountIdentity struct {
	AccountID uint
	Username  string
	Found     bool
}

// ResolveAccountIdentity 解析連線將實際使用的帳號身分（accountID=0＝預設帳號）。
//
// 與 GetWithCredentialsForAccount 共用 resolveAssetAccount，故客體綁定 fail-close
// 語義完全一致；差別只在不碰密文——簽發點只需要判定，不需要（也不該）解密憑證
func (s *AssetService) ResolveAccountIdentity(assetID, accountID uint) (AccountIdentity, error) {
	account, err := resolveAssetAccount(database.DB, assetID, accountID)
	if err != nil {
		return AccountIdentity{}, err
	}
	if account == nil {
		return AccountIdentity{}, nil
	}
	return AccountIdentity{AccountID: account.ID, Username: account.Username, Found: true}, nil
}
