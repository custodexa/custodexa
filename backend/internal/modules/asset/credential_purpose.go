package asset

import (
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 憑證用途一致：同一筆憑證的未刪除掛載，用途（登入帳號／執行身分）必須全部相同。
//
// 共用憑證若在甲台是執行身分、在乙台是登入帳號，人員在乙台連線就拿得到與甲台執行身分
// 同一組秘密，「執行身分不能拿來連線」形同虛設。判定在已持該憑證列鎖的交易內呼叫，
// 序列化由憑證列鎖承擔。

// ErrCredentialPurposeMismatch 憑證已以另一種用途掛在其他資產上。
var ErrCredentialPurposeMismatch = errors.New("這組憑證已用於另一種用途（登入帳號或堡壘機專用帳號），不可混用")

// ErrAssetAccountExecutorManaged 既有帳號端點的目標是執行身分：只能經執行身分端點處理。
var ErrAssetAccountExecutorManaged = errors.New("這筆是堡壘機專用帳號，請由資產的專用帳號區塊處理")

// assertCredentialPurpose 憑證的其他未刪除掛載用途與 purpose 不同即拒絕。
func assertCredentialPurpose(tx *gorm.DB, credentialID uint, purpose string) error {
	if credentialID == 0 {
		return nil
	}
	var other int64
	if err := tx.Model(&model.AssetAccount{}).
		Where("credential_id = ? AND purpose <> ?", credentialID, purpose).
		Count(&other).Error; err != nil {
		return fmt.Errorf("檢查憑證用途失敗: %w", err)
	}
	if other > 0 {
		return ErrCredentialPurposeMismatch
	}
	return nil
}
