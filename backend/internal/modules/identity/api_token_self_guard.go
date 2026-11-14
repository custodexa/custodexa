package identity

import (
	"fmt"
	"strings"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
)

// 以 API token 認證的請求不能改動所屬帳號本人的登入材料、狀態與角色，也不能改動本人所屬身分來源的
// 映射規則與提供者設定。
//
// 判定依據是請求主體的事實：只有 API token 閘門建立的主體帶 APITokenAuthMethod；人類工作階段與
// agent 鑰匙的主體不帶，行為不變。判定以實際變更為準（值與現況相同不拒絕），呼叫端在寫入交易內、
// 讀到現值之後呼叫。

// ErrAPITokenSelfChange 以 API token 改動所屬帳號本人的受限設定。
var ErrAPITokenSelfChange = &PrincipalError{Code: apierror.CodeAuthAPITokenSelfChangeForbidden, Status: 403}

// DenyReasonAPITokenSelf 指派關卡以此原因碼拒絕 API token 改動所屬帳號本人的角色。
const DenyReasonAPITokenSelf = "api_token_self_change"

// ViaAPIToken 這個操作者是否由以 API token 認證的請求建構（所屬帳號＝UserID）。
func (o Operator) ViaAPIToken() bool {
	return !o.system && o.UserID != 0 && o.Principal != nil && o.Principal.UserID == o.UserID &&
		o.Principal.Facts.AuthMethod == APITokenAuthMethod
}

// apiTokenSelfChange 以 API token 對所屬帳號本人做出實際變更時回 ErrAPITokenSelfChange。
func apiTokenSelfChange(op Operator, targetID uint, changed bool) error {
	if changed && targetID != 0 && targetID == op.UserID && op.ViaAPIToken() {
		return ErrAPITokenSelfChange
	}
	return nil
}

// accountOpAlwaysChanges 這些帳號操作對所屬帳號本人一律構成受限變更：設定密碼、綁定與解除外部身分、停用、刪除。
// 停用以 API token 認證的帳號必然啟用中，停用一定是實際變更；啟用對啟用中的帳號不是變更，不在此列。
// 停用兩步驟驗證是否構成變更取決於現況，由呼叫端判定。
func accountOpAlwaysChanges(a AccountOperation) bool {
	switch a {
	case AccountOpPasswordChange, AccountOpExternalBound, AccountOpExternalUnbound, AccountOpDisable, AccountOpDelete:
		return true
	}
	return false
}

// apiTokenOwnerInSource 所屬帳號是否在某個身分來源有外部身分。
//
//   - 目錄來源：帳號是目錄來源的帳號即屬之（目錄來源唯一；這類帳號沒有外部身分資料列）。
//   - 外部身分提供者：帳號有任一外部身分的簽發者與用戶端識別與該提供者相同；以身分域比對，不以設定的識別比對。
//
// 本地且沒有任何外部身分的帳號不屬於任何來源。
func apiTokenOwnerInSource(tx *gorm.DB, ownerID uint, kind string, sourceID uint) (bool, error) {
	switch kind {
	case model.RoleMappingChannelKindDirectory:
		return apiTokenOwnerIsDirectoryAccount(tx, ownerID)
	case model.RoleMappingChannelKindProvider:
		var p model.OIDCProvider
		if err := tx.Unscoped().Select("id", "issuer", "client_id").First(&p, sourceID).Error; err != nil {
			return false, fmt.Errorf("讀取身分提供者失敗: %w", err)
		}
		return apiTokenOwnerInIdentityDomain(tx, ownerID, p.Issuer, p.ClientID)
	default:
		return false, ErrMappingSourceKind
	}
}

// apiTokenOwnerIsDirectoryAccount 帳號是否為目錄來源的帳號。
func apiTokenOwnerIsDirectoryAccount(tx *gorm.DB, ownerID uint) (bool, error) {
	var u model.User
	if err := tx.Unscoped().Select("id", "is_ldap", "provisioning_origin").First(&u, ownerID).Error; err != nil {
		return false, fmt.Errorf("讀取帳號失敗: %w", err)
	}
	return u.IsLDAP || u.ProvisioningOrigin == model.AuthSourceLDAP, nil
}

// apiTokenOwnerInIdentityDomain 帳號是否有身分域（簽發者＋用戶端識別）相同的外部身分。
func apiTokenOwnerInIdentityDomain(tx *gorm.DB, ownerID uint, issuer, clientID string) (bool, error) {
	var n int64
	if err := tx.Model(&model.UserExternalIdentity{}).
		Where("user_id = ? AND issuer = ? AND client_id = ?", ownerID, strings.TrimSpace(issuer), strings.TrimSpace(clientID)).
		Count(&n).Error; err != nil {
		return false, fmt.Errorf("讀取外部身分失敗: %w", err)
	}
	return n > 0, nil
}

// apiTokenSourceSelfGate 以 API token 寫入所屬帳號本人所屬身分來源的映射規則或提供者設定時拒絕。
func apiTokenSourceSelfGate(tx *gorm.DB, op Operator, kind string, sourceID uint) error {
	if !op.ViaAPIToken() {
		return nil
	}
	in, err := apiTokenOwnerInSource(tx, op.UserID, kind, sourceID)
	if err != nil {
		return err
	}
	if in {
		return ErrAPITokenSelfChange
	}
	return nil
}

// apiTokenProviderDomainSelfGate 以 API token 建立、更新或刪除與所屬帳號外部身分同身分域的提供者設定時拒絕。
func apiTokenProviderDomainSelfGate(tx *gorm.DB, op Operator, issuer, clientID string) error {
	if !op.ViaAPIToken() {
		return nil
	}
	in, err := apiTokenOwnerInIdentityDomain(tx, op.UserID, issuer, clientID)
	if err != nil {
		return err
	}
	if in {
		return ErrAPITokenSelfChange
	}
	return nil
}
