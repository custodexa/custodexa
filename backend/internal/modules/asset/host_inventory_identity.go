package asset

import (
	"errors"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 盤點的登入身分：只回一個已納管帳號，不回候選清單；取密與選身分綁在同一個來源實作，
// 日後接上其他身分時只換來源實作與組裝根，盤點本體不動。

var (
	ErrInventoryPlatformUnsupported = errors.New("inventory: platform unsupported")
	ErrInventoryNoAccount           = errors.New("inventory: asset has no default account")
	ErrInventoryNoSecret            = errors.New("inventory: default account has no effective secret")
)

// inventoryIdentity 一次盤點的登入身分。
type inventoryIdentity struct {
	AccountID uint
	Mode      string
	// Username 專用帳號身分的帳號名（預設帳號身分為空）；只供審計與頻率鍵使用，不進讀取回應。
	Username string
}

// inventoryIdentitySource 決定盤點用哪個已納管帳號登入，並負責取該身分的密文。
type inventoryIdentitySource interface {
	Resolve(tx *gorm.DB, asset *model.Asset) (inventoryIdentity, error)
	Credentials(asset *model.Asset, id inventoryIdentity) (*AssetCredentials, error)
}

// inventoryPlatformSupported 只支援 POSIX：協定為 SSH 且有效改密通道恰為 posix_ssh。
func inventoryPlatformSupported(a *model.Asset) bool {
	return a.Protocol == model.ProtocolSSH && a.EffectiveRotationChannel() == model.RotationChannelPosixSSH
}

// inventoryCredentialFetcher 依（資產、帳號）取憑證的窄介面（AssetService 實作）。
type inventoryCredentialFetcher interface {
	GetWithCredentialsForAccount(assetID, accountID uint) (*AssetCredentials, error)
}

// defaultAccountIdentitySource 以資產的預設帳號降級盤點。
type defaultAccountIdentitySource struct {
	creds inventoryCredentialFetcher
}

func newDefaultAccountIdentitySource(f inventoryCredentialFetcher) *defaultAccountIdentitySource {
	return &defaultAccountIdentitySource{creds: f}
}

// Resolve 取該資產的預設帳號；沒有則 ErrInventoryNoAccount；沒有生效密文則 ErrInventoryNoSecret。
func (s *defaultAccountIdentitySource) Resolve(tx *gorm.DB, asset *model.Asset) (inventoryIdentity, error) {
	if !inventoryPlatformSupported(asset) {
		return inventoryIdentity{}, ErrInventoryPlatformUnsupported
	}
	var acc model.AssetAccount
	err := tx.Where("asset_id = ? AND is_default = ?", asset.ID, true).First(&acc).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return inventoryIdentity{}, ErrInventoryNoAccount
	}
	if err != nil {
		return inventoryIdentity{}, err
	}
	id := inventoryIdentity{AccountID: acc.ID, Mode: model.HostAccountIdentityDefault}
	c, err := s.Credentials(asset, id)
	if err != nil {
		return inventoryIdentity{}, err
	}
	c.Destroy()
	return id, nil
}

// Credentials 取執行當下的生效版本；空憑證束即沒有生效密文。
func (s *defaultAccountIdentitySource) Credentials(asset *model.Asset, id inventoryIdentity) (*AssetCredentials, error) {
	c, err := s.creds.GetWithCredentialsForAccount(asset.ID, id.AccountID)
	if errors.Is(err, ErrAssetAccountNotFound) {
		return nil, ErrInventoryNoAccount
	}
	if err != nil {
		return nil, err
	}
	if c.AccountID != id.AccountID {
		c.Destroy()
		return nil, ErrInventoryNoAccount
	}
	if c.Password.IsEmpty() && c.PrivateKey.IsEmpty() {
		c.Destroy()
		return nil, ErrInventoryNoSecret
	}
	return c, nil
}
