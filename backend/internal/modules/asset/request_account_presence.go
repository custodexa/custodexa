package asset

import (
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// RequestAccountPresent checks authoritative credential names on live login mounts
// (an executor mount answers the same as a missing account).
// No credential material is returned to the request module.
func RequestAccountPresent(db *gorm.DB, assetID uint, name string) (bool, error) {
	var n int64
	err := db.Table("asset_accounts aa").Joins("JOIN credentials c ON c.id=aa.credential_id AND c.deleted_at IS NULL").Where("aa.asset_id=? AND aa.deleted_at IS NULL AND aa.purpose=? AND c.username=?", assetID, model.AccountPurposeLogin, name).Count(&n).Error
	return n > 0, err
}
