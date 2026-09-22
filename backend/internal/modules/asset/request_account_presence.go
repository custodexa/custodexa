package asset

import "gorm.io/gorm"

// RequestAccountPresent checks authoritative credential names on live mounts.
// No credential material is returned to the request module.
func RequestAccountPresent(db *gorm.DB, assetID uint, name string) (bool, error) {
	var n int64
	err := db.Table("asset_accounts aa").Joins("JOIN credentials c ON c.id=aa.credential_id AND c.deleted_at IS NULL").Where("aa.asset_id=? AND aa.deleted_at IS NULL AND c.username=?", assetID, name).Count(&n).Error
	return n > 0, err
}
