package authz

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 常設連線資格與帳號範圍測試共用的 fixture：不假設 seedRequestFixture 給了使用者什麼授權，
// 每個 helper 先清掉該使用者對該資產的全部直授列，再寫入指定的授權。

// clearDirectGrants 硬刪使用者對資產的全部直授授權列（含臨時授權）。
func clearDirectGrants(t *testing.T, db *gorm.DB, userID, assetID uint) {
	t.Helper()
	if err := db.Unscoped().Where("user_id = ? AND asset_id = ?", userID, assetID).Delete(&model.AssetAuthorization{}).Error; err != nil {
		t.Fatalf("clear grants: %v", err)
	}
}

// setStanding 使用者對資產只持一筆常設 connect，帳號範圍為 accounts（空＝全部帳號）。
func setStanding(t *testing.T, db *gorm.DB, userID, assetID uint, accounts ...string) {
	t.Helper()
	clearDirectGrants(t, db, userID, assetID)
	u, a := userID, assetID
	row := model.AssetAuthorization{UserID: &u, AssetID: &a, Permission: model.PermissionConnect, GrantedBy: 3, Source: model.AuthorizationSourceManual}
	if len(accounts) > 0 {
		row.Accounts = model.NormalizeAccountScope(accounts)
	}
	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("seed standing connect: %v", err)
	}
}

// setViewOnly 使用者對資產只持常設 view。
func setViewOnly(t *testing.T, db *gorm.DB, userID, assetID uint) {
	t.Helper()
	clearDirectGrants(t, db, userID, assetID)
	u, a := userID, assetID
	if err := db.Create(&model.AssetAuthorization{UserID: &u, AssetID: &a, Permission: model.PermissionView, GrantedBy: 3, Source: model.AuthorizationSourceManual}).Error; err != nil {
		t.Fatalf("seed view: %v", err)
	}
}

// addAssetAccount 讓資產上存在指定帳號名（帳號存在性檢查用）。
func addAssetAccount(t *testing.T, db *gorm.DB, assetID uint, name string) {
	t.Helper()
	c := model.Credential{Username: name, Scope: model.CredentialScopeDedicated, SecretType: "password", ProtocolFamily: model.ProtocolFamilySSH}
	if err := db.Create(&c).Error; err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	if err := db.Create(&model.AssetAccount{AssetID: assetID, CredentialID: c.ID, Username: name}).Error; err != nil {
		t.Fatalf("seed asset account: %v", err)
	}
}

// ticketRows 回傳該使用者名下全部臨時授權列（核准流來源）。
func ticketRows(t *testing.T, db *gorm.DB, userID uint) []model.AssetAuthorization {
	t.Helper()
	var rows []model.AssetAuthorization
	if err := db.Where("user_id = ? AND source = ?", userID, model.AuthorizationSourceTicket).Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("load tickets: %v", err)
	}
	return rows
}

func countRows(t *testing.T, db *gorm.DB, m any) int64 {
	t.Helper()
	var n int64
	if err := db.Model(m).Count(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// scopeIs 帳號範圍是否恰為指定名單（空名單＝全部帳號）。
func scopeIs(got model.AccountScope, want ...string) bool {
	if len(want) == 0 {
		return got.IsAll()
	}
	if got.IsAll() || len(got) != len(want) {
		return false
	}
	for _, w := range want {
		if !got.Contains(w) {
			return false
		}
	}
	return true
}
