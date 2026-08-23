package authz

import (
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupCascadeDB 級聯撤銷的真 SQLite 環境（軟刪語義必須實跑才算驗過）。
func setupCascadeDB(t *testing.T) (*AssetAuthorizationService, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.UserGroup{}, &model.Asset{}, &model.AssetGroup{},
		&model.AssetNode{}, &model.AssetAuthorization{}, &model.ApproverScope{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewAssetAuthorizationService(db), db
}

func uptrCascade(v uint) *uint { return &v }

// TestCascadeRevokeByAssetGroup 節點刪除的級聯撤銷本體（tx-taking 窄 port）。
//
// **遷移說明（是否放寬：否）**：這三條 DB 級斷言（授權軟刪留痕、
// 審核範圍失效、筆數回傳）原本在 asset 的 `TestAssetGroupDeleteRevokesGrants` 內。
// 撤銷本體收口到 authz 後，asset 的測試不得 import authz（authz→asset 存在，
// 會構成 test import cycle），故本體斷言隨實作一起搬來；asset 側改為斷言
// 「在交易內恰好委派一次、引數正確、兩個筆數落進審計、且 asset 自己不碰 authz 的表」。
func TestCascadeRevokeByAssetGroup(t *testing.T) {
	svc, db := setupCascadeDB(t)
	gid := uint(1)
	if err := db.Create(&model.AssetGroup{Name: "G"}).Error; err != nil {
		t.Fatalf("seed group: %v", err)
	}
	uid := uint(7)
	if err := db.Create(&model.AssetAuthorization{
		UserID: &uid, AssetGroupID: &gid, Permission: model.PermissionConnect, GrantedBy: 1,
	}).Error; err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	if err := db.Create(&model.ApproverScope{
		ApproverID: uptrCascade(9), AssetGroupID: &gid, GrantedBy: 1,
	}).Error; err != nil {
		t.Fatalf("seed scope: %v", err)
	}
	// 他節點的授權不得被誤傷
	other := uint(2)
	if err := db.Create(&model.AssetGroup{Name: "other"}).Error; err != nil {
		t.Fatalf("seed other group: %v", err)
	}
	if err := db.Create(&model.AssetAuthorization{
		UserID: &uid, AssetGroupID: &other, Permission: model.PermissionView, GrantedBy: 1,
	}).Error; err != nil {
		t.Fatalf("seed other grant: %v", err)
	}

	var revoked, revokedScopes int64
	err := db.Transaction(func(tx *gorm.DB) error {
		var e error
		revoked, revokedScopes, e = svc.RevokeByAssetGroup(tx, gid)
		return e
	})
	if err != nil {
		t.Fatalf("RevokeByAssetGroup: %v", err)
	}
	if revoked != 1 || revokedScopes != 1 {
		t.Fatalf("連動撤銷筆數 = (%d, %d), want (1, 1)", revoked, revokedScopes)
	}

	// 授權記錄應被軟刪（預設 scope 查不到、Unscoped 查得到）
	var active int64
	db.Model(&model.AssetAuthorization{}).Where("asset_group_id = ?", gid).Count(&active)
	if active != 0 {
		t.Errorf("活躍授權應為 0, got %d", active)
	}
	var all int64
	db.Unscoped().Model(&model.AssetAuthorization{}).Where("asset_group_id = ?", gid).Count(&all)
	if all != 1 {
		t.Errorf("軟刪記錄應留存供審計, got %d", all)
	}
	// approver 範圍同步軟刪
	var activeScopes int64
	db.Model(&model.ApproverScope{}).Where("asset_group_id = ?", gid).Count(&activeScopes)
	if activeScopes != 0 {
		t.Errorf("活躍審核範圍應為 0, got %d", activeScopes)
	}
	// 他節點不得被誤傷
	var otherActive int64
	db.Model(&model.AssetAuthorization{}).Where("asset_group_id = ?", other).Count(&otherActive)
	if otherActive != 1 {
		t.Errorf("他節點授權不得被誤傷, got %d", otherActive)
	}
}

// TestCascadeRevokeByUserGroup 群組刪除的級聯撤銷本體：
// 授權軟刪＋群組作審核方／作申請人群組的兩類範圍皆失效。
func TestCascadeRevokeByUserGroup(t *testing.T) {
	svc, db := setupCascadeDB(t)
	gid := uint(1)
	if err := db.Create(&model.UserGroup{Name: "G"}).Error; err != nil {
		t.Fatalf("seed group: %v", err)
	}
	aid := uint(1)
	if err := db.Create(&model.AssetAuthorization{
		UserGroupID: &gid, AssetID: &aid, Permission: model.PermissionConnect, GrantedBy: 1,
	}).Error; err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	if err := db.Create(&model.ApproverScope{ApproverGroupID: &gid, AssetID: &aid, GrantedBy: 1}).Error; err != nil {
		t.Fatalf("seed actor scope: %v", err)
	}
	if err := db.Create(&model.ApproverScope{ApproverID: uptrCascade(1), SubjectGroupID: &gid, GrantedBy: 1}).Error; err != nil {
		t.Fatalf("seed subject-group scope: %v", err)
	}

	var revoked int64
	err := db.Transaction(func(tx *gorm.DB) error {
		var e error
		revoked, e = svc.RevokeByUserGroup(tx, gid)
		return e
	})
	if err != nil {
		t.Fatalf("RevokeByUserGroup: %v", err)
	}
	if revoked != 1 {
		t.Fatalf("連動撤銷授權筆數 = %d, want 1", revoked)
	}
	var activeScopes int64
	db.Model(&model.ApproverScope{}).
		Where("approver_group_id = ? OR subject_group_id = ?", gid, gid).Count(&activeScopes)
	if activeScopes != 0 {
		t.Errorf("群組審核範圍應連動軟刪（兩類皆須失效）, got %d 活躍", activeScopes)
	}
	var active int64
	db.Model(&model.AssetAuthorization{}).Where("user_group_id = ?", gid).Count(&active)
	if active != 0 {
		t.Errorf("活躍授權應為 0, got %d", active)
	}
}

// TestCascadeRevokeByUser 帳號刪除的級聯撤銷本體：
// 該人作審核方（approver_id）或作申請人（subject_user_id）的範圍皆失效。
func TestCascadeRevokeByUser(t *testing.T) {
	svc, db := setupCascadeDB(t)
	uid := uint(3)
	aid := uint(1)
	if err := db.Create(&model.ApproverScope{ApproverID: uptrCascade(uid), AssetID: &aid, GrantedBy: 1}).Error; err != nil {
		t.Fatalf("seed actor scope: %v", err)
	}
	if err := db.Create(&model.ApproverScope{
		ApproverID: uptrCascade(9), SubjectUserID: uptrCascade(uid), GrantedBy: 1,
	}).Error; err != nil {
		t.Fatalf("seed subject scope: %v", err)
	}
	// 他人的範圍不得被誤傷
	if err := db.Create(&model.ApproverScope{ApproverID: uptrCascade(9), AssetID: &aid, GrantedBy: 1}).Error; err != nil {
		t.Fatalf("seed other scope: %v", err)
	}

	if err := db.Transaction(func(tx *gorm.DB) error {
		return svc.RevokeByUser(tx, uid)
	}); err != nil {
		t.Fatalf("RevokeByUser: %v", err)
	}
	var active int64
	db.Model(&model.ApproverScope{}).
		Where("approver_id = ? OR subject_user_id = ?", uid, uid).Count(&active)
	if active != 0 {
		t.Errorf("使用者審核範圍應連動軟刪, got %d 活躍", active)
	}
	var others int64
	db.Model(&model.ApproverScope{}).Where("approver_id = ?", 9).Count(&others)
	if others != 1 {
		t.Errorf("他人的審核範圍不得被誤傷, got %d", others)
	}
}
