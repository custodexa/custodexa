package identity

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/authz"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestUserServiceDeleteCascade 使用者軟刪連動清理（approval-routing-quorum D-7，
// 對抗驗證 aaa2018 #2）：作審核方/申請人的審核範圍連動軟刪、群組成員關係清除，
// 不留幽靈引用與殘留成員資格
func TestUserServiceDeleteCascade(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	// RefreshToken 為必要：Delete 於同交易內推進 credential_epoch 並撤銷 refresh
	//（idp-oidc-integration 2.8 起），缺表會讓刪除以「撤銷刷新憑證失敗」整筆回滾
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserGroup{},
		&model.Asset{}, &model.ApproverScope{}, &model.AuditLog{},
		&model.RefreshToken{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	svc := NewUserService(db, authz.NewAssetAuthorizationService(db))

	u := model.User{Username: "victim", Email: strPtr("v@x")}
	if err := db.Create(&u).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := db.Create(&model.UserGroup{Name: "G"}).Error; err != nil {
		t.Fatalf("seed group: %v", err)
	}
	if err := db.Exec("INSERT INTO user_group_members (user_group_id, user_id) VALUES (1, ?)", u.ID).Error; err != nil {
		t.Fatalf("seed member: %v", err)
	}
	if err := db.Create(&model.Asset{Name: "a1", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1}).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	aid := uint(1)
	// 作審核方（approver_id）＋作申請人（subject_user_id）各一筆
	if err := db.Create(&model.ApproverScope{ApproverID: &u.ID, AssetID: &aid, GrantedBy: 1}).Error; err != nil {
		t.Fatalf("seed actor scope: %v", err)
	}
	if err := db.Create(&model.ApproverScope{ApproverID: uptrScope(2), SubjectUserID: &u.ID, GrantedBy: 1}).Error; err != nil {
		t.Fatalf("seed subject scope: %v", err)
	}

	if err := svc.Delete(u.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// 審核範圍連動軟刪（作審核方與作申請人兩筆皆失效）
	var activeScopes int64
	db.Model(&model.ApproverScope{}).
		Where("approver_id = ? OR subject_user_id = ?", u.ID, u.ID).
		Count(&activeScopes)
	if activeScopes != 0 {
		t.Errorf("使用者審核範圍應連動軟刪, got %d 活躍", activeScopes)
	}
	// 群組成員關係清除（否則殘留列可回復審核方群組資格）
	var members int64
	db.Table("user_group_members").Where("user_id = ?", u.ID).Count(&members)
	if members != 0 {
		t.Errorf("群組成員關係應清除, got %d", members)
	}
	// 使用者本身軟刪
	var alive int64
	db.Model(&model.User{}).Where("id = ?", u.ID).Count(&alive)
	if alive != 0 {
		t.Errorf("使用者應軟刪, got %d 活躍", alive)
	}
}

// TestUserServiceAddRole 冪等追加單一角色（approval-routing-quorum 一站式代配，
// codex #1）：不覆蓋既有角色集、重複追加 no-op、未知使用者/角色明確拒絕——
// 對照 AssignRoles 整包替換語義，代配路徑不得以過期快照蓋回他處變更
func TestUserServiceAddRole(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Role{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	svc := NewUserService(db, authz.NewAssetAuthorizationService(db))

	for _, r := range []string{"user", "approver"} {
		if err := db.Create(&model.Role{Name: r}).Error; err != nil {
			t.Fatalf("seed role %s: %v", r, err)
		}
	}
	u := model.User{Username: "alice", Email: strPtr("a@x")}
	if err := db.Create(&u).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := db.Exec("INSERT INTO user_roles (user_id, role_id) VALUES (?, 1)", u.ID).Error; err != nil {
		t.Fatalf("seed existing role: %v", err)
	}

	if err := svc.AddRole(u.ID, "approver"); err != nil {
		t.Fatalf("AddRole: %v", err)
	}
	var count int64
	db.Table("user_roles").Where("user_id = ?", u.ID).Count(&count)
	if count != 2 {
		t.Errorf("追加後應保留既有角色（user+approver 共 2），得 %d", count)
	}

	// 冪等：同角色再追加 no-op
	if err := svc.AddRole(u.ID, "approver"); err != nil {
		t.Fatalf("重複 AddRole 應 no-op: %v", err)
	}
	db.Table("user_roles").Where("user_id = ?", u.ID).Count(&count)
	if count != 2 {
		t.Errorf("重複追加不應增列，得 %d", count)
	}

	if err := svc.AddRole(u.ID, "nonexistent"); !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("未知角色應 ErrRoleNotFound: %v", err)
	}
	if err := svc.AddRole(9999, "approver"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("未知使用者應 ErrUserNotFound: %v", err)
	}
}
