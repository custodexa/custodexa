package identity

import (
	"errors"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 使用者群組刪除後同名重建。
//
// 正式庫的群組名稱唯一索引只計未刪除列（部分唯一，由增量 migration 建立）；以 model 建表的測試庫
// 依 `uniqueIndex` 標記建出的是涵蓋全部列的唯一索引。不換掉的話，重建必然撞索引，測到的是夾具而
// 不是產品行為，故夾具換成與正式庫相同形狀的索引（使用者名稱索引的既有作法）。
var userGroupNameLiveUniqueFixture = []string{
	`DROP INDEX IF EXISTS idx_user_groups_name`,
	`CREATE UNIQUE INDEX idx_user_groups_name ON user_groups (name) WHERE deleted_at IS NULL`,
}

func useLiveUniqueGroupName(t *testing.T, db *gorm.DB) {
	t.Helper()
	for _, stmt := range userGroupNameLiveUniqueFixture {
		if err := db.Exec(stmt).Error; err != nil {
			t.Fatalf("群組名稱部分唯一索引: %v", err)
		}
	}
}

// recreateFixture 一個帶成員與一筆授權的群組，刪除後回傳其識別與連動撤銷的授權識別。
func recreateFixture(t *testing.T, svc *UserGroupService, db *gorm.DB, name string) (oldID, grantID uint) {
	t.Helper()
	users := seedUsers(t, db, name+"-member")
	g, err := svc.Create(&UserGroupRequest{Name: name, Description: "first"})
	if err != nil {
		t.Fatalf("建立群組: %v", err)
	}
	if _, err := svc.ReplaceMembers(g.ID, []uint{users[0].ID}); err != nil {
		t.Fatalf("加入成員: %v", err)
	}
	asset := model.Asset{Name: name + "-asset", Protocol: "ssh", Host: "198.51.100.10", Port: 22, CreatedBy: 1}
	if err := db.Create(&asset).Error; err != nil {
		t.Fatalf("建立資產: %v", err)
	}
	grant := model.AssetAuthorization{UserGroupID: &g.ID, AssetID: &asset.ID, Permission: model.PermissionConnect, GrantedBy: 1}
	if err := db.Create(&grant).Error; err != nil {
		t.Fatalf("建立授權: %v", err)
	}
	if revoked, err := svc.Delete(g.ID, 1, "admin", "203.0.113.5"); err != nil || revoked != 1 {
		t.Fatalf("刪除群組: revoked=%d err=%v", revoked, err)
	}
	return g.ID, grant.ID
}

func TestUserGroupRecreateAfterDelete(t *testing.T) {
	t.Run("fixture_precondition_full_unique_index_blocks_recreate", func(t *testing.T) {
		// 前提：未換索引時（舊版的形狀）刪除後同名建立被判重複，證明下列案例依賴部分唯一索引
		svc, db := setupUserGroupDB(t)
		recreateFixture(t, svc, db, "legacy")
		if _, err := svc.Create(&UserGroupRequest{Name: "legacy"}); !errors.Is(err, ErrUserGroupNameExists) {
			t.Fatalf("涵蓋全部列的唯一索引下，同名重建應回名稱重複，得 %v", err)
		}
	})

	t.Run("recreate_gets_new_id_and_revoked_grants_stay_revoked", func(t *testing.T) {
		svc, db := setupUserGroupDB(t)
		useLiveUniqueGroupName(t, db)
		oldID, grantID := recreateFixture(t, svc, db, "ops")

		g, err := svc.Create(&UserGroupRequest{Name: "ops", Description: "second"})
		if err != nil {
			t.Fatalf("刪除後同名建立應成功: %v", err)
		}
		if g.ID == oldID {
			t.Fatalf("重建的群組應得到新的識別，得到舊識別 %d", g.ID)
		}
		got, err := svc.Get(g.ID)
		if err != nil {
			t.Fatalf("讀取重建的群組: %v", err)
		}
		if got.Name != "ops" || got.Description != "second" || len(got.UserIDs) != 0 || len(got.Users) != 0 {
			t.Fatalf("重建的群組應為全新、無成員：%+v", got)
		}
		// 原群組連動撤銷的授權不恢復：仍為軟刪、仍指向舊識別，新群組名下沒有任何授權
		var revoked model.AssetAuthorization
		if err := db.Unscoped().First(&revoked, grantID).Error; err != nil {
			t.Fatalf("讀取已撤銷授權: %v", err)
		}
		if !revoked.DeletedAt.Valid || revoked.UserGroupID == nil || *revoked.UserGroupID != oldID {
			t.Fatalf("原授權應維持撤銷並指向舊群組：%+v", revoked)
		}
		if n, err := svc.AuthorizationCount(g.ID); err != nil || n != 0 {
			t.Fatalf("新群組不應帶任何授權：n=%d err=%v", n, err)
		}
		if n, err := svc.AuthorizationCount(oldID); err != nil || n != 0 {
			t.Fatalf("舊群組的授權不應恢復：n=%d err=%v", n, err)
		}
		// 列表只有新群組
		groups, err := svc.List()
		if err != nil || len(groups) != 1 || groups[0].ID != g.ID {
			t.Fatalf("列表應只含重建的群組：%+v %v", groups, err)
		}
	})

	t.Run("live_group_name_still_conflicts", func(t *testing.T) {
		svc, db := setupUserGroupDB(t)
		useLiveUniqueGroupName(t, db)
		recreateFixture(t, svc, db, "ops")
		if _, err := svc.Create(&UserGroupRequest{Name: "ops"}); err != nil {
			t.Fatalf("重建: %v", err)
		}
		if _, err := svc.Create(&UserGroupRequest{Name: "ops"}); !errors.Is(err, ErrUserGroupNameExists) {
			t.Fatalf("現存群組同名建立應回名稱重複，得 %v", err)
		}
		other, err := svc.Create(&UserGroupRequest{Name: "dev"})
		if err != nil {
			t.Fatalf("建立另一個群組: %v", err)
		}
		if _, err := svc.Update(other.ID, &UserGroupRequest{Name: "ops"}); !errors.Is(err, ErrUserGroupNameExists) {
			t.Fatalf("改名成現存群組的名稱應回名稱重複，得 %v", err)
		}
	})

	t.Run("deleted_group_keeps_its_name_in_audit_and_history", func(t *testing.T) {
		svc, db := setupUserGroupDB(t)
		useLiveUniqueGroupName(t, db)
		oldID, _ := recreateFixture(t, svc, db, "ops")
		var before model.AuditLog
		if err := db.Where("resource = ? AND action = ? AND resource_id = ?", model.ResourceUserGroup, model.ActionDelete, oldID).
			First(&before).Error; err != nil {
			t.Fatalf("刪除的稽核列應存在: %v", err)
		}
		if !strings.Contains(before.Details, `"group_name":"ops"`) {
			t.Fatalf("刪除的稽核列應記下群組名稱：%s", before.Details)
		}

		g, err := svc.Create(&UserGroupRequest{Name: "ops"})
		if err != nil {
			t.Fatalf("重建: %v", err)
		}
		// 重建後再把新群組改名，舊群組的稽核列與資料列都不應被牽動
		if _, err := svc.Update(g.ID, &UserGroupRequest{Name: "ops-renamed"}); err != nil {
			t.Fatalf("改名: %v", err)
		}
		var after model.AuditLog
		if err := db.First(&after, before.ID).Error; err != nil {
			t.Fatalf("重讀稽核列: %v", err)
		}
		if after.Details != before.Details || after.ResourceID == nil || *after.ResourceID != oldID {
			t.Fatalf("刪除的稽核列不應改變：前 %s，後 %s", before.Details, after.Details)
		}
		var deleted model.UserGroup
		if err := db.Unscoped().First(&deleted, oldID).Error; err != nil {
			t.Fatalf("讀取已刪除群組列: %v", err)
		}
		if deleted.Name != "ops" || !deleted.DeletedAt.Valid {
			t.Fatalf("已刪除群組應保留刪除當時的名稱：%+v", deleted)
		}
	})
}
